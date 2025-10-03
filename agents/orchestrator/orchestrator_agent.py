# This is the IT support orchestrator agent which
# contains information about the collaborator agents
# and also contains information about the knowledge base
# that it has access to. This orchestrator agent is responsible for
# handling deterministic and non deterministic flows, and handing off to a
# fallback agent in case there are any generic questions, multi turn conversations
# required to get more information from the user, or if the user comes in with
# no context about which IT service group they belong to (for example Infrastructure team, etc).
import os
import re
import sys
import json
import time
import boto3
import logging
import argparse
from utils import *
from constants import *
from pathlib import Path
# this is the agent library that is used to create the orchestrator
# agent in the orchestrator graph
from strands import Agent
from typing import Dict, Any
from response_types import *
# load the environment variables to 
# export the cloudwatch data to the genAI observability 
# dashboard using Bedrock agentcore and strands
from dotenv import load_dotenv
# To correlate traces across multiple agent runs, 
# we will associate a session ID with our telemetry data using the 
# Open Telemetry baggage
from opentelemetry import baggage, context
# import the strands agents and strands tools that we will be using
from datetime import datetime
# this is used to create a "BedrockModel"
# View more information on the models supported here: 
# https://strandsagents.com/latest/documentation/docs/user-guide/concepts/model-providers/amazon-bedrock/ 
from strands.models import BedrockModel
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional, List
# importing the strands multi agent base class with the graph type pattern
from strands.multiagent import GraphBuilder
from bedrock_agentcore.memory import MemoryClient
from strands.tools.mcp.mcp_client import MCPClient
from strands.agent.agent_result import AgentResult
from strands.types.content import ContentBlock, Message
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.memory.constants import StrategyType
from mcp.client.streamable_http import streamablehttp_client 
from strands.multiagent.base import MultiAgentBase, NodeResult, Status, MultiAgentResult
# these are the functions that are used to fetch the latest information about 
# the user preferences, summaries and the user semantics based on the user question
# at both, the orchestrator and the sub agent level - this is configurable and can be
# changed within the functions.
from memory_utils import create_memory, get_memory_context, store_conversation
# Initialize the memory client to work with bedrock agentcore memory
mem_client = MemoryClient(region_name=boto3.session.Session().region_name)
# Also create client alias for consistency with example patterns
client = mem_client

# this is a parse argument function where we will be able to send 
# in the session id, user type, experiment id, and other metadata
# as custom fields
def parse_arguments():
    parser = argparse.ArgumentParser(description='IT Support orchestrator agent with Session Tracking')
    # this is a cli argument (session id) which can be used when running this agent locally,
    # otherwise, this file will generate a uuid and the agent name appended as a session id
    parser.add_argument('--session-id',
                       type=str,
                       required=False,
                       help='Session ID to associate with this agent run (optional, will generate timestamp-based ID if not provided)')
    parser.add_argument('--access-token',
                       type=str,
                       required=False,
                       help='Cognito access token for user metadata extraction (optional, can also use COGNITO_ACCESS_TOKEN env var)')
    parser.add_argument('--query',
                       type=str,
                       required=False,
                       help='Query to process in non-interactive mode (optional, will start interactive CLI if not provided)')
    args = parser.parse_args()
    # Generate session ID if not provided
    if not args.session_id:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        args.session_id = f"it-support-agent-{timestamp}"
        print(f"Generated session ID: {args.session_id}")
    return args

def set_session_context(session_id):
    """
    Set the session ID in OpenTelemetry baggage for trace correlation
    This function is to set the baggage for the context session id that is provided
    for OTEL metric tracking for agents hosted outside of agentcore runtime
    """
    ctx = baggage.set_baggage("session.id", session_id)
    token = context.attach(ctx)
    logging.info(f"Session ID '{session_id}' attached to telemetry context")
    return token

# display the OTEL related environment variables
otel_vars = [
    # these are the environment variables that are required to enable python distro, 
    # the python configurator, the protocol over which telemetry data will be sent, 
    # the headers (session id, trace id, etc), etc.
    "OTEL_PYTHON_DISTRO",
    "OTEL_PYTHON_CONFIGURATOR",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_RESOURCE_ATTRIBUTES",
    "AGENT_OBSERVABILITY_ENABLED",
    "OTEL_TRACES_EXPORTER"
]
print("Open telemetry configuration:")
for var in otel_vars:
    value = os.getenv(var)
    if value:
        print(f'{var}={value}')

logger = logging.getLogger(__name__)
logger.info(f"Initialized the memory client for the orchestrator agent: {mem_client}")

try:
    config_data = load_config(CONFIG_FPATH)
    if config_data:
        # Log the top-level keys for debugging
        if isinstance(config_data, dict):
            print(f"Config top-level keys: {list(config_data.keys())}")
    else:
        print("Config data is None or empty")
        raise ValueError("Config data is empty")
except Exception as e:
    print(f"Error loading config: {str(e)}")
    raise

# read the orchestrator agent prompt template
# This contains information about the model that the orchestrator agent will use
orchestrator_agent_model_info: Dict = config_data['model_information'].get('orchestrator_agent_model_info')
# This contains information about the prompt that the orchestrator agent will use
orchestrator_agent_infra_info: Dict = config_data['agent_infra_resources'].get('orchestrator_agent_resources')
orch_inference_parameters: Dict = orchestrator_agent_model_info.get('inference_parameters')

# Fallback agent has been moved to service_desk_agent in sub_agents folder
# this is the information used for observability
cloudwatch_agent_infra_info: Dict = config_data['agent_infra_resources'].get('cloudwatch_agent_resources')
prompt_template_dir: str = config_data['agent_infra_resources']['prompt_template_directory']
# fetch the system prompt for the orchestrator agent
orchestrator_prompt_template_fpath: str = os.path.join(prompt_template_dir, orchestrator_agent_infra_info.get('system_prompt'))

# Read and format the template
print(f"The orchestrator will have access to the information about the available agents via MCP...")
with open(orchestrator_prompt_template_fpath, 'r') as f:
    orchestrator_system_prompt = f.read()
    
# this is where the model is rendered from the config file. All the model information
# is provided in the config file and more inference parameters can be added, specific model 
# ids, etc.
orchestrator_agent_model_id: str = orchestrator_agent_model_info['model_id']
# initialize the bedrock model for the orchestrator agent
orchestrator_model = BedrockModel(
    model_id=orchestrator_agent_model_id,
    aws_region= boto3.session.Session().region_name,
    max_tokens=orch_inference_parameters['max_tokens'],
    temperature=orch_inference_parameters['temperature'],
    top_p=orch_inference_parameters['top_p'],
    caching=orch_inference_parameters['caching'],
    stop_sequences=['<json>', '</json>']
)

# Parse arguments and set session context at module level for OpenTelemetry instrumentation
args = parse_arguments()

# -------------------------------------------------------
# CREATE MEMORY FOR ALL AGENTS
# In this, we will create the following namespaces for each of the scenarios:
# 1. Global memory: There will be a global memory that will be stored in terms of the following:
#   - Questions that are generic and can be handled using a fallback agent 
#   - User preferences, semantics and summaries of such interactions
#
# 2. Agent specific memory: This is the memory namespace that is pertained to each agent exposed via MCP
#   - Questions that are routed to specific agents
#   - Agent level user preferences, semantics and summaries of sessions
# -------------------------------------------------------
memory_id = None
namespace_structure = None

if config_data['agent_infra_resources'].get('use_existing_memory') is True:
    memory_id = config_data['agent_infra_resources'].get('memory_id')
    print(f"Using existing memory: {memory_id}")
else:
    print("Creating new memory...")
    memory_id = create_memory(
        memory_client=mem_client,
        memory_name=f"orchestrator_memory_{int(time.time())}",
        memory_execution_role_arn=config_data['agent_infra_resources']['memory_execution_role'],
        actor_id=config_data['agent_infra_resources']['actor_id']
    )
    print(f"✅ Created memory ID: {memory_id}")
# Use a consistent actor_id for memory operations instead of using memory_id
# This ensures the namespaces are predictable and user-friendly
actor_id = config_data['agent_infra_resources'].get('actor_id', 'default_user')
session_id = args.session_id
print(f"Using actor_id: {actor_id} for memory operations")

# -----------------------------------------------------
# INITIALIZE THE MCP CLIENT
# -----------------------------------------------------
def create_streamable_http_transport(mcp_url: str, access_token: str):
    """
    This function initializes the streamable http client for MCP
    In here the acess token is generated on the fly using the gateway inbound authentication
    information - this means the discovery URL (with domain enabled), the client ID and the 
    client secret
    """
    return streamablehttp_client(mcp_url, headers={"Authorization": f"Bearer {access_token}"})

def get_full_tools_list(client):
    """
    List tools w/ support for pagination
    """
    more_tools = True
    tools = []
    pagination_token = None
    while more_tools:
        print(f"Going to list down all of the tools --> (Agents and MCP servers) available in agentcore gateway")
        tmp_tools = client.list_tools_sync(pagination_token=pagination_token)
        tools.extend(tmp_tools)
        if tmp_tools.pagination_token is None:
            more_tools = False
        else:
            more_tools = True 
            pagination_token = tmp_tools.pagination_token
    return tools

def run_orchestrator_agent(orchestrator_system_prompt, mcp_url, query, client_credentials):
    """
    Creates and returns an orchestrator agent with the specified configuration.
    
    Args:
        orchestrator_system_prompt: The system prompt for the orchestrator agent
    
    Returns:
        Agent: The configured orchestrator agent
    """
    access_token = get_access_token(client_credentials=config_data['agent_gateway']['inbound_auth_info'])
    print(f"Access token that will be used to connect with the gateway: {access_token[:20]}")
    mcp_client = MCPClient(lambda: create_streamable_http_transport(mcp_url, access_token))
    with mcp_client:
        tools = get_full_tools_list(mcp_client)
        print(f"Fetched the following tools from the Agent Gateway: {tools}, going to invoke the orchestrator agent now...")
        orchestrator_agent = Agent(
            system_prompt=orchestrator_system_prompt,
            model=orchestrator_model,
            tools=tools,
            callback_handler=comprehensive_callback_handler
        )
        response = orchestrator_agent(query)
        print(f"Received a response from the orchestrator agent: {response}")
    return response

class FunctionNode(MultiAgentBase):
    """
    Execute deterministic Python functions as graph nodes.
    This node enables the creation of custom nodes within a Strands agentic 
    graph to have a deterministic workflow like system.
    """
    def __init__(self, func, name: str = None, output_dir: str = "./results", state=None):
        super().__init__()
        self.func = func
        self.name = name or func.__name__
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.shared_state = state

    def __call__(self, task, **kwargs):
        """Synchronous entrypoint: run the async invoke, then extract and return the result."""
        import asyncio
        mar: MultiAgentResult = asyncio.run(self.invoke_async(task, **kwargs))
        # grab the NodeResult for this node
        node = mar.results[self.name]
        # Extract text from the AgentResult within NodeResult
        if hasattr(node.result, 'message') and hasattr(node.result.message, 'content'):
            if isinstance(node.result.message.content, list):
                return node.result.message.content[0].text
            else:
                return str(node.result.message.content)
        return str(node.result)

    async def invoke_async(self, task, **kwargs):
        """Execute function and create AgentResult"""
        start_time = time.time()
        
        # Execute the wrapped function with state
        result = self.func(task, self.shared_state)

        agent_result = AgentResult(
            stop_reason="end_turn",
            message=Message(role="assistant", content=[ContentBlock(text=str(result))]),
            metrics=None,
            state=self.shared_state
        )

        # Return wrapped in MultiAgentResult
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.name: NodeResult(result=agent_result)},
            execution_count=1,
            execution_time=int((time.time() - start_time) * 1000),
        )

# -------------------------------------------------
# NODE 1: DETERMINISTIC DECISION: AGENT IDENTIFIER
# -------------------------------------------------
def agent_identifier(task, state):
    """
   This node does the following:
   
   This node extracts the history from the previous conversations (semantics, preferences and summaries) and hydrates the memory
   based on the new user question and then checks if: 
   
   1. User context is present: If the user context is present, then this node fetches the routing policy from the dynamoDB table, checks
   if there is a match between the user product context and the agents and then checks which one of the enabled domain agents are more similar
   to the user context and routes the response to that agent.
   
   2. User context is missing: If the user context is missing, then the query is routed to the orchestrator that decides which of the tool to call
   based on the tools that it has available from agentcore gateway
    """
    original_query = extract_prompt(task)
    print(f"=== NODE 1: AGENT IDENTIFIER ===\nOriginal Query: {original_query}")
    # === CHECK FOR ACTIVE PLUGIN SESSION ===
    # This is done to check if there are any active sticky sessions, then that is used
    # to route the request to the previously called agent from gateway
    global active_plugin_sessions
    if session_id in active_plugin_sessions:
        active_session = active_plugin_sessions[session_id]
        print(f"=== ACTIVE PLUGIN SESSION FOUND ===\nSession: {active_session}")
        result = {
            "continue_with_plugin": True,
            "plugin_name": active_session['plugin_name'],
            "plugin_url": active_session['plugin_url'],
            "original_query": original_query,
            "filtered_text": original_query
        }
        return json.dumps(result, indent=2)

    # === STORE INPUT AT GRAPH START ===
    # This is to store the question from the user in memory. This is where the user question comes in 
    # (this is the entry point of the graph). In this case, the user message is stored in context
    store_conversation(
        memory_client=mem_client,
        memory_id=memory_id,
        base_user_id=actor_id,
        user_message=original_query,
        # this is empty because only the user message needs to be 
        # stored and not the assistant message
        assistant_message="",
        session_id=session_id
    )
    print(f"Stored the user message in memory in NODE 1: {original_query}")
    # === RETRIEVE RELEVANT CONTEXT FROM MEMORY ===
    # Get semantic search results for this query using utility function
    memory_context = get_memory_context(
        memory_client=mem_client,
        memory_id=memory_id,
        base_user_id=actor_id,
        query=original_query,
        session_id=session_id
    )
    # retrieve the previous semantic, preferences and summaries 
    # and add it to the prompt 
    semantic_results = memory_context.get('semantics', [])
    semantic_results_str = " | ".join(semantic_results) if semantic_results else ""
    preferences_results = memory_context.get('preferences', [])
    preferences_results_str = " | ".join(preferences_results) if preferences_results else ""
    summaries_results = memory_context.get('summaries', [])
    summaries_results_str = " | ".join(summaries_results) if summaries_results else ""
    print(
    f"Semantics: {semantic_results_str}\n"
    f"Preferences: {preferences_results_str}\n"
    f"Summaries: {summaries_results_str}"
        )
    # === USER METADATA PRE-CHECK ===
    # first, this question flows through the guardrails.
    # In this case here are the steps that follow:
    # 1. We check the agent rules in the policy table, and check for which agent matches the user context
    # if there is an agent match then we go to the next node which is the list tools - we check if that matched agent is registered
    # as a tool, then the tool is invoked.
    # 2. If the user comes in with no context or there is no matching that is done, then the orchestrator gets the user question
    # and has autonomy to decide which agent to route the request to - a product sub agent or a fallback agent
    print(f"=== PERFORMING USER METADATA PRE-CHECK ===")
    try:
        # Get user metadata and agents from state
        print(f"Fetching the user metadata...")
        user_metadata = config_data.get('user_metadata')
        print(f"User metadata: {user_metadata}")
        # --------------------------------------------------------------
        # GET THE AGENTS FROM THE ROUTING POLICY TABLE
        # --------------------------------------------------------------
        # this is the dynamoDB table that contains information about the routing policy that 
        # can be managed by the administrator team - end teams should be able to add their own product categories
        # and enabled agents
        registry_table = config_data['agent_registry'].get('table_name')
        print(f"Going to use the following dynamoDB table to fetch the routing policy details: {registry_table}")
        agents_list = load_agent_mapping_from_policy_table(registry_table)
        # --------------------------------------------------------------
        # FETCH THE MATCH BASED ON USER CONTEXTUAL INFORMATION
        # --------------------------------------------------------------
        matched_agent = perform_user_contextual_matching(user_metadata, agents_list)
        print(f"Received the match result for deterministic flows: {matched_agent}")
        if matched_agent:
            print(f"=== AGENT FROM THE REGISTRY {matched_agent} FOUND, SKIPPING THE ORCHESTRATOR ===")
            print(f"PRESELECTED AGENT: {matched_agent}")
            result = {
                "potential_candidate": matched_agent,
                "reasoning": f"User metadata matched {matched_agent}, skipping orchestrator",
                "original_query": original_query,
            }
            print(f"SKIPPING ORCHESTRATOR - ROUTING DIRECTLY TO THE AGENT EXECUTOR NODE WITH: {matched_agent}")
            return json.dumps(result, indent=2)
    except Exception as e:
        print(f"Error in user metadata precheck: {e}")
    # === IF THERE IS NO USER CONTEXT, THEN INVOLVE THE ORCHESTRATOR ===
    print(f"=== NO USER CONTEXT FOUND - PROCEEDING TO ORCHESTRATOR ===")
    # Call the retrieve and route tool with the original query
    history: str = f"semantic history: {semantic_results_str}, user preferences: {preferences_results_str}, past summaries: {summaries_results_str}"
    system_prompt_injected_with_history: str = orchestrator_system_prompt.format(history=history, 
                                                                                 ORCHESTRATOR_ASSISTANCE_NEEDED=str(ORCHESTRATOR_INITIALIZATION_RESPONSE_TYPES))
    orchestrator_response = run_orchestrator_agent(system_prompt_injected_with_history,
                                                   config_data['agent_gateway']['gateway_url'],
                                                   original_query,
                                                   client_credentials=config_data['agent_gateway']['inbound_auth_info'])
    print(f"RESPONSE FROM THE ORCHESTRATOR WHEN THERE IS NO USER CONTEXT: {orchestrator_response}")
    # Extract the text content from AgentResult if needed
    response_text = str(orchestrator_response)
    if hasattr(orchestrator_response, 'message'):
        message = orchestrator_response.message
        if hasattr(message, 'content') and message.content:
            if isinstance(message.content, list) and len(message.content) > 0:
                response_text = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])
            else:
                response_text = str(message.content)
    # Try to extract JSON from the response
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```|(\{.*\})", response_text, re.DOTALL)
    parsed_json_str = json_block.group(1) or json_block.group(2) if json_block else None
    print(f"Extracted JSON from the orchestrator response: {parsed_json_str}")
    # If no JSON found, treat entire response as direct answer
    if not parsed_json_str:
        print(f"⚠️ No JSON found in orchestrator response - treating as direct text response")
        # Create a structured response for direct text answer
        structured_response = {
            "response_message": response_text,
            "response_type": "text",
            "agent_used": "Default",
            "timestamp": datetime.now().isoformat()
        }
        # Store in memory
        response_json = json.dumps(structured_response, indent=2)
        success = store_conversation(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            user_message="",
            assistant_message=response_json,
            tool_name="Default",
            session_id=session_id
        )
        if success:
            print(f"✅ Stored orchestrator text response in memory")
        # Return structured response that signals direct answer
        return json.dumps(structured_response, indent=2)
    parsed_json = json.loads(parsed_json_str) if parsed_json_str else {}
    # Check if orchestrator provided a direct response (has "response" field but no "potential_candidate")
    if parsed_json.get("response") and not parsed_json.get("potential_candidate"):
        print(f"=== ORCHESTRATOR PROVIDED DIRECT RESPONSE IN JSON ===")
        # Transform to expected format
        structured_response = {
            "response_message": parsed_json.get("response"),
            "response_type": "text",
            "agent_used": "Default",
            "timestamp": datetime.now().isoformat()
        }

        # Store in memory
        response_json = json.dumps(structured_response, indent=2)
        success = store_conversation(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            user_message="",
            assistant_message=response_json,
            tool_name="Default",
            session_id=session_id
        )
        if success:
            print(f"✅ Stored orchestrator direct response in memory")
        return json.dumps(structured_response, indent=2)
    # Otherwise, add the original query and continue with routing
    parsed_json["filtered_text"] = original_query
    # Convert back to string
    enhanced_json_str = json.dumps(parsed_json, indent=2)
    print(f"Enhanced JSON with original query: {enhanced_json_str}")
    return enhanced_json_str

# ----------------------------------------------
# UNIFIED ROUTING DECISION
# ----------------------------------------------
def unified_routing_decision(state) -> Optional[str]:
    """
    Single router that handles all routing decisions from agent_identifier:
    - Returns 'agent_executor' for new agent execution
    - Returns 'continue_with_plugin' for continuing plugin sessions
    - Returns None for direct user response (no further routing needed)
    """
    try:
        # Get the result from the agent_identifier node
        if hasattr(state, 'results') and 'agent_identifier' in state.results:
            agent_identifier_result = state.results['agent_identifier'].result
            if hasattr(agent_identifier_result, 'results') and 'agent_identifier' in agent_identifier_result.results:
                # Get the actual response message
                response_content = agent_identifier_result.results['agent_identifier'].result.message['content'][0]['text']
                print(f"Agent identifier response content: {response_content}")
                # Parse the JSON response
                agent_identifier_response = json.loads(response_content)
                print(f"Parsed agent identifier response: {json.dumps(agent_identifier_response, indent=2, default=str)}")
                # Determine routing destination
                if agent_identifier_response.get("continue_with_plugin"):
                    print(f"✅ ACTIVE STICKY SESSION FOUND.... CONTINUING WITH PLUGIN: {agent_identifier_response.get('plugin_name')}")
                    return "continue_with_plugin"
                elif agent_identifier_response.get("potential_candidate"):
                    return "agent_executor"
                else:
                    print(f"❌ No routing destination found - returning response to user")
                    return None
            else:
                print(f"Could not find agent_identifier results in nested structure")
                return None
        else:
            print(f"Could not find agent_identifier results in state")
            return None
    except Exception as e:
        print(f"An error occurred in unified routing decision: {e}")
        import traceback
        traceback.print_exc()
        raise e

# ----------------------------------------------
# ORCHESTRATOR FALLBACK NODE
# ----------------------------------------------
def orchestrator_fallback(task, state):
    """
    Handle OUT_OF_SCOPE and ERROR responses by routing back to orchestrator.
    """
    try:
        print(f"ORCHESTRATOR FALLBACK NODE: Processing task")
        # Extract the agent response from task
        agent_response = json.loads(task) if isinstance(task, str) else task
        print(f"Agent response for fallback: {json.dumps(agent_response, indent=2)}")
        # Handle both list and dict responses
        original_query = ""
        if isinstance(agent_response, list):
            # Extract text content from list format
            for item in agent_response:
                if isinstance(item, dict) and 'text' in item:
                    text_content = item['text']
                    # Try to extract JSON from the text if it contains structured data
                    if text_content.startswith('{') and text_content.endswith('}'):
                        try:
                            parsed_json = json.loads(text_content)
                            if 'original_query' in parsed_json or 'filtered_text' in parsed_json:
                                print(f"Going to invoke the orchestrator fallback using the following query: {parsed_json.get('original_query') or parsed_json.get('filtered_text')}")
                                original_query = parsed_json.get('original_query', '') or parsed_json.get('filtered_text', '')
                                break
                        except json.JSONDecodeError:
                            pass
                    # Also check for "Original Task:" pattern
                    if "Original Task:" in text_content:
                        original_query = text_content.replace("Original Task:", "").strip()
                        break
        elif isinstance(agent_response, dict):
            # Handle dict format (original logic)
            original_query = agent_response.get('original_query', '') or \
                            agent_response.get('filtered_text', '') or \
                            str(task)

        # Fallback to using the task as string if no query found
        if not original_query:
            original_query = str(task)
        print(f"Original query for orchestrator fallback: {original_query}")
        # Extract structured JSON response from agent response to pass as string
        agent_response_json = ""
        if isinstance(agent_response, list):
            # Look for JSON in text content
            for item in agent_response:
                if isinstance(item, dict) and 'text' in item:
                    text_content = item['text']
                    if text_content.startswith('{') and text_content.endswith('}'):
                        try:
                            # Validate it's proper JSON
                            json.loads(text_content)
                            agent_response_json = text_content
                            break
                        except json.JSONDecodeError:
                            pass
        elif isinstance(agent_response, dict):
            agent_response_json = json.dumps(agent_response)
        print(f"Extracted agent response JSON: {agent_response_json}")
        # Retrieve memory context for orchestrator
        memory_context = get_memory_context(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            query=original_query,
            session_id=session_id
        )
        semantic_results = memory_context.get('semantics', [])
        preferences_results = memory_context.get('preferences', [])
        summaries_results = memory_context.get('summaries', [])
        history = f"semantic history: {' | '.join(semantic_results)}, user preferences: {' | '.join(preferences_results)}, past summaries: {' | '.join(summaries_results)}"
        # Create enhanced system prompt with context about the failed agent
        fallback_context = (f"Previous agent response was OUT_OF_SCOPE or ERROR.\n"
                           f"Agent response JSON: {agent_response_json}\n"
                           f"Original user query: {original_query}\n\n"
                           f"Please provide a comprehensive answer or route to an appropriate agent.")

        enhanced_system_prompt = f"{orchestrator_system_prompt.format(history=history, ORCHESTRATOR_ASSISTANCE_NEEDED=str(ORCHESTRATOR_INITIALIZATION_RESPONSE_TYPES))}\n\nFALLBACK CONTEXT:\n{fallback_context}"
        print(f"🔄 Invoking orchestrator agent for fallback...")
        # Call orchestrator agent
        orchestrator_response = run_orchestrator_agent(
            enhanced_system_prompt,
            config_data['agent_gateway']['gateway_url'],
            original_query,
            client_credentials=config_data['agent_gateway']['inbound_auth_info']
        )

        print(f"🔄 Orchestrator fallback response: {orchestrator_response}")
        # Convert AgentResult to serializable format
        if hasattr(orchestrator_response, 'message'):
            # Extract text content from AgentResult
            message = orchestrator_response.message
            if hasattr(message, 'content') and message.content:
                if isinstance(message.content, list) and len(message.content) > 0:
                    response_text = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])
                else:
                    response_text = str(message.content)
            else:
                response_text = str(orchestrator_response)
        else:
            response_text = str(orchestrator_response)

        # Store the orchestrator response in memory
        success = store_conversation(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            user_message="",
            assistant_message=response_text,
            session_id=session_id
        )
        if success:
            print(f"✅ Stored orchestrator fallback response in memory")

        return response_text
    except Exception as e:
        logger.error(f"Orchestrator fallback error: {e}")
        error_response = {
            "error": "orchestrator_fallback_failed",
            "details": str(e),
            "timestamp": datetime.now().isoformat()
        }
        return json.dumps(error_response, indent=2)

# ----------------------------------------------
# RESPONSE HANDLER NODE - ROUTER FOR RESPONSE TYPE
# ----------------------------------------------
def plugin_response_router(state) -> bool:
    """
    Routes OUT_OF_SCOPE/ERROR responses to orchestrator fallback.
    """
    try:
        # State is already a MultiAgentResult, access results directly
        node_result = state.results['agent_executor']
        agent_result = node_result.result
        # Check if agent_result is a MultiAgentResult (nested structure)
        if hasattr(agent_result, 'results') and 'agent_executor' in agent_result.results:
            # Extract the actual AgentResult from the nested MultiAgentResult
            actual_agent_result = agent_result.results['agent_executor'].result
            message = actual_agent_result.message
        else:
            # It's already an AgentResult
            message = agent_result.message
        content = message.get('content', []) if isinstance(message, dict) else []
        if content:
            # Parse the JSON response
            response_data = json.loads(content[0]['text'])
            response_type = response_data.get('response_type', 'text').lower()
            print(f"RECEIVED THE RESPONSE SIGNAL FROM THE DOMAIN AGENT: {response_type}")
            # Handle more_info_needed by storing session state
            if response_type == 'more_info_needed':
                global active_plugin_sessions
                agent_used = response_data.get('agent_used')
                if agent_used:
                    print(f"✅ Detected more_info_needed - activating sticky session for agent: {agent_used}")
                    # If the domain plugin response is more_info_needed, then the plug in session is activated 
                    # with the name of the tool, the gateway url to be invoked and also the timestamp
                    # NOTE: When the agent is invoked in the following session, then this sticky-session will be
                    # detected and the user request will be directly routed to the domain plugin with the memory
                    # and context without going through the routing logic again
                    active_plugin_sessions[session_id] = {
                        'plugin_name': agent_used,
                        'plugin_url': config_data['agent_gateway']['gateway_url'], 
                        'timestamp': datetime.now().isoformat()
                    }
                    save_active_sessions(active_plugin_sessions)  # Persist to file
                    print(f"✅ Stored active plugin session: {active_plugin_sessions[session_id]}")
                # Don't route to fallback for more_info_needed - return directly to user
                return False
            should_route = response_type in ['out_of_scope', 'error']
            return should_route
    except (KeyError, AttributeError, json.JSONDecodeError, IndexError) as e:
        print(f"An error occurred while getting signal from the domain agent that was executed in the agent executor node: {e}")
        raise e

# ----------------------------------------------
# CONTINUE WITH PLUGIN NODE
# ----------------------------------------------
def continue_with_plugin(task, state):
    """Continue conversation with the same plugin that requested more info."""
    try:
        print(f"Task received in CONTINUE WITH PLUGIN NODE: {task}")
        # Extract data from task
        data = extract_json_quick(task)
        plugin_name = data.get("plugin_name")
        original_query = data.get("original_query") or data.get("filtered_text")
        # === GET MEMORY CONTEXT BEFORE TOOL INVOCATION ===
        print(f"\n🧠 EXTRACTING MEMORY CONTEXT BEFORE TOOL INVOCATION...")
        memory_context = get_memory_context(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            query=original_query,
            tool_name=plugin_name, 
            session_id=session_id
        )
        # Build context-prefixed query
        context_parts = []
        if memory_context.get('preferences'):
            context_parts.append(f"User Preferences: {' | '.join(memory_context['preferences'])}")
        if memory_context.get('semantics'):
            context_parts.append(f"Relevant Knowledge: {' | '.join(memory_context['semantics'])}")
        if memory_context.get('summaries'):
            context_parts.append(f"Session History: {' | '.join(memory_context['summaries'])}")
        if memory_context.get('recent_turns'):
            context_parts.append(f"Recent Conversations: {' | '.join(memory_context['recent_turns'])}")
        # Create context-prefixed query
        if context_parts:
            context_string = "Context: " + " || ".join(context_parts)
            context_prefixed_query = f"{context_string}\n\nUser Query: {original_query}"
            print(f"\n📋 CONTEXT-PREFIXED QUERY PREPARED:")
            print(f"   📊 Context length: {len(context_string)} chars")
            print(f"   📝 Total query length: {len(context_prefixed_query)} chars")
        else:
            context_prefixed_query = original_query
            print(f"\n📋 NO CONTEXT AVAILABLE - Using original query")
        print(f"Continuing conversation with plugin: {plugin_name}")
        print(f"User query: {original_query}")

        # Get access token for gateway
        access_token = get_access_token(client_credentials=config_data['agent_gateway']['inbound_auth_info'])
        gateway_url = config_data['agent_gateway']['gateway_url']
        tool_response = invoke_gateway_tool_direct(plugin_name, context_prefixed_query, gateway_url, access_token)
        # Tool invocation succeeded, extract the response
        gateway_response = tool_response.get('response')
        # Extract response data using utility function
        response_message, response_type = extract_response_data(gateway_response)
        print(f"EXTRACTED RESPONSE MESSAGE: {response_message}")
        print(f"EXTRACTED RESPONSE TYPE: {response_type}")
        final_response_message = response_message
        # Create structured response
        structured_response = {
            "response_message": final_response_message,
            "response_type": response_type,
            "agent_used": plugin_name,
            "continued_conversation": True,
            "timestamp": datetime.now().isoformat()
        }

        # Clear active session if response is complete
        global active_plugin_sessions
        if response_type.lower() not in ['more_info_needed']:
            if session_id in active_plugin_sessions:
                del active_plugin_sessions[session_id]
                save_active_sessions(active_plugin_sessions)  # Persist to file
                print(f"✅ Cleared active plugin session for session: {session_id} because agent deemed it 'complete'")
        # Store response in memory
        response_text = json.dumps(structured_response, indent=2)
        success = store_conversation(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            user_message="",
            assistant_message=response_text,
            tool_name=plugin_name,
            session_id=session_id, 
            
        )
        if success:
            print(f"✅ Stored continued conversation response in memory from: {plugin_name}")
        return json.dumps(structured_response, indent=2)
    except Exception as e:
        logger.error(f"Continue with plugin error: {e}")
        raise e

# ----------------------------------------------
# AGENT EXECUTOR NODE
# ----------------------------------------------
def agent_executor_process(task, state):
    """NODE 2: AGENT EXECUTOR - Execute selected agent/tool with memory context"""
    try:
        print("\n" + "="*80)
        print("🔧 NODE 2: AGENT EXECUTOR - Executing selected agent")
        print("="*80)

        # Extract data using the existing extract_json_quick function
        data = extract_json_quick(task)
        agent_name = data.get("potential_candidate")
        original_query = data.get("filtered_text") or data.get("original_query")
        # === GET MEMORY CONTEXT BEFORE TOOL INVOCATION ===
        print(f"\n🧠 EXTRACTING MEMORY CONTEXT BEFORE TOOL INVOCATION...")
        memory_context = get_memory_context(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            query=original_query,
            tool_name=agent_name,  # Pass tool name for tool-specific memory
            session_id=session_id
        )
        # Build context-prefixed query
        context_parts = []
        if memory_context.get('preferences'):
            context_parts.append(f"User Preferences: {' | '.join(memory_context['preferences'])}")
        if memory_context.get('semantics'):
            context_parts.append(f"Relevant Knowledge: {' | '.join(memory_context['semantics'])}")
        if memory_context.get('summaries'):
            context_parts.append(f"Session History: {' | '.join(memory_context['summaries'])}")
        if memory_context.get('recent_turns'):
            context_parts.append(f"Recent Conversations: {' | '.join(memory_context['recent_turns'])}")

        # Create context-prefixed query
        if context_parts:
            context_string = "Context: " + " || ".join(context_parts)
            context_prefixed_query = f"{context_string}\n\nUser Query: {original_query}"
        else:
            context_prefixed_query = original_query
            print(f"\n📋 NO CONTEXT AVAILABLE - Using original query")

        print(f"\nLooking for tools in AgentCore Gateway...")
        # Get access token for gateway
        access_token = get_access_token(client_credentials=config_data['agent_gateway']['inbound_auth_info'])
        gateway_url = config_data['agent_gateway']['gateway_url']
        # List available tools from gateway
        print("Listing tools from the gateway...")
        tools_response = list_tools_from_gateway(gateway_url, access_token)
        print(f"Retrieved tools response: {json.dumps(tools_response, indent=2, default=str)}")
        # Match user product context with available tools
        print("Matching user product context with available tools...")
        user_metadata = config_data['user_metadata']
        print(f"Going to check if the domain plugin is present in the gateway...")
        matched_tool = match_user_context_with_gateway_tools(user_metadata, tools_response)
        if not matched_tool:
            # If no tool matches, fall back to using the agent_name from orchestrator decision
            if not agent_name:
                raise ValueError("No tool matched user context and no agent specified by orchestrator")
            matched_tool = agent_name
            print(f"No tool matched user context, using orchestrator decision: {matched_tool}")
        else:
            print(f"✅ Found matching tool: {matched_tool}")
        # Invoke the matched tool directly through gateway
        print(f"Invoking gateway agent: {matched_tool} with context prefilled query: {context_prefixed_query}")
        # call the tool directly that has been matched to the user based on the user context
        tool_response = invoke_gateway_tool_direct(matched_tool, context_prefixed_query, gateway_url, access_token)
        # Tool invocation succeeded, extract the response
        gateway_response = tool_response.get('response')
        print(f"TOOL RESPONSE DIRECTLY FROM AGENTCORE GATEWAY: {gateway_response}")
        # Extract response data using utility function
        response_message, response_type = extract_response_data(gateway_response)
        print(f"EXTRACTED RESPONSE MESSAGE: {response_message}")
        print(f"EXTRACTED RESPONSE TYPE: {response_type}")
        final_response_message = response_message
        # Create structured response with both content and type for plugin router
        structured_response = {
            "response_message": final_response_message,
            "response_type": response_type,
            "agent_used": matched_tool,
            "timestamp": datetime.now().isoformat()
        }
        # === STORE FINAL RESPONSE AT GRAPH END ===
        response_text = json.dumps(structured_response, indent=2)
        success = store_conversation(
            memory_client=mem_client,
            memory_id=memory_id,
            base_user_id=actor_id,
            user_message=original_query,
            assistant_message=response_text,
            tool_name=matched_tool,
            session_id=session_id
        )
        if success:
            print(f"✅ Stored gateway tool response in memory from: {matched_tool}")
        return json.dumps(structured_response, indent=2)
    except Exception as e:
        logger.error(f"Agent executor error: {e}")
        raise e

# ============================================================================
# CREATE THE GRAPH WITH SHARED STATE
# ============================================================================
# Add shared state for tracking active plugin sessions
# Use a file-based storage for cross-process session persistence
SESSION_STORAGE_FILE = os.path.join(ACTIVE_SESSION_FPATH)

def load_active_sessions():
    """Load active plugin sessions from file"""
    try:
        if os.path.exists(SESSION_STORAGE_FILE):
            with open(SESSION_STORAGE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load session storage: {e}")
    return {}

def save_active_sessions(sessions):
    """Save active plugin sessions to file"""
    try:
        # Clean up old sessions (older than 1 hour)
        current_time = datetime.now()
        cleaned_sessions = {}
        for sid, session_data in sessions.items():
            try:
                session_timestamp = datetime.fromisoformat(session_data['timestamp'])
                time_diff = (current_time - session_timestamp).total_seconds()
                if time_diff < 3600:  # Keep sessions less than 1 hour old
                    cleaned_sessions[sid] = session_data
                else:
                    print(f"Cleaning up old session: {sid} (age: {time_diff/60:.1f} minutes)")
            except (KeyError, ValueError):
                # If timestamp is missing or invalid, keep the session
                cleaned_sessions[sid] = session_data

        with open(SESSION_STORAGE_FILE, 'w') as f:
            json.dump(cleaned_sessions, f, indent=2)
    except Exception as e:
        print(f"Warning: Failed to save session storage: {e}")

# Load existing sessions at startup
active_plugin_sessions = load_active_sessions()
user_metadata_config = config_data.get('user_metadata')
provided_context = user_metadata_config.get('provided_context')
product = provided_context.get('service')

# Use product name as the user metadata
product_name = product.get('name', 'Default') if product else 'Default'
metadata_name = product_name
metadata_attributes = [product_name]

# Create metadata description from the product context
try:
    user_metadata_description = f"User of {product_name}"
    print(f"Created user metadata description: {user_metadata_description}")
except Exception as e:
    print(f"An error occurred while creating a user metadata description: {e}")
    user_metadata_description = ''

builder = GraphBuilder()
print("Created GraphBuilder instance")

# Create nodes
agent_identifier_node = FunctionNode(
    func=agent_identifier,
    name="agent_identifier"
)
builder.add_node(agent_identifier_node, node_id="agent_identifier")
agent_executor_node = FunctionNode(
    func=agent_executor_process,
    name="agent_executor"
)
builder.add_node(agent_executor_node, node_id="agent_executor")
continue_with_plugin_node = FunctionNode(
    func=continue_with_plugin,
    name="continue_with_plugin"
)
builder.add_node(continue_with_plugin_node, node_id="continue_with_plugin")
orchestrator_fallback_node = FunctionNode(
    func=orchestrator_fallback,
    name="orchestrator_fallback"
)
builder.add_node(orchestrator_fallback_node, node_id="orchestrator_fallback")
# Route from agent_identifier to either agent_executor OR continue_with_plugin
builder.add_edge("agent_identifier", "agent_executor", condition=lambda state: unified_routing_decision(state) == "agent_executor")
builder.add_edge("agent_identifier", "continue_with_plugin", condition=lambda state: unified_routing_decision(state) == "continue_with_plugin")

# Route from agent_executor to orchestrator_fallback if response type is OUT_OF_SCOPE/ERROR
builder.add_edge("agent_executor", "orchestrator_fallback", condition=plugin_response_router)

# Route from continue_with_plugin back to itself if more_info_needed, or complete if done
def continue_plugin_router(state) -> bool:
    """Check if continue_with_plugin response needs more info (loop back) or is complete."""
    try:
        node_result = state.results['continue_with_plugin']
        agent_result = node_result.result

        # Check if agent_result is nested
        if hasattr(agent_result, 'results') and 'continue_with_plugin' in agent_result.results:
            actual_agent_result = agent_result.results['continue_with_plugin'].result
            message = actual_agent_result.message
        else:
            message = agent_result.message

        content = message.get('content', []) if isinstance(message, dict) else []

        if content:
            response_data = json.loads(content[0]['text'])
            response_type = response_data.get('response_type', 'text').lower()

            # Handle more_info_needed by updating session and staying in continue loop
            if response_type == 'more_info_needed':
                # Session is already updated in continue_with_plugin function
                print(f"Continue with plugin needs more info - will loop back on next user input")
                return False  # Don't route to fallback

            # For other response types, clear session and complete
            return response_type in ['out_of_scope', 'error']
    except Exception as e:
        print(f"Error in continue plugin router: {e}")
        return False

builder.add_edge("continue_with_plugin", "orchestrator_fallback", condition=continue_plugin_router)

print("Added conditional routing edges to graph")

# Set the entry point to the graph
builder.set_entry_point("agent_identifier")
graph = builder.build()
print(f"Graph built successfully! -> {graph}")

def interactive_cli():
    """
    Simple command-line interface to interact with the agent directly.
    Updated to handle the new graph structure with multiple exit points.
    """
    print("\n" + "="*80)
    print("🤖 IT Support Orchestrator Agent Interactive CLI")
    print("="*80)
    print("Type your questions about IT support services below.")
    print("Type 'exit', 'quit', or 'q' to end the session.")
    print("="*80 + "\n")
    
    while True:
        context_token = None
        try:
            # Clear tool_use_ids
            global tool_use_ids
            tool_use_ids.clear()

            # Get user input
            user_input = input("\n👤 You: ")

            # Check exit
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("\n👋 Goodbye!")
                break

            # Skip empty
            if not user_input.strip():
                continue

            # Execute graph
            # Here, we will set the session context for telemtry
            context_token = set_session_context(args.session_id)
            start_time = time.time()
            graph_result = graph(user_input)
            
            # Determine which node was the last one executed based on the new graph structure
            final_node = None
            node_name = None

            # Check for orchestrator_fallback (orchestrator handling OUT_OF_SCOPE/ERROR)
            if "orchestrator_fallback" in graph_result.results:
                final_node = graph_result.results["orchestrator_fallback"]
                node_name = "orchestrator_fallback"
                print(f"Final node executed: {node_name} (orchestrator fallback completed)")

            # Check for continue_with_plugin (continued plugin conversation)
            elif "continue_with_plugin" in graph_result.results:
                final_node = graph_result.results["continue_with_plugin"]
                node_name = "continue_with_plugin"
                print(f"Final node executed: {node_name} (continued plugin conversation completed)")

            # Check for agent_executor (successful agent execution)
            elif "agent_executor" in graph_result.results:
                final_node = graph_result.results["agent_executor"]
                node_name = "agent_executor"
                print(f"Final node executed: {node_name} (agent execution completed)")

            # Check for agent_identifier (routing decision made)
            elif "agent_identifier" in graph_result.results:
                final_node = graph_result.results["agent_identifier"]
                node_name = "agent_identifier"
                print(f"Final node executed: {node_name} (routing decision made)")

            else:
                print("❌ No recognized node found in results")
                print(f"Available nodes: {list(graph_result.results.keys())}")
                continue
        
            # Fallback to the old parsing method for other nodes or if structured response is not available
            agent_result = final_node.result

            # Check if it's actually nested MultiAgentResult
            if hasattr(agent_result, 'results'):
                # It's a MultiAgentResult, get the inner node
                if node_name in agent_result.results:
                    agent_result = agent_result.results[node_name].result

            # Now extract from AgentResult
            if hasattr(agent_result, 'message'):
                message = agent_result.message
                content = message.get('content', []) if isinstance(message, dict) else message.content

                if content and len(content) > 0:
                    # Get text from first content block
                    json_text = content[0].get('text') if isinstance(content[0], dict) else content[0].text

                    # Format output using the utility function
                    formatted_output, is_json = format_output(json_text)

                    if is_json:
                        # Parse to get structured data for smart handling
                        try:
                            response_json = json.loads(json_text)

                            # Handle different response types with appropriate messaging
                            if node_name == "agent_identifier":
                                # Routing decision from orchestrator
                                verdict = response_json.get("verdict")
                                if verdict == "yes":
                                    agent_name = response_json.get("potential_sub_agent")
                                    reasoning = response_json.get("reasoning", "")
                                    print(f"\n🤖 Routing to {agent_name}: {reasoning}")
                                else:
                                    print(f"\n🤖 Orchestrator Decision:")
                                    print(formatted_output)

                            elif node_name == "orchestrator_fallback":
                                # Orchestrator fallback response - display as fallback message
                                print(f"\n🔄 Orchestrator Fallback Response:")
                                print(formatted_output)

                            else:
                                # Unknown node type
                                print(f"\n🤖 Response from {node_name}:")
                                print(formatted_output)

                        except json.JSONDecodeError:
                            # Fallback to formatted output
                            print(f"\n🤖 Response from {node_name}:")
                            print(formatted_output)
                    else:
                        # It's a plain string - display as such
                        print(f"\n🤖 Response from {node_name}:")
                        print(formatted_output)

                    print(f"\n⏱️ Time: {time.time() - start_time:.2f}s")
                else:
                    print("\n❌ No message in result")
            else:
                print("\n❌ No result in node")
        finally:
            # Detach context when done
            if context_token is not None:
                context.detach(context_token)
                logger.info(f"Session context for '{args.session_id}' detached")

# initialize the cloudwatch client to create the log group and the log stream
cloudwatch_client = boto3.client("logs")
print(f"Initialized the cloudwatch client: {cloudwatch_client}")

try:
    response = cloudwatch_client.create_log_group(logGroupName=cloudwatch_agent_infra_info.get('log_group_name'))
    print(f"Created the log group: {response}")
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
        print(f"Log group already exists: {cloudwatch_agent_infra_info.get('log_group_name')}")
    else:
        print(f"Error creating log group: {e}")

try:
    response = cloudwatch_client.create_log_stream(
        logGroupName=cloudwatch_agent_infra_info.get('log_group_name'), 
        logStreamName=cloudwatch_agent_infra_info.get('log_stream_name')
    )
    print(f"Created the log stream: {response}")
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
        print(f"Log stream already exists: {cloudwatch_agent_infra_info.get('log_stream_name')}")
    else:
        print(f"Error creating log stream: {e}")

def process_single_query(query: str):
    """
    Process a single query and return the result (non-interactive mode).
    """
    print(f"\n🤖 Processing query: {query}")
    print("="*80)

    try:
        # Clear tool_use_ids
        global tool_use_ids
        tool_use_ids.clear()

        # Execute graph
        start_time = time.time()
        graph_result = graph(query)

        # Determine which node was the last one executed based on the new graph structure
        final_node = None
        node_name = None

        # Check for orchestrator_fallback (orchestrator handling OUT_OF_SCOPE/ERROR)
        if "orchestrator_fallback" in graph_result.results:
            final_node = graph_result.results["orchestrator_fallback"]
            node_name = "orchestrator_fallback"
            print(f"Final node executed: {node_name} (orchestrator fallback completed)")

        # Check for continue_with_plugin (continued plugin conversation)
        elif "continue_with_plugin" in graph_result.results:
            final_node = graph_result.results["continue_with_plugin"]
            node_name = "continue_with_plugin"
            print(f"Final node executed: {node_name} (continued plugin conversation completed)")

        # Check for agent_executor (successful agent execution)
        elif "agent_executor" in graph_result.results:
            final_node = graph_result.results["agent_executor"]
            node_name = "agent_executor"
            print(f"Final node executed: {node_name} (agent execution completed)")

        # Check for agent_identifier (routing decision made)
        elif "agent_identifier" in graph_result.results:
            final_node = graph_result.results["agent_identifier"]
            node_name = "agent_identifier"
            print(f"Final node executed: {node_name} (routing decision made)")

        else:
            print("❌ No recognized node found in results")
            print(f"Available nodes: {list(graph_result.results.keys())}")
            return

        # Fallback to the old parsing method for other nodes or if structured response is not available
        agent_result = final_node.result

        # Check if it's actually nested MultiAgentResult
        if hasattr(agent_result, 'results'):
            # It's a MultiAgentResult, get the inner node
            if node_name in agent_result.results:
                agent_result = agent_result.results[node_name].result

        # Now extract from AgentResult
        if hasattr(agent_result, 'message'):
            message = agent_result.message
            content = message.get('content', []) if isinstance(message, dict) else message.content

            if content and len(content) > 0:
                # Get text from first content block
                json_text = content[0].get('text') if isinstance(content[0], dict) else content[0].text

                # Format output using the utility function
                formatted_output, is_json = format_output(json_text)

                if is_json:
                    # Parse to get structured data for smart handling
                    try:
                        response_json = json.loads(json_text)

                        # Handle different response types with appropriate messaging
                        if node_name == "agent_identifier":
                            # Routing decision from orchestrator
                            verdict = response_json.get("verdict")
                            if verdict == "yes":
                                agent_name = response_json.get("potential_sub_agent")
                                reasoning = response_json.get("reasoning", "")
                                print(f"\n🤖 Routing to {agent_name}: {reasoning}")
                            else:
                                print(f"\n🤖 Orchestrator Decision:")
                                print(formatted_output)

                        elif node_name == "orchestrator_fallback":
                            # Orchestrator fallback response - display as fallback message
                            print(f"\n🔄 Orchestrator Fallback Response:")
                            print(formatted_output)

                        elif node_name == "agent_executor" or node_name == "continue_with_plugin":
                            # For agent responses with structured data, output the JSON for Streamlit
                            print(json_text)
                        elif node_name == "agent_identifier":
                            # Check if this is a direct orchestrator response (has response_message)
                            if response_json.get("response_message"):
                                # Output structured JSON for Streamlit
                                print(json_text)
                            else:
                                # Regular routing decision
                                print(f"\n🤖 Response from {node_name}:")
                                print(formatted_output)
                        else:
                            # Unknown node type
                            print(f"\n🤖 Response from {node_name}:")
                            print(formatted_output)

                    except json.JSONDecodeError:
                        # Fallback to formatted output
                        print(f"\n🤖 Response from {node_name}:")
                        print(formatted_output)
                else:
                    # It's a plain string - display as such
                    print(f"\n🤖 Response from {node_name}:")
                    print(formatted_output)

                print(f"\n⏱️ Time: {time.time() - start_time:.2f}s")
            else:
                print("\n❌ No message in result")
        else:
            print("\n❌ No result in node")

    except json.JSONDecodeError as e:
        print(f"\n❌ Invalid JSON: {e}")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check if query is provided via command line argument
    if args.query:
        # Non-interactive mode - process single query
        print(f"\n🚀 Running in non-interactive mode")
        process_single_query(args.query)
    else:
        # Interactive mode - start CLI
        print(f"\n🚀 Running in interactive mode")
        interactive_cli()
    # finally:
    #     # Clean up the session context when the program exits
    #     context.detach(context_token)
    #     print(f"Session context for '{args.session_id}' detached at program exit")