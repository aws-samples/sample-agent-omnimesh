# Infrastructure Agent with LangGraph Implementation
# This creates a graph with two nodes: query processor and react agent with tools
import re
import os
import sys
import json
import boto3
import logging
import operator
# importing langchain variables
# in this case we want to build a prompt with the
# infrastructure system prompt. If the question is related to infrastructure (cloud, networking, servers),
# then the agent responds with an infrastructure based dummy valid response and
# if the question is not about infrastructure, then the agent provides an error
# response. This error response will be handled at the orchestrator level.
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate
)
# in this case we will be using the chatbedrock model
from langchain_aws import ChatBedrock
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from langchain_core.prompts import PromptTemplate
from langgraph.graph import StateGraph, END, START
# import the bedrock agent core application
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from typing import Dict, List, Optional, Union, Any, TypedDict, Annotated

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Get the current directory of this file
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from utils import *
from response_types import ResponseType

# Load configuration
possible_config_paths = [
    os.path.join(parent_dir, 'config.yaml'),
    os.path.join(current_dir, 'config.yaml'),
    os.path.join(os.getcwd(), 'config.yaml'),
    'config.yaml'
]

config_data = None
CONFIG_FPATH = None

for config_path in possible_config_paths:
    if os.path.exists(config_path):
        CONFIG_FPATH = config_path
        break

if CONFIG_FPATH is None:
    raise FileNotFoundError("config.yaml not found")

config_data = load_config(CONFIG_FPATH)

# Load model configuration
agent_model_info: Dict = config_data['model_information'].get('agent_model_info')
agent_infra_info: Dict = config_data['agent_infra_resources'].get('agent_resources')
inference_parameters: Dict = agent_model_info.get('inference_parameters')
prompt_template_dir: str = config_data['agent_infra_resources']['prompt_template_directory']
# This is the dummy response that the infrastructure agent provides if the question is about infrastructure
valid_response_fpath: str = os.path.abspath(config_data['agent_infra_resources'].get('valid_response_path'))
# This is the dummy response that the infrastructure agent provides if the question is not about infrastructure, in this case
# the agent should respond with an error response that the orchestrator should then be able to handle
erroneous_response_fpath: str = os.path.abspath(config_data['agent_infra_resources'].get('erroneous_response_path'))
print(f"Going to use the dummy valid response path: {valid_response_fpath} and the dummy erroneous response path: {erroneous_response_fpath} to simulate the infrastructure agent's behaviour...")

# Load agent prompt template from file specified in config
system_prompt_filename: str = agent_infra_info.get('system_prompt')
system_prompt_path = os.path.join(current_dir, prompt_template_dir, system_prompt_filename)

try:
    with open(system_prompt_path, 'r', encoding='utf-8') as f:
        agent_prompt_template_raw = f.read()

    # Format the prompt template with ResponseType values
    agent_prompt_template_content = agent_prompt_template_raw.format(
        more_info_needed=ResponseType.MORE_INFO_NEEDED,
        out_of_scope=ResponseType.OUT_OF_SCOPE,
        error=ResponseType.ERROR, 
        completed=ResponseType.COMPLETED,
    )
    print(f"Successfully loaded and formatted agent prompt from: {system_prompt_path}")
    print(f"Content of the system prompt: {agent_prompt_template_content}")
except FileNotFoundError:
    print(f"Agent prompt file not found at: {system_prompt_path}")
    raise FileNotFoundError(f"Agent prompt file not found: {system_prompt_path}")
except Exception as e:
    print(f"Error reading agent prompt file: {e}")
    raise

# Initialize the ChatBedrock model
model = ChatBedrock(
    model_id=agent_model_info['model_id'],
    region_name=boto3.session.Session().region_name,
    model_kwargs={
        "max_tokens": inference_parameters['max_tokens'],
        "temperature": inference_parameters['temperature'],
        "top_p": inference_parameters['top_p'],
        "stop_sequences": inference_parameters['stop_sequences']
    }
)
print(f"Initialized the ChatBedrock model for the infrastructure agent: {model}")

@tool
def health_check() -> Dict:
    """Health check tool that returns status information.

    Returns:
        Dict: Health status with JSON structure
    """
    return {
        "statusCode": 200,
        "response_type": ResponseType.MODEL_RESPONSE,
        "response_message": "Health check passed - Infrastructure Agent is running",
    }

# Extract and parse the JSON response
def extract_json_from_response(response_text):
    """Extract JSON from the response text, handling various formats."""
    if not response_text or not isinstance(response_text, str):
        print(f"Invalid response_text: {response_text}")
        return None

    try:
        # Try to parse the entire response as JSON first
        return json.loads(response_text.strip())
    except json.JSONDecodeError as e:
        print(f"Failed to parse full response as JSON: {e}")

        # If that fails, try to find JSON within the text
        # Look for JSON block markers
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',  # ```json { ... } ```
            r'```\s*(\{.*?\})\s*```',      # ``` { ... } ```
            r'(\{[^{}]*"response_type"[^{}]*\})',  # Look for objects containing "response_type"
            r'(\{[^{}]*"is_infrastructure"[^{}]*\})',  # Look for objects containing "is_infrastructure"
            r'(\{.*?\})'                    # Any JSON object
        ]

        for pattern in json_patterns:
            match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
            if match:
                try:
                    json_str = match.group(1).strip()
                    print(f"Attempting to parse extracted JSON: {json_str}")
                    return json.loads(json_str)
                except json.JSONDecodeError as nested_e:
                    print(f"Failed to parse extracted JSON: {nested_e}")
                    continue

        # If no JSON found, return None
        print(f"No valid JSON found in response: {response_text}")
        return None


@tool
def chat_handler(user_query: str) -> Dict:
    """Handle queries and determine appropriate response type based on content.

    Args:
        user_query: The user's question

    Returns:
        Dict: Response with appropriate response_type and message
    """
    try:
        # Create system prompt and directly invoke the model
        system_prompt = ChatPromptTemplate.from_messages([
            ("system", agent_prompt_template_content),
            ("human", "{user_query}")
        ])

        print(f"Analyzing query to determine response type...")

        # Format the prompt and invoke the model directly
        formatted_prompt = system_prompt.format(user_query=user_query)
        print(f"Formatted prompt: {formatted_prompt}")
        model_response = model.invoke(formatted_prompt)

        # Extract the response text
        final_text = model_response.content if hasattr(model_response, "content") else str(model_response)
        print(f"Raw model response: {final_text}")

        # Extract the JSON response
        parsed_response = extract_json_from_response(final_text)

        if parsed_response and isinstance(parsed_response, dict):
            return parsed_response
        else:
            # Failed to parse response - return error with better details
            print(f"Failed to parse agent response. Raw response was: {final_text}")
            error_msg = f"Unable to parse model response. Raw response: {final_text[:200]}..."
            return {
                "response_type": ResponseType.ERROR,
                "response_message": error_msg,
                "status": "error",
                "raw_response": final_text
            }
            
    except Exception as e:
        print(f"An error occurred while processing the query: {e}")
        return {
            "response_type": ResponseType.ERROR,
            "response_message": f"An error occurred while processing your query: {str(e)}",
            "status": "error"
        }
    
# Define the state for our graph
class AgentState(TypedDict):
    """State for the Infrastructure agent graph."""
    user_question: str
    response: Dict[str, Any]
    question: str

def get_user_question(state: AgentState) -> AgentState:
    """First node: Extract and classify the user question.
    
    Args:
        state: Current agent state containing user_question
        
    Returns:
        Updated state with question
    """
    print(f"Processing user question: {state['user_question']}")
    question = state['user_question'].lower()
    return {
        **state,
        'question': question
    }

def return_json_response(state: AgentState) -> AgentState:
    """Second node: Process the query using direct LLM call.

    Args:
        state: Current agent state with user_question and question

    Returns:
        Updated state with JSON response from direct LLM call
    """
    try:
        user_question = state['user_question']
        question = state['question']

        print(f"Processing {question} query: {user_question}")
        
        # Check if user question contains health-related keywords
        if 'health' in user_question.lower() or 'healthy' in user_question.lower():
            print("Health-related query detected. Calling health_check function.")
            response = health_check()
            print(f"Health check response: {response}")
            return {
                **state,
                'response': response
            }
        else:
            print(f"Going to invoke the chat handler to respond to the user question")
            # Use the chat_handler function which now includes response type determination
            response = chat_handler(user_question)
            print(f"Generated response with type: {response.get('response_type')}")
            return {
                **state,
                'response': response
            }
    except Exception as e:
        print(f"Error in return_json_response: {e}")
        error_response = {
            "statusCode": 500,
            "response_type": ResponseType.ERROR,
            "response_message": f"Internal server error: {str(e)}",
            "status": "error"
        }

        return {
            **state,
            'response': error_response
        }

# Build the LangGraph with custom nodes
def build_infrastructure_agent_graph():
    """Builds the LangGraph with two custom nodes."""
    try:
        # Create the state graph
        workflow = StateGraph(AgentState)

        # Add nodes
        workflow.add_node("get_user_question", get_user_question)
        workflow.add_node("return_json_response", return_json_response)

        # Define the flow
        workflow.add_edge(START, "get_user_question")
        workflow.add_edge("get_user_question", "return_json_response")
        workflow.add_edge("return_json_response", END)

        # Compile the graph
        agent_graph = workflow.compile()
        print("Successfully created LangGraph with custom nodes")
        return agent_graph
    except Exception as e:
        logger.error(f"Error building LangGraph: {e}")
        raise

# initialize the bedrock agentcore application
app = BedrockAgentCoreApp()
print(f"Initialized the bedrock agentcore app: {app}")

@app.entrypoint
def infrastructure_agent_handler(payload: Dict) -> Dict:
    """Entrypoint for the Infrastructure agent using custom LangGraph nodes."""
    # Build the custom agent graph
    agent_graph = build_infrastructure_agent_graph()

    try:
        user_query = payload.get('prompt') or payload.get('user_query', '')

        if not user_query:
            return {
                "statusCode": 400,
                "response_type": ResponseType.ERROR,
                "response_message": "Bad request: user query must be non-empty."
            }

        # Check if it's a health check request
        if user_query.lower() in ['health', 'health check', 'status']:
            return {
                "statusCode": 200,
                "response_type": ResponseType.MODEL_RESPONSE,
                "response_message": "Health check passed - Infrastructure Agent is running"
            }

        # Use the agent graph to process the query
        initial_state = {
            "user_question": user_query,
            "response": {},
            "question": ""
        }

        result = agent_graph.invoke(initial_state)

        # Return the response with appropriate response_type
        return result["response"]

    except Exception as e:
        logger.error(f"Error in infrastructure_agent_handler: {e}")
        return {
            "statusCode": 500,
            "response_type": ResponseType.ERROR,
            "response_message": f"Error: {str(e)}"
        }

# Interactive CLI for testing
def interactive_cli():
    """Interactive command-line interface for testing the agent."""
    print("\n Infrastructure Agent - LangGraph with Custom Nodes and Response Types")
    print("Type 'exit' to quit, 'health' for health check.")
    print(f"Available response types: {[attr for attr in dir(ResponseType) if not attr.startswith('_')]}")

    # Build the agent graph
    agent_graph = build_infrastructure_agent_graph()

    while True:
        try:
            user_input = input("\n You: ").strip()

            if user_input.lower() in ['exit', 'quit', 'q']:
                break

            if not user_input:
                continue

            # Check if it's a health check request
            if user_input.lower() in ['health', 'health check', 'status']:
                response = {
                    "statusCode": 200,
                    "response_type": ResponseType.MODEL_RESPONSE,
                    "response_message": "Health check passed - Infrastructure Agent is running"
                }
                print(json.dumps(response, indent=2))
                continue

            # Use the agent graph to process the query
            initial_state = {
                "user_question": user_input,
                "response": {},
                "question": ""
            }

            result = agent_graph.invoke(initial_state)

            # Display the response with response_type
            print(f" Response Type: {result['response'].get('response_type', 'unknown')}")
            print(json.dumps(result["response"], indent=2))

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {str(e)}")

# Main execution
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_cli()
    else:
        logger.info(f"Running the agent on bedrock agentcore runtime...")
        app.run()