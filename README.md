# Agent Omnimesh - Enterprise IT Assistant: Multi-Agentic Implementation with AgentCore, LangGraph & Strands
# Need VPC private network connectivity with AgentCore Gateway

***Omnimesh - Universal network of agents and services***

**IMPORTANT**: This code is intended for demonstration and proof-of-concept purposes only. It is not designed or verified for production use. Before implementing this code in you environment, thoroughly analyze and adapt it to align with your specific business requirements and security standards. AWS cannot warrant the security or functionality of this sample code.

## Overview

**WATCH THE E2E DEMONSTRATION AND SOLUTION WALKTHROUGH: https://www.youtube.com/watch?v=FEuO7P5tAi8**

This solution contains the `multi-agent` implementation of an Enterprise IT Support Assistant using Amazon Bedrock `AgentCore` and Strands Agents SDK. Bedrock `AgentCore` enables you to deploy and operate highly effective agents securely, at scale using any framework and model. With Amazon Bedrock `AgentCore`, developers can accelerate AI agents into production with scale, reliability, and security, critical to real-world deployment.

Strands Agents enables customers to build `multi-agent` architectures in a model-driven approach with a few lines of code, with autonomy and low-level access to building `Agentic` workflows, in a completely model-agnostic way. The IT Support Assistant uses a Strands graph as an orchestrator that coordinates with multiple other agents available via `AgentCore` Gateway, using `AgentCore` Identity, Observability and Memory (both at a global and a sub-agent level).

The solution is developed in a hyper-flexible way to extend the orchestrator functionality, add custom features to the code and optimize for accuracy and different user flows.

![img](/agents/img/arch.png)

**Want to bring your own agent?** See [Bring Your Own Agent](bring_your_own_agent.md) for instructions on adding new agents or MCP endpoints to the AgentCore Gateway.

## Proposed Flows

The solution supports two primary user interaction flows:

### Scenario 1: Deterministic Routing to Sub-Agents - User Request Contains Service Context

![img](/agents/img/with_context.png)

If the user sends a request to the IT Support assistant with Service Context in their metadata (e.g., user from Infrastructure team), the following happens:

1. Query hits the assistant which is an orchestrator strands graph. The graph first checks whether the service context in the user request metadata is provided as a reference in the agent registry (DynamoDB table with agents and a list of available sub-agents that can help), and then checks for the available sub-agents that can be used for that user service (in this case Infrastructure).

2. Gets the most similar available sub-agent for assistance (e.g., Infrastructure agent).

3. Skips the orchestrator agent reasoning and routes the user request directly to the agent_executor_node. This node connects to AgentCore gateway using the MCP URL (using inbound authentication) and lists all the available agents registered as tools.

4. Finds if there is a tool that is the same as the matched agent from before (Infrastructure), and directly does a call_tool on that MCP tool (which is a domain agent).

5. The MCP Tool (in this case, the agent) can respond with the following signals:
   - `out_of_scope`: If the question is about another agent or some other topic, the sub-agent sends an out of scope signal.
   - `more_info_needed`: If the question is generic or about Infrastructure, the agent will directly talk to the user without the orchestrator agent involvement.
   - `complete`: If the domain agent has completed answering the user question, it gives a complete signal.
   - `error`: In the case of an error, the domain agent gives an error signal.

6. If the signal from the domain agent is `out_of_scope` or `error`, then the previous conversation history (user preferences, semantics, session summaries), last k turns and the current error message goes to the orchestrator agent. The orchestrator then decides whether there is another domain agent in the gateway to help assist with the user request.

7. If there is no other agent in the gateway to help with the user request, the user question is finally routed to the Service Desk agent (which is also backed behind the gateway) to engage in multi-turn conversations and get more information from the user.

**Note:** The user session sticky-ness is maintained with an `active_plugin_session` flag. If the user asks a question that skips the orchestrator and matches with an agent from the gateway, the `active_plugin_session` is activated until the domain agent sends a signal that the user request is completed and no more info is needed from that agent.

### Scenario 2: User Request Metadata Contains No Service Context

When no service context is provided:

1. Query hits IT Support Assistant (orchestrator graph). With no service context in metadata, the Assistant uses routing logic and recent conversation memory (preferences, semantics, summaries) to decide which tool/agent in the Agent Gateway to call.

2. Selects the most likely domain agent from the Gateway's registered tools (e.g., Infrastructure, Development Tools, Database, Service Desk, etc.) based on semantic match to the user query.

3. Assistant invokes the candidate via the Agent Gateway (call_tool on the MCP tool). No registry filter is applied because no service context was provided.

4. Domain agent returns one of four signals as described in Scenario 1, and the same flow follows.

## Solution Implementation

The solution implementation is divided into two main portions: **Agent Infrastructure** and **Agent Orchestration**.

### Agent Infrastructure: AgentCore & Agent Registry

#### AgentCore Runtime

`AgentCore` Runtime primitive provides server-less execution environments with session isolation for AI agents. This solution uses domain sub-agents built on `LangGraph`. We use `AgentCore` runtime to deploy and host `LangGraph` domain agents at scale. This solution contains multiple domain agents: `Infrastructure`, `Development Tools`, `Database`, and `Service Desk`. Each agent is a domain-based `LangGraph` agent that has its own functionality. They are all integrated with inbound authentication using `AgentCore` Identity and Amazon Cognito.

#### AgentCore Gateway

All agents are registered as REST API `OpenAPI` targets to `AgentCore` gateway with their OAuth credentials (for outbound authentication from the gateway to the agents). The `AgentCore` Gateway serves as a centralized entry point and orchestration layer that aggregates multiple individual agents as tools through a single Model Context Protocol (MCP) endpoint.

##### Key features:
- **Dual Authentication**: Handles both inbound authentication (client to gateway using AWS Cognito JWT tokens) and outbound authentication (gateway to individual agent runtimes using OAuth 2.0)
- **Agent Registration**: Uses `OpenAPI` specifications to define and register available agents as tools, with their endpoints pointing to specific Bedrock `AgentCore` runtime URLs
- **Protocol Translation**: Converts MCP tool calls into appropriate agent runtime invocations, abstracting the underlying agent communication details
- **Dynamic Agent Management**: Supports adding new agents by updating the OpenAPI specification and re-running the gateway creation process

#### Agent Registry

The agent registry is a catalog of IT services and the agents that can help with each service-related question. This is a DynamoDB table that contains information about IT services and associated domain agents. This is beneficial when a user comes in with some service context - information from this registry is used to deterministically determine which sub-agent to call directly without the orchestrator agent's involvement.

#### AgentCore Memory

Amazon Bedrock `AgentCore` Memory lets you create and manage memory resources that store conversation context for your AI agents. Short-term memory and long-term memory (user preferences, summaries and semantic facts) are tracked as part of both the orchestrator agent and the domain agents that are invoked through the gateway.

The implementation of memory is two-fold:

1. **IT Support Assistant (Orchestrator memory/Shared memory across all agents & environment)**: The orchestrator agent maintains and stores long-term memory (user preferences, semantics and summaries) across all agents.

2. **Domain level agent memory**: Each domain agent can maintain its own memory context in its interaction with the IT Support assistant. Each tool call has its own namespace from where the memory is stored and retrieved.

##### Memory Functionality

The memory system provides semantic search across four types of stored information:

1. `User Preferences` - Personal settings (global + tool-specific)
2. `Semantic Knowledge` - Important facts and context
3. `Session Summaries` - Previous conversation summaries
4. `Recent Turns` - Last 3-5 conversation exchanges
5. `Semantic search` - Semantic search over the relevant conversations from the history

##### Memory Architecture - Two-Layer Structure

1. **Global Memory** - Shared across all agents using base user ID (it-support-user)
2. **Tool-Specific Memory** - Isolated per tool using compound ID (it-support-user__Infrastructure)

Three Storage Strategies:
- User Preferences: `/preferences/{actorId}` - Settings that persist
- Semantic Memory: `/semantics/{actorId}` - Long-term factual knowledge
- Session Summaries: `/summaries/{actorId}/{sessionId}` - Conversation continuity

```
Orchestrator Memory (Global)
 /preferences/it-support-user
 /semantics/it-support-user
 /summaries/it-support-user/{sessionId}

Tool-Specific Memory
 /preferences/it-support-user__Infrastructure
 /semantics/it-support-user__Infrastructure
 [Other tools...]
```

#### AgentCore Identity

`AgentCore` Identity is integrated at 2 levels:

1. **Inbound Authentication**:
   - `OAuth` support for access to Gateway
   - `OAuth` support for access to various sub-agents running on Runtime

2. **Outbound Authentication**:
   - `OAuth` support for Gateway access to external tools (i.e., IT domain agents and MCP servers)

### IT Support Assistant: Strands Graph

The IT Support Assistant is built using the Strands Custom Graph implementation. Strands graph is crucial for this use case because it offers:

1. **Hybrid workflow**: Reserve LLM calls for complex reasoning while handling routing/memory in fast custom nodes
2. **Deterministic routing**: Use precise, rule-based branching (no LLM ambiguity) for response type and tool selection
3. **LLM bypass for memory ops**: Perform context retrieval/storage directly in code to cut cost and latency
4. **Business-logic first**: agent_identifier enforces exact policies: active session checks, user metadata matching, and context hydration
5. **Structured data branching**: unified_routing_decision and plugin_response_router drive if/else paths from typed inputs, not free-text
6. **FunctionNode wrapping**: Encapsulate Python functions as nodes for reliable, composable execution steps
7. **Predictable execution paths**: Eliminate stochastic model behavior for critical control flow
8. **Performance & cost efficiency**: Keep hot-path operations lightweight; pay for LLM only when reasoning is truly needed
9. **Fine-grained control**: Tight governance over which agent/tool runs, with explicit policies and guards

#### Strands Architectural Flow

The orchestrator is designed as a graph with 4 nodes and 2 edges for different functionalities.

##### Nodes & Edges

1. **Agent identifier node**: This is the entry-point of the graph. Based on the user question, this node first checks if there is service context in the user metadata request. If so, this node implements a matching logic to search for relevant/similar services in an agent registry and available sub-agents. If there is a match, then it chooses the agent to route to from the agent registry. This is the deterministic flow where no orchestrator agent is involved. If the user comes in with no context, then the request is sent to the orchestrator strands agent that connects to AgentCore gateway, lists the agents, and checks for whether there is an agent that can help with the user request. If there is no domain agent to assist with the user request, then the orchestrator decides to route the agent to a Service Desk agent.

2. **Unified router conditional edge**: This is the edge after node 1 that checks for two things. First, if there is a sticky session between a user and a domain agent from the gateway from a prior interaction, then it directly routes it to the continue sticky session node that invokes the domain agent from AgentCore gateway. If an agent is selected otherwise, then that is sent to the Agent executor node.

3. **Agent executor node**: This node uses the potential agent from the previous nodes, lists the tools from AgentCore gateway, checks if there is any tool that matches the potential_agent_selection from before, and then calls that tool using the tool_call invocation via MCP. The response then goes to the plug-in router conditional edge.

4. **Plug-in router conditional edge**: This takes the response from the agent executor node. If the response from the sub-agent is `out_of_scope` or `error`, then it decides to fallback to the orchestrator. If the response is `more_info_needed`, then it decides to route it back to the user and maintains the sticky-session (using a flag variable) until the domain agent has answered the question.

5. **Orchestrator fallback node**: This is the node where the orchestrator agent is used if the domain agent response is `out_of_scope` or `error`. The orchestrator agent then decides which other tool to call via AgentCore gateway and if there is no agent then call the Service Desk agent from the gateway.

6. **Continue sticky session node**: If a user query comes in with the sticky session flag enabled, then the request is routed here. The request will contain the name of the previous tool call from the gateway, which is then invoked again using the latest memory and context of the conversation until the domain agent decides that the interaction with the user is complete.

## Running the Solution in Your AWS Account

Follow these steps in order to deploy and run the IT Support Assistant solution in your AWS account:

Execute the following command in your terminal to instantiate the `uv` environment:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv venv && source .venv/bin/activate && uv pip sync pyproject.toml
UV_PROJECT_ENVIRONMENT=.venv
uv add zmq
python -m ipykernel install --user --name=.venv --display-name="Python (uv env)"
```

### Step 1: Create Sub-Agents

**NOTE**: View the example annotated configuration file that is used while running the orchestrator [here](agents/orchestrator/config_yaml.template.md)

Navigate to the `agents/sub_agents/README.md` file for detailed information on creating sub-agents. These sub-agents can be:
- Agents you deploy on `AgentCore` Runtime, OR
- Existing agents deployed as HTTP endpoints

**Important:** Note down the HTTP endpoints and IDP (Identity Provider) information for your agents, as you will need them for gateway configuration.

### Step 2: Configure Agent Identity (IDP)

If you don't have an existing IDP for your agents, you need to create one. This solution supports OAuth 2.0 authentication.

Navigate to the `agents/agent_idp/README.md` file for instructions on setting up Amazon Cognito as your Identity Provider for agent authentication.

### Step 3: Create AgentCore Gateway

Once your sub-agents and IDP are configured, create the `AgentCore` Gateway that will serve as the central entry point for all your agents.

Navigate to the `agents/agent_gateway/README.md` file for detailed instructions on setting up the gateway with your agents' endpoints and OAuth credentials.

### Step 4: Create Knowledge Base and Guardrails (Optional)

If your orchestrator application requires a knowledge base or guardrails, configure them now. These will be used within your orchestrator to enhance agent capabilities and ensure safe operations.

Refer to Amazon Bedrock documentation for creating:
- Knowledge Bases for retrieval-augmented generation (RAG)
- Guardrails for content filtering and safety

### Step 5: Create Agent Registry

The agent registry is a DynamoDB table that maps IT services to their associated domain agents, enabling deterministic routing based on user context.

Navigate to the `agents/agent_mapping/README.md` file for instructions on creating and populating the agent registry with your IT services and domain agents.

### Step 6: Configure the Orchestrator Agent

Finally, configure the orchestrator agent that will coordinate all interactions. Navigate to the `agents/orchestrator/` directory and configure the following in the `config.yaml` file:

#### Required Configurations:

1. **Gateway Configuration**:
   - `gateway_url`: The MCP URL of your AgentCore Gateway
   - `gateway_inbound_auth`: Client ID, Client Secret, and Discovery URL for gateway authentication

2. **Memory Configuration**:
   - `memory_execution_role`: IAM role ARN for AgentCore Memory access
   - `memory_id`: The AgentCore Memory ID for storing conversation context

3. **Model Configuration**:
   - `embeddings_model`: The embeddings model used for matching user product context with products in the DynamoDB registry
   - `reasoning_model`: The LLM model used by the orchestrator for decision-making

4. **Agent Prompts**:
   - Customize the orchestrator's behavior by editing `agents/orchestrator/agent_prompts/orchestrator_agent_system_prompt.txt`
   - This prompt defines how the orchestrator reasons about agent selection and user interactions

5. **User Metadata**:
   - Configure sample user metadata in `config.yaml` to simulate different user contexts and IT service scenarios

#### Key Files:

- **`config.yaml`**: Main configuration file containing all settings
- **`orchestrator_agent.py`**: Main orchestrator implementation using Strands graph
- **`memory_utils.py`**: Memory utilities for managing AgentCore Memory operations (preferences, semantics, summaries)
- **`agent_prompts/`**: Directory containing system prompts for the orchestrator

#### Streamlit Application:

The solution includes a Streamlit-based web interface for testing and demonstration:
- Navigate to `agents/orchestrator/streamlit/`
- Run the Streamlit app to interact with the IT Support Assistant through a user-friendly interface
- The app displays conversation history, agent routing decisions, and memory context

### Step 7: Run the Orchestrator

After completing all configurations, you can run the orchestrator:

```bash
# Navigate to the orchestrator directory
cd agents/orchestrator

# Install dependencies (if using uv)
uv sync

# Run the orchestrator (example)
python orchestrator_agent.py

# Or run the Streamlit app
cd streamlit
streamlit run streamlit_app.py
```

## Support

For issues, questions, or contributions, please refer to the individual README files in each component directory for specific guidance.
