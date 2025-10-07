# Agent onboarding

This is a dummy agent for infrastructure support built on LangGraph that is hosted on Bedrock AgentCore runtime with OAuth 2.0.

## About: Orchestration handling

This is a simulation of the Infrastructure sub agent. This agent has access to infrastructure information (cloud, networking, servers) through the system prompt. This agent
does as follows:

1. If the user question is not about infrastructure but about some other product, then the agent should respond with the following JSON:

```bash
{
  "response_type": "out_of_scope",
  "response_message": "I'm specifically designed to help with infrastructure questions (cloud, networking, servers). For other topics..."
}
```

it provides an `out_of_scope` model response which is a signal to the orchestrator to know that the question is out of scope. The logic to handle and decide for that is
not in the orchestrator agent's scope.

2. If the user question is about infrastructure and the infrastructure agent is able to respond to the user question completely, then the agent responds with the following:

```bash
{
  "response_type": "model_response",
  "response_message": "Infrastructure management involves cloud resources, networking configuration, and server administration..."
}
```

it provides an `model_response` model response which is a signal to the orchestrator that the user question has been answered, in this case the logic would tell to go directly to user user and not through the orchestrator agent.
The logic to handle and decide for that is not in the orchestrator agent's scope.

3. If the user question is about infrastructure or it is a general question which requires a follow up, then the agent should respond with the following JSON:

```bash
{
  "response_type": "more_info_needed",
  "response_message": "Hello! I'm your Infrastructure assistant...."
}
```

It provides an `more_info_needed` model response which is a signal to the orchestrator to know that more information is needed to answer the user question. The logic to handle and decide for that is
not in the orchestrator agent's scope. This requires there to be sticky-ness between the sub agent and the end user.

4. If there is an error from the user question then the following is the JSON response:

```bash
{
  "response_type": "error",
  "response_message": "..."
}
```

If there is an error in calling the agent then this is what the orchestrator gets from the agent.

This section provides an overview on the signal component. This defines when the sub agent should or should not consult an orchestrator agent. If the response is an `error` or `out_of_scope`, then the orchestrator handles the
next steps. If the response is `model_response` or `more_info_needed`, then the information passes back to the user.

## How to run?

To run this agent, follow the steps below:

1. Set up cognito - we will be using the same IDP for all of the agents, so if you have run this already, you do not have to re-run this:

```bash
python agent_idp/setup_cognito.py
```

This will set up a cognito user pool, user and return a `cognito_config.json` with information about the following:

```json
{
  "pool_id": "",
  "client_id": "",
  "bearer_token": "",
  "discovery_url": ""
}
```

2. Run the agent on Bedrock agentcore runtime:

```bash
agentcore configure -e infrastructure_agent.py
```

Once the agent is launching on agentcore runtime, then provide the runtime execution role, the inbound authentication (`discovery_url` and `client_id`) from the `cognito_config.json` file. View an example of the file below:

```json
{
  "pool_id": "",
  "client_id": "<take this client id>",
  "bearer_token": "",
  "discovery_url": "<take this discovery url>"
}
```

3. Launch the agent to agentcore runtime:

```bash
agentcore launch
```

4. Invoke the plug-in/domain agent:

```bash
cd agents/
python invoke_agent.py
```

Next, provide the region, the cognito discovery URL, the client id and then invoke the agent.
