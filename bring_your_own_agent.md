# Bring Your Own Agent

To add a new agent to the IT Support Assistant solution, you need to bring a new OpenAPI specification referring to your agent or MCP endpoint and add it to the AgentCore Gateway. The agent will be automatically reflected the next time the orchestrator runs.

## Steps to Add Your Agent

1. **Create an OpenAPI Specification**: Define your agent's endpoint, request/response schemas, and operation IDs in an OpenAPI YAML file. View other similar files in the `agents/agent_gateway/agent_specifications/` directory.

2. **Add to AgentCore Gateway**: Register your OpenAPI specification as a target in the AgentCore Gateway. This can be done on the Gateway console by adding a new target and having that be a REST API OpenAPI spec as an inline schema with an identity provider.

3. **Update Agent Registry (Optional)**: If your agent is service-specific, add an entry to the Agent Registry (DynamoDB table) to enable deterministic routing when users provide service context.

For detailed instructions on adding a new agent as an OpenAPI spec to the gateway, see: [Agent Gateway README](/agents/agent_gateway/README.md)

## What Happens Next

Once your agent is registered with the gateway:
- The orchestrator will automatically discover it as an available tool
- Users can interact with your agent through the IT Support Assistant
- Your agent will participate in the multi-agent workflow with full observability, memory, and authentication support