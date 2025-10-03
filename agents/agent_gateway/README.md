# Amazon Bedrock AgentCore Gateway Setup

## Overview
This guide explains how to create and configure an Amazon Bedrock AgentCore Gateway that provides centralized access to multiple agent endpoints through a unified MCP (Model Context Protocol) interface. The gateway handles authentication, routing, and provides a single entry point for all your agents.

## How Amazon Bedrock AgentCore Gateway Works

Amazon Bedrock AgentCore Gateway acts as a unified entry point that:

1. **Centralizes Access**: Provides a single URL endpoint for accessing multiple agents
2. **Handles Authentication**: Manages both inbound (user-to-gateway) and outbound (gateway-to-agent) OAuth authentication
3. **Routes Requests**: Directs requests to the appropriate agent based on OpenAPI specifications
4. **Protocol Translation**: Supports MCP protocol for seamless integration with agent runtimes
5. **Simplifies Management**: Reduces complexity by managing multiple agents through a single gateway

### Gateway Architecture

```
User/Client
    |
    | (Inbound OAuth Authentication)
    v
AgentCore Gateway
    |
    | (Outbound OAuth Authentication)
    v
Multiple Agent Endpoints (Targets)
```

## Prerequisites

Before setting up the gateway, ensure you have:

1. **Agent Endpoints**: One or more agents registered through Amazon Bedrock AgentCore Runtime
   - See the [sub_agents](../sub_agents/README.md) folder for agent creation instructions
   - Alternatively, use existing HTTP endpoints for your agents

2. **Agent Identity Provider (IdP)**: OAuth credentials for agent authentication
   - See [agent_idp/README.md](../agent_idp/README.md) for setting up Cognito as your IdP
   - Or collect credentials from your existing OIDC-compliant IdP

3. **AWS Account**: With permissions to create and manage:
   - Amazon Bedrock AgentCore Gateways
   - IAM roles
   - S3 buckets
   - Cognito (if using Cognito for authentication)

4. **Python Environment**: Python 3.11+ with required dependencies

## Step 1: Create OpenAPI Specification Files

After registering your agents through Amazon Bedrock AgentCore Runtime or setting up your HTTP endpoints, you need to create OpenAPI specification files that describe how to access each agent.

### Understanding OpenAPI Specifications

Each agent needs an OpenAPI spec file that defines:
- Agent endpoint URL
- Request/response schemas
- Operation IDs (tool names exposed to the gateway)
- Optional parameters and headers

### Example: Infrastructure Agent Specification

Create a YAML file in the `agent_specifications/` directory:

```yaml
openapi: 3.0.0
info:
  title: Infrastructure
  version: 1.0.3
  description: >
    Enterprise IT Infrastructure agent for cloud, networking, and server management.
    This agent analyzes user queries and provides assistance with infrastructure-related topics.
    The operationId is the tool name the Gateway exposes to agents.
    Auth (inbound/outbound) is configured on the Gateway target, not in this spec.

# ARN baked into the server URL (percent-encoded)
servers:
  - url: https://bedrock-agentcore.us-west-2.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-west-2%3A218208277580%3Aruntime%2Finfrastructure_agent-4ABKfq4ujN/invocations

paths:
  /:
    post:
      operationId: Infrastructure
      summary: Invoke Infrastructure runtime agent
      description: >
        Proxy a prompt to the AgentCore Runtime HTTPS endpoint for infrastructure-related assistance.

      parameters:
        - name: qualifier
          in: query
          required: false
          description: Target a specific runtime version/alias
          schema:
            type: string
            default: DEFAULT

        - name: Mcp-Session-Id
          in: header
          required: false
          schema: { type: string }

      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [prompt]
              properties:
                prompt:
                  type: string
                  description: Natural language instruction for the Infrastructure agent
                  example: "How do I configure AWS VPC peering?"

      responses:
        '200':
          description: Successful invocation
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        '4XX':
          description: Client error from the runtime endpoint
        '5XX':
          description: Server error from the runtime endpoint
```

### Key Points for OpenAPI Specs

- **Server URL**: Include the full Amazon Bedrock AgentCore Runtime endpoint (with percent-encoded ARN)
- **Operation ID**: This becomes the tool name exposed by the gateway
- **Authentication**: Not specified in the OpenAPI spec - configured at the gateway target level
- **File Naming**: Use descriptive names (e.g., `infrastructure-agent.yaml`, `database-agent.yaml`)
- **Location**: Place all specification files in the `agent_specifications/` directory

## Step 2: Configure Gateway Inbound Authentication (Gateway IdP)

The gateway needs inbound authentication to control who can access it. This is configured using any OIDC-compliant IdP.

### Using Cognito for Inbound Authentication

If you don't have an existing IdP, you can create a Cognito user pool for gateway access:

```bash
cd gateway_idp
python setup_cognito_gateway_inbound.py
```

This creates a `cognito_config.json` file with:
- **Pool ID**: Cognito user pool ID
- **Client ID**: OAuth client ID for gateway access
- **Discovery URL**: OIDC discovery endpoint

### Using an Existing IdP

If you have an existing OIDC-compliant IdP, collect:
- Pool ID (or equivalent identifier)
- Client ID(s) that should be allowed to access the gateway
- Discovery URL (OIDC discovery endpoint)

### Configuration in setup_gateway.yaml

Add the inbound authentication configuration to `setup_gateway.yaml`:

```yaml
gateway_config:
  name: "enterprise-it-gateway"
  bucket_name: your-s3-bucket-name
  description: "AgentCore Gateway for IT support agents"
  protocol_type: "MCP"
  agent_spec: agent_specifications/agent_spec.yaml

  # Inbound authentication configuration
  use_existing_inbound_auth: yes
  inbound_auth:
    # Cognito user pool ID (or IdP equivalent)
    pool_id: "<user-pool-id>"
    # Client IDs allowed to access the gateway
    client_id:
      - "<client-id>"
    # OIDC discovery URL
    discovery_url: "https://cognito-idp.us-west-2.amazonaws.com/.../.well-known/openid-configuration"
```

## Step 3: Configure Agent Identity (Outbound Authentication)

The gateway needs credentials to authenticate with your agents. All agents should ideally share the same identity to reduce complexity.

### Shared Agent Identity

Configure the outbound authentication in `setup_gateway.yaml`:

```yaml
gateway_config:
  # ... (inbound auth config above)

  # OAuth provider configuration for agent authentication
  sub_agents_outbound_authorization:
    # Name of the identity provider for agents
    name: ""
    # Cognito domain name (if using Cognito)
    domain_name: "it-support-agent"
    # Agent identity credentials (from agent_idp/cognito_config.json)
    pool_id: ""
    client_id: ""
    client_secret: ""
    discovery_url: "https://cognito-idp.us-west-2.amazonaws.com/.../.well-known/openid-configuration"
```

### Where to Get Agent Identity Information

**Option 1**: If you created agents using the `agent_idp` setup:
- Use the credentials from `agent_idp/cognito_config.json`

**Option 2**: If you have existing agents with their own IdP:
- Collect the pool ID, client ID, client secret, and discovery URL from your agent's IdP

**Important**: All agents registered with this gateway should use the same identity provider to simplify authentication management.

## Step 4: Complete Gateway Configuration

Ensure your `setup_gateway.yaml` file is complete:

```yaml
gateway_config:
  # Gateway name
  name: "enterprise-it-gateway"

  # S3 bucket where OpenAPI specs will be uploaded
  bucket_name: <your-bucket-name-here>

  # Gateway description
  description: "AgentCore Gateway for enterprise IT support agents"

  # Protocol type (MCP for Amazon Bedrock AgentCore)
  protocol_type: "MCP"

  # Path to the folder containing agent OpenAPI specifications
  agent_spec: agent_specifications/agent_spec.yaml

  # Inbound authentication (user -> gateway)
  use_existing_inbound_auth: yes
  inbound_auth:
    pool_id: ""
    client_id:
      - ""
    discovery_url: "https://cognito-idp.us-west-2.amazonaws.com/.../.well-known/openid-configuration"

  # Outbound authentication (gateway -> agents)
  sub_agents_outbound_authorization:
    name: ""
    domain_name: "enterprise-it-agent"
    pool_id: ""
    client_id: ""
    client_secret: ""
    discovery_url: "https://cognito-idp.us-west-2.amazonaws.com/.../.well-known/openid-configuration"
```

## Step 5: Create the Gateway

Run the gateway creation script:

```bash
python create_gateway.py
```

### What This Script Does

![img](../img/gw_overview.png)

1. **Creates IAM Role**: Sets up the necessary IAM role for gateway operations
2. **Configures OAuth Provider**: Creates or uses existing OAuth provider for agent authentication
3. **Creates Gateway**: Initializes the Amazon Bedrock `AgentCore` Gateway with authentication configuration
4. **Uploads Specifications**: Uploads all `OpenAPI` spec files from `agent_specifications/` to S3
5. **Creates Gateway Targets**: Registers each agent as a target in the gateway
6. **Saves Configuration**: Writes gateway details to `gateway_results.json`

### Expected Output

The script will:
- Display progress for each step
- Create or reuse an existing gateway with the specified name
- Upload each OpenAPI specification file to S3
- Create a gateway target for each specification
- Save comprehensive gateway information to `gateway_results.json`

## Step 6: Review Gateway Results

After successful creation, check the `gateway_results.json` file:

```json
{
  "gateway_info": {
    "gateway_id": "enterprise-it-gateway",
    "gateway_name": "enterprise-it-gateway",
    "gateway_url": "https://...gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp",
    "description": "Agent Gateway for enterprise IT support agents"
  },
  "authentication": {
    "authorizer_type": "CUSTOM_JWT",
    "protocol_type": "MCP",
    "discovery_url": "https://cognito-idp.us-west-2.amazonaws.com/.../.well-known/openid-configuration",
    "allowed_clients": [""],
    "role_arn": "arn:aws:iam:::role/agentcore-agent-gateway-new-role"
  },
  "cognito_config": {
    "name": "NewProvider",
    "domain_name": "enterprise-it-agent-...",
    "pool_id": "",
    "client_id": "",
    "client_secret": "",
    "discovery_url": "https://cognito-idp.us-west-2.amazonaws.com//.well-known/openid-configuration"
  },
  "oauth_provider": {
    "provider_arn": "arn:aws:bedrock-agentcore:us-west-2::token-vault/default/oauth2credentialprovider/NewProvider",
    "provider_name": "NewProvider",
    "scopes": [
      "https://enterprise-it-agent/us-west-/admin",
      "https://enterprise-it-agent/us-west-/read",
      "https://enterprise-it-agent/us-west-/write"
    ]
  },
  "targets": [
    {
      "target_name": "Infrastructure",
      "spec_file": "infrastructure.yaml",
      "description": "OpenAPI Target with S3 URI for Infrastructure",
      "openapi_s3_uri": "s3://fmbench-deep-dive/infrastructure.yaml"
    },
    {
      "target_name": "Database",
      "spec_file": "database.yaml",
      "description": "OpenAPI Target with S3 URI for Database",
      "openapi_s3_uri": "s3://fmbench-deep-dive/database.yaml"
    }
  ]
}
```

### Gateway Results Sections

- **gateway_info**: Gateway ID, name, URL, and description
- **authentication**: Inbound authentication configuration
- **cognito_config**: Outbound authentication credentials for agents
- **oauth_provider**: OAuth provider details and scopes
- **targets**: List of all agents registered as gateway targets

## Step 7: Verify in AWS Console

1. Navigate to the Amazon Bedrock console
2. Go to Amazon Bedrock AgentCore section
3. Select "Gateways" from the navigation menu
4. Find your gateway by name (e.g., "enterprise-it-gateway")
5. Verify:
   - Gateway status is "Active"
   - All targets are listed and active
   - Authentication configuration is correct



## Adding Targets to an Existing Gateway

To add new agents or MCP servers to an existing gateway, you need to create a new OpenAPI specification and register it via the gateway's REST API.

### Step 1: Create OpenAPI Specification for the New Agent

Add a new YAML file to `agent_specifications/` following the same format as existing agents:

```yaml
openapi: 3.0.0
info:
  title: NewAgent
  version: 1.0.0
  description: Description of your new agent

servers:
  - url: https://your-agent-endpoint.com

paths:
  /:
    post:
      operationId: NewAgent
      summary: Invoke new agent
      description: Description of what this agent does

      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [prompt]
              properties:
                prompt:
                  type: string
                  description: User query for the agent

      responses:
        '200':
          description: Successful invocation
          content:
            application/json:
              schema:
                type: object
```

### Step 2: Create a new target on the AWS AgentCore Gateway page

Follow the steps here: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-schema-openapi.html

## Authentication Flow

### Inbound Authentication (User to Gateway)

1. User obtains OAuth token from gateway IdP (e.g., Cognito)
2. User includes token in request to gateway URL
3. Gateway validates token using configured discovery URL
4. Gateway authorizes request based on allowed client IDs

### Outbound Authentication (Gateway to Agents)

1. Gateway obtains OAuth token from agent IdP using client credentials
2. Gateway includes token when invoking agent endpoints
3. Agent validates token and processes request
4. Gateway returns agent response to user

## Additional Resources

- [Amazon Bedrock AgentCore Documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [Agent Identity Provider Setup](../agent_idp/README.md)
- [Sub-Agents Documentation](../sub_agents/README.md)
- [OpenAPI 3.0 Specification](https://swagger.io/specification/)
