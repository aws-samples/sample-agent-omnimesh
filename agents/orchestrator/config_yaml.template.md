# Configuration Template Documentation

This document provides detailed explanations for each section of the `config.yaml` file used in the AgentCore multi-agent orchestrator system.

## agent_gateway

Configuration for the AgentCore gateway that routes requests to agents.

```yaml
agent_gateway:
  gateway_url: https://your-gateway.gateway.bedrock-agentcore.region.amazonaws.com/mcp
  inbound_auth_info:
    client_id: your-cognito-client-id
    client_secret: your-cognito-client-secret
    discovery_url: https://your-auth-domain.auth.region.amazoncognito.com/.well-known/openid-configuration
```

### Fields

- **gateway_url**: The URL endpoint of the AgentCore gateway. This is the main entry point for all agent requests and is created during the gateway provisioning process. The gateway routes incoming requests to the appropriate agents based on the request context.

- **inbound_auth_info**: OAuth 2.0 authentication configuration used to access agents within the AgentCore gateway. This information is used in the gateway creation process for inbound authentication and authorization.
  - **client_id**: The Cognito OAuth client ID for authenticating requests to the gateway
  - **client_secret**: The Cognito OAuth client secret (keep this secure and never commit to version control)
  - **discovery_url**: The OpenID Connect discovery URL for the Cognito user pool. This URL provides OAuth endpoints and configuration needed for authentication

## agent_infra_resources

Infrastructure resources required by the agents, including knowledge bases, logging, and memory.

```yaml
agent_infra_resources:
  actor_id: user-identifier
  agent_kb_resources:
    orchestrator_agent:
      description: Knowledge base description
      information_directory: local_directory_with_knowledge_files
      kb_name: knowledge-base-name
      knowledge_base_bucket_name: s3-bucket-name
  cloudwatch_agent_resources:
    log_group_name: agents/agent-name
    log_stream_name: stream-name
  memory_execution_role: arn:aws:iam::account-id:role/RoleName
  memory_id: unique-memory-id
  orchestrator_agent_resources:
    system_prompt: system_prompt_file.txt
  prompt_template_directory: directory_with_prompts
  use_existing_memory: true
```

### Fields

- **actor_id**: A unique identifier for the user or system acting on behalf of requests. Used for tracking, logging, and attribution of agent actions.

- **agent_kb_resources**: Configuration for knowledge bases used by agents. Knowledge bases provide retrieval-augmented generation (RAG) capabilities.
  - **orchestrator_agent**: Knowledge base specific to the orchestrator agent
    - **description**: Human-readable description of what information this knowledge base contains
    - **information_directory**: Local directory path containing files to be ingested into the knowledge base
    - **kb_name**: The name of the Amazon Bedrock knowledge base resource
    - **knowledge_base_bucket_name**: S3 bucket where knowledge base documents are stored

- **cloudwatch_agent_resources**: Amazon CloudWatch logging configuration for monitoring and debugging agent behavior
  - **log_group_name**: CloudWatch log group where agent logs are stored (typically follows pattern `agents/agent-name`)
  - **log_stream_name**: CloudWatch log stream within the log group for organizing logs

- **memory_execution_role**: IAM role ARN that grants the agent permission to access and manage its memory storage. This role needs permissions for DynamoDB or the chosen memory backend. See [Amazon Bedrock AgentCore Memory Documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/configure-memory.html)

- **memory_id**: Unique identifier for the agent's memory storage. Memory allows agents to maintain context across conversations and sessions.

- **orchestrator_agent_resources**: Resources specific to the orchestrator agent
  - **system_prompt**: Path to a text file containing the system prompt that defines the orchestrator's behavior and instructions

- **prompt_template_directory**: Directory containing prompt template files used by agents for various tasks

- **use_existing_memory**: Boolean flag indicating whether to reuse an existing memory resource (`true`) or create a new one (`false`)

## agent_registry

Configuration for the agent registry, which manages agent discovery and routing.

```yaml
agent_registry:
  embeddings_model_info_semantic_search:
    model_id: amazon.titan-embed-text-v2:0
  table_name: user-agent-mappings
```

### Fields

- **embeddings_model_info_semantic_search**: Configuration for the embeddings model used for semantic search when routing requests to agents
  - **model_id**: The Amazon Bedrock model ID for generating embeddings. Used to understand semantic similarity between user queries and agent capabilities

- **table_name**: DynamoDB table name that stores mappings between users and their available agents. This registry enables dynamic agent discovery and user-specific agent routing.

## general

High-level metadata about the multi-agent system.

```yaml
general:
  description: Description of the multi-agent system and its purpose
  name: System-name
```

### Fields

- **description**: A detailed description of the multi-agent system, explaining its purpose and capabilities

- **name**: A unique name for the multi-agent system instance

## model_information

Configuration for the AI models used by agents, including inference parameters and guardrails.

```yaml
model_information:
  orchestrator_agent_model_info:
    guardrail_id: guardrail-id
    guardrail_version: DRAFT
    inference_parameters:
      caching: true
      max_tokens: 4000
      temperature: 0.1
      top_p: 0.92
    model_id: us.anthropic.claude-3-7-sonnet-20250219-v1:0
```

### Fields

- **orchestrator_agent_model_info**: Model configuration for the orchestrator agent
  - **guardrail_id**: Amazon Bedrock Guardrail ID that enforces content filtering, safety policies, and sensitive information protection
  - **guardrail_version**: Version of the guardrail to use (`DRAFT` for testing or a specific version number for production)
  - **inference_parameters**: Parameters controlling model behavior
    - **caching**: Whether to enable prompt caching for improved performance and reduced costs
    - **max_tokens**: Maximum number of tokens the model can generate in a response
    - **temperature**: Controls randomness in responses (0.0-1.0). Lower values are more deterministic
    - **top_p**: Nucleus sampling parameter controlling diversity. Lower values make output more focused
  - **model_id**: The specific Amazon Bedrock model identifier to use (includes region prefix for cross-region inference)

## user_metadata

Context and metadata about the user and their environment, used to personalize agent responses.

```yaml
user_metadata:
  provided_context:
    detected_country: US
    host: domain.com
    locale: en-US
    service:
      capabilities:
        - Capability 1
        - Capability 2
      category: Category
      name: Service Name
      version: Version Number
    url: https://domain.com/service
```

### Fields

- **provided_context**: Rich contextual information passed to agents for personalized responses
  - **detected_country**: The user's country code for localization and regional information
  - **host**: The domain from which the request originated
  - **locale**: User's language and region preference (e.g., `en-US`, `fr-FR`)
  - **service**: Information about the IT service context
    - **capabilities**: List of IT service capabilities or features relevant to the user's query
    - **category**: Service category (e.g., `Infrastructure`, `Development Tools`, `Database`, `Service Desk`)
    - **name**: Service name
    - **version**: Service version number
  - **url**: The URL of the service or page where the user is working

This context allows agents to provide service-specific, localized, and contextually relevant responses.