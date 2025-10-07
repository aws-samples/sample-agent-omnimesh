# Enterprise IT Assistant AgentCore Memory System

Amazon Bedrock AgentCore Memory lets you create and manage memory resources that store conversation context for your AI agents. Short-term memory and long-term memory (user preferences, summaries and semantic facts) are tracked as a part of both the orchestrator agent and the domain agents that are invoked through the gateway. The implementation of memory is two-fold:

1. **Enterprise IT Assistant (Orchestrator memory/Shared memory across all agents & environment)**: The orchestrator agent maintains and stores long term memory (user preferences, semantics and summaries) across all agents.
2. **Domain level agent memory**: Each domain agent can maintain its own memory context.

## Memory Functionality

### 1. Retrieve/Semantic Search on Relevant Memories
The memory system provides semantic search capabilities across different memory types:
- **User Preferences**: Personal settings and preferences stored globally or per tool
- **Semantic Knowledge**: Important facts and contextual information
- **Session Summaries**: Summaries of previous conversation sessions
- **Recent Conversation Turns**: Last 3-5 conversation exchanges for context

### 2. Memory Storage Strategies

The AgentCore Memory system implements three key strategies:

#### User Preferences Strategy
- **Namespace**: `/preferences/{actorId}`
- **Purpose**: Captures user preferences and settings
- **Scope**: Global user preferences that persist across sessions and tools

#### Semantic Memory Strategy
- **Namespace**: `/semantics/{actorId}`
- **Purpose**: Stores semantic knowledge and important contextual facts
- **Scope**: Long-term factual information relevant to the user

#### Session Summary Strategy
- **Namespace**: `/summaries/{actorId}/{sessionId}`
- **Purpose**: Maintains session summaries for conversation continuity
- **Scope**: Session-specific summaries that help maintain context across conversation turns

## Memory Architecture

### Actor ID Structure
The memory system uses a hierarchical actor ID structure:
- **Global Context**: `{base_user_id}` (e.g., "enterprise-it-user")
- **Tool-Specific Context**: `{base_user_id}__{tool_name}` (e.g., "enterprise-it-user__Infrastructure")

### Namespace Organization
Memory namespaces are structured as follows:
```
/preferences/{actorId}           # User preferences (global)
/preferences/{actorId}__ToolName # User preferences (tool-specific)
/semantics/{actorId}             # Semantic knowledge (global)
/semantics/{actorId}__ToolName   # Semantic knowledge (tool-specific)
/summaries/{actorId}/{sessionId} # Session summaries
```

### Memory Operations

#### Memory Creation
```python
memory_id = create_memory(
    memory_client=mem_client,
    memory_name=f"orchestrator_memory_{timestamp}",
    memory_execution_role_arn=memory_execution_role,
    actor_id=actor_id,
    event_expiry_days=90
)
```

#### Memory Retrieval
```python
context = get_memory_context(
    memory_client=mem_client,
    memory_id=memory_id,
    base_user_id=user_id,
    query=user_query,
    tool_name=current_tool,
    session_id=session_id
)
```

#### Conversation Storage
```python
store_conversation(
    memory_client=mem_client,
    memory_id=memory_id,
    base_user_id=user_id,
    user_message=user_input,
    assistant_message=assistant_response,
    tool_name=current_tool,
    session_id=session_id
)
```

## Memory Context Integration

The memory system provides comprehensive context by combining:

1. **Global Preferences**: User settings that apply across all tools
2. **Tool-Specific Preferences**: Settings specific to the current tool being used
3. **Global Semantics**: General knowledge about the user and their work
4. **Tool-Specific Semantics**: Knowledge specific to the current tool context
5. **Session Summaries**: Summaries of previous related conversations
6. **Recent Turns**: Last 3 conversation exchanges for immediate context

## Memory Storage in the Graph

Memory is integrated into the orchestrator agent graph at multiple levels:

### Global Memory Layer
- **Storage Location**: Orchestrator agent maintains global memory accessible to all domain agents
- **Actor ID**: Uses base user ID (e.g., "enterprise-it-user") for global context
- **Persistence**: Long-term storage with 90-day expiry for events
- **Access Pattern**: Shared across all agent interactions within the session

### Agent-Specific Memory Layer
- **Storage Location**: Each domain agent can access tool-specific memory namespaces
- **Actor ID**: Uses compound ID format: `{base_user_id}__{tool_name}`
- **Persistence**: Tool-specific preferences and semantics stored separately
- **Access Pattern**: Isolated to specific agent/tool interactions

### Graph Storage Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Memory                      │
│                                                             │
│  Global Namespace: /preferences/enterprise-it-user         │
│                   /semantics/enterprise-it-user            │
│                   /summaries/enterprise-it-user/{sessionId}│
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                  Tool-Specific Memory                       │
│                                                             │
│  Infrastructure:  /preferences/enterprise-it-user__Infrastructure│
│                  /semantics/enterprise-it-user__Infrastructure  │
│                                                             │
│  Database:       /preferences/enterprise-it-user__Database │
│                  /semantics/enterprise-it-user__Database   │
│                                                             │
│  Other Tools:    /preferences/enterprise-it-user__{ToolName}│
│                  /semantics/enterprise-it-user__{ToolName} │
└─────────────────────────────────────────────────────────────┘
```

The memory is stored using Amazon Bedrock AgentCore Memory service, which provides:
- **Vector-based semantic search** for retrieving relevant memories
- **Automatic memory extraction** using configured strategies
- **Event-based storage** for conversation turns and interactions
- **Namespace isolation** for different contexts and tools
- **Configurable retention policies** with automatic expiry

## Simplified Memory Flow Sequence

sequenceDiagram
  participant U as User
  participant O as Orchestrator
  participant M as Memory
  participant D as Domain Agent

  Note over U,D: Memory Storage & Retrieval Flow

  %% 1. User query arrives and stored
  U->>O: User Query
  O->>M: Store user query
  Note right of M: Store: Initial user message

  %% 2. Retrieve context for routing
  O->>M: Retrieve memory context
  M-->>O: Return context (preferences, semantics, summaries)
  Note right of M: Retrieve: User context for routing

  %% 3. Route to domain agent with context
  O->>D: Route to agent + memory context
  D->>M: Retrieve tool-specific context
  M-->>D: Return tool context
  Note right of M: Retrieve: Tool-specific memory

  %% 4. Agent response and storage
  D-->>O: Agent response
  O->>M: Store conversation (user + assistant)
  Note right of M: Store: Complete conversation exchange

  %% 5. Final response
  O-->>U: Final response
