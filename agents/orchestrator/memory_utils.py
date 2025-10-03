"""
Simplified memory utilities for orchestrator agent.
Handles namespaced memory operations with tool-specific contexts.
"""
import re
import time
import json
import logging
import traceback
from typing import Dict, Any, Optional, List
from datetime import datetime
from bedrock_agentcore.memory import MemoryClient
from bedrock_agentcore.memory.constants import StrategyType, Role
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def create_memory(
    memory_client,
    memory_name: str,
    memory_execution_role_arn: str,
    actor_id: str,
    event_expiry_days: int = 90,
    max_wait: int = 300,
    poll_interval: int = 10
) -> Optional[str]:
    """
    Create orchestrator memory with user preferences, semantic, and session summary strategies.

    The {actorId} placeholder will be dynamically replaced with the actual actor ID.

    Args:
        memory_client: MemoryClient instance
        memory_name: Name for the memory instance
        memory_execution_role_arn: IAM role ARN for memory execution
        actor_id: Actor ID for namespace generation
        event_expiry_days: Days before events expire (default: 90)
        max_wait: Maximum wait time for memory creation (default: 300)
        poll_interval: Polling interval for status checks (default: 10)

    Returns:
        memory_id: The ID of the created memory, or None if creation failed
    """
    memory_id = None

    try:
        logger.info(f"Creating orchestrator memory: {memory_name}")
        # in here, we are defining the strategy type to extract the user preferences, semantics and summaries 
        # and we are storing it at a global and an agent level (for which we have an actor id in the namespace)
        strategies = [
            {
                StrategyType.USER_PREFERENCE.value: {
                    "name": "UserPreferences",
                    "description": "Captures user preferences",
                    "namespaces": ["/preferences/{actorId}"]
                }
            },
            {
                StrategyType.SEMANTIC.value: {
                    "name": "SemanticMemory",
                    "description": "Stores semantic knowledge",
                    "namespaces": ["/semantics/{actorId}"]
                }
            },
            {
                StrategyType.SUMMARY.value: {
                    "name": "SessionSummaries",
                    "description": "Session summaries",
                    "namespaces": ["/summaries/{actorId}/{sessionId}"]
                }
            }
        ]

        memory = memory_client.create_memory_and_wait(
            name=memory_name,
            description="Orchestrator Agent with Long-Term Memory",
            memory_execution_role_arn=memory_execution_role_arn,
            strategies=strategies,
            event_expiry_days=event_expiry_days,
            max_wait=max_wait,
            poll_interval=poll_interval
        )

        memory_id = memory['id']
        logger.info(f"✅ Memory created successfully with ID: {memory_id}")
        return memory_id

    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationException' and "already exists" in str(e):
            # If memory already exists, retrieve its ID
            try:
                memories = memory_client.list_memories()
                memory_id = next((m['id'] for m in memories if m['id'].startswith(memory_name)), None)
                logger.info(f"Memory already exists. Using existing memory ID: {memory_id}")
                return memory_id
            except Exception as list_error:
                logger.error(f"Failed to list existing memories: {list_error}")
        else:
            logger.error(f"ClientError creating memory: {e}")

    except Exception as e:
        logger.error(f"❌ ERROR: {e}")
        traceback.print_exc()

        # Cleanup on error - delete the memory if it was partially created
        if memory_id:
            try:
                memory_client.delete_memory_and_wait(memory_id=memory_id)
                logger.info(f"Cleaned up memory: {memory_id}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up memory: {cleanup_error}")

    return None

def get_actor_id(base_user_id: str, tool_name: str | None) -> str:
    # "enterprise-it-user" for global; "enterprise-it-user__infrastructure_agent" when a tool is used
    return base_user_id if not tool_name else f"{base_user_id}__{tool_name}"

def get_namespace(base_user_id: str, memory_type: str = "preferences", tool_name: str = None) -> str:
    """Generate namespace - global or tool-specific."""
    sanitize = lambda s: re.sub(r'[^A-Za-z0-9/_\-\*]', '_', s or '')

    if tool_name:
        return f"{sanitize(base_user_id)}/{memory_type}/{sanitize(tool_name)}"
    return f"{sanitize(base_user_id)}/{memory_type}/global"

def retrieve_memory(
    memory_client,
    memory_id: str,
    base_user_id: str,
    query: str,
    memory_type: str = "preferences",
    tool_name: str = None,
    session_id: str = None
) -> List[str]:
    """Retrieve memories from namespace using correct AWS Bedrock AgentCore format."""
    try:
        # The namespaces should NOT have leading/trailing slashes in the actual ID parts
        # They should match EXACTLY what was defined in the strategy
        if memory_type == "preferences":
            # Match the strategy namespace: "/preferences/{actorId}"
            namespace = f"/preferences/{base_user_id}"
        elif memory_type == "semantics":
            # Match the strategy namespace: "/semantics/{actorId}"
            namespace = f"/semantics/{base_user_id}"
        elif memory_type == "summaries":
            if session_id:
                # Match the strategy namespace: "/summaries/{actorId}/{sessionId}"
                namespace = f"/summaries/{base_user_id}/{session_id}"
            else:
                raise ValueError(f"session_id is required for summaries memory_type")
        else:
            raise ValueError(f"Unknown memory_type: {memory_type}")
        
        clean_query = query.strip('\'"')
        
        logger.info(f"Retrieving memories from namespace: {namespace} with query: {clean_query}")
        # and ensure the namespace parameter matches exactly
        print(f"🧠 Retrieving memories: {namespace}")
        response = memory_client.retrieve_memories(
            memory_id=memory_id,
            namespace=namespace,
            query=clean_query,
            top_k=5
        )
        # Debug logging to see what's returned
        # Store raw response for debugging (removed verbose logging)
        
        memories = []
        if response:  # Check if response is not empty
            for memory_record in response:
                if isinstance(memory_record, dict):
                    # The structure might be different - check various possible keys
                    content = memory_record.get('content', 
                              memory_record.get('body', 
                              memory_record.get('text', '')))
                    
                    if isinstance(content, dict):
                        text = content.get('text', content.get('body', ''))
                    else:
                        text = str(content).strip()
                    
                    if text:
                        memories.append(text)
                        logger.debug(f"Retrieved memory: {text[:100]}...")
        
        logger.info(f"Retrieved {len(memories)} memories from namespace: {namespace}")
        return memories
        
    except Exception as e:
        logger.warning(f"Failed to retrieve {memory_type} from namespace: {e}")
        logger.debug(f"Full error: {e}", exc_info=True)
        return []


def get_memory_context(
    memory_client,
    memory_id: str,
    base_user_id: str,
    query: str,
    tool_name: str = None,
    session_id: str = None
) -> Dict[str, List[str]]:
    """Get comprehensive memory context - global + tool-specific if tool is used."""
    context = {'preferences': [], 'semantics': [], 'summaries': [], 'recent_turns': []}

    # Always get global context
    context['preferences'].extend(
        retrieve_memory(memory_client, memory_id, base_user_id, query, "preferences", None)
    )
    context['semantics'].extend(
        retrieve_memory(memory_client, memory_id, base_user_id, query, "semantics", None)
    )

    # Get summaries if session_id provided
    if session_id:
        context['summaries'].extend(
            retrieve_memory(memory_client, memory_id, base_user_id, query, "summaries", None, session_id)
        )

    # Add tool-specific context if tool is being used
    if tool_name:
        context['preferences'].extend(
            retrieve_memory(memory_client, memory_id, base_user_id, query, "preferences", tool_name)
        )
        context['semantics'].extend(
            retrieve_memory(memory_client, memory_id, base_user_id, query, "semantics", tool_name)
        )

    # Get last 3 conversation turns if session_id provided
    if session_id:
        try:
            recent_turns = memory_client.get_last_k_turns(
                memory_id=memory_id,
                actor_id=base_user_id,
                session_id=session_id,
                k=3
            )

            # Format turns for context
            for turn in recent_turns:
                if isinstance(turn, dict):
                    # Try different possible keys for user and assistant messages
                    user_msg = turn.get('user_message', turn.get('user', turn.get('messages', {}).get('user', '')))
                    assistant_msg = turn.get('assistant_message', turn.get('assistant', turn.get('messages', {}).get('assistant', '')))

                    # Also try to extract from messages array if that's the format
                    if not user_msg and not assistant_msg and 'messages' in turn:
                        messages = turn.get('messages', [])
                        for msg in messages:
                            if isinstance(msg, dict):
                                role = msg.get('role', '').upper()
                                content = msg.get('content', '')
                                if role == 'USER':
                                    user_msg = content
                                elif role == 'ASSISTANT':
                                    assistant_msg = content

                    if user_msg or assistant_msg:
                        formatted_turn = f"User: {user_msg}\nAssistant: {assistant_msg}"
                        context['recent_turns'].append(formatted_turn)

            logger.info(f"Retrieved {len(context['recent_turns'])} recent conversation turns")
        except Exception as e:
            logger.warning(f"Failed to retrieve recent turns: {e}")

    logger.info(f"Memory context: {len(context['preferences'])} preferences, {len(context['semantics'])} semantics, {len(context['summaries'])} summaries, {len(context['recent_turns'])} recent turns")
    return context


def store_conversation(
    memory_client,
    memory_id: str,
    base_user_id: str,
    user_message: str,
    assistant_message: str,
    tool_name: str = None,
    session_id: str = None,
) -> bool:
    """Store a conversation exchange."""
    try:
        # Use consistent actor_id format
        actor_id = base_user_id
        session_id = session_id or f"session_{int(time.time())}"

        logger.info(f"Storing conversation - Actor: {actor_id}, Session: {session_id}")

        # Build messages list as tuples (text, role) as expected by create_event API
        messages = []

        if user_message and user_message.strip():
            messages.append((user_message.strip(), "USER"))

        if assistant_message and assistant_message.strip():
            messages.append((assistant_message.strip(), "ASSISTANT"))

        # Skip if no messages to store
        if not messages:
            logger.warning("Both user and assistant messages are empty, skipping conversation storage")
            return False

        # Create memory event with available messages
        memory_client.create_event(
            memory_id=memory_id,
            actor_id=actor_id,
            session_id=session_id,
            messages=messages
        )

        context_type = f"tool-specific ({tool_name})" if tool_name else "global"
        logger.info(f"✅ Stored {context_type} conversation")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to store conversation: {e}")
        logger.debug(f"Full error details: {e}", exc_info=True)
        return False