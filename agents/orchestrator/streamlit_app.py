"""
Enterprise IT Orchestrator Streamlit Application
This application uses the same patterns as the orchestrator agent for:
- Agent registry (DynamoDB table)
- Gateway access with proper authentication
- Access token handling via OAuth2 client credentials
- Memory integration with AgentCore
"""

import streamlit as st
import os
import sys
import json
import boto3
import yaml
import time
import re
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Add the current directory and parent directory to sys.path to import orchestrator modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(current_dir)
sys.path.append(parent_dir)

# Import orchestrator utilities from parent directory
from utils import (
    load_config,
    get_access_token,
    load_agent_mapping_from_policy_table,
    list_tools_from_gateway,
    invoke_gateway_tool_direct,
    perform_user_contextual_matching
)
from memory_utils import get_memory_context
from bedrock_agentcore.memory import MemoryClient

# Load environment variables
load_dotenv()

@st.cache_data
def load_orchestrator_config():
    """Load the orchestrator configuration file"""
    try:
        config_path = os.path.join(current_dir, 'config.yaml')
        if not os.path.exists(config_path):
            st.error(f"Config file not found at: {config_path}")
            return None
        return load_config(config_path)
    except Exception as e:
        st.error(f"Failed to load config: {str(e)}")
        return None

def init_memory_client():
    """Initialize the memory client using the same pattern as orchestrator"""
    try:
        mem_client = MemoryClient(region_name=boto3.session.Session().region_name)
        return mem_client
    except Exception as e:
        st.error(f"Failed to initialize memory client: {str(e)}")
        return None

def get_orchestrator_access_token(config_data: Dict) -> Optional[str]:
    """Get access token using the same method as orchestrator"""
    try:
        gateway_config = config_data.get('agent_gateway', {})
        inbound_auth_info = gateway_config.get('inbound_auth_info', {})
        return get_access_token(client_credentials=inbound_auth_info)
    except Exception as e:
        st.error(f"Failed to get access token: {str(e)}")
        return None

def get_agent_registry_data(config_data: Dict) -> List:
    """Get agent registry data using the same DynamoDB table as orchestrator"""
    try:
        registry_config = config_data.get('agent_registry', {})
        table_name = registry_config.get('table_name')
        if not table_name:
            st.warning("No agent registry table configured")
            return []
        return load_agent_mapping_from_policy_table(table_name)
    except Exception as e:
        st.error(f"Failed to load agent registry: {str(e)}")
        return []


def add_agent_to_registry(
    table_name: str,
    user_id: str,
    agent_name: str
) -> bool:
    """Add an agent to a user's enabled agents list"""
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)

        # Get current item
        response = table.get_item(Key={'user_id': user_id})

        if 'Item' in response:
            # Update existing item
            enabled_agents = response['Item'].get('enabled_agents', [])
            if agent_name not in enabled_agents:
                enabled_agents.append(agent_name)
                table.update_item(
                    Key={'user_id': user_id},
                    UpdateExpression='SET enabled_agents = :agents',
                    ExpressionAttributeValues={':agents': enabled_agents}
                )
                return True
            else:
                st.warning(f"Agent '{agent_name}' already enabled for '{user_id}'")
                return False
        else:
            # Create new item
            table.put_item(
                Item={
                    'user_id': user_id,
                    'enabled_agents': [agent_name]
                }
            )
            return True
    except Exception as e:
        st.error(f"Failed to add agent: {str(e)}")
        return False


def delete_agent_from_registry(
    table_name: str,
    user_id: str,
    agent_name: str
) -> bool:
    """Remove an agent from a user's enabled agents list"""
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)

        # Get current item
        response = table.get_item(Key={'user_id': user_id})

        if 'Item' in response:
            enabled_agents = response['Item'].get('enabled_agents', [])
            if agent_name in enabled_agents:
                enabled_agents.remove(agent_name)

                if enabled_agents:
                    # Update with remaining agents
                    table.update_item(
                        Key={'user_id': user_id},
                        UpdateExpression='SET enabled_agents = :agents',
                        ExpressionAttributeValues={':agents': enabled_agents}
                    )
                else:
                    # Delete item if no agents left
                    table.delete_item(Key={'user_id': user_id})

                return True
            else:
                st.warning(f"Agent '{agent_name}' not found for '{user_id}'")
                return False
        else:
            st.warning(f"User ID '{user_id}' not found in registry")
            return False
    except Exception as e:
        st.error(f"Failed to delete agent: {str(e)}")
        return False


def update_agent_in_registry(
    table_name: str,
    user_id: str,
    old_agent_name: str,
    new_agent_name: str
) -> bool:
    """Update an agent name in a user's enabled agents list"""
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)

        # Get current item
        response = table.get_item(Key={'user_id': user_id})

        if 'Item' in response:
            enabled_agents = response['Item'].get('enabled_agents', [])
            if old_agent_name in enabled_agents:
                # Replace old agent name with new one
                enabled_agents = [new_agent_name if a == old_agent_name else a for a in enabled_agents]
                table.update_item(
                    Key={'user_id': user_id},
                    UpdateExpression='SET enabled_agents = :agents',
                    ExpressionAttributeValues={':agents': enabled_agents}
                )
                return True
            else:
                st.warning(f"Agent '{old_agent_name}' not found for '{user_id}'")
                return False
        else:
            st.warning(f"User ID '{user_id}' not found in registry")
            return False
    except Exception as e:
        st.error(f"Failed to update agent: {str(e)}")
        return False


def delete_product_from_registry(
    table_name: str,
    user_id: str
) -> bool:
    """Delete a product/user from the registry"""
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)

        table.delete_item(Key={'user_id': user_id})
        return True
    except Exception as e:
        st.error(f"Failed to delete product: {str(e)}")
        return False

def get_gateway_tools_data(config_data: Dict) -> List:
    """Get gateway tools using the same method as orchestrator"""
    try:
        access_token = get_orchestrator_access_token(config_data)
        if not access_token:
            return []

        gateway_config = config_data.get('agent_gateway', {})
        gateway_url = gateway_config.get('gateway_url')

        if not gateway_url:
            st.warning("No gateway URL configured")
            return []

        tools_response = list_tools_from_gateway(gateway_url, access_token)
        return tools_response.get('result', {}).get('tools', [])
    except Exception as e:
        st.error(f"Failed to get gateway tools: {str(e)}")
        return []


def call_orchestrator_simple(query: str, config_data: Dict, memory_client, session_id: str = None) -> Dict:
    """Call orchestrator_agent.py and capture response without terminal display"""
    try:
        import subprocess
        import sys

        # Path to orchestrator_agent.py
        orchestrator_path = os.path.join(current_dir, 'orchestrator_agent.py')

        if not os.path.exists(orchestrator_path):
            print(f"❌ Error: orchestrator_agent.py file not found at {orchestrator_path}")
            return {
                "error": "orchestrator_agent.py file not found",
                "response_type": "error",
                "timestamp": datetime.now().isoformat(),
                "logs": []
            }

        # Create environment
        env = os.environ.copy()

        print(f"🚀 Starting orchestrator_agent.py with query: {query}")
        print(f"📍 Working directory: {current_dir}")
        print(f"🔧 Python executable: {sys.executable}")
        print(f"🆔 Session ID: {session_id}")

        # Build command with session ID
        cmd = [sys.executable, orchestrator_path, '--query', query]
        if session_id:
            cmd.extend(['--session-id', session_id])

        # Run the orchestrator process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=current_dir,
            env=env
        )

        # Process output and log to terminal
        output_lines = []
        current_response = ""
        response_started = False

        print("📋 Orchestrator output:")
        print("-" * 80)

        for line in iter(process.stdout.readline, ''):
            if line:
                line = line.rstrip()
                output_lines.append(line)

                # Print all logs to terminal (where streamlit is running)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {line}")

                # Capture response
                if "🤖 Response from" in line or ("Response:" in line and not response_started):
                    response_started = True
                    current_response = ""
                elif response_started and line.strip() and not line.startswith("⏱️"):
                    current_response += line + "\n"

        print("-" * 80)

        # Wait for process completion
        process.stdout.close()
        return_code = process.wait()

        full_output = '\n'.join(output_lines)

        if return_code == 0:
            print(f"✅ Orchestrator completed successfully (return code: {return_code})")

            # Extract final response - look for structured JSON response first
            response_text = "Processing completed"
            response_type = "text"
            agent_used = "orchestrator_agent.py"

            # Try to find the structured JSON response in output
            # The orchestrator prints JSON directly from agent_executor or continue_with_plugin nodes
            # Look for lines that start with '{' and contain "response_message"
            json_found = False

            # Strategy 1: Look for standalone JSON (printed directly by orchestrator)
            for i, line in enumerate(output_lines):
                # Look for a line that starts with '{' - could be start of JSON
                if line.strip().startswith('{'):
                    # Try single-line JSON first
                    try:
                        response_json = json.loads(line)
                        # Check if this is the response JSON we're looking for
                        if "response_message" in response_json:
                            response_text = response_json.get("response_message", response_text)
                            response_type = response_json.get("response_type", response_type)
                            agent_used = response_json.get("agent_used", agent_used)
                            print(f"✅ Found single-line JSON response at line {i}")
                            json_found = True
                            break
                    except json.JSONDecodeError:
                        # Try multi-line JSON from this point
                        json_lines = [line]
                        brace_count = line.count('{') - line.count('}')

                        # Collect all lines until braces are balanced
                        for j in range(i+1, min(i+50, len(output_lines))):
                            next_line = output_lines[j]
                            # Stop at timing or separator markers
                            if next_line.strip().startswith("⏱️") or next_line.strip().startswith("---"):
                                break

                            json_lines.append(next_line)
                            brace_count += next_line.count('{') - next_line.count('}')

                            # When braces are balanced, try to parse
                            if brace_count == 0:
                                try:
                                    json_str = '\n'.join(json_lines)
                                    print(f"🔍 Attempting to parse multi-line JSON starting at line {i}")
                                    print(f"🔍 JSON string preview: {json_str[:150]}...")
                                    response_json = json.loads(json_str)

                                    # Verify this is the response JSON we want
                                    if "response_message" in response_json:
                                        response_text = response_json.get("response_message", response_text)
                                        response_type = response_json.get("response_type", response_type)
                                        agent_used = response_json.get("agent_used", agent_used)
                                        print(f"✅ Found multi-line JSON response")
                                        print(f"🔍 Response message: {response_text[:100]}..." if len(response_text) > 100 else f"🔍 Response message: {response_text}")
                                        json_found = True
                                        break
                                    else:
                                        # Valid JSON but not the response we want, keep looking
                                        print(f"⚠️ Found valid JSON but missing 'response_message' field")
                                except json.JSONDecodeError as e:
                                    print(f"⚠️ Failed to parse multi-line JSON: {e}")
                                    # Continue looking for other JSON blocks
                                break

                        if json_found:
                            break

            # Strategy 2: Look after specific markers like "🤖 Orchestrator Decision:"
            if not json_found:
                for i, line in enumerate(output_lines):
                    if "🤖 Orchestrator Decision:" in line or "Orchestrator Decision:" in line:
                        # JSON should start on the next line
                        json_start_idx = i + 1
                        if json_start_idx < len(output_lines):
                            json_lines = []
                            brace_count = 0
                            started = False
                            for j in range(json_start_idx, len(output_lines)):
                                line = output_lines[j]
                                if line.strip().startswith("⏱️") or line.strip().startswith("---"):
                                    break
                                if '{' in line:
                                    started = True
                                if started:
                                    json_lines.append(line)
                                    brace_count += line.count('{') - line.count('}')
                                    if brace_count == 0:
                                        break

                            if json_lines:
                                try:
                                    json_str = '\n'.join(json_lines)
                                    response_json = json.loads(json_str)
                                    response_text = response_json.get("response_message", response_text)
                                    response_type = response_json.get("response_type", response_type)
                                    agent_used = response_json.get("agent_used", agent_used)
                                    print(f"✅ Found JSON after marker at line {i}")
                                    json_found = True
                                    break
                                except json.JSONDecodeError as e:
                                    print(f"⚠️ Failed to parse JSON after marker: {e}")
                                    pass

            # Fallback: Look for agent identification
            if response_text == "Processing completed":
                for line in reversed(output_lines):
                    if "🤖 Response from" in line:
                        if "Response from" in line:
                            agent_part = line.split("Response from")[-1].strip()
                            if agent_part and not agent_part.startswith("orchestrator"):
                                agent_used = agent_part.replace(":", "").strip()

                        # Get response content
                        line_idx = output_lines.index(line)
                        response_lines = []
                        for i in range(line_idx + 1, len(output_lines)):
                            if output_lines[i].strip() and not output_lines[i].startswith("⏱️"):
                                response_lines.append(output_lines[i])
                            elif output_lines[i].startswith("⏱️"):
                                break
                        if response_lines:
                            response_text = '\n'.join(response_lines)
                        break

                # Final fallback to last meaningful lines
                if response_text == "Processing completed" and output_lines:
                    meaningful_lines = [line for line in output_lines[-10:] if line.strip() and not line.startswith("⏱️") and not line.startswith('{') and not line.strip() == '}']
                    if meaningful_lines:
                        response_text = meaningful_lines[-1]

            # Don't print the full response in logs to avoid clutter
            print(f"🤖 Final response extracted: [{len(response_text)} characters]")
            print(f"🎯 Agent used: {agent_used}")
            print(f"📋 Response type: {response_type}")

            return {
                "response_message": response_text,
                "response_type": response_type,
                "agent_used": agent_used,
                "timestamp": datetime.now().isoformat(),
                "full_output": full_output
            }
        else:
            print(f"❌ Orchestrator failed with return code: {return_code}")
            return {
                "error": f"Orchestrator failed with return code: {return_code}",
                "response_type": "error",
                "timestamp": datetime.now().isoformat(),
                "full_output": full_output
            }

    except Exception as e:
        print(f"❌ Exception in orchestrator call: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "error": f"Agent call failed: {str(e)}",
            "response_type": "error",
            "timestamp": datetime.now().isoformat()
        }

def main():
    # Page configuration
    st.set_page_config(
        page_title="Enterprise IT Orchestrator Assistant",
        page_icon="🤖",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # Load orchestrator configuration
    config_data = load_orchestrator_config()
    if not config_data:
        st.error("Failed to load configuration")
        st.stop()

    # Initialize memory client
    memory_client = init_memory_client()

    # Custom CSS for clean chat interface
    st.markdown("""
    <style>
    .stApp {
        background-color: #ffffff;
        color: #000000;
    }
    .main-header {
        text-align: center;
        color: #333333;
        margin-bottom: 1rem;
        font-family: 'Arial Black', sans-serif;
        font-weight: bold;
    }
    .chat-message-user {
        background: #007acc;
        color: white;
        padding: 1rem;
        border-radius: 15px;
        margin: 0.5rem 0;
        text-align: right;
        font-family: 'Arial', sans-serif;
    }
    .chat-message-assistant {
        background: #f8f9fa;
        color: #000000;
        padding: 1rem;
        border-radius: 15px;
        margin: 0.5rem 0;
        border: 1px solid #007acc;
        font-family: 'Arial', sans-serif;
    }
    .log-entry {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 0.75em;
        padding: 4px 8px;
        margin: 1px 0;
        border-radius: 4px;
        border-left: 3px solid;
        background-color: #f8f9fa;
    }
    .log-info {
        border-left-color: #007acc;
        background-color: #f8fbff;
    }
    .log-warning {
        border-left-color: #ffa500;
        background-color: #fffaf0;
    }
    .log-error {
        border-left-color: #dc3545;
        background-color: #fdf2f2;
    }
    .log-timestamp {
        color: #666;
        font-weight: bold;
        font-size: 0.9em;
    }
    .log-message {
        color: #333;
        margin-left: 8px;
    }
    </style>
    """, unsafe_allow_html=True)

    # Title
    st.markdown('<h1 class="main-header">🤖 Enterprise IT Orchestrator Assistant</h1>', unsafe_allow_html=True)

    # Initialize session state
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'user_context' not in st.session_state:
        st.session_state.user_context = config_data.get('user_metadata', {}).get('provided_context', {})
    if 'test_messages' not in st.session_state:
        st.session_state.test_messages = {}
    # Initialize persistent session ID for orchestrator agent
    if 'orchestrator_session_id' not in st.session_state:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        st.session_state.orchestrator_session_id = f"streamlit-session-{timestamp}"
        print(f"Created new persistent session ID: {st.session_state.orchestrator_session_id}")

    # Create tabs with default selection handling
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = 1  # Default to IT Assistant tab

    # Create tabs with selected tab state management
    tab_names = ["User Context", "IT Assistant", "Gateway", "AgentRegistry", "Memory & Config"]

    # Display tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(tab_names)

    with tab1:
        st.markdown("### User Context Configuration")
        st.markdown("Edit the user context that will be used for routing and agent matching.")

        # Editable User Context
        col1, col2 = st.columns([2, 1])

        with col1:
            st.markdown("#### Edit User Context")

            # Service Information
            st.markdown("**Service Information:**")
            service_name = st.text_input(
                "Service Name",
                value=st.session_state.user_context.get('service', {}).get('name', ''),
                help="The IT service name (e.g., AWS Infrastructure, GitHub Enterprise)"
            )

            service_version = st.text_input(
                "Service Version",
                value=st.session_state.user_context.get('service', {}).get('version', ''),
                help="The version of the service (e.g., Latest, v2.0)"
            )

            service_category = st.selectbox(
                "Service Category",
                options=["Infrastructure", "Development Tools", "Database", "Service Desk", "Security", "Networking"],
                index=0 if not st.session_state.user_context.get('service', {}).get('category') else
                    ["Infrastructure", "Development Tools", "Database", "Service Desk", "Security", "Networking"].index(
                        st.session_state.user_context.get('service', {}).get('category', 'Infrastructure')
                    ) if st.session_state.user_context.get('service', {}).get('category') in ["Infrastructure", "Development Tools", "Database", "Service Desk", "Security", "Networking"] else 0,
                help="The category of the IT service"
            )

            # Context Information
            st.markdown("**Context Information:**")
            locale = st.selectbox(
                "Locale",
                options=["en-US", "en-UK", "de-DE", "fr-FR", "ja-JP", "zh-CN"],
                index=0 if not st.session_state.user_context.get('locale') else
                    ["en-US", "en-UK", "de-DE", "fr-FR", "ja-JP", "zh-CN"].index(
                        st.session_state.user_context.get('locale', 'en-US')
                    ) if st.session_state.user_context.get('locale') in ["en-US", "en-UK", "de-DE", "fr-FR", "ja-JP", "zh-CN"] else 0
            )

            detected_country = st.text_input(
                "Detected Country",
                value=st.session_state.user_context.get('detected_country', 'US'),
                help="The detected country code"
            )

            host = st.text_input(
                "Host",
                value=st.session_state.user_context.get('host', 'company.com'),
                help="The host domain"
            )

            url = st.text_input(
                "URL",
                value=st.session_state.user_context.get('url', ''),
                help="The current URL context"
            )

            # Capabilities (multi-select)
            available_capabilities = [
                "AWS Cloud Infrastructure", "EC2 Management", "VPC Configuration",
                "S3 Storage", "IAM Management", "CloudFormation",
                "GitHub Enterprise", "CI/CD Pipelines", "Docker Management",
                "Kubernetes Orchestration", "PostgreSQL", "MySQL", "MongoDB",
                "User Account Management", "Software Installation", "Help Desk Support"
            ]

            current_capabilities = st.session_state.user_context.get('service', {}).get('capabilities', [])
            selected_capabilities = st.multiselect(
                "Service Capabilities",
                options=available_capabilities,
                default=current_capabilities if isinstance(current_capabilities, list) else [],
                help="Select the capabilities this IT service provides"
            )

            # Update button
            if st.button("Update User Context", type="primary"):
                st.session_state.user_context = {
                    'locale': locale,
                    'detected_country': detected_country,
                    'host': host,
                    'url': url,
                    'service': {
                        'name': service_name,
                        'version': service_version,
                        'category': service_category,
                        'capabilities': selected_capabilities
                    }
                }
                st.success("✅ User context updated successfully!")
                st.rerun()

        with col2:
            st.markdown("#### Current Context")
            st.json(st.session_state.user_context)

            # Save to config option
            if st.button("Save to Config File"):
                # Update the actual config file
                config_data['user_metadata']['provided_context'] = st.session_state.user_context
                try:
                    config_path = os.path.join(current_dir, 'config.yaml')
                    with open(config_path, 'w') as f:
                        yaml.dump(config_data, f, default_flow_style=False)
                    st.success("✅ Context saved to config.yaml!")
                except Exception as e:
                    st.error(f"Failed to save config: {str(e)}")

    with tab2:
        st.markdown("### IT Assistant")
        st.markdown("Chat")

        # User Context Display
        current_service = st.session_state.user_context.get('service', {})
        service_name = current_service.get('name', 'Not Set')
        service_version = current_service.get('version', 'Not Set')
        service_category = current_service.get('category', 'Not Set')
        context_display = f"{service_name} v{service_version} ({service_category})"

        st.info(f"Context: {context_display}")

        # Chat interface (full width)
        st.markdown("#### 💬 Chat")

        # Chat history container
        chat_container = st.container()
        with chat_container:
            if st.session_state.chat_history:
                for message in st.session_state.chat_history[-10:]:  # Show last 10
                    if message['role'] == 'user':
                        st.markdown(f'<div class="chat-message-user">👤 {message["content"]}</div>',
                                  unsafe_allow_html=True)
                    else:
                        response_message = message.get("content", "No response")
                        response_type = message.get("metadata", {}).get("response_type", "text")
                        agent_used = message.get("metadata", {}).get("agent_used", "orchestrator")

                        # Format the response based on type
                        if response_type == "markdown":
                            # Display markdown content
                            st.markdown(f'<div class="chat-message-assistant">🤖 {response_message}</div>',
                                      unsafe_allow_html=True)
                        elif response_type == "code":
                            # Display code content
                            st.markdown(f'<div class="chat-message-assistant">🤖</div>',
                                      unsafe_allow_html=True)
                            st.code(response_message)
                        elif response_type == "html":
                            # Display HTML content (be careful with this)
                            st.markdown(response_message, unsafe_allow_html=True)
                        else:
                            # Display text content (default)
                            st.markdown(f'<div class="chat-message-assistant">🤖 {response_message}</div>',
                                      unsafe_allow_html=True)

                        # Display response metadata in a small expander
                        with st.expander("Response Details", expanded=False):
                            st.text(f"Type: {response_type}")
                            st.text(f"Agent: {agent_used}")
                            st.text(f"Timestamp: {message.get('timestamp', 'N/A')}")

        # Input form
        with st.form(key="simple_chat_form", clear_on_submit=True):
            user_input = st.text_input("Ask me anything:", placeholder="How do I configure S3 buckets?")

            col_send, col_clear = st.columns([3, 1])
            with col_send:
                send_button = st.form_submit_button("Send", type="primary", use_container_width=True)
            with col_clear:
                clear_button = st.form_submit_button("Clear", use_container_width=True)

        # Handle clear button
        if clear_button:
            st.session_state.chat_history = []
            print("🗑️ Chat cleared by user")
            st.rerun()

        # Handle send button with simple processing
        if send_button and user_input.strip():
            # Add user message to chat
            st.session_state.chat_history.append({
                "role": "user",
                "content": user_input,
                "timestamp": datetime.now()
            })

            # Update config and save to file so orchestrator_agent.py picks up changes
            config_data['user_metadata']['provided_context'] = st.session_state.user_context
            try:
                config_path = os.path.join(current_dir, 'config.yaml')
                with open(config_path, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
            except Exception as e:
                st.error(f"Failed to save config: {str(e)}")

            # Show processing status
            with st.spinner("Processing your request..."):
                # Process the request
                try:
                    response = call_orchestrator_simple(
                        user_input,
                        config_data,
                        memory_client,
                        session_id=st.session_state.orchestrator_session_id
                    )

                    # Extract and clean the response - only get response_message
                    print(f"🔍 DEBUG: Raw response from orchestrator: {json.dumps(response, indent=2, default=str)}")

                    assistant_message = response.get("response_message", "No response")
                    response_type = response.get("response_type", "text")

                    print(f"🔍 DEBUG: Extracted response_message: {assistant_message[:200] if len(assistant_message) > 200 else assistant_message}")
                    print(f"🔍 DEBUG: Response type: {response_type}")

                    # Try to parse if it's a JSON string (double-encoded)
                    if isinstance(assistant_message, str) and assistant_message.strip().startswith('{'):
                        try:
                            parsed_response = json.loads(assistant_message)
                            print(f"🔍 DEBUG: Parsed nested JSON successfully")
                            assistant_message = parsed_response.get("response_message", assistant_message)
                            response_type = parsed_response.get("response_type", response_type)
                        except json.JSONDecodeError as e:
                            # Not valid JSON, use as is
                            print(f"🔍 DEBUG: Not nested JSON: {e}")
                            pass

                    # Remove any leading/trailing whitespace and quotes
                    assistant_message = assistant_message.strip().strip('"').strip("'")
                    print(f"🔍 DEBUG: After initial cleanup: {assistant_message[:200] if len(assistant_message) > 200 else assistant_message}")

                    # The response_message should already be extracted correctly from the JSON
                    # At this point, assistant_message should contain only the actual message content
                    # No additional cleaning should be needed if extraction worked correctly

                    # Final safety check: if we somehow still have a full JSON string,
                    # try to extract response_message one more time
                    if assistant_message.startswith('{') and assistant_message.endswith('}'):
                        try:
                            final_json = json.loads(assistant_message)
                            if "response_message" in final_json:
                                assistant_message = final_json["response_message"]
                                print(f"🔍 DEBUG: Extracted response_message from final JSON check")
                        except json.JSONDecodeError:
                            # If it's not valid JSON, just use as-is
                            print(f"🔍 DEBUG: Final JSON parse failed, using as-is")
                            pass

                    # Final cleanup of any remaining quotes
                    assistant_message = assistant_message.strip()

                    # Debug: Print what we're about to display
                    print(f"✅ Final cleaned message for Streamlit display: {assistant_message}")
                    print(f"📋 Message length: {len(assistant_message)} characters")

                    # Add assistant response to chat
                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": assistant_message,
                        "timestamp": datetime.now(),
                        "metadata": {
                            **response,
                            "response_type": response_type
                        }
                    })

                except Exception as e:
                    print(f"❌ Streamlit error: {str(e)}")
                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": f"Sorry, I encountered an error: {str(e)}",
                        "timestamp": datetime.now()
                    })

            # Refresh the page to show the new message
            st.rerun()



    with tab3:
        st.markdown("### Gateway")

        # Gateway configuration from config
        gateway_config = config_data.get('agent_gateway', {})
        gateway_url = gateway_config.get('gateway_url', 'Not configured')

        st.markdown("#### Gateway Configuration")
        col1, col2 = st.columns(2)

        with col1:
            st.code(f"Gateway URL: {gateway_url}")

        with col2:
            # Test access token
            try:
                access_token = get_orchestrator_access_token(config_data)
                if access_token:
                    st.success("✅ Access Token: Valid")
                else:
                    st.error("❌ Access Token: Failed")
            except Exception as e:
                st.error(f"❌ Access Token Error: {str(e)}")

        # Load and display tools
        st.markdown("#### Available Tools/Agents")
        with st.spinner("Loading gateway tools..."):
            tools = get_gateway_tools_data(config_data)

        if tools:
            st.success(f"✅ Found {len(tools)} tools in gateway")

            # Tools metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Agents", len(tools))
            with col2:
                agent_count = len([t for t in tools])
                st.metric("Active Agents", agent_count)
            with col3:
                st.metric("Gateway Status", "Active")

            # Agent boxes - display as cards like in the screenshot
            st.markdown("#### Available Agents")

            # Display agents in a grid layout
            cols = st.columns(3)
            for i, tool in enumerate(tools):
                with cols[i % 3]:
                    with st.container():
                        st.markdown(f"""
                        <div class="agent-card">
                            <div class="agent-title">{tool.get('name', 'Unknown Agent')}</div>
                            <div class="agent-description">{tool.get('description', 'No description available')[:100]}...</div>
                        </div>
                        """, unsafe_allow_html=True)

                        # Test message input for each agent
                        agent_name = tool.get('name', 'Unknown')
                        test_key = f"test_input_{agent_name}"

                        # Initialize test message for this agent if not exists
                        if test_key not in st.session_state.test_messages:
                            st.session_state.test_messages[test_key] = ""

                        test_message = st.text_input(
                            "Test Message:",
                            key=f"msg_{agent_name}",
                            placeholder=f"Enter message to test {agent_name}",
                            value=st.session_state.test_messages[test_key]
                        )

                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if st.button(f"Test Agent", key=f"test_{agent_name}", help=f"Test {agent_name} with your message"):
                                if test_message.strip():
                                    st.session_state.test_messages[test_key] = test_message
                                    try:
                                        with st.spinner(f"Testing {agent_name}..."):
                                            access_token = get_orchestrator_access_token(config_data)
                                            test_response = invoke_gateway_tool_direct(
                                                agent_name,
                                                test_message,
                                                gateway_url,
                                                access_token
                                            )
                                        st.success(f"✅ {agent_name} responded successfully")

                                        # Create a dropdown to select response format
                                        response_format = st.selectbox(
                                            "Select Response View:",
                                            ["Formatted Response", "Full JSON Response", "Raw Gateway Response"],
                                            key=f"response_format_{agent_name}"
                                        )

                                        with st.expander("View Response", expanded=True):
                                            if response_format == "Formatted Response":
                                                # Try to extract and format the response nicely
                                                try:
                                                    gateway_response = test_response.get('response', {})
                                                    if isinstance(gateway_response, dict) and 'result' in gateway_response:
                                                        result = gateway_response['result']
                                                        if isinstance(result, dict) and 'content' in result:
                                                            content = result['content']
                                                            if isinstance(content, list) and len(content) > 0:
                                                                first_content = content[0]
                                                                if isinstance(first_content, dict) and 'text' in first_content:
                                                                    try:
                                                                        parsed_content = json.loads(first_content['text'])
                                                                        st.markdown(f"**Agent:** {agent_name}")
                                                                        st.markdown(f"**Response:** {parsed_content.get('response_message', first_content['text'])}")
                                                                        st.markdown(f"**Type:** {parsed_content.get('response_type', 'text')}")
                                                                    except json.JSONDecodeError:
                                                                        st.markdown(f"**Agent:** {agent_name}")
                                                                        st.markdown(f"**Response:** {first_content['text']}")
                                                                else:
                                                                    st.json(first_content)
                                                            else:
                                                                st.json(content)
                                                        else:
                                                            st.json(result)
                                                    else:
                                                        st.json(gateway_response)
                                                except:
                                                    st.json(test_response)
                                            elif response_format == "Full JSON Response":
                                                # Show the structured response
                                                gateway_response = test_response.get('response', {})
                                                st.json(gateway_response)
                                            else:
                                                # Show the complete raw response
                                                st.json(test_response)
                                    except Exception as e:
                                        st.error(f"❌ {agent_name} test failed: {str(e)}")
                                        # Show error details in expander
                                        with st.expander("Error Details"):
                                            st.text(str(e))
                                else:
                                    st.warning("Please enter a test message first")

                        with col2:
                            if st.button(f"Clear", key=f"clear_{agent_name}", help="Clear test message"):
                                st.session_state.test_messages[test_key] = ""
                                st.rerun()
        else:
            st.warning("⚠️ No tools found in gateway")

    with tab4:
        st.markdown("### Agent Registry")
        st.markdown("View and manage registered agents from the DynamoDB table")

        # Get table name
        registry_config = config_data.get('agent_registry', {})
        table_name = registry_config.get('table_name', 'Not configured')

        # Initialize session state for managing multiple agents
        if 'new_agents' not in st.session_state:
            st.session_state.new_agents = []

        # Management Section - Only Add Agent
        st.markdown("#### Add Agent")

        # Add Agent Form - Simple and small
        with st.form(key="add_agent_form"):
            add_product = st.text_input("Service Name", key="add_product", placeholder="e.g., AWS Infrastructure")
            enabled_agents = st.text_input(
                "Enabled Agents (comma-separated)",
                key="enabled_agents",
                placeholder="e.g., infrastructure_agent, service_desk_agent"
            )

            add_col1, add_col2 = st.columns([3, 1])
            with add_col1:
                add_submit = st.form_submit_button("Add", type="primary", use_container_width=True)
            with add_col2:
                clear_form = st.form_submit_button("Clear", use_container_width=True)

            if add_submit and add_product and enabled_agents:
                if table_name != 'Not configured':
                    # Parse the comma-separated agents
                    agents_list = [agent.strip() for agent in enabled_agents.split(',') if agent.strip()]

                    with st.spinner(f"Adding {len(agents_list)} agent(s)..."):
                        # Add all agents to the registry
                        success_count = 0
                        for agent_name in agents_list:
                            if add_agent_to_registry(table_name, add_product, agent_name):
                                success_count += 1

                        if success_count > 0:
                            st.success(f"✅ Added {success_count} agent(s) to '{add_product}'")
                            st.cache_data.clear()
                            time.sleep(0.5)
                            st.rerun()
                else:
                    st.error("Registry table not configured")

        st.markdown("---")

        # Delete Product Section
        st.markdown("#### Delete Product")
        del_col1, del_col2 = st.columns([2, 1])
        with del_col1:
            with st.form(key="delete_product_form"):
                delete_product_id = st.text_input("Service/User ID to Delete", key="delete_product_id", placeholder="e.g., AWS Infrastructure")
                st.warning("⚠️ This will delete the entire service entry and all its agents")
                delete_product_submit = st.form_submit_button("Delete Service", type="secondary", use_container_width=True)

                if delete_product_submit and delete_product_id:
                    if table_name != 'Not configured':
                        with st.spinner("Deleting service..."):
                            if delete_product_from_registry(table_name, delete_product_id):
                                st.success(f"✅ Deleted service '{delete_product_id}'")
                                st.cache_data.clear()
                                time.sleep(0.5)
                                st.rerun()
                    else:
                        st.error("Registry table not configured")

        st.markdown("---")

        # Load agent registry data
        st.markdown("#### Current Registry")
        with st.spinner("Loading agent registry..."):
            agents = get_agent_registry_data(config_data)

        if agents:
            st.success(f"✅ Found {len(agents)} registered services")

            # Agent registry metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Registered Services", len(agents))
            with col2:
                # agents is a list of tuples (user_id, enabled_agents), not dicts with status
                # Count unique enabled agents across all users (avoid duplicates)
                unique_enabled_agents = set()
                for user_id, enabled_agents in agents:
                    unique_enabled_agents.update(enabled_agents)
                total_enabled_agents = len(unique_enabled_agents)
                st.metric("Total Enabled Agents", total_enabled_agents)
            with col3:
                st.metric("Registry Table", table_name.split('-')[-1] if table_name != 'Not configured' else 'Unknown')

            # Display agents in a grid layout
            st.markdown("#### Registered Services")

            # Display agents in a table format showing Available Services and their enabled agents
            st.markdown("#### Available Services and Enabled Agents")

            # Create a DataFrame-like structure to display the data
            for i, agent_mapping in enumerate(agents):
                # agent_mapping is a tuple: (user_id, enabled_agents)
                user_id, enabled_agents = agent_mapping

                with st.container():
                    # Display as a card showing the product and its enabled agents
                    st.markdown(f"""
                    <div class="agent-card">
                        <div class="agent-title">Available Product: {user_id}</div>
                        <div class="agent-description">
                            <strong>Enabled Agents:</strong><br>
                            {', '.join(enabled_agents) if enabled_agents else 'No agents enabled'}
                        </div>
                        <div style="margin-top: 10px;">
                            <span style="background: #007acc; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">
                                Product
                            </span>
                            <span style="background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 5px;">
                                {len(enabled_agents)} Agent(s)
                            </span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Agent details in expandable section with individual delete buttons
                    with st.expander(f"View Details - {user_id}"):
                        st.markdown(f"**Product:** {user_id}")
                        st.markdown(f"**Total Agents:** {len(enabled_agents)}")
                        st.markdown("---")

                        # Display each agent with a delete button beside it
                        for agent_name in enabled_agents:
                            agent_col1, agent_col2 = st.columns([3, 1])

                            with agent_col1:
                                st.markdown(f"• {agent_name}")

                            with agent_col2:
                                if st.button(f"Delete", key=f"del_{user_id}_{agent_name}", type="secondary"):
                                    if table_name != 'Not configured':
                                        with st.spinner(f"Deleting {agent_name}..."):
                                            if delete_agent_from_registry(table_name, user_id, agent_name):
                                                st.success(f"✅ Deleted '{agent_name}'")
                                                st.cache_data.clear()
                                                time.sleep(0.5)
                                                st.rerun()
                                    else:
                                        st.error("Registry table not configured")

        else:
            st.warning("⚠️ No agents found in registry")
            st.info(f"Registry table: {table_name}")

    with tab5:
        st.markdown("### 🧠 Memory & Configuration")

        # Memory configuration
        memory_config = config_data.get('agent_infra_resources', {})
        memory_id = memory_config.get('mtemory_id')
        actor_id = memory_config.get('actor_id')
        use_existing = memory_config.get('use_existing_memory', False)

        st.markdown("#### Memory Configuration")
        col1, col2 = st.columns(2)

        with col1:
            st.code(f"""
Memory ID: {memory_id}
Actor ID: {actor_id}
Use Existing: {use_existing}
            """)

        with col2:
            if memory_client:
                st.success("✅ Memory Client: Connected")

                # Test memory context retrieval
                if st.button("Test Memory Context"):
                    try:
                        test_query = "test query for memory context"
                        context = get_memory_context(
                            memory_client=memory_client,
                            memory_id=memory_id,
                            base_user_id=actor_id,
                            query=test_query,
                            session_id="streamlit_session"
                        )
                        st.json(context)
                    except Exception as e:
                        st.error(f"Memory test failed: {str(e)}")
            else:
                st.error("❌ Memory Client: Not connected")

        # Full configuration display
        st.markdown("#### Complete Configuration")
        if st.checkbox("Show Full Config"):
            st.json(config_data)

        # Model information
        model_info = config_data.get('model_information', {})
        orch_model = model_info.get('orchestrator_agent_model_info', {})

        st.markdown("#### Model Configuration")
        st.code(f"""
Model ID: {orch_model.get('model_id', 'Not set')}
Temperature: {orch_model.get('inference_parameters', {}).get('temperature', 'Not set')}
Max Tokens: {orch_model.get('inference_parameters', {}).get('max_tokens', 'Not set')}
Guardrail ID: {orch_model.get('guardrail_id', 'Not set')}
        """)


    # Sidebar
    with st.sidebar:
        st.markdown("<h3 style='color: #333333; margin-bottom: 10px;'>Orchestrator Status</h3>", unsafe_allow_html=True)

        # Configuration status
        if config_data:
            st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #333; border: 1px solid #007acc;'>Config Loaded</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #666; border: 1px solid #cccccc;'>Config Failed</div>", unsafe_allow_html=True)

        if memory_client:
            st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #333; border: 1px solid #007acc;'>Memory Client</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #666; border: 1px solid #cccccc;'>Memory Client</div>", unsafe_allow_html=True)

        try:
            access_token = get_orchestrator_access_token(config_data)
            if access_token:
                st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #333; border: 1px solid #007acc;'>Gateway Auth</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #666; border: 1px solid #cccccc;'>Gateway Auth</div>", unsafe_allow_html=True)
        except:
            st.markdown("<div style='background-color: #ffffff; padding: 8px; border-radius: 4px; margin-bottom: 5px; color: #666; border: 1px solid #cccccc;'>Gateway Auth</div>", unsafe_allow_html=True)

        st.markdown("---")

        # Control buttons
        if st.button("Refresh All"):
            st.cache_data.clear()
            st.rerun()

        if st.button("Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()

        if st.button("Clear Session"):
            # Reset session ID to force new session
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            st.session_state.orchestrator_session_id = f"streamlit-session-{timestamp}"
            print(f"Reset session ID: {st.session_state.orchestrator_session_id}")
            st.rerun()

        # Configuration file path
        st.markdown("<h3 style='color: #333333; margin-bottom: 10px; margin-top: 20px;'>Configuration</h3>", unsafe_allow_html=True)
        st.code(f"Config: {current_dir}/config.yaml")

        # Environment info
        st.markdown("### Environment")
        st.code(f"""
AWS Region: {boto3.session.Session().region_name}
Python Path: {current_dir}
        """)

if __name__ == "__main__":
    main()