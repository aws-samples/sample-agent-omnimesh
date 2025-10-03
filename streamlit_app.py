#!/usr/bin/env python3
"""
Streamlit Frontend for IT Support Agent Core Orchestrator
"""
import streamlit as st
import json
import boto3
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import time
import sys
import os
from pathlib import Path

# Add the agents directory to Python path
sys.path.append(str(Path(__file__).parent / "agents"))
sys.path.append(str(Path(__file__).parent / "agents" / "orchestrator"))

from agents.orchestrator.utils import (
    fetch_cognito_user_metadata,
    reauthenticate_user,
    load_config,
    save_config,
    list_tools_from_gateway,
    match_user_context_with_gateway_tools,
    invoke_gateway_tool_direct,
    get_access_token
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="IT Support Agent Core Frontend",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for black theme with good readability
st.markdown("""
<style>
    /* Apply black theme to main app container */
    .stApp {
        background-color: #000000;
        color: #ffffff;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #000000;
    }
    
    /* Center the main title */
    .main-title {
        text-align: center;
        font-size: 3rem;
        font-weight: bold;
        color: #00d4ff;
        margin-bottom: 2rem;
        text-shadow: 1px 1px 2px rgba(0,212,255,0.3);
    }
    
    /* Style buttons with dark theme */
    .stButton > button {
        background-color: #00d4ff;
        color: #0e1117;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        transition: all 0.3s;
        font-weight: 600;
    }
    
    .stButton > button:hover {
        background-color: #00b8e6;
        transform: translateY(-1px);
        box-shadow: 0 4px 8px rgba(0,212,255,0.3);
    }
    
    /* Style metrics with dark theme */
    [data-testid="metric-container"] {
        background-color: #ffffff;
        border: 1px solid #ffffff;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(255,255,255,0.1);
        color: #000000;
    }
    
    /* Agent card styling for white theme */
    .agent-card {
        background-color: #ffffff;
        border: 1px solid #ffffff;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 8px rgba(255,255,255,0.2);
        color: #000000;
    }
    
    .agent-tag {
        background-color: #00d4ff;
        color: #0e1117;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: 600;
        margin-right: 6px;
        display: inline-block;
        margin-bottom: 4px;
    }
    
    /* Input field styling */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {
        background-color: #ffffff !important;
        color: #000000 !important;
        border: 1px solid #ffffff !important;
    }
    
    /* Form styling */
    .stForm {
        border: 1px solid #ffffff;
        border-radius: 8px;
        background-color: #ffffff;
        padding: 1rem;
        color: #000000;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #000000;
        border-radius: 8px 8px 0 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #ffffff;
        background-color: #000000;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #ffffff !important;
        color: #000000 !important;
    }
    
    /* Chat message styling */
    .stChatMessage {
        background-color: #ffffff !important;
        border: 1px solid #ffffff !important;
        color: #000000 !important;
    }
    
    /* Code block styling */
    code {
        background-color: #262626 !important;
        color: #00d4ff !important;
        padding: 2px 4px;
        border-radius: 4px;
    }
    
    /* Info, success, error message styling */
    .stInfo {
        background-color: #1a2332 !important;
        border-left: 4px solid #00d4ff !important;
        color: #fafafa !important;
    }
    
    .stSuccess {
        background-color: #1a2b1a !important;
        border-left: 4px solid #00ff88 !important;
        color: #fafafa !important;
    }
    
    .stError {
        background-color: #2b1a1a !important;
        border-left: 4px solid #ff4444 !important;
        color: #fafafa !important;
    }
    
    .stWarning {
        background-color: #2b261a !important;
        border-left: 4px solid #ffaa00 !important;
        color: #fafafa !important;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: #ffffff !important;
        color: #000000 !important;
        border: 1px solid #ffffff !important;
    }
    
    .streamlit-expanderContent {
        background-color: #ffffff !important;
        border: 1px solid #ffffff !important;
        border-top: none !important;
        color: #000000 !important;
    }
</style>
""", unsafe_allow_html=True)

class StreamlitAgentInterface:
    """Main Streamlit application class for the Agent Core interface"""
    
    def __init__(self):
        self.region = "us-west-2"
        self.orchestrator_config = self._load_orchestrator_config()
        self._initialize_session_state()
        
    def _load_orchestrator_config(self) -> Dict[str, Any]:
        """Load orchestrator configuration from YAML file"""
        try:
            config_path = Path(__file__).parent / "agents" / "orchestrator" / ".bedrock_agentcore.yaml"
            if config_path.exists():
                config = load_config(config_path)
                if config:
                    return config.get("agents", {}).get("enterprise_it_orchestrator_agent", {})
            logger.warning("Orchestrator config not found, using defaults")
            return {}
        except Exception as e:
            logger.error(f"Error loading orchestrator config: {e}")
            return {}
    
    def _initialize_session_state(self):
        """Initialize Streamlit session state variables"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'user_metadata' not in st.session_state:
            st.session_state.user_metadata = {}
        if 'bearer_token' not in st.session_state:
            st.session_state.bearer_token = None
        if 'chat_messages' not in st.session_state:
            st.session_state.chat_messages = []
        if 'agent_logs' not in st.session_state:
            st.session_state.agent_logs = []
        if 'registered_agents' not in st.session_state:
            st.session_state.registered_agents = []
    
    def _authenticate_user(self, client_id: str, username: str, password: str) -> bool:
        """Authenticate user with Cognito"""
        try:
            cognito_client = boto3.client('cognito-idp', region_name=self.region)
            auth_response = cognito_client.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            
            bearer_token = auth_response['AuthenticationResult']['AccessToken']
            st.session_state.bearer_token = bearer_token
            
            # Fetch user metadata
            user_metadata = fetch_cognito_user_metadata(bearer_token, self.region)
            st.session_state.user_metadata = user_metadata
            st.session_state.authenticated = True
            
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def _get_agent_arn_and_url(self) -> tuple:
        """Get agent ARN and construct URL from config or AWS"""
        try:
            # Try to get from config first
            if self.orchestrator_config:
                agent_arn = self.orchestrator_config.get("bedrock_agentcore", {}).get("agent_arn")
                if agent_arn:
                    encoded_arn = agent_arn.replace(':', '%3A').replace('/', '%2F')
                    agent_url = f"https://bedrock-agentcore.{self.region}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier=DEFAULT"
                    return agent_arn, agent_url
            
            # Fallback to SSM parameter
            ssm_client = boto3.client('ssm', region_name=self.region)
            agent_arn_response = ssm_client.get_parameter(Name='/mcp_server/runtime/agent_arn')
            agent_arn = agent_arn_response['Parameter']['Value']
            
            encoded_arn = agent_arn.replace(':', '%3A').replace('/', '%2F')
            agent_url = f"https://bedrock-agentcore.{self.region}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier=DEFAULT"
            
            return agent_arn, agent_url
            
        except Exception as e:
            logger.error(f"Error getting agent ARN/URL: {e}")
            return None, None
    
    def _invoke_orchestrator_agent(self, user_message: str) -> Dict[str, Any]:
        """Enhanced orchestrator agent invocation with gateway routing"""
        try:
            # Log user query start
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "type": "ROUTING_START",
                "message": f"Starting routing process for query: {user_message}"
            }
            st.session_state.agent_logs.append(log_entry)

            # Get user metadata from config
            user_metadata = st.session_state.user_metadata

            # Get gateway configuration from config
            config_path = Path(__file__).parent / "agents" / "orchestrator" / "config.yaml"
            config_data = load_config(config_path)

            if not config_data:
                return {"error": "Could not load configuration"}

            gateway_config = config_data.get("agent_gateway", {})
            gateway_url = gateway_config.get("gateway_url")
            auth_info = gateway_config.get("inbound_auth_info", {})

            if not gateway_url:
                return {"error": "Gateway URL not configured"}

            # Get access token for gateway
            try:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "AUTH",
                    "message": "Getting access token for gateway authentication"
                }
                st.session_state.agent_logs.append(log_entry)

                access_token = get_access_token(auth_info)

                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "AUTH_SUCCESS",
                    "message": "Successfully obtained gateway access token"
                }
                st.session_state.agent_logs.append(log_entry)

            except Exception as auth_error:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "AUTH_ERROR",
                    "error": f"Failed to get access token: {str(auth_error)}"
                }
                st.session_state.agent_logs.append(log_entry)
                return {"error": f"Authentication failed: {str(auth_error)}"}

            # List tools from gateway
            try:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "TOOL_DISCOVERY",
                    "message": "Discovering available tools from gateway"
                }
                st.session_state.agent_logs.append(log_entry)

                tools_response = list_tools_from_gateway(gateway_url, access_token)

                tools = tools_response.get("result", {}).get("tools", [])
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "TOOL_DISCOVERY_SUCCESS",
                    "message": f"Found {len(tools)} available tools: {[t.get('name', 'Unknown') for t in tools]}"
                }
                st.session_state.agent_logs.append(log_entry)

            except Exception as tools_error:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "TOOL_DISCOVERY_ERROR",
                    "error": f"Failed to list tools: {str(tools_error)}"
                }
                st.session_state.agent_logs.append(log_entry)
                return {"error": f"Tool discovery failed: {str(tools_error)}"}

            # Match user context with tools
            try:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "MATCHING_START",
                    "message": f"Matching user context (product: {user_metadata.get('provided_context', {}).get('product', {}).get('name', 'Unknown')}) with available tools"
                }
                st.session_state.agent_logs.append(log_entry)

                matched_tool = match_user_context_with_gateway_tools(user_metadata, tools_response)

                if matched_tool:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "MATCHING_SUCCESS",
                        "message": f"Matched to tool: {matched_tool}"
                    }
                    st.session_state.agent_logs.append(log_entry)
                else:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "MATCHING_FAILED",
                        "message": "No matching tool found for user context"
                    }
                    st.session_state.agent_logs.append(log_entry)
                    return {"error": "No matching agent found for your product context"}

            except Exception as match_error:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "MATCHING_ERROR",
                    "error": f"Tool matching failed: {str(match_error)}"
                }
                st.session_state.agent_logs.append(log_entry)
                return {"error": f"Tool matching failed: {str(match_error)}"}

            # Invoke the matched tool
            try:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "TOOL_INVOCATION",
                    "message": f"Invoking tool '{matched_tool}' with query: {user_message}"
                }
                st.session_state.agent_logs.append(log_entry)

                tool_response = invoke_gateway_tool_direct(matched_tool, user_message, gateway_url, access_token)

                if "error" in tool_response:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "TOOL_ERROR",
                        "error": f"Tool invocation failed: {tool_response['error']}"
                    }
                    st.session_state.agent_logs.append(log_entry)
                    return tool_response
                else:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "TOOL_SUCCESS",
                        "message": f"Tool '{matched_tool}' responded successfully"
                    }
                    st.session_state.agent_logs.append(log_entry)
                    return tool_response

            except Exception as invoke_error:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "TOOL_INVOCATION_ERROR",
                    "error": f"Tool invocation failed: {str(invoke_error)}"
                }
                st.session_state.agent_logs.append(log_entry)
                return {"error": f"Tool invocation failed: {str(invoke_error)}"}

        except Exception as e:
            error_msg = f"Error in orchestrator agent routing: {str(e)}"
            logger.error(error_msg)

            # Log the error
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "type": "ROUTING_ERROR",
                "error": error_msg
            }
            st.session_state.agent_logs.append(log_entry)

            return {"error": error_msg}
    
    def _load_registered_agents(self) -> List[Dict[str, Any]]:
        """Load registered agents from DynamoDB"""
        try:
            # This would typically come from a config file or environment
            table_name = "enterprise_it_agent_registry"
            
            agents = load_agents_from_registry(table_name)
            agent_list = []
            
            for agent in agents:
                # Handle both object and dict formats
                if hasattr(agent, '__dict__'):
                    # Object format
                    agent_info = {
                        "name": getattr(agent, 'name', 'Unknown Agent'),
                        "description": getattr(agent, 'description', 'No description available'),
                        "url": getattr(agent, 'target_agent', getattr(agent, 'url', '')),
                        "capabilities": getattr(agent, 'capabilities', []),
                        "tags": getattr(agent, 'tags', []),
                        "use_oauth": getattr(agent, 'use_oauth', False),
                        "oauth_credentials": getattr(agent, 'oauth_credentials', {})
                    }
                else:
                    # Dict format
                    agent_info = {
                        "name": agent.get('agent_name', agent.get('name', 'Unknown Agent')),
                        "description": agent.get('description', 'No description available'),
                        "url": agent.get('agent_url', agent.get('url', '')),
                        "capabilities": agent.get('capabilities', []),
                        "tags": agent.get('tags', []),
                        "use_oauth": agent.get('use_oauth', False) == 'yes' or agent.get('use_oauth', False) is True,
                        "oauth_credentials": agent.get('oauth_credentials', {})
                    }
                
                agent_list.append(agent_info)
                logger.info(f"Loaded agent: {agent_info['name']} at {agent_info['url']}")
            
            logger.info(f"Successfully loaded {len(agent_list)} agents from registry")
            return agent_list
            
        except Exception as e:
            logger.error(f"Error loading registered agents: {e}")
            # Return some sample data for testing if registry fails
            return []
    
    def _register_agent(self, agent_data: Dict[str, Any]) -> bool:
        """Register a new agent in DynamoDB"""
        try:
            # This is a simplified version - in production you'd use the actual registry
            dynamodb = boto3.resource('dynamodb', region_name=self.region)
            table_name = "enterprise_it_agent_registry"
            table = dynamodb.Table(table_name)
            
            item = {
                "agent_url": agent_data["url"],  # Primary key field
                "agent_name": agent_data["name"],
                "agent_type": "langgraph",
                "version": "1.0.0",
                "description": agent_data["description"],
                "keywords": agent_data.get("tags", []),
                "capabilities": agent_data.get("capabilities", []),
                "related_products": agent_data.get("tags", []),
                "tags": agent_data.get("tags", []),
                "status": "active",
                "created_at": datetime.now().isoformat(),
                "use_oauth": "yes" if agent_data.get("use_oauth", False) else "no",
                "oauth_credentials": agent_data.get("oauth_credentials", {}),
                "display_id": f"{agent_data['name']}-{int(time.time())}"
            }
            
            table.put_item(Item=item)
            return True
            
        except Exception as e:
            logger.error(f"Error registering agent: {e}")
            st.error(f"Error registering agent: {str(e)}")
            return False
    
    def render_signin_page(self):
        """Render the sign-in page"""
        st.markdown('<h1 class="main-title">🔐 Sign In</h1>', unsafe_allow_html=True)
        
        with st.container():
            col1, col2, col3 = st.columns([1, 2, 1])
            
            with col2:
                st.markdown("### Welcome to IT Support Assistant")
                st.markdown("Please sign in with your IdP credentials to continue.")
                
                with st.form("signin_form"):
                    # Extract client ID from orchestrator config
                    client_id = None
                    if self.orchestrator_config:
                        auth_config = self.orchestrator_config.get("authorizer_configuration", {})
                        jwt_config = auth_config.get("customJWTAuthorizer", {})
                        allowed_clients = jwt_config.get("allowedClients", [])
                        if allowed_clients:
                            client_id = allowed_clients[0]
                    
                    if not client_id:
                        client_id_input = st.text_input(
                            "Client ID",
                            help="Your Cognito App Client ID"
                        )
                    else:
                        st.info(f"Using configured Client ID: {client_id}")
                        client_id_input = client_id
                    
                    username = st.text_input(
                        "Username",
                        value="ituser",
                        help="Your Cognito username"
                    )
                    
                    password = st.text_input(
                        "Password",
                        type="password",
                        value="MyPassword123!",
                        help="Your Cognito password"
                    )
                    
                    submit_button = st.form_submit_button("Sign In", type="primary")
                    
                    if submit_button:
                        if not client_id_input:
                            st.error("Please provide a Client ID")
                        elif not username or not password:
                            st.error("Please provide both username and password")
                        else:
                            with st.spinner("Authenticating..."):
                                if self._authenticate_user(client_id_input, username, password):
                                    st.success("Authentication successful! Redirecting...")
                                    st.rerun()
    
    def render_chat_interface(self):
        """Render the chat interface tab"""
        st.header("💬 Chat with Orchestrator Agent")
        
        # Display agent info
        if self.orchestrator_config:
            with st.expander("Agent Information", expanded=False):
                st.json(self.orchestrator_config)
        
        # Chat messages container
        chat_container = st.container()
        
        # Display chat history
        with chat_container:
            for message in st.session_state.chat_messages:
                with st.chat_message(message["role"]):
                    st.write(message["content"])
                    if "timestamp" in message:
                        st.caption(f"Sent at: {message['timestamp']}")
        
        # Chat input
        if prompt := st.chat_input("Ask the orchestrator agent anything..."):
            # Add user message to chat
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.chat_messages.append({
                "role": "user",
                "content": prompt,
                "timestamp": timestamp
            })
            
            # Display user message immediately
            with st.chat_message("user"):
                st.write(prompt)
                st.caption(f"Sent at: {timestamp}")
            
            # Get agent response
            with st.chat_message("assistant"):
                with st.spinner("Agent is thinking..."):
                    response = self._invoke_orchestrator_agent(prompt)
                
                if isinstance(response, dict) and "error" in response:
                    st.error(response["error"])
                    assistant_response = f"I encountered an error: {response['error']}"
                else:
                    # Extract the response text from the agent response
                    if isinstance(response, dict):
                        assistant_response = response.get("output", str(response))
                    else:
                        assistant_response = str(response)
                    
                    st.write(assistant_response)
                
                response_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.caption(f"Response at: {response_timestamp}")
            
            # Add assistant response to chat
            st.session_state.chat_messages.append({
                "role": "assistant", 
                "content": assistant_response,
                "timestamp": response_timestamp
            })
            
            st.rerun()
    
    def render_agent_registry(self):
        """Render the agent registry tab"""
        st.header("🤖 Agent Registry")
        
        # Create tabs for registration and viewing
        reg_tab, view_tab = st.tabs(["Register Agent", "View Registered Agents"])
        
        with reg_tab:
            st.subheader("Register New Agent")
            
            with st.form("register_agent_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    agent_name = st.text_input(
                        "Agent Name *",
                        value="Development Tools Assistant",
                        help="Unique name for the agent"
                    )
                    
                    agent_url = st.text_input(
                        "Agent URL *",
                        value="https://bedrock-agentcore.us-west-2.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-west-2%3A218208277580%3Aruntime%2Fdevelopment_tools_agent-KDFi87DS4I/invocations?qualifier=DEFAULT",
                        help="HTTP endpoint for the agent"
                    )
                    
                    agent_description = st.text_area(
                        "Description *",
                        value="This agent is responsible for delivering CI/CD, GitHub, Docker, and development tools assistance",
                        help="Detailed description of the agent's purpose"
                    )
                
                with col2:
                    capabilities = st.text_area(
                        "Capabilities",
                        value="api_documentation",
                        help="List capabilities, one per line"
                    )
                    
                    tags = st.text_input(
                        "Tags",
                        value="development, ci-cd, github",
                        help="Comma-separated tags for categorization"
                    )
                    
                    use_oauth = st.checkbox(
                        "Use OAuth Authentication",
                        value=True,
                        help="Check if this agent requires OAuth"
                    )
                
                if use_oauth:
                    st.subheader("OAuth Configuration")
                    oauth_discovery_url = st.text_input(
                        "Discovery URL",
                        value="https://cognito-idp.us-west-2.amazonaws.com/us-west-2_0cwqv2zYn/.well-known/openid-configuration"
                    )
                    oauth_client_id = st.text_input(
                        "OAuth Client ID",
                        value="2l91ptf0tvjj16n16qhuocmdoa"
                    )
                
                submit_agent = st.form_submit_button("Register Agent", type="primary")
                
                if submit_agent:
                    if not agent_name or not agent_url or not agent_description:
                        st.error("Please fill in all required fields (marked with *)")
                    else:
                        # Prepare agent data
                        agent_data = {
                            "name": agent_name,
                            "url": agent_url,
                            "description": agent_description,
                            "capabilities": [cap.strip() for cap in capabilities.split('\n') if cap.strip()] if capabilities else [],
                            "tags": [tag.strip() for tag in tags.split(',') if tag.strip()] if tags else [],
                            "use_oauth": use_oauth
                        }
                        
                        if use_oauth:
                            agent_data["oauth_credentials"] = {
                                "discovery_url": oauth_discovery_url,
                                "client_id": oauth_client_id
                            }
                        
                        with st.spinner("Registering agent..."):
                            if self._register_agent(agent_data):
                                st.success(f"Agent '{agent_name}' registered successfully!")
                                # Refresh the registered agents list
                                st.session_state.registered_agents = self._load_registered_agents()
                                st.rerun()
        
        with view_tab:
            st.subheader("Registered Agents")
            
            # Refresh button
            if st.button("🔄 Refresh Agent List"):
                st.session_state.registered_agents = self._load_registered_agents()
                st.rerun()
            
            # Load agents if not already loaded
            if not st.session_state.registered_agents:
                with st.spinner("Loading registered agents..."):
                    st.session_state.registered_agents = self._load_registered_agents()
            
            # Display agents count
            if st.session_state.registered_agents:
                st.info(f"Found {len(st.session_state.registered_agents)} registered agents")
                
                # Display agents in a more structured way
                for agent in st.session_state.registered_agents:
                    with st.container():
                        # Create a bordered container for each agent
                        st.markdown(f"""
                        <div style="border: 1px solid #ffffff; border-radius: 8px; padding: 1rem; margin: 1rem 0; background-color: #ffffff; box-shadow: 0 2px 8px rgba(255,255,255,0.2);">
                            <h4 style="color: #000000; margin-bottom: 0.5rem;">🤖 {agent['name']}</h4>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Agent details in columns
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Description:**")
                            st.write(agent.get('description', 'No description available'))
                            
                            st.write("**Agent URL:**")
                            st.code(agent['url'], language=None)
                            
                            # Authentication status
                            auth_status = "🔒 OAuth Enabled" if agent.get('use_oauth', False) else "🔓 No Authentication"
                            st.write(f"**Authentication:** {auth_status}")
                        
                        with col2:
                            # Display capabilities
                            capabilities = agent.get('capabilities', [])
                            if capabilities:
                                st.write("**Capabilities:**")
                                for cap in capabilities:
                                    st.write(f"• {cap}")
                            else:
                                st.write("**Capabilities:** Not specified")
                            
                            # Display tags
                            tags = agent.get('tags', [])
                            if tags:
                                st.write("**Tags:**")
                                tag_html = ""
                                for tag in tags:
                                    tag_html += f"<span class='agent-tag'>{tag}</span> "
                                st.markdown(tag_html, unsafe_allow_html=True)
                            
                        st.divider()  # Add separator between agents
                        
            else:
                st.info("No registered agents found. Register some agents using the 'Register Agent' tab to see them here.")
                st.markdown("""
                **To get started:**
                1. Click on the "Register Agent" tab above
                2. Fill out the agent registration form
                3. Your registered agents will appear here
                """)

    def render_product_context_editor(self):
        """Render the product context editor tab"""
        st.header("⚙️ Product Context Configuration")

        # Load current config
        config_path = Path(__file__).parent / "agents" / "orchestrator" / "config.yaml"
        config_data = load_config(config_path)

        if not config_data:
            st.error("Could not load configuration file")
            return

        current_user_metadata = config_data.get("user_metadata", {})
        current_context = current_user_metadata.get("provided_context", {})
        current_product = current_context.get("product", {})

        st.markdown("### Current Product Context")
        st.json(current_user_metadata)

        st.markdown("### Edit Product Context")

        with st.form("product_context_form"):
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Basic Information")
                locale = st.text_input(
                    "Locale",
                    value=current_context.get("locale", "en-US")
                )
                detected_country = st.text_input(
                    "Detected Country",
                    value=current_context.get("detected_country", "US")
                )
                host = st.text_input(
                    "Host",
                    value=current_context.get("host", "company.com")
                )
                url = st.text_input(
                    "URL",
                    value=current_context.get("url", "https://company.com/services/infrastructure")
                )

            with col2:
                st.subheader("Product Information")
                product_name = st.selectbox(
                    "Service Name",
                    options=["Infrastructure", "DevelopmentTools", "Database", "ServiceDesk", "Other"],
                    index=0 if current_product.get("name") == "Infrastructure" else
                          1 if current_product.get("name") == "DevelopmentTools" else
                          2 if current_product.get("name") == "Database" else
                          3 if current_product.get("name") == "Maya" else
                          4 if current_product.get("name") == "3ds Max" else
                          5 if current_product.get("name") == "Inventor" else
                          6 if current_product.get("name") == "Civil 3D" else 7
                )

                if product_name == "Other":
                    product_name = st.text_input(
                        "Custom Product Name",
                        value=current_product.get("name", "")
                    )

                service_version = st.text_input(
                    "Service Version",
                    value=current_product.get("version", "Latest")
                )
                service_category = st.text_input(
                    "Service Category",
                    value=current_product.get("category", "Infrastructure")
                )

            st.subheader("Service Capabilities")
            capabilities_text = st.text_area(
                "Capabilities (one per line)",
                value="\n".join(current_product.get("capabilities", [])),
                height=150
            )

            submitted = st.form_submit_button("Update Service Context", type="primary")

            if submitted:
                # Parse capabilities
                capabilities = [cap.strip() for cap in capabilities_text.split('\n') if cap.strip()]

                # Create updated user metadata
                updated_user_metadata = {
                    "provided_context": {
                        "locale": locale,
                        "detected_country": detected_country,
                        "host": host,
                        "url": url,
                        "product": {
                            "name": product_name,
                            "version": product_version,
                            "category": product_category,
                            "capabilities": capabilities
                        }
                    }
                }

                # Update config
                config_data["user_metadata"] = updated_user_metadata

                # Save config
                if save_config(config_data, config_path):
                    st.success(f"✅ Product context updated successfully! Product: {product_name}")

                    # Update session state
                    updated_user_metadata["username"] = "ituser"
                    st.session_state.user_metadata = updated_user_metadata

                    # Add log entry
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "CONFIG_UPDATE",
                        "message": f"Product context updated to: {product_name} (Version: {product_version})"
                    }
                    st.session_state.agent_logs.append(log_entry)

                    st.rerun()
                else:
                    st.error("❌ Failed to save configuration")

        st.markdown("---")
        st.markdown("### Instructions")
        st.markdown("""
        1. **Update the product context** above to match your use case
        2. **Click 'Update Product Context'** to save changes
        3. **Go to the Chat tab** and ask a question
        4. **Check the Terminal tab** to see routing logs showing which agent was matched and invoked
        5. **The system will route** your question to the appropriate agent based on the product context
        """)

    def render_terminal_tab(self):
        """Render the terminal/logs tab"""
        st.header("📋 Agent Execution Logs")
        
        # Controls
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            if st.button("🔄 Refresh Logs"):
                st.rerun()
        
        with col2:
            if st.button("🗑️ Clear Logs"):
                st.session_state.agent_logs = []
                st.rerun()
        
        with col3:
            auto_scroll = st.checkbox("Auto-scroll", value=True)
        
        # Display logs
        if st.session_state.agent_logs:
            # Create container for logs
            log_container = st.container()
            
            with log_container:
                for i, log_entry in enumerate(reversed(st.session_state.agent_logs)):
                    timestamp = log_entry.get("timestamp", "Unknown")
                    log_type = log_entry.get("type", "INFO")
                    message = log_entry.get("message", "")
                    error = log_entry.get("error", "")

                    # Format timestamp
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        formatted_time = dt.strftime("%H:%M:%S")
                    except:
                        formatted_time = timestamp

                    # Color code and format by log type
                    if log_type in ["ERROR", "AUTH_ERROR", "TOOL_DISCOVERY_ERROR", "MATCHING_ERROR", "TOOL_INVOCATION_ERROR", "TOOL_ERROR", "ROUTING_ERROR"]:
                        st.error(f"🔴 **{formatted_time} - {log_type.replace('_', ' ')}**")
                        if error:
                            st.code(error, language="text")
                        elif message:
                            st.write(message)

                    elif log_type in ["ROUTING_START", "AUTH", "TOOL_DISCOVERY", "MATCHING_START", "TOOL_INVOCATION"]:
                        st.info(f"🔵 **{formatted_time} - {log_type.replace('_', ' ')}**")
                        if message:
                            st.write(message)

                    elif log_type in ["AUTH_SUCCESS", "TOOL_DISCOVERY_SUCCESS", "MATCHING_SUCCESS", "TOOL_SUCCESS"]:
                        st.success(f"🟢 **{formatted_time} - {log_type.replace('_', ' ')}**")
                        if message:
                            st.write(message)

                    elif log_type == "CONFIG_UPDATE":
                        st.success(f"⚙️ **{formatted_time} - CONFIG UPDATE**")
                        if message:
                            st.write(message)

                    elif log_type == "MATCHING_FAILED":
                        st.warning(f"🟡 **{formatted_time} - MATCHING FAILED**")
                        if message:
                            st.write(message)

                    elif log_type == "REQUEST":
                        st.info(f"📤 **{formatted_time} - REQUEST**")
                        st.write(f"URL: {log_entry.get('url', 'N/A')}")
                        if "payload" in log_entry:
                            st.json(log_entry["payload"])

                    elif log_type == "RESPONSE":
                        st.success(f"📥 **{formatted_time} - RESPONSE**")
                        st.write(f"Status Code: {log_entry.get('status_code', 'N/A')}")
                        if "response" in log_entry:
                            try:
                                response_data = json.loads(log_entry["response"])
                                st.code(json.dumps(response_data, indent=2, default=str))
                            except json.JSONDecodeError:
                                st.code(log_entry["response"])
                    else:
                        # Default formatting for other log types
                        st.info(f"ℹ️ **{formatted_time} - {log_type}**")
                        if message:
                            st.write(message)
                        elif error:
                            st.code(error, language="text")

                    st.divider()
        else:
            st.info("No logs available. Start chatting with the agent to see execution logs here.")
    
    def run(self):
        """Main application runner"""
        # Centered main title with custom styling
        st.markdown('<h1 class="main-title">🤖 IT Support Assistant</h1>', unsafe_allow_html=True)
        
        # Check if user is authenticated
        if not st.session_state.authenticated:
            self.render_signin_page()
        else:
            # Display user info in sidebar
            with st.sidebar:
                st.success(f"✅ Signed in as: {st.session_state.user_metadata.get('username', 'Unknown')}")
                
                if st.button("🚪 Sign Out"):
                    # Clear session state
                    for key in st.session_state.keys():
                        del st.session_state[key]
                    st.rerun()
                
                # User metadata display
                with st.expander("👤 User Information"):
                    st.json(st.session_state.user_metadata)
            
            # Main application tabs
            tab1, tab2, tab3, tab4 = st.tabs(["💬 Chat", "🤖 Agent Registry", "⚙️ Product Context", "📋 Terminal"])

            with tab1:
                self.render_chat_interface()

            with tab2:
                self.render_agent_registry()

            with tab3:
                self.render_product_context_editor()

            with tab4:
                self.render_terminal_tab()


def main():
    """Application entry point"""
    app = StreamlitAgentInterface()
    app.run()


if __name__ == "__main__":
    main()