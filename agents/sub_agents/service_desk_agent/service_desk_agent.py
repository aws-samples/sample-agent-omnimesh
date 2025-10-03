# Service Desk Agent with LangGraph Implementation (Revised)
# - Fixes @tool misuse causing `'int' object has no attribute 'parent_run_id'`
# - Ensures JSON-serializable responses for MCP/Gateway (no Enums in payloads)
# - chat_handler takes a string
# - Robust error handling and consistent envelopes

import re
import os
import sys
import json
import boto3
import logging
from typing import Dict, List, Optional, Union, Any, TypedDict

from langchain.prompts.chat import ChatPromptTemplate
from langchain_aws import ChatBedrock
from langgraph.graph import StateGraph, END, START
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# --- Logging -----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# --- Imports from project ----------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from utils import *  # noqa: F401,F403  (assumed existing project helpers)
from response_types import ResponseType  # Enum or str constants in your project

# --- Config load -------------------------------------------------------------
possible_config_paths = [
    os.path.join(parent_dir, "config.yaml"),
    os.path.join(current_dir, "config.yaml"),
    os.path.join(os.getcwd(), "config.yaml"),
    "config.yaml",
]

CONFIG_FPATH = next((p for p in possible_config_paths if os.path.exists(p)), None)
if CONFIG_FPATH is None:
    raise FileNotFoundError("config.yaml not found")

config_data = load_config(CONFIG_FPATH)

# Model + agent config keys (service desk agent specific)
agent_model_info: Dict = config_data["model_information"].get("service_desk_agent_info")
inference_parameters: Dict = agent_model_info.get("inference_parameters") or {}
system_prompt_filename: str = agent_model_info.get("system_prompt_fpath")

system_prompt_path = os.path.join(current_dir, system_prompt_filename)
try:
    with open(system_prompt_path, "r", encoding="utf-8") as f:
        agent_prompt_template_raw = f.read()
except FileNotFoundError:
    raise FileNotFoundError(f"Agent prompt file not found: {system_prompt_path}")

# Ensure ResponseType tokens are injected as strings (MCP-safe)
def _rt(v) -> str:
    """Return string value for ResponseType or pass-through strings."""
    try:
        # If Enum-like
        return v.value if hasattr(v, "value") else str(v)
    except Exception:
        return str(v)

agent_prompt_template_content = agent_prompt_template_raw.format(
    more_info_needed=_rt(ResponseType.MORE_INFO_NEEDED),
    out_of_scope=_rt(ResponseType.OUT_OF_SCOPE),
    error=_rt(ResponseType.ERROR),
)

logger.info(f"Loaded system prompt from: {system_prompt_path}")

# --- Model init --------------------------------------------------------------
region = boto3.session.Session().region_name
model = ChatBedrock(
    model_id=agent_model_info["model_id"],
    region_name=region,
    model_kwargs={
        "max_tokens": inference_parameters.get("max_tokens", 2048),
        "temperature": inference_parameters.get("temperature", 0.1),
        "top_p": inference_parameters.get("top_p", 0.92),
        "stop_sequences": inference_parameters.get(
            "stop_sequences", ["</invoke>", "</answer>", "</error>"]
        ),
    },
)
logger.info(f"Initialized ChatBedrock for service desk agent in region={region}")

# --- Helpers -----------------------------------------------------------------
def health_check() -> Dict:
    """Basic health check (no @tool; keep it trivial and JSON-serializable)."""
    return {
        "statusCode": 200,
        "response_type": _rt(ResponseType.MODEL_RESPONSE),
        "response_message": "Health check passed - Service Desk Agent is running",
        "status": "ok",
    }

def error_envelope(message: str, status_code: int = 500) -> Dict:
    return {
        "statusCode": status_code,
        "response_type": _rt(ResponseType.ERROR),
        "response_message": message,
        "status": "error",
    }

def extract_json_from_response(response_text: str) -> Optional[Dict[str, Any]]:
    """Extract JSON from LLM response; supports fenced/inline variants."""
    if not isinstance(response_text, str) or not response_text.strip():
        return None

    # 1) Try full parse
    try:
        return json.loads(response_text.strip())
    except json.JSONDecodeError:
        pass

    # 2) Try patterns
    patterns = [
        r"```json\s*(\{.*?\})\s*```",
        r"```\s*(\{.*?\})\s*```",
        r"(\{[^{}]*\"response_type\"[^{}]*\})",
        r"(\{[^{}]*\"is_service_desk\"[^{}]*\})",
        r"(\{.*?\})",
    ]
    for pat in patterns:
        m = re.search(pat, response_text, re.DOTALL | re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    return None

# --- Core LLM handler --------------------------------------------------------
def chat_handler(user_query: str) -> str:
    """
    Orchestrates: (1) retrieve KB, (2) construct prompt, (3) call LLM,
    (4) return string response directly.
    """
    try:
        top_k = agent_model_info.get("top_k", 5)

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", agent_prompt_template_content),
                ("human", "{user_query}"),
            ]
        )

        messages = prompt.format_messages(user_query=user_query)
        model_response = model.invoke(messages)

        final_text = getattr(model_response, "content", str(model_response))
        return final_text.strip()

    except Exception as e:
        logger.exception("Unhandled error in chat_handler")
        return f"An error occurred while processing your query: {str(e)}"

# --- LangGraph state & nodes -------------------------------------------------
class AgentState(TypedDict):
    """State for the Service Desk agent graph."""
    user_question: str
    response: str
    question: str

def get_user_question(state: AgentState) -> AgentState:
    logger.info(f"Processing user question: {state.get('user_question')}")
    q = (state.get("user_question") or "").strip()
    return {**state, "question": q.lower()}

def return_string_response(state: AgentState) -> AgentState:
    try:
        user_question = state["user_question"]
        q_lower = state["question"]

        logger.info(f"Processing query: {user_question}")

        if q_lower in ("health", "health check", "status"):
            return {**state, "response": "Health check passed - Service Desk Agent is running"}

        # Use the clean chat_handler (string input)
        resp = chat_handler(user_question)
        return {**state, "response": resp}

    except Exception as e:
        logger.exception("Error in return_string_response")
        return {**state, "response": f"Internal server error: {str(e)}"}

def build_service_desk_agent_graph():
    """Builds the LangGraph with two custom nodes."""
    try:
        workflow = StateGraph(AgentState)
        workflow.add_node("get_user_question", get_user_question)
        workflow.add_node("return_string_response", return_string_response)

        workflow.add_edge(START, "get_user_question")
        workflow.add_edge("get_user_question", "return_string_response")
        workflow.add_edge("return_string_response", END)

        agent_graph = workflow.compile()
        logger.info("Successfully created LangGraph with custom nodes (service_desk).")
        return agent_graph
    except Exception as e:
        logger.error(f"Error building LangGraph: {e}")
        raise

# --- Bedrock AgentCore runtime app ------------------------------------------
app = BedrockAgentCoreApp()
logger.info(f"Initialized the bedrock agentcore app: {app}")

@app.entrypoint
def service_desk_agent_handler(payload: Dict) -> str:
    """
    Entrypoint for the Service Desk agent using custom LangGraph nodes.
    Returns a simple string response.
    """
    agent_graph = build_service_desk_agent_graph()
    try:
        user_query = (payload.get("prompt") or payload.get("user_query") or "").strip()

        if not user_query:
            return "Bad request: user query must be non-empty."

        if user_query.lower() in ("health", "health check", "status"):
            return "Health check passed - Service Desk Agent is running"

        initial_state: AgentState = {
            "user_question": user_query,
            "response": "",
            "question": "",
        }
        result = agent_graph.invoke(initial_state)

        # Return the string response directly
        return result.get("response") or "No response generated"

    except Exception as e:
        logger.exception("Error in service_desk_agent_handler")
        return f"Error: {str(e)}"

# --- Optional: CLI runner ----------------------------------------------------
def interactive_cli():
    print("\n🤖 Service Desk Agent - LangGraph (String Response Version)")
    print("Type 'exit' to quit, 'health' for health check.")

    agent_graph = build_service_desk_agent_graph()

    while True:
        try:
            user_input = input("\n👤 You: ").strip()
            if user_input.lower() in ("exit", "quit", "q"):
                break
            if not user_input:
                continue

            if user_input.lower() in ("health", "health check", "status"):
                print("🤖 Health check passed - Service Desk Agent is running")
                continue

            initial_state: AgentState = {
                "user_question": user_input,
                "response": "",
                "question": "",
            }
            result = agent_graph.invoke(initial_state)

            response = result.get("response") or "No response generated"
            print(f"🤖 {response}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_cli()
    else:
        logger.info("Running the agent on bedrock agentcore runtime...")
        app.run()
