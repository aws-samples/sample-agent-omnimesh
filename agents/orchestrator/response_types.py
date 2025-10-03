from typing import List, Optional, Any

class ResponseType:
    PRODUCT_COMMAND = "product_command"
    TEXT = "text"
    HTML = "html"
    IMAGE = "image"
    MARKDOWN = "markdown"
    CHOICE = "choice" # TODO: deprecate?
    OPTIONS = "options"
    CODE = "code"
    ERROR = "error" # important
    REFERENCE = "reference"
    WORKFLOW = "workflow"
    MORE_INFO_NEEDED = "more_info_needed" # important
    # add a sticky-ness completion type here
    SESSION_COMPLETED = "session_completed"
    OUT_OF_SCOPE = "out_of_scope" # important
    TABLE = "table"
    ATTACHMENTS = "attachments"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"

# Define the list of the response types the requires assistance from the orchestrator
ORCHESTRATOR_INITIALIZATION_RESPONSE_TYPES = [ResponseType.ERROR, ResponseType.OUT_OF_SCOPE]