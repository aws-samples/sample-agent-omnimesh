class ResponseType:
    PRODUCT_COMMAND = "product_command"
    TEXT = "text"
    HTML = "html"
    IMAGE = "image"
    MARKDOWN = "markdown"
    CHOICE = "choice" # TODO: deprecate?
    OPTIONS = "options"
    CODE = "code"
    ERROR = "error"
    REFERENCE = "reference"
    WORKFLOW = "workflow"
    MORE_INFO_NEEDED = "more_info_needed"
    OUT_OF_SCOPE = "out_of_scope"
    TABLE = "table"
    ATTACHMENTS = "attachments"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    # signal to give to the orchestrator agent to show that
    # the sub-agent has completed its task and no further
    # interaction is needed (this is where the user sticky session with the domain
    # agent can be closed)
    COMPLETED = "completed"