flowchart TD
  Auth["Shared Inbound Auth:\nAgentCore Identity + Amazon Cognito"]

  subgraph InfraRT["Infrastructure Runtime (serverless, isolated)"]
    I["Infrastructure Agent (LangGraph)"]
  end

  subgraph DevToolsRT["Development Tools Runtime (serverless, isolated)"]
    D["Development Tools Agent (LangGraph)"]
  end

  subgraph DatabaseRT["Database Runtime (serverless, isolated)"]
    DB["Database Agent (LangGraph)"]
  end

  subgraph DefaultRT["Default Runtime (serverless, isolated)"]
    Df["Service Desk Agent (LangGraph)"]
  end

  Auth --- InfraRT
  Auth --- DevToolsRT
  Auth --- DatabaseRT
  Auth --- DefaultRT
