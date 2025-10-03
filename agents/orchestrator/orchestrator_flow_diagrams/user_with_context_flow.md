sequenceDiagram
  participant U as User App
  box rgb(230,245,255) Enterprise IT Assistant
    participant A as Enterprise IT Assistant
    participant AR as Agent Registry
    participant AG as Agent Gateway
  end
  participant D as Domain Agent (runtime)
  participant S as Service Desk Agent (fallback)

  %% Flow starts with Enterprise IT Assistant
  U->>A: Query (with service context)
  A->>AR: Check enabled domain agents
  AR-->>A: Match? (yes/no)

  alt Match found
    A->>AG: Resolve agent in Gateway
    AG->>D: Invoke matched Domain Agent (runtime)

    alt more_info_needed
      D-->>U: Ask follow-up (sticky session)
      loop Until complete
        U->>D: Provide follow-up
        D-->>U: more_info_needed / complete
      end
      D-->>U: Final answer
    else complete
      D-->>U: Final answer
    else out_of_scope / error
      D-->>A: out_of_scope / error
      A->>AG: Try another eligible agent
      alt Another agent found
        AG->>D: Invoke other Domain Agent
      else No other agent
        A->>AG: Resolve Service Desk Agent
        AG->>S: Invoke Service Desk Agent (fallback)
        S-->>U: Final answer
      end
    end
  end
