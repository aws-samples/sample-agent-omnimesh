# this is a file that will take in an agent arn and
# convert it into an http url that can then be used in 
# invoking the agent with the required set of credentials
#!/usr/bin/env python3
import urllib.parse
from boto3.session import Session

def build_agent_url(agent_arn: str) -> str:
    session = Session()
    region = session.region_name or "us-west-2"
    endpoint = f"https://bedrock-agentcore.{region}.amazonaws.com"
    escaped = urllib.parse.quote(agent_arn, safe="")
    return f"{endpoint}/runtimes/{escaped}/invocations?qualifier=DEFAULT"

def main():
    arn = input("Enter your Bedrock AgentCore ARN: ").strip()
    if not arn:
        print("No ARN provided. Exiting.")
        return
    url = build_agent_url(arn)
    print("\nInvocation URL:\n", url)

if __name__ == "__main__":
    main()
