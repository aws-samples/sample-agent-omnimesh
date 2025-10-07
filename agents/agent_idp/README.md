# Agent Identity Provider (IDP)

## Overview
This folder provides a Cognito-based identity provider setup for securing agent HTTP endpoints with OAuth authentication. This configuration enables gateway-to-agent authentication using OAuth client credentials flow.

## Prerequisites

**Before using this folder, determine your current setup:**

### Option 1: You Already Have a Configured Agent
If you already have an agent running as an HTTP service with identity configuration, **skip this setup** and collect the following information for gateway configuration. This can be any other OIDC-compliant `IdP`, in this example we are using `Cognito` as the `IdP`:

- **User Pool ID**: The `Cognito` user pool ID
- **Domain Name**: The `Cognito` domain name
- **Client ID**: OAuth client ID for the agent
- **Client Secret**: OAuth client secret
- **Discovery URL**: The OAuth discovery endpoint URL

You will need these credentials when creating the gateway to configure outbound authentication from the gateway to your agent.

### Option 2: You Need to Create Identity Configuration
If you don't have an agent with identity configuration yet, **start here first** before creating your agent:

1. Run the setup script from this folder:
   ```bash
   python setup_cognito.py
   ```

2. This script will:
   - Create a `Cognito` user pool configured for OAuth client credentials flow
   - Generate a `cognito_config.json` file containing all required credentials

3. The generated `cognito_config.json` will contain:
   - User Pool ID
   - Domain Name
   - Client ID
   - Client Secret
   - Discovery URL

4. Use these credentials when creating your agents:
   - Navigate to the `sub_agents` folder
   - Follow the README instructions for creating agents
   - When launching the agent runtime, you will be prompted to provide:
     - Discovery URL (from `cognito_config.json`)
     - Client ID (from `cognito_config.json`)

5. Later, when creating the gateway, use these same credentials to configure outbound authentication from the gateway to your agent.

## Customization

You can modify the `setup_cognito_user_pool()` function in `setup_cognito.py` to customize the Cognito user pool configuration according to your specific requirements.

## Usage Flow

```
1. Run setup_cognito.py (if needed)
   |
   v
2. Obtain OAuth credentials (cognito_config.json)
   |
   v
3. Create and launch agent with these credentials
   |
   v
4. Configure gateway with same credentials for authentication
```

## Important Notes

- The generated `cognito_config.json` file contains sensitive credentials. Do not commit this file to version control.
- Keep the OAuth credentials secure and share them only through secure channels.
- The same credentials are used for both agent runtime configuration and gateway outbound authentication configuration.

## Next Steps

Once you have your agent `IdP` information and your agent endpoints, then move to the `agent_gateway` folder to register your agents with the `AgentCore Gateway`. Follow the instructions in the `agent_gateway/README.md` to complete the gateway setup and agent registration process.