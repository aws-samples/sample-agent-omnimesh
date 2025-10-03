import os
import sys
import yaml
import json
import boto3
import logging
import time
import uuid
sys.path.insert(0, ".")
sys.path.insert(1, "..")
from utils import *
from pathlib import Path
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import Dict, List, Any, Union, Optional

# Create a logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Remove existing handlers
logger.handlers.clear()

# Add a simple handler
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] p%(process)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def find_existing_gateway(gateway_name: str) -> Optional[Dict]:
    """
    Check if gateway already exists.

    Args:
        gateway_name: Name of the gateway to search for

    Returns:
        Gateway details if found, None otherwise
    """
    gateway_client = boto3.client('bedrock-agentcore-control')

    try:
        response = gateway_client.list_gateways()
        print(f"All gateways in your account: {response}")
        gateways = response.get('items', [])

        for gateway in gateways:
            if gateway.get('name') == gateway_name:
                logger.info(f"Found existing gateway: {gateway.get('gatewayId')}")
                return {
                    'gatewayId': gateway.get('gatewayId'),
                    'gatewayUrl': gateway.get('gatewayUrl')
                }

        logger.info(f"No existing gateway found with name: {gateway_name}")
        return None
    except Exception as e:
        logger.error(f"Error checking for existing gateway: {e}")
        return None

def setup_ssm_parameters_for_cognito(cognito_config: Dict, app_name: str = "agentcore"):
    """
    Set up SSM parameters based on cognito_config.json for use with the credential provider.

    Args:
        cognito_config: Dictionary containing Cognito configuration
        app_name: Application name for SSM parameter prefix
    """
    ssm = boto3.client("ssm")

    # Extract cognito region from discovery URL
    discovery_url = cognito_config["discovery_url"]
    pool_id = cognito_config["pool_id"]
    domain_name = cognito_config["domain_name"]

    # Extract region from discovery URL (format: https://cognito-idp.{region}.amazonaws.com/...)
    region = discovery_url.split('.')[2]

    # Build the required SSM parameters
    parameters = {
        f"/app/{app_name}/machine_client_id": cognito_config["client_id"],
        f"/app/{app_name}/cognito_secret": cognito_config["client_secret"],
        f"/app/{app_name}/cognito_discovery_url": discovery_url,
        f"/app/{app_name}/cognito_auth_url": f"https://{domain_name}.auth.{region}.amazoncognito.com/oauth2/authorize",
        f"/app/{app_name}/cognito_token_url": f"https://{domain_name}.auth.{region}.amazoncognito.com/oauth2/token"
    }

    # Store parameters in SSM
    for param_name, param_value in parameters.items():
        try:
            ssm.put_parameter(
                Name=param_name,
                Value=param_value,
                Type="String",
                Overwrite=True
            )
            logger.info(f"✅ Stored SSM parameter: {param_name}")
        except Exception as e:
            logger.error(f"❌ Failed to store SSM parameter {param_name}: {e}")
            raise
    logger.info(f"🎉 All SSM parameters configured for app: {app_name}")

# First load the config.yaml file which contains information about the
# gateway that will be required in agentcore gateway creation
# Load the config file.
config_data: Dict = load_config('setup_gateway.yaml')
logger.info(f"Loaded the gateway config file: {json.dumps(config_data, indent=4)}")

# Next, we will create the agentcore gateway role
agentcore_gateway_iam_role = create_agentcore_gateway_role("agent-gateway-new")
logger.info(f"Created the agentcore agent gateway role: {agentcore_gateway_iam_role}")

# Create OAuth provider for agent authentication if configured
# ------------------------------------------------
# OUTBOUND OAUTH TO SUB AGENTS
# ------------------------------------------------
oauth_provider_arn = None
# this assumes that you are providing the identity of the agents at the gateway level
if 'sub_agents_outbound_authorization' in config_data['gateway_config']:
    oauth_config = config_data['gateway_config']['sub_agents_outbound_authorization']
    provider_name = oauth_config.get('name')
    app_name = "agentcore"
    logger.info(f"Getting or creating OAuth provider: {provider_name}")
    # Setup SSM parameters from cognito_config.json
    setup_ssm_parameters_for_cognito(oauth_config, app_name)
    # Use the new utility function to get or create the credential provider
    try:
        cognito_provider = get_or_create_cognito_credential_provider(
            provider_name=provider_name,
            app_name=app_name
        )
        oauth_provider_arn = cognito_provider["credentialProviderArn"]
        logger.info(f"✅ Using OAuth provider with ARN: {oauth_provider_arn}")
    except Exception as e:
        logger.error(f"❌ Failed to get or create OAuth provider: {e}")
        raise

# For inbound authentication, this gateway will cognito. This can be changed with
# a choice of IdP
# First, lets create the gateway client
gateway_client = boto3.client('bedrock-agentcore-control')
logger.info(f"Initialized the gateway client: {gateway_client}")

# ------------------------------------------------
# INBOUND OAUTH TO THE GATEWAY
# ------------------------------------------------
use_existing_inbound_idp: Optional[bool] = config_data['gateway_config']['use_existing_inbound_auth']
if use_existing_inbound_idp:
    print(f"Use existing inbound is set to {use_existing_inbound_idp}")
    auth_config = {
        "customJWTAuthorizer": {
            "allowedClients": config_data['gateway_config']['inbound_auth'].get('client_id'),
            "discoveryUrl": config_data['gateway_config']['inbound_auth'].get('discovery_url')
        }
    }
else:
    print(f"Create the inbound auth info through the IDP set up steps...")
    raise

logger.info(f"Going to use cognito for inbound authentication: {auth_config}")

# Check if gateway already exists
gateway_name = config_data['gateway_config'].get('name', "agent-gateway")
print(f"Going to create or use the {gateway_name} gateway...")
existing_gateway = find_existing_gateway(gateway_name)

if existing_gateway:
    logger.info(f"Using existing gateway: {existing_gateway['gatewayId']}")
    gatewayID = existing_gateway['gatewayId']
    gatewayURL = existing_gateway['gatewayUrl']
else:
    # create the agent gateway
    agent_gateway_response = gateway_client.create_gateway(
        # This IAM role must have permissions to create, list and delete gateways
        name=gateway_name,
        roleArn = agentcore_gateway_iam_role['Arn'],
        protocolType = 'MCP',
        authorizerType = 'CUSTOM_JWT',
        authorizerConfiguration = auth_config,
        description = "Agent Gateway that contains all Enterprise IT Service Agents"
    )
    logger.info(f"Created the agent gateway: {agent_gateway_response}")
    gatewayID = agent_gateway_response["gatewayId"]
    gatewayURL = agent_gateway_response["gatewayUrl"]

print(f"Fetched the agent gateway ID: {gatewayID} and URL: {gatewayURL}")

# Create an S3 client
session = boto3.session.Session()
s3_client = session.client('s3')
sts_client = session.client('sts')

# Retrieve AWS account ID and region
account_id = sts_client.get_caller_identity()["Account"]
region = session.region_name

# bucket that will contain the openAPI spec
bucket_name = config_data['gateway_config'].get('bucket_name')

# Get the agent specification folder path
agent_spec_path = config_data['gateway_config'].get('agent_spec')
if not agent_spec_path:
    logger.warning("No agent_spec path specified in configuration")
else:
    # Extract the directory path from the agent_spec
    agent_spec_dir = os.path.dirname(agent_spec_path)

    # Get all YAML files from the agent_specifications folder
    spec_files = [f for f in os.listdir(agent_spec_dir) if f.endswith('.yaml')]

    if not spec_files:
        logger.warning(f"No YAML files found in {agent_spec_dir}")
    else:
        logger.info(f"Found {len(spec_files)} agent specification files")

        # Configure credential provider if OAuth provider was created
        credential_config = []
        if oauth_provider_arn:
            # Use the correct scopes that match what the sub-agents expect
            # Based on the agent_idp token, the sub-agents expect these resource server scopes
            scopes = [
                f"https://enterprise-it-agent/{oauth_config['pool_id']}/admin",
                f"https://enterprise-it-agent/{oauth_config['pool_id']}/read",
                f"https://enterprise-it-agent/{oauth_config['pool_id']}/write"
            ]
            credential_config = [
                {
                    "credentialProviderType": "OAUTH",
                    "credentialProvider": {
                        "oauthCredentialProvider": {
                            "providerArn": oauth_provider_arn,
                            "scopes": scopes
                        }
                    }
                }
            ]
            logger.info(f"Using OAuth credential provider with scopes: {scopes}")

        # Process each specification file
        for spec_file in spec_files:
            agent_spec_file = os.path.join(agent_spec_dir, spec_file)
            object_key = spec_file

            # Upload the OpenAPI specification file to S3
            try:
                with open(agent_spec_file, 'rb') as file_data:
                    response = s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=file_data)

                # Construct the S3 URI of the uploaded object
                openapi_s3_uri = f's3://{bucket_name}/{object_key}'
                logger.info(f'Uploaded OpenAPI spec to S3 URI: {openapi_s3_uri}')

            except Exception as e:
                logger.error(f'Error uploading OpenAPI file {spec_file}: {e}')
                continue  # Continue with next file

            # Create the gateway target configuration
            openapi_s3_target_config = {
                "mcp": {
                    "openApiSchema": {
                        "s3": {
                            "uri": openapi_s3_uri
                        }
                    }
                }
            }

            # Generate target name from filename: replace underscores with dashes, remove .yaml extension
            target_name = os.path.splitext(spec_file)[0].replace('_', '-')

            # Create the gateway target
            try:
                target_response = gateway_client.create_gateway_target(
                    gatewayIdentifier=gatewayID,
                    name=target_name,
                    description=f'OpenAPI Target with S3 URI for {target_name}',
                    targetConfiguration=openapi_s3_target_config,
                    credentialProviderConfigurations=credential_config
                )

                logger.info(f"Created gateway target: {target_response}")
                print(f"Gateway target '{target_name}' created successfully")

                # Print response metadata for debugging
                response_metadata = target_response['ResponseMetadata']
                logger.info(f"Target creation response metadata: {response_metadata}")

            except Exception as e:
                logger.error(f'Error creating gateway target {target_name}: {e}')
                continue  # Continue with next file

# Save gateway results to JSON file
gateway_results = {
    "gateway_info": {
        "gateway_id": gatewayID,
        "gateway_name": gateway_name,
        "gateway_url": gatewayURL,
        "description": "Agent Gateway that contains all Enterprise IT Service Agents"
    },
    "authentication": {
        "authorizer_type": "CUSTOM_JWT",
        "protocol_type": "MCP",
        "discovery_url": config_data['gateway_config']['inbound_auth'].get('discovery_url'),
        "allowed_clients": config_data['gateway_config']['inbound_auth'].get('client_id'),
        "role_arn": agentcore_gateway_iam_role['Arn']
    },
    "cognito_config": oauth_config
}

# Add OAuth provider info if it was created
if oauth_provider_arn:
    gateway_results["oauth_provider"] = {
        "provider_arn": oauth_provider_arn,
        "provider_name": provider_name,
        "scopes": scopes if 'scopes' in locals() else ["agentcore/access"]
    }

# Add target info - collect information about all targets created
if agent_spec_path:
    gateway_results["targets"] = []
    agent_spec_dir = os.path.dirname(agent_spec_path)
    spec_files = [f for f in os.listdir(agent_spec_dir) if f.endswith('.yaml')]

    for spec_file in spec_files:
        target_name = os.path.splitext(spec_file)[0].replace('_', '-')
        openapi_s3_uri = f's3://{bucket_name}/{spec_file}'
        gateway_results["targets"].append({
            "target_name": target_name,
            "spec_file": spec_file,
            "description": f"OpenAPI Target with S3 URI for {target_name}",
            "openapi_s3_uri": openapi_s3_uri
        })

# Save to JSON file
output_file = "gateway_results.json"
try:
    with open(output_file, 'w') as f:
        json.dump(gateway_results, f, indent=2, default=str)
    logger.info(f"Gateway results saved to {output_file}")
    print(f"Gateway configuration saved to {output_file}")
except Exception as e:
    logger.error(f"Error saving gateway results: {e}")
    raise