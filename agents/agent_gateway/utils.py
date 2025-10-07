import boto3
import json
import time
from boto3.session import Session
import botocore
import requests
import os
import time
import logging
import yaml
import hmac
import hashlib
import base64
from typing import Optional, Dict, Union, Any, List
from pathlib import Path
from botocore.exceptions import ClientError
from botocore.config import Config

# set a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def _calculate_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """
    Calculate the SECRET_HASH required for Cognito authentication
    when the client has a secret configured.

    Args:
        username: Username for authentication
        client_id: Cognito User Pool client ID
        client_secret: Cognito User Pool client secret

    Returns:
        str: Base64 encoded HMAC-SHA256 hash
    """
    message = username + client_id
    dig = hmac.new(
        str(client_secret).encode('UTF-8'),
        str(message).encode('UTF-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def _create_resource_server_with_scopes(cognito_client, pool_id, region):
    """
    Create a resource server with custom scopes for AgentCore OAuth.

    Args:
        cognito_client: Boto3 Cognito IDP client
        pool_id: Cognito User Pool ID
        region: AWS region

    Returns:
        Resource server identifier for use in scopes
    """
    resource_server_identifier = "agentcore"

    try:
        # Check if resource server already exists
        try:
            existing = cognito_client.describe_resource_server(
                UserPoolId=pool_id,
                Identifier=resource_server_identifier
            )
            logger.info(f"Resource server already exists: {resource_server_identifier}")
            return resource_server_identifier
        except cognito_client.exceptions.ResourceNotFoundException:
            pass

        # Create resource server with custom scopes
        logger.info(f"Creating resource server: {resource_server_identifier}")

        response = cognito_client.create_resource_server(
            UserPoolId=pool_id,
            Identifier=resource_server_identifier,
            Name="AgentCore Resource Server",
            Scopes=[
                {
                    'ScopeName': 'access',
                    'ScopeDescription': 'Access to AgentCore services'
                }
            ]
        )

        logger.info(f"Successfully created resource server: {resource_server_identifier}")
        return resource_server_identifier

    except Exception as e:
        logger.error(f"Error creating resource server: {e}")
        # Return identifier anyway in case it exists
        return resource_server_identifier

def setup_cognito_user_pool(password=None):
    """
    Set up a Cognito User Pool for authentication and authorization
    this uses the cognito idp client and uses a pre configured idp and
    password. This in a production scenario would be your configured
    IdP that would contain your pool id, client id, and admin configurations
    for username and password for re authentication and using that
    to configure inbound authentication with specific scopes within the agent

    Args:
        password: Password for the test user. If None, uses default.
    """
    boto_session = Session()
    region = boto_session.region_name
    # Initialize Cognito client
    cognito_client = boto3.client('cognito-idp', region_name=region)
    try:
        # Create User Pool
        logger.info(f"Going to host an agent and for that, creating a user pool...")
        user_pool_response = cognito_client.create_user_pool(
            PoolName='agent_identity_directory',
            Policies={
                'PasswordPolicy': {
                    'MinimumLength': 8
                }
            }
        )
        pool_id = user_pool_response['UserPool']['Id']

        # Create resource server with custom scopes
        logger.info(f"Creating resource server with custom scopes...")
        resource_server_id = _create_resource_server_with_scopes(cognito_client, pool_id, region)

        # Create App Client
        logger.info(f"Creating user pool client....")
        app_client_response = cognito_client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName='ServerPoolClient',
            GenerateSecret=True,
            ExplicitAuthFlows=[
                'ALLOW_USER_PASSWORD_AUTH',
                'ALLOW_REFRESH_TOKEN_AUTH'
            ],
            # Enable OAuth flows for client credentials (machine-to-machine)
            SupportedIdentityProviders=['COGNITO'],
            AllowedOAuthFlows=['client_credentials'],
            AllowedOAuthScopes=[
                f'{resource_server_id}/access'  # Custom AgentCore scope - this is the primary scope needed
            ],
            AllowedOAuthFlowsUserPoolClient=True
        )
        logger.info(f"Created user pool client: {app_client_response}")
        client_id = app_client_response['UserPoolClient']['ClientId']
        client_secret = app_client_response['UserPoolClient']['ClientSecret']
        logger.info(f"Created user pool client id: {client_id}")
        # Create User
        logger.info(f"Creating user...")
        cognito_client.admin_create_user(
            UserPoolId=pool_id,
            Username='enterprisetestuser',
            TemporaryPassword='Temp123!',
            MessageAction='SUPPRESS'
        )
        # Set Permanent Password
        user_password = password or 'MyPassword123!'  # Fallback for backward compatibility
        cognito_client.admin_set_user_password(
            UserPoolId=pool_id,
            Username='enterprisetestuser',
            Password=user_password,
            Permanent=True
        )
        # Calculate SECRET_HASH for authentication
        secret_hash = _calculate_secret_hash('enterprisetestuser', client_id, client_secret)
        # Authenticate User and get Access Token
        auth_response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'enterprisetestuser',
                'PASSWORD': user_password,
                'SECRET_HASH': secret_hash
            }
        )
        bearer_token = auth_response['AuthenticationResult']['AccessToken']
        # Output the required values
        print(f"Pool id: {pool_id}")
        # this is the OIDC to connect to which will contain the authorization details, scopes, the tokens and information
        # required by the client to connect to the agent
        print(f"Discovery URL: https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration")
        print(f"Client ID: {client_id}")
        print(f"Bearer Token: {bearer_token}")

        # Return values if needed for further processing
        return {
            'pool_id': pool_id,
            'client_id': client_id,
            'client_secret': client_secret,
            'bearer_token': bearer_token,
            'discovery_url': f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration",
            'resource_server': resource_server_id,
            'custom_scope': f'{resource_server_id}/access'
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

    
def load_config(config_file: Union[Path, str]) -> Optional[Dict]:
    """
    Load configuration from a local file.

    :param config_file: Path to the local file
    :return: Dictionary with the loaded configuration
    """
    try:
        config_data: Optional[Dict] = None
        logger.debug(f"Loading config from local file system: {config_file}")
        content = Path(config_file).read_text()
        config_data = yaml.safe_load(content)
        logger.debug(f"Successfully loaded config from: {config_file}")
    except Exception as e:
        logger.error(f"Error loading config from local file system: {e}")
        config_data = None
    return config_data

def create_agentcore_gateway_role(gateway_name):
    iam_client = boto3.client('iam')
    agentcore_gateway_role_name = f'agentcore-{gateway_name}-role'
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:*",
                    "bedrock:*",
                    "agent-credential-provider:*",
                    "iam:PassRole",
                    "secretsmanager:*",
                    "lambda:InvokeFunction"
                ],
                "Resource": "*"
            }
        ]
    }

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock-agentcore.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": f"{account_id}"
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    }
                }
            }
        ]
    }

    assume_role_policy_document_json = json.dumps(
        assume_role_policy_document
    )

    role_policy_document = json.dumps(role_policy)
    # Check if role already exists before attempting creation
    try:
        # Try to get existing role
        existing_role = iam_client.get_role(RoleName=agentcore_gateway_role_name)
        print(f"Role {agentcore_gateway_role_name} already exists, using existing role")
        agentcore_iam_role = existing_role['Role']
    except iam_client.exceptions.NoSuchEntityException:
        # Role doesn't exist, create it
        try:
            created_role = iam_client.create_role(
                RoleName=agentcore_gateway_role_name,
                AssumeRolePolicyDocument=assume_role_policy_document_json
            )
            agentcore_iam_role = created_role['Role']
            print(f"Created new role {agentcore_gateway_role_name}")
            # Pause to make sure role is created
            time.sleep(10)
        except iam_client.exceptions.EntityAlreadyExistsException:
            print("Role already exists -- deleting and creating it again")
        try:
            policies = iam_client.list_role_policies(
                RoleName=agentcore_gateway_role_name,
                MaxItems=100
            )
        except iam_client.exceptions.NoSuchEntityException:
            print(f"Role {agentcore_gateway_role_name} not found during cleanup")
            policies = {'PolicyNames': []}
        print("policies:", policies)
        for policy_name in policies['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=agentcore_gateway_role_name,
                PolicyName=policy_name
            )
        print(f"deleting {agentcore_gateway_role_name}")
        iam_client.delete_role(
            RoleName=agentcore_gateway_role_name
        )
        print(f"recreating {agentcore_gateway_role_name}")
        created_role = iam_client.create_role(
            RoleName=agentcore_gateway_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )
        agentcore_iam_role = created_role['Role']

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_gateway_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_gateway_role_name
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role


# ============================================================================
# COGNITO CREDENTIAL PROVIDER MANAGEMENT
# ============================================================================

def get_aws_region() -> str:
    """Get AWS region from session or environment."""
    session = Session()
    region = session.region_name
    if not region:
        region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
    return region


def get_ssm_parameter(parameter_name: str, region: Optional[str] = None) -> str:
    """
    Retrieve a parameter from AWS Systems Manager Parameter Store.

    Args:
        parameter_name: The name of the SSM parameter
        region: AWS region (uses default if not provided)

    Returns:
        The parameter value

    Raises:
        ClientError: If parameter not found or access denied
    """
    if not region:
        region = get_aws_region()

    ssm = boto3.client("ssm", region_name=region)

    try:
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response["Parameter"]["Value"]
    except ClientError as e:
        logger.error(f"Failed to retrieve SSM parameter {parameter_name}: {e}")
        raise


def _store_provider_name_in_ssm(provider_name: str, app_name: str = "agentcore", region: Optional[str] = None):
    """Store credential provider name in SSM parameter."""
    if not region:
        region = get_aws_region()

    ssm = boto3.client("ssm", region_name=region)
    param_name = f"/app/{app_name}/cognito_provider"

    try:
        ssm.put_parameter(
            Name=param_name, Value=provider_name, Type="String", Overwrite=True
        )
        logger.info(f"🔐 Stored provider name in SSM: {param_name}")
    except ClientError as e:
        logger.error(f"⚠️ Failed to store provider name in SSM: {e}")
        raise


def _get_provider_name_from_ssm(app_name: str = "agentcore", region: Optional[str] = None) -> Optional[str]:
    """Get credential provider name from SSM parameter."""
    if not region:
        region = get_aws_region()

    ssm = boto3.client("ssm", region_name=region)
    param_name = f"/app/{app_name}/cognito_provider"

    try:
        response = ssm.get_parameter(Name=param_name)
        return response["Parameter"]["Value"]
    except ClientError:
        return None


def _delete_ssm_param(app_name: str = "agentcore", region: Optional[str] = None):
    """Delete SSM parameter for provider."""
    if not region:
        region = get_aws_region()

    ssm = boto3.client("ssm", region_name=region)
    param_name = f"/app/{app_name}/cognito_provider"

    try:
        ssm.delete_parameter(Name=param_name)
        logger.info(f"🧹 Deleted SSM parameter: {param_name}")
    except ClientError as e:
        logger.warning(f"⚠️ Failed to delete SSM parameter: {e}")


def create_cognito_credential_provider(
    provider_name: str,
    app_name: str = "agentcore",
    region: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a Cognito OAuth2 credential provider for AgentCore.

    Args:
        provider_name: Name for the credential provider
        app_name: Application name for SSM parameter paths (default: agentcore)
        region: AWS region (uses session default if not provided)

    Returns:
        Dictionary containing the created provider information

    Raises:
        Exception: If provider creation fails
    """
    if not region:
        region = get_aws_region()

    identity_client = boto3.client("bedrock-agentcore-control", region_name=region)

    try:
        logger.info("📥 Fetching Cognito configuration from SSM...")

        # Generic SSM parameter paths
        client_id = get_ssm_parameter(f"/app/{app_name}/machine_client_id", region)
        logger.info(f"✅ Retrieved client ID: {client_id}")

        client_secret = get_ssm_parameter(f"/app/{app_name}/cognito_secret", region)
        logger.info(f"✅ Retrieved client secret: {client_secret[:4]}***")

        issuer_url = get_ssm_parameter(f"/app/{app_name}/cognito_discovery_url", region)
        # Remove .well-known/openid-configuration path for OAuth2 provider
        issuer = issuer_url.replace("/.well-known/openid-configuration", "")
        auth_url = get_ssm_parameter(f"/app/{app_name}/cognito_auth_url", region)
        token_url = get_ssm_parameter(f"/app/{app_name}/cognito_token_url", region)

        logger.info(f"✅ Issuer: {issuer}")
        logger.info(f"✅ Authorization Endpoint: {auth_url}")
        logger.info(f"✅ Token Endpoint: {token_url}")

        logger.info("⚙️  Creating OAuth2 credential provider...")
        cognito_provider = identity_client.create_oauth2_credential_provider(
            name=provider_name,
            credentialProviderVendor="CustomOauth2",
            oauth2ProviderConfigInput={
                "customOauth2ProviderConfig": {
                    "oauthDiscovery": {
                    "discoveryUrl": issuer_url
                    },
                    "clientId": client_id,
                    "clientSecret": client_secret,
                }
            },
        )
        logger.info(f"✅ OAuth2 credential provider created successfully: {cognito_provider}")
        provider_arn = cognito_provider["credentialProviderArn"]
        logger.info(f"   Provider ARN: {provider_arn}")
        logger.info(f"   Provider Name: {cognito_provider['name']}")

        # Store provider name in SSM
        _store_provider_name_in_ssm(provider_name, app_name, region)

        return cognito_provider

    except Exception as e:
        logger.error(f"❌ Error creating Cognito credential provider: {str(e)}")
        raise


def delete_cognito_credential_provider(
    provider_name: str,
    app_name: str = "agentcore",
    region: Optional[str] = None
) -> bool:
    """
    Delete a Cognito OAuth2 credential provider.

    Args:
        provider_name: Name of the provider to delete
        app_name: Application name for SSM parameter paths
        region: AWS region

    Returns:
        True if deletion successful, False otherwise
    """
    if not region:
        region = get_aws_region()

    identity_client = boto3.client("bedrock-agentcore-control", region_name=region)

    try:
        logger.info(f"🗑️  Deleting OAuth2 credential provider: {provider_name}")

        identity_client.delete_oauth2_credential_provider(name=provider_name)

        logger.info("✅ OAuth2 credential provider deleted successfully")

        # Clean up SSM parameter
        _delete_ssm_param(app_name, region)

        return True

    except Exception as e:
        logger.error(f"❌ Error deleting credential provider: {str(e)}")
        return False


def list_cognito_credential_providers(region: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all OAuth2 credential providers.

    Args:
        region: AWS region

    Returns:
        List of credential provider dictionaries
    """
    if not region:
        region = get_aws_region()

    identity_client = boto3.client("bedrock-agentcore-control", region_name=region)

    try:
        providers = []
        next_token = None

        # Paginate through all providers
        while True:
            if next_token:
                response = identity_client.list_oauth2_credential_providers(
                    maxResults=20,
                    nextToken=next_token
                )
            else:
                response = identity_client.list_oauth2_credential_providers(maxResults=20)

            providers.extend(response.get("credentialProviders", []))
            next_token = response.get("nextToken")

            if not next_token:
                break

        return providers

    except Exception as e:
        logger.error(f"❌ Error listing credential providers: {str(e)}")
        return []


def find_cognito_provider_by_name(provider_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Check if a credential provider exists by name.

    Args:
        provider_name: Name of the provider to find
        region: AWS region

    Returns:
        Provider dictionary if exists, None otherwise
    """
    providers = list_cognito_credential_providers(region)
    for provider in providers:
        if provider.get("name") == provider_name:
            logger.info(f"Found existing credential provider: {provider_name}")
            return provider
    return None


def get_or_create_cognito_credential_provider(
    provider_name: str,
    app_name: str = "agentcore",
    region: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get existing or create a new Cognito OAuth2 credential provider for AgentCore.
    If a provider with the same name exists, return it instead of creating a new one.

    Args:
        provider_name: Name for the credential provider
        app_name: Application name for SSM parameter paths (default: agentcore)
        region: AWS region (uses session default if not provided)

    Returns:
        Dictionary containing the provider information

    Raises:
        Exception: If provider creation fails
    """
    if not region:
        region = get_aws_region()

    # Check if provider already exists
    existing_provider = find_cognito_provider_by_name(provider_name, region)
    if existing_provider:
        logger.info(f"✅ Using existing OAuth2 credential provider: {provider_name}")
        logger.info(f"   Provider ARN: {existing_provider.get('credentialProviderArn')}")
        return existing_provider

    # Provider doesn't exist, create it
    logger.info(f"Provider '{provider_name}' not found, creating new one...")
    return create_cognito_credential_provider(provider_name, app_name, region)
