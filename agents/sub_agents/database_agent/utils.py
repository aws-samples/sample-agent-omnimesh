# this is the file that will be used to contain utility functions for the agents
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
from typing import Optional, Dict, Union
from pathlib import Path
from botocore.exceptions import ClientError

# set a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize S3 client
s3_client = boto3.client('s3')
# Initialize the bedrock runtime client. This is used to 
# query search results from the FMC and Meraki KBs
bedrock_agent_runtime_client = boto3.client('bedrock-agent-runtime') 


def load_config(config_file: Union[Path, str]) -> Optional[Dict]:
    """
    Load configuration from a local file.

    :param config_file: Path to the local file
    :return: Dictionary with the loaded configuration
    """
    try:
        config_data: Optional[Dict] = None
        logger.info(f"Loading config from local file system: {config_file}")
        content = Path(config_file).read_text()
        config_data = yaml.safe_load(content)
        logger.info(f"Loaded config from local file system: {config_data}")
    except Exception as e:
        logger.error(f"Error loading config from local file system: {e}")
        config_data = None
    return config_data

def create_s3_bucket_for_kb(s3_bucket_name: str, region: str) -> bool:
    """
    Create an S3 bucket for the knowledge base and verify its existence

    Args:
        s3_bucket_name (str): Name of the S3 bucket to create
        region (str): AWS region where the bucket should be created
    
    Returns:
        bool: True if bucket exists and is accessible, False otherwise
    """
    try:
        # First try to check if bucket exists
        try:
            s3_bucket_exists: bool = False
            s3_client.head_bucket(Bucket=s3_bucket_name)
            logger.info(f"Bucket {s3_bucket_name} already exists and is accessible")
            s3_bucket_exists=True
        except ClientError as e:
            if e.response['Error']['Code'] != '404':
                logger.error(f"Error checking bucket existence: {str(e)}")
                return s3_bucket_exists
        # Bucket doesn't exist, create it
        logger.info(f"Creating S3 bucket {s3_bucket_name} in region {region}")
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=s3_bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=s3_bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                }
            )   
        # Verify the bucket was created successfully by checking it exists
        s3_client.head_bucket(Bucket=s3_bucket_name)
        logger.info(f"Successfully created and verified S3 bucket {s3_bucket_name}")
        s3_bucket_exists=True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'BucketAlreadyOwnedByYou':
            logger.info(f"Bucket {s3_bucket_name} already exists and is owned by you")
            s3_bucket_exists=True
        elif error_code == 'BucketAlreadyExists':
            logger.error(f"Bucket {s3_bucket_name} already exists but is owned by another account")
        else:
            logger.error(f"Error creating/verifying S3 bucket: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error creating/verifying S3 bucket: {str(e)}")
    return s3_bucket_exists

def upload_file_to_s3(file_path, bucket_name):
    """
    Upload a single file to S3 bucket
    """
    # Get the filename from the path
    file_name = os.path.basename(file_path)
    try:
        logger.info(f"Uploading file {file_name} to bucket {bucket_name}")
        s3_client.upload_file(file_path, bucket_name, file_name)
        logger.info(f"Successfully uploaded {file_name}")
    except Exception as e:
        logger.info(f"Error uploading file: {str(e)}")
        raise

def make_msg(role, text):
    return {
        "role": role,
        "content": [{"text": text}]
    }

def inference(model, messages, inference_config, system_prompt):
    """
    Simple call using AWS Bedrock Converse API
    
    Args:
        model: boto3 bedrock-runtime client
        messages: List of message dicts with role and content
        system_prompt: Optional system prompt string
    
    Returns:
        str: The response text
    """
    try:
        # Simple Converse API call
        bedrock_client = boto3.client('bedrock-runtime')
        response = bedrock_client.converse(
            modelId=model,
            messages=messages,
            system=[{"text": system_prompt}],
            inferenceConfig=inference_config
        )
        
        # Extract the text from response
        print(f"Response from the router model: {response}")
        return response['output']['message']['content'][0]['text']
    except Exception as e:
        return f"Error: {str(e)}"


def create_agentcore_role(agent_name):
    iam_client = boto3.client('iam')
    agentcore_role_name = f'agentcore-{agent_name}-role'
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BedrockPermissions",
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                "Resource": "*"
            },
            {
                "Sid": "ECRImageAccess",
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer"
                ],
                "Resource": [
                    f"arn:aws:ecr:{region}:{account_id}:repository/<your-repo-id>"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogStreams",
                    "logs:CreateLogGroup"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*"
                ]
            },
            {
                "Sid": "ECRTokenAccess",
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken"
                ],
                "Resource": "*"
            },
            {
            "Effect": "Allow",
            "Action": [
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "xray:GetSamplingRules",
                "xray:GetSamplingTargets"
                ],
             "Resource": [ "*" ]
             },
             {
                "Effect": "Allow",
                "Resource": "*",
                "Action": "cloudwatch:PutMetricData",
                "Condition": {
                    "StringEquals": {
                        "cloudwatch:namespace": "bedrock-agentcore"
                    }
                }
            },
            {
                "Sid": "GetAgentAccessToken",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
                ],
                "Resource": [
                  f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default",
                  f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default/workload-identity/{agent_name}-*"
                ]
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
    # Create IAM Role for the Lambda function
    try:
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

        # Pause to make sure role is created
        time.sleep(10)
    except iam_client.exceptions.EntityAlreadyExistsException:
        print("Role already exists -- deleting and creating it again")
        policies = iam_client.list_role_policies(
            RoleName=agentcore_role_name,
            MaxItems=100
        )
        print("policies:", policies)
        for policy_name in policies['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=agentcore_role_name,
                PolicyName=policy_name
            )
        print(f"deleting {agentcore_role_name}")
        iam_client.delete_role(
            RoleName=agentcore_role_name
        )
        print(f"recreating {agentcore_role_name}")
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_role_name
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role

def setup_cognito_user_pool():
    """
    Set up a Cognito User Pool for authentication and authorization
    this uses the cognito idp client and uses a pre configured idp and 
    password. This in a production scenario would be your configured
    IdP that would contain your pool id, client id, and admin configurations
    for username and password for re authentication and using that
    to configure inbound authentication with specific scopes within the agent
    """
    boto_session = Session()
    region = boto_session.region_name
    # Initialize Cognito client
    cognito_client = boto3.client('cognito-idp', region_name=region)
    try:
        # Create User Pool
        logger.info(f"Going to host an agent and for that, creating a user pool...")
        user_pool_response = cognito_client.create_user_pool(
            PoolName='contact_agent_identity_directory',
            Policies={
                'PasswordPolicy': {
                    'MinimumLength': 8
                }
            }
        )
        pool_id = user_pool_response['UserPool']['Id']
        # Create App Client
        logger.info(f"Creating user pool client....")
        app_client_response = cognito_client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName='contactServerPoolClient',
            GenerateSecret=False,
            ExplicitAuthFlows=[
                'ALLOW_USER_PASSWORD_AUTH',
                'ALLOW_REFRESH_TOKEN_AUTH'
            ]
        )
        logger.info(f"Created user pool client: {app_client_response}")
        client_id = app_client_response['UserPoolClient']['ClientId']
        logger.info(f"Created user pool client id: {client_id}")
        # Create User
        logger.info(f"Creating user...")
        cognito_client.admin_create_user(
            UserPoolId=pool_id,
            Username='contact',
            TemporaryPassword='Temp123!',
            MessageAction='SUPPRESS'
        )
        # Set Permanent Password
        cognito_client.admin_set_user_password(
            UserPoolId=pool_id,
            Username='contact',
            Password='MyPassword123!',
            Permanent=True
        )
        # Authenticate User and get Access Token
        auth_response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'contact',
                'PASSWORD': 'MyPassword123!'
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
            'bearer_token': bearer_token,
            'discovery_url':f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"
        }
    except Exception as e:
        print(f"Error: {e}")
        return None


def reauthenticate_user(client_id):
    boto_session = Session()
    region = boto_session.region_name
    # Initialize Cognito client
    cognito_client = boto3.client('cognito-idp', region_name=region)
    # Authenticate User and get Access Token
    auth_response = cognito_client.initiate_auth(
        ClientId=client_id,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': 'contact',
            'PASSWORD': 'MyPassword123!'
        }
    )
    bearer_token = auth_response['AuthenticationResult']['AccessToken']
    return bearer_token


