# this is the file that will be used to contain utility functions for the agents
import boto3
import json
import time
from datetime import datetime
from boto3.session import Session
import botocore
import requests
import os
import time
import logging
import yaml
from textwrap import wrap
from typing import Optional, Dict, Union, List, Tuple, Any
from pathlib import Path
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import sys

# set a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize S3 client
s3_client = boto3.client('s3')
# Initialize the bedrock runtime client. This is used to 
# query search results from the FMC and Meraki KBs
bedrock_agent_runtime_client = boto3.client('bedrock-agent-runtime') 

# initialize the tools that are used and we will keep a track of this in the comprehensive callback handler
tool_use_ids=[]

# callback handlers are functionalities which will allow us to intercept and process
# events live from the agent's execution lifecycle
def comprehensive_callback_handler(**kwargs):
    """
    Enhanced comprehensive callback handler
    This callback handler will output the reasoning text, the data, tools
    being used, the result of the tool call, errors and raw events.
    """
    try:
        # === REASONING EVENTS (Agent's thinking process) ===
        if kwargs.get("reasoning", False):
            if "reasoningText" in kwargs:
                reasoning_text = kwargs['reasoningText']
                logger.debug(f"🧠 REASONING: {reasoning_text}")
                
            if "reasoning_signature" in kwargs:
                logger.debug(f"🔍 REASONING SIGNATURE: {kwargs['reasoning_signature']}")
        
        # === TEXT GENERATION EVENTS ===
        elif "data" in kwargs:
            # Log streamed text chunks from the model (reduce logging)
            if kwargs.get("complete", False):
                logger.debug("Text generation completed")
        
        # === TOOL EVENTS ===
        elif "current_tool_use" in kwargs:
            tool = kwargs["current_tool_use"]
            tool_use_id = tool.get("toolUseId")
            
            if tool_use_id and tool_use_id not in tool_use_ids:
                tool_name = tool.get('name', 'unknown_tool')
                tool_input = tool.get('input', {})
                
                logger.info(f"🔧 USING TOOL: {tool_name}")
                if tool_input and logger.level <= logging.DEBUG:
                    logger.debug(f"📥 TOOL INPUT: {tool_input}")
                tool_use_ids.append(tool_use_id)
        
        # === TOOL RESULTS ===
        elif "tool_result" in kwargs:
            tool_result = kwargs["tool_result"]
            result_content = tool_result.get("content", [])
            
            if logger.level <= logging.DEBUG:
                logger.debug(f"📤 TOOL RESULT: {result_content}")
        
        # === LIFECYCLE EVENTS ===
        elif kwargs.get("init_event_loop", False):
            logger.debug("🔄 Event loop initialized")
            
        elif kwargs.get("start_event_loop", False):
            logger.debug("▶️ Event loop cycle starting")
            
        elif kwargs.get("start", False):
            logger.debug("📝 New cycle started")
            
        elif kwargs.get("complete", False):
            logger.debug("✅ Cycle completed")
            
        elif kwargs.get("force_stop", False):
            reason = kwargs.get("force_stop_reason", "unknown reason")
            logger.warning(f"🛑 Event loop force-stopped: {reason}")
        
        # === MESSAGE EVENTS ===
        elif "message" in kwargs:
            message = kwargs["message"]
            role = message.get("role", "unknown")
            logger.debug(f"📬 New message created: {role}")
        
        # === ERROR EVENTS ===
        elif "error" in kwargs:
            error_info = kwargs["error"]
            logger.error(f"❌ ERROR: {error_info}")

        # === RAW EVENTS (for debugging) ===
        elif "event" in kwargs:
            # Only log raw events in debug mode to prevent spam
            if logger.level <= logging.DEBUG:
                logger.debug(f"🔍 RAW EVENT: {kwargs['event']}")
        
        # === DELTA EVENTS ===
        elif "delta" in kwargs:
            # Only show deltas in debug mode
            if logger.level <= logging.DEBUG:
                logger.debug(f"📊 DELTA: {kwargs['delta']}")
        
        # === CATCH-ALL FOR DEBUGGING ===
        else:
            # Only log unknown events in debug mode
            if logger.level <= logging.DEBUG:
                logger.debug(f"❓ OTHER EVENT: {kwargs}")
    
    except Exception as callback_error:
        # Prevent callback errors from crashing the agent
        logger.error(f"❌ CALLBACK ERROR: {callback_error}")
        pass

def retrieve_kb_chunks(
    query: str,
    kb_id: str,
    number_of_results: int = 5
) -> str:
    """
    Retrieve relevant information from the Amazon Bedrock Knowledge Base using the Retrieve API.
    
    Args:
        query: The user's question or query to search for in the knowledge base
        number_of_results: Number of relevant chunks to retrieve (default: 5)
        
    Returns:
        Retrieved information from the knowledge base as a formatted string
    """
    try:
        print(f"Retrieving knowledge base chunks for query: {query}")
        
        # Initialize the Bedrock Agent Runtime client
        bedrock_agent_runtime = boto3.client('bedrock-agent-runtime')
        
        # Prepare the request payload for the Retrieve API
        request_payload = {
            "retrievalQuery": {
                "text": query
            },
            "retrievalConfiguration": {
                "vectorSearchConfiguration": {
                    "numberOfResults": number_of_results
                }
            }
        }
        
        # Call the Bedrock Knowledge Base Retrieve API
        response = bedrock_agent_runtime.retrieve(
            knowledgeBaseId=kb_id,
            **request_payload
        )
        
        # Extract retrieval results
        retrieval_results = response.get('retrievalResults', [])
        
        logger.info(f"Retrieved {len(retrieval_results)} chunks from knowledge base")
        
        if not retrieval_results:
            return "No relevant information found in the knowledge base for this query."
        
        # Format the retrieved chunks into a readable string
        formatted_results = []
        for i, result in enumerate(retrieval_results, 1):
            # Extract content
            content = result.get('content', {})
            text_content = content.get('text', 'No content available')
            
            # Extract score
            score = result.get('score', 'N/A')
            
            # Extract location/source information
            location = result.get('location', {})
            location_type = location.get('type', 'unknown')
            
            # Get source URI based on location type
            source_uri = 'Unknown source'
            if location_type == 's3':
                source_uri = location.get('s3Location', {}).get('uri', 'Unknown S3 source')
            elif location_type == 'web':
                source_uri = location.get('webLocation', {}).get('url', 'Unknown web source')
            elif location_type == 'confluence':
                source_uri = location.get('confluenceLocation', {}).get('url', 'Unknown Confluence source')
            
            # Extract metadata
            metadata = result.get('metadata', {})
            
            formatted_chunk = f"""
                Chunk {i} (Relevance Score: {score:.4f}):
                Source: {source_uri}
                Location Type: {location_type}
                Content: {text_content}
                Metadata: {json.dumps(metadata, indent=2) if metadata else 'No metadata available'}
                {"="*80}
                """
            formatted_results.append(formatted_chunk)
        
        result = f"""
            Retrieved {len(retrieval_results)} relevant chunks from the knowledge base:

            {''.join(formatted_results)}
            """
        print(f"TOOL OUTPUT FROM THE KB LOOK UP TOOL: {result}")
        print(f"Formatted retrieval result length: {len(result)} characters")
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        error_msg = f"AWS ClientError - {error_code}: {error_message}"
        print(error_msg)
        return f"Unable to retrieve information from knowledge base: {error_msg}"
        
    except Exception as e:
        error_msg = f"Error retrieving from knowledge base: {str(e)}"
        print(error_msg)
        return f"Unable to retrieve information from knowledge base: {str(e)}"

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
                    f"arn:aws:ecr:{region}:{account_id}:repository/{<add-your-repo-name>}"
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
                "Resource": "{<add-your-repo-name>}"
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

from typing import Any, Dict, List

def _normalize_profile(attrs: Dict[str, str]) -> str | None:
    # Prefer custom:profile (Cognito default for custom attrs), fallback to plain profile
    return attrs.get("custom:profile") or attrs.get("profile")

def _as_attr_dict(resp: Dict[str, Any]) -> Dict[str, str]:
    # resp is output of cognito-idp get_user
    return {a["Name"]: a["Value"] for a in resp.get("UserAttributes", [])}

def get_user_via_idp(access_token: str, region: str = "us-west-2") -> Dict[str, Any]:
    """
    Minimal: return sub and profile via Cognito IdP GetUser.
    """
    try:
        import boto3
        idp = boto3.client("cognito-idp", region_name=region)
        resp = idp.get_user(AccessToken=access_token)
        print(f"USER INFORMATION FROM THE GET USER CALL: {resp}")
        attrs = _as_attr_dict(resp)
        return {"sub": attrs.get("sub"), "profile": _normalize_profile(attrs)}
    except Exception as e:
        logger.error(f"Error getting user via IdP: {e}")
        return {"sub": None, "profile": None}

def get_user(access_token: str, region: str = "us-west-2") -> Dict[str, Any]:
    """
    AWS Cognito GetUser API implementation that matches the AWS API specification.
    
    Args:
        access_token: A valid access token that Amazon Cognito issued to the currently signed-in user.
                     Must include a scope claim for aws.cognito.signin.user.admin.
        region: AWS region for the Cognito service
        
    Returns:
        Dictionary containing user information in AWS GetUser API format:
        - Username: The username of the current user
        - UserAttributes: Array of user attributes
        - PreferredMfaSetting: User's preferred MFA setting
        - UserMFASettingList: List of user's MFA settings
        - MFAOptions: MFA options for the user
    """
    try:
        import boto3
        idp = boto3.client("cognito-idp", region_name=region)
        resp = idp.get_user(AccessToken=access_token)
        
        # Transform response to match AWS API specification
        return {
            "Username": resp.get("Username", ""),
            "UserAttributes": resp.get("UserAttributes", []),
            "PreferredMfaSetting": resp.get("PreferredMfaSetting"),
            "UserMFASettingList": resp.get("UserMFASettingList", []),
            "MFAOptions": resp.get("MFAOptions", [])
        }
        
    except ClientError as e:
        logger.error(f"Cognito GetUser API error - {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in GetUser: {e}")
        raise

def fetch_cognito_user_metadata(access_token: str, region: str = "us-west-2") -> Dict[str, Any]:
    """
    Full user record via Cognito IdP GetUser (NOT OIDC userInfo).
    Enhanced to use the new get_user function.
    """
    try:
        user_response = get_user(access_token, region)
        
        # Convert UserAttributes to dict format for easier access
        attrs = {attr["Name"]: attr["Value"] for attr in user_response.get("UserAttributes", [])}

        user_info: Dict[str, Any] = {
            "username": user_response.get("Username", ""),
            "sub": attrs.get("sub"),
            "name": attrs.get("name") or attrs.get("given_name") or attrs.get("preferred_username")
                    or attrs.get("email") or "Unknown User",
            "email": attrs.get("email"),
            "given_name": attrs.get("given_name"),
            "family_name": attrs.get("family_name"),
            "preferred_username": attrs.get("preferred_username"),
            "profile": _normalize_profile(attrs),
            "preferred_mfa_setting": user_response.get("PreferredMfaSetting"),
            "mfa_settings": user_response.get("UserMFASettingList", []),
            "mfa_options": user_response.get("MFAOptions", []),
            # include all custom:* attrs for convenience
            **{k: v for k, v in attrs.items() if k.startswith("custom:")},
            "raw_attributes": attrs,
            "raw_response": user_response
        }
        print(f"Retrieved user metadata - username: {user_info.get('username')}, sub: {user_info.get('sub')}")
        return user_info
    except ClientError as e:
        logger.error(f"Cognito User Pools API error - {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error fetching user metadata: {e}")
        return {}

def extract_user_attributes_from_cognito(user_info: Dict[str, Any],
                                         cognito_mapping: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a configured list of attributes; supports both 'profile' and 'custom:profile'.
    Filters out None/empty values, flattens lists.
    """
    # normalize: expose 'profile' even if only custom:profile exists
    if "profile" not in user_info and "custom:profile" in user_info:
        user_info["profile"] = user_info["custom:profile"]

    selected: List[str] = []
    for attr in cognito_mapping.get("user_attributes", []):
        val = user_info.get(attr)
        if val is None:
            # try the custom: prefix automatically
            if not attr.startswith("custom:"):
                val = user_info.get(f"custom:{attr}")
        if val is None or (isinstance(val, str) and not val.strip()):
            continue
        if isinstance(val, list):
            selected.extend([str(v) for v in val if isinstance(v, (str, int, float)) and str(v).strip()])
        else:
            selected.append(str(val))

    # append groups if present
    groups = user_info.get("cognito:groups")
    if groups:
        if isinstance(groups, list):
            selected.extend([str(g) for g in groups if str(g).strip()])
        else:
            selected.append(str(groups))

    # de-dup while preserving order
    seen = set()
    cleaned = []
    for v in selected:
        if v not in seen:
            seen.add(v)
            cleaned.append(v)

    return {
        "name": user_info.get("name") or user_info.get("email") or "Unknown User",
        "attributes": cleaned
    }

def setup_cognito_user_pool():
    import time, uuid, base64, requests
    import boto3
    from botocore.session import Session as BotoSession
    from botocore.exceptions import ClientError

    session = BotoSession()
    region = session.get_config_variable('region') or 'us-west-2'
    cognito = boto3.client('cognito-idp', region_name=region)

    # 1) Create User Pool
    print(f"Going to create the cognito user pool...")
    pool = cognito.create_user_pool(
        PoolName='agent_identity_directory',
        Policies={'PasswordPolicy': {'MinimumLength': 8}}
    )
    print(f"Created the cognito user pool: {pool}")
    pool_id = pool['UserPool']['Id']

    # 2) Create a Resource Server + scopes for client_credentials
    #    Identifier must look like a URI-ish string; name is friendly.
    rs_identifier = f"https://enterprise-it-agent/{pool_id}"
    try:
        print(f"Going to create the resource server...")
        cognito.create_resource_server(
            UserPoolId=pool_id,
            Identifier=rs_identifier,
            Name='Enterprise IT Agent API',
            Scopes=[
                {'ScopeName': 'read', 'ScopeDescription': 'Read access'},
                {'ScopeName': 'write', 'ScopeDescription': 'Write access'},
            ]
        )
    except cognito.exceptions.ResourceNotFoundException:
        pass
    except ClientError as e:
        if e.response['Error']['Code'] != 'InvalidParameterException':
            raise

    # 3) Create App Client with OAuth enabled + scopes
    print(f"Going to create the cognito user pool client...")
    app = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName='ServerPoolClient',
        GenerateSecret=True,
        AllowedOAuthFlows=['client_credentials'],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[
            f"{rs_identifier}/read",
            f"{rs_identifier}/write",
        ],
        EnableTokenRevocation=True
    )
    client_id = app['UserPoolClient']['ClientId']
    client_secret = app['UserPoolClient']['ClientSecret']
    print(f"Created the app client: {app}")
    # 4) Create hosted domain (globally unique); then wait for DNS
    domain_name = f"enterprise-it-agent-{str(uuid.uuid4())[:8]}"
    cognito.create_user_pool_domain(Domain=domain_name, UserPoolId=pool_id)
    print(f"Created the user pool domain...")
    # 4a) Poll describe_user_pool_domain until it's visible, then probe DNS/HTTPS
    def domain_ready():
        try:
            print(f"Checking if the domain is ready...")
            d = cognito.describe_user_pool_domain(Domain=domain_name)
            return 'DomainDescription' in d and d['DomainDescription'].get('Domain') == domain_name
        except ClientError:
            return False

    # AWS Documentation states: "New custom domains can take up to one hour to propagate"
    # For prefix domains, it's usually much faster (up to 1 minute)
    max_attempts = 180  # up to ~15 minutes with exponential backoff

    for attempt in range(max_attempts):
        if domain_ready():
            try:
                # Check token endpoint instead - it's more reliable for readiness
                r = requests.head(f"https://{domain_name}.auth.{region}.amazoncognito.com/oauth2/token", timeout=10)
                if r.status_code in (200, 400, 405, 501):  # any sane response means DNS is live
                    print(f"✅ Domain is ready after {attempt + 1} attempts ({(attempt * 3) // 60}m {(attempt * 3) % 60}s)")
                    break
            except requests.RequestException as e:
                if attempt % 20 == 0:  # Log progress every ~1 minute
                    elapsed_min = (attempt * 3) // 60
                    elapsed_sec = (attempt * 3) % 60
                    print(f"⏳ Still waiting for domain... {elapsed_min}m {elapsed_sec}s elapsed (attempt {attempt + 1}/{max_attempts})")
                    if attempt == 0:
                        print("💡 AWS Cognito domains can take up to 1 hour to fully propagate")
                pass
        # Exponential backoff with max 10 seconds
        sleep_time = min(3 + (attempt * 0.05), 10)
        time.sleep(sleep_time)
    else:
        print("⚠️  Domain readiness check timed out after 15 minutes, but continuing anyway...")
        print("💡 The domain may still work - AWS Cognito domains can take up to 1 hour to be fully ready")
        print("💡 You can try running the script again later if token retrieval fails")

    # 5) Get token with client_credentials + scopes
    token_url = f"https://{domain_name}.auth.{region}.amazoncognito.com/oauth2/token"
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {'Authorization': f'Basic {basic}', 'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'client_credentials',
        'scope': f"{rs_identifier}/read {rs_identifier}/write"
    }

    # retry loop for transient 5xx after fresh domain
    for i in range(6):
        resp = requests.post(token_url, headers=headers, data=data, timeout=10)
        if resp.status_code == 200:
            token = resp.json()['access_token']
            break
        if resp.status_code >= 500:
            time.sleep(2 ** i)
            continue
        raise RuntimeError(f"Failed to get token: {resp.status_code} - {resp.text}")

    discovery_url = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"

    print(f"Pool id: {pool_id}")
    print(f"Domain name: {domain_name}")
    print(f"Discovery URL: {discovery_url}")
    print(f"Client ID: {client_id}")
    print(f"Client Secret: {client_secret}")
    print(f"Bearer Token: {token}")

    return {
        'pool_id': pool_id,
        'domain_name': domain_name,
        'client_id': client_id,
        'client_secret': client_secret,
        'bearer_token': token,
        'discovery_url': discovery_url
    }



def _calculate_secret_hash(username, client_id, client_secret):
    """Calculate the SECRET_HASH required for Cognito authentication when client has a secret."""
    import hmac
    import hashlib
    import base64

    message = username + client_id
    secret_hash = base64.b64encode(
        hmac.new(
            client_secret.encode(),
            message.encode(),
            digestmod=hashlib.sha256
        ).digest()
    ).decode()
    return secret_hash

def reauthenticate_user(client_id, client_secret=None):
    """
    Reauthenticate user with Cognito, handling both cases with and without client secret.

    Args:
        client_id: Cognito client ID
        client_secret: Optional client secret. If not provided, will attempt discovery.

    Returns:
        Bearer token for authentication
    """
    boto_session = Session()
    region = boto_session.region_name
    cognito_client = boto3.client('cognito-idp', region_name=region)

    username = 'enterprisetestuser'
    password = 'MyPassword123!'

    # First, try without SECRET_HASH
    auth_parameters = {
        'USERNAME': username,
        'PASSWORD': password
    }

    try:
        # Try authentication without SECRET_HASH first
        auth_response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters=auth_parameters
        )
        bearer_token = auth_response['AuthenticationResult']['AccessToken']
        return bearer_token

    except cognito_client.exceptions.NotAuthorizedException as e:
        error_msg = str(e)
        if "SECRET_HASH was not received" in error_msg or "SECRET_HASH" in error_msg:
            # Client requires SECRET_HASH, but we don't have the client secret
            if not client_secret:
                raise Exception(
                    f"Cognito client {client_id} is configured with a secret, but client_secret was not provided. "
                    "You need to provide the client secret to authenticate, or reconfigure the Cognito client "
                    "to not require a secret (set 'Generate client secret' to false in the Cognito console)."
                )

            # Calculate SECRET_HASH and try again
            auth_parameters['SECRET_HASH'] = _calculate_secret_hash(username, client_id, client_secret)

            auth_response = cognito_client.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters=auth_parameters
            )
            bearer_token = auth_response['AuthenticationResult']['AccessToken']
            return bearer_token
        else:
            # Different authentication error, re-raise
            raise

# The ApplyGuardrail request allows customer to pass all their content that should be 
# guarded using their defined Guardrail. The source field should be set to INPUT when the 
# content to evaluated is from a user, typically the LLM prompt. The source should be set to 
# OUTPUT when the model output Guardrail should be enforced, typically an LLM response.
TEXT_UNIT: int = 1000 # characters
LIMIT_TEXT_UNIT: int = 25
bedrock_runtime = boto3.client("bedrock-runtime", region_name=boto3.session.Session().region_name)

def check_severe_violations(violations):
    # When guardrail intervenes either the action on the request is BLOCKED or NONE
    # Here we check how many of the violations lead to blocking the request
    severe_violations = [violation['action']=='BLOCKED' for violation in violations]
    return sum(severe_violations)

def is_policy_assessement_blocked(assessments):
    # While creating the guardrail you could specify multiple types of policies.
    # At the time of assessment all the policies should be checked for potential violations
    # If there is even 1 violation that blocks the request, the entire request is blocked
    blocked = []
    for assessment in assessments:
        if 'topicPolicy' in assessment:
            blocked.append(check_severe_violations(assessment['topicPolicy']['topics']))
        if 'wordPolicy' in assessment:
            if 'customWords' in assessment['wordPolicy']:
                blocked.append(check_severe_violations(assessment['wordPolicy']['customWords']))
            if 'managedWordLists' in assessment['wordPolicy']:
                blocked.append(check_severe_violations(assessment['wordPolicy']['managedWordLists']))
        if 'sensitiveInformationPolicy' in assessment:
            if 'piiEntities' in assessment['sensitiveInformationPolicy']:
                blocked.append(check_severe_violations(assessment['sensitiveInformationPolicy']['piiEntities']))
            if 'regexes' in assessment['sensitiveInformationPolicy']:
                blocked.append(check_severe_violations(assessment['sensitiveInformationPolicy']['regexes']))
        if 'contentPolicy' in assessment:
            blocked.append(check_severe_violations(assessment['contentPolicy']['filters']))
    severe_violation_count = sum(blocked)
    print(f'\033[91m::Guardrail:: {severe_violation_count} severe violations detected\033[0m')
    return severe_violation_count>0

def apply_guardrail(text, text_source_type, guardrail_id, guardrail_version="DRAFT"):
    print(f'\n\n\033[91m::Guardrail:: Applying guardrail with {(len(text)//TEXT_UNIT)+1} text units\033[0m\n')
    response = bedrock_runtime.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion=guardrail_version, 
        source=text_source_type, # can be 'INPUT' or 'OUTPUT'
        content=[{"text": {"text": text}}]
    )
    if response['action'] == 'GUARDRAIL_INTERVENED':
        is_blocked = is_policy_assessement_blocked(response['assessments'])
        alternate_text = ' '.join([output['text'] for output in response['outputs']])
        return is_blocked, alternate_text, response
    else:
        # Return the default response in case of no guardrail intervention
        return False, text, response

def apply_guardrail_full_text(text, text_source_type, guardrail_id, guardrail_version="DRAFT"):
    text_length = len(text)
    filtered_text = ''
    if text_length <= LIMIT_TEXT_UNIT*TEXT_UNIT:
        return apply_guardrail(text, text_source_type, guardrail_id, guardrail_version)
    else:
        # If the text length is greater than the default text unit limits then it's better to chunk the text to avoid throttling.
        for i, chunk in enumerate(wrap(text, LIMIT_TEXT_UNIT*TEXT_UNIT)):
            print(f'::Guardrail::Applying guardrails at chunk {i+1}')
            is_blocked, alternate_text, response = apply_guardrail(chunk, text_source_type, guardrail_id, guardrail_version)
            if is_blocked:
                filtered_text = alternate_text
                break
            # It could be the case that guardrails intervened and anonymized PII in the input text,
            # we can then take the output from guardrails to create filtered text response.
            filtered_text += alternate_text
        return is_blocked, filtered_text, response


# ============================================================================
# CREATE ENHANCED MULTI-AGENT MEMORY ARCHITECTURE
# ============================================================================

from typing import Any, Dict, Tuple

def create_multi_agent_memory_dual_namespaces(
    memory_client,
    memory_name: str,
    region: str,
    memory_execution_role_arn: str,
    actor_id: str,
    session_id: str,
    event_expiry_days: int = 90,
    max_wait: int = 300,
    poll_interval: int = 10,
) -> Tuple[str, Dict[str, Any]]:
    """
    Create a Bedrock AgentCore Memory with TWO scopes:
      1) /global  (per-user, agent-agnostic)
      2) /agents/{agentId} (per-agent)
    Using exactly THREE strategies:
      - UserPreferences
      - SemanticMemory
      - SessionSummaries

    Returns:
        (memory_id, namespace_structure)
    """
    try:
        logger.info(f"Creating dual-namespace memory: {memory_name}")

        # ----- Namespaces -----
        # Global (per-user) scope
        GLOBAL_USER_PREFS     = f"/global/users/{actor_id}/preferences"
        GLOBAL_SEMANTICS      = f"/global/knowledge/{actor_id}/semantics"
        GLOBAL_SEMANTICS_FBK  = "/global/fallback/semantics"  # generic Qs handled by a fallback agent
        GLOBAL_SUMMARIES      = f"/global/summaries/{actor_id}/{session_id}/summaries"

        # Agent-specific scope
        AGENT_PREFS           = "/agents/{agentId}/users/{actorId}/preferences"
        AGENT_SEMANTICS       = "/agents/{agentId}/knowledge/{actorId}/semantics"
        AGENT_SUMMARIES       = "/agents/{agentId}/summaries/{actorId}/{sessionId}/summaries"

        # ----- Three built-in strategies with BOTH scopes -----
        strategies = [
            {
                "userPreferenceMemoryStrategy": {
                    "name": "UserPreferences",
                    "description": "User and agent-level preferences.",
                    "namespaces": [
                        GLOBAL_USER_PREFS,
                        AGENT_PREFS,  # dynamic placeholders supported by AgentCore
                    ],
                }
            },
            {
                "semanticMemoryStrategy": {
                    "name": "SemanticMemory",
                    "description": "Facts/knowledge captured globally and per-agent.",
                    "namespaces": [
                        GLOBAL_SEMANTICS,
                        GLOBAL_SEMANTICS_FBK,   # for generic/fallback-eligible Q&A
                        AGENT_SEMANTICS,
                    ],
                }
            },
            {
                "summaryMemoryStrategy": {
                    "name": "SessionSummaries",
                    "description": "Summaries captured globally and per-agent for routing and recall.",
                    "namespaces": [
                        GLOBAL_SUMMARIES,
                        AGENT_SUMMARIES,
                    ],
                }
            },
        ]

        memory = memory_client.create_memory_and_wait(
            name=memory_name,
            memory_execution_role_arn=memory_execution_role_arn,
            strategies=strategies,
            description=f"Dual-namespace (global + agent) memory for {memory_name}",
            event_expiry_days=event_expiry_days,
            max_wait=max_wait,
            poll_interval=poll_interval,
        )

        memory_id = memory.get("id")
        logger.info(f"✅ Created memory: {memory_id}")

        namespace_structure = {
            "global": {
                "preferences": GLOBAL_USER_PREFS,
                "semantics": GLOBAL_SEMANTICS,
                "fallback_semantics": GLOBAL_SEMANTICS_FBK,
                "summaries": GLOBAL_SUMMARIES,
            },
            "agent": {
                "base": "/agents/{agentId}",
                "preferences": AGENT_PREFS,
                "semantics": AGENT_SEMANTICS,
                "summaries": AGENT_SUMMARIES,
            },
            "placeholders": {"agentId": "{agentId}", "actorId": "{actorId}", "sessionId": "{sessionId}"},
        }

        return memory_id, namespace_structure

    except Exception as e:
        logger.error(f"Failed to create memory: {e}")
        raise


def setup_memory_enabled_agent(
    memory_id: str,
    actor_id: str,
    session_id: str,
    namespace: str,
    system_prompt: str,
    model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    aws_region: Optional[str] = None
):
    """
    Set up an agent with memory capabilities using AgentCoreMemoryToolProvider.
    
    Args:
        memory_id: ID of the memory instance
        actor_id: Actor ID for the session
        session_id: Session ID
        namespace: Namespace for memory operations
        system_prompt: System prompt for the agent
        model_id: Model ID to use (default: Claude 3.5 Sonnet)
        aws_region: AWS region (uses session default if not provided)
        
    Returns:
        Configured Agent instance with memory tools
    """
    try:
        from strands import Agent
        from strands.models import BedrockModel
        from strands_tools.agent_core_memory import AgentCoreMemoryToolProvider
        
        if not aws_region:
            aws_region = boto3.session.Session().region_name
            
        logger.info(f"Setting up memory-enabled agent with memory_id: {memory_id}")
        
        # Create memory tool provider
        provider = AgentCoreMemoryToolProvider(
            memory_id=memory_id,
            actor_id=actor_id,
            session_id=session_id,
            namespace=namespace
        )
        
        # Create model
        model = BedrockModel(
            model_id=model_id,
            aws_region=aws_region
        )
        
        # Create agent with memory tools
        agent = Agent(
            tools=provider.tools,
            model=model,
            system_prompt=system_prompt
        )
        
        logger.info(f"✅ Created memory-enabled agent with {len(provider.tools)} memory tools")
        return agent
        
    except Exception as e:
        logger.error(f"Failed to setup memory-enabled agent: {e}")
        raise


def hydrate_memory_with_conversation(
    memory_client,
    memory_id: str,
    actor_id: str,
    session_id: str,
    conversation_messages: List[Dict[str, str]]
) -> bool:
    """
    Hydrate memory with initial conversation messages.
    
    Args:
        memory_client: MemoryClient instance
        memory_id: ID of the memory instance
        actor_id: Actor ID
        session_id: Session ID
        conversation_messages: List of conversation messages with 'role' and 'content'
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Hydrating memory {memory_id} with {len(conversation_messages)} messages")
        
        for message in conversation_messages:
            role = message.get('role', 'USER').upper()
            content = message.get('content', '')
            
            if not content:
                continue
            print(f"🔍 DEBUG [utils.py]: Creating memory event - memory_id: {memory_id}, actor_id: {actor_id}, session_id: {session_id}")
            print(f"🔍 DEBUG [utils.py]: Creating memory event with content: {content[:100]}..." if len(content) > 100 else f"🔍 DEBUG [utils.py]: Creating memory event with content: {content}")

            # Convert to the new messages format
            memory_client.create_event(
                memory_id=memory_id,
                actor_id=actor_id,
                session_id=session_id,
                messages=[(content, role)]
            )
            print(f"🔍 DEBUG [utils.py]: Successfully created memory event for role: {role}")
        logger.info(f"✅ Successfully hydrated memory with conversation history")
        return True
        
    except Exception as e:
        logger.error(f"Failed to hydrate memory: {e}")
        return False


def retrieve_memory_context(
    memory_client,
    memory_id: str,
    actor_id: str,
    query: str,
    session_id: str = None,
    max_results: int = 5,
    user_id: str = None
) -> Dict[str, List[Dict]]:
    """
    Retrieve relevant context from different memory strategies using RetrieveMemoryRecords API.

    Args:
        memory_client: MemoryClient instance
        memory_id: ID of the memory instance
        actor_id: Actor ID (for backward compatibility)
        query: Search query
        session_id: Session ID for summary retrieval
        max_results: Maximum results per strategy
        user_id: User ID for memory namespaces (preferred over actor_id)

    Returns:
        Dictionary with results from different memory strategies
    """
    import re

    try:
        logger.info(f"Retrieving memory context for query: {query}")

        # Use user_id if provided, otherwise fall back to actor_id
        effective_user_id = user_id or actor_id
        logger.info(f"Using effective_user_id: {effective_user_id}")

        # Sanitizer that preserves only allowed chars for namespaces
        sanitize = lambda s: re.sub(r'[^A-Za-z0-9/_\-\*]', '_', s or '')

        context = {
            'preferences': [],
            'semantics': [],
            'summaries': []
        }

        # Build namespaces to match what was created in create_simple_orchestrator_memory
        # The namespaces are: /{actor_id}/preferences, /{actor_id}/semantics, /{actor_id}/summaries/{sessionId}
        pref_namespace = f"/{sanitize(effective_user_id)}/preferences"
        sem_namespace = f"/{sanitize(effective_user_id)}/semantics"

        # For summaries: single session or all sessions
        if session_id:
            summary_namespace = f"/{sanitize(effective_user_id)}/summaries/{sanitize(session_id)}"
        else:
            summary_namespace = f"/{sanitize(effective_user_id)}/summaries/*"

        logger.info(f"Using namespaces - Pref: {pref_namespace}, Sem: {sem_namespace}, Sum: {summary_namespace}")

        # Strip quotes from query if present
        clean_query = query.strip('\'"')

        # Retrieve user preferences using new API
        try:
            print(f"🔍 DEBUG [utils.py]: Retrieving user preferences from namespace: {pref_namespace}")
            print(f"🔍 DEBUG [utils.py]: Using memory_id: {memory_id}")
            print(f"🔍 DEBUG [utils.py]: Using query: '{clean_query}'")

            # Use RetrieveMemoryRecords API
            pref_resp = memory_client.retrieve_memory_records(
                memoryId=memory_id,
                namespace=pref_namespace,
                searchCriteria={
                    'searchQuery': clean_query,
                    'topK': max_results
                }
            )

            print(f"🔍 DEBUG [utils.py]: Preferences response type: {type(pref_resp)}")
            print(f"🔍 DEBUG [utils.py]: Preferences response: {json.dumps(pref_resp, indent=2, default=str)}")

            # Extract memory content from the new API response format
            pref_context = []
            memories = pref_resp.get('memoryRecords', [])
            for memory in memories:
                if isinstance(memory, dict):
                    # New API format has 'summary' field
                    text = memory.get('summary', '').strip()
                    if text:
                        pref_context.append(text)
            context['preferences'] = pref_context
            print(f"Retrieved {len(pref_context)} user preferences from LTM")
        except Exception as e:
            logger.warning(f"Failed to retrieve preferences: {e}")
            print(f"🔍 DEBUG [utils.py]: Exception in preferences retrieval: {e}")
            import traceback
            traceback.print_exc()

        # Retrieve session summaries using new API
        try:
            print(f"🔍 DEBUG [utils.py]: Retrieving session summaries from namespace: {summary_namespace}")
            print(f"🔍 DEBUG [utils.py]: Using memory_id: {memory_id}")
            print(f"🔍 DEBUG [utils.py]: Using query: '{clean_query}'")

            # Use RetrieveMemoryRecords API
            summary_resp = memory_client.retrieve_memory_records(
                memoryId=memory_id,
                namespace=summary_namespace,
                searchCriteria={
                    'searchQuery': clean_query,
                    'topK': max_results
                }
            )

            print(f"🔍 DEBUG [utils.py]: Summaries response type: {type(summary_resp)}")
            print(f"🔍 DEBUG [utils.py]: Summaries response: {json.dumps(summary_resp, indent=2, default=str)}")

            summary_context = []
            memories = summary_resp.get('memoryRecords', [])
            for memory in memories:
                if isinstance(memory, dict):
                    # New API format has 'summary' field
                    text = memory.get('summary', '').strip()
                    if text:
                        summary_context.append(text)
            context['summaries'] = summary_context
            print(f"Retrieved {len(summary_context)} session summaries from LTM")
        except Exception as e:
            logger.warning(f"Failed to retrieve summaries: {e}")
            print(f"🔍 DEBUG [utils.py]: Exception in summaries retrieval: {e}")
            import traceback
            traceback.print_exc()

        # Retrieve semantic memories using new API
        try:
            print(f"🔍 DEBUG [utils.py]: Retrieving from semantic namespace: {sem_namespace}")
            print(f"🔍 DEBUG [utils.py]: Using clean query: '{clean_query}'")

            # Use RetrieveMemoryRecords API
            sem_resp = memory_client.retrieve_memory_records(
                memoryId=memory_id,
                namespace=sem_namespace,
                searchCriteria={
                    'searchQuery': clean_query,
                    'topK': max_results
                }
            )

            print(f"🔍 DEBUG [utils.py]: Raw semantic response type: {type(sem_resp)}")
            print(f"🔍 DEBUG [utils.py]: Raw semantic response: {json.dumps(sem_resp, indent=2, default=str)}")

            # Extract memory content from the new API response format
            sem_context = []
            memories = sem_resp.get('memoryRecords', [])
            print(f"🔍 DEBUG [utils.py]: Processing {len(memories)} semantic memories")

            for i, memory in enumerate(memories):
                print(f"🔍 DEBUG [utils.py]: Processing semantic memory {i+1}: {json.dumps(memory, indent=2, default=str)}")
                if isinstance(memory, dict):
                    # New API format has 'summary' field
                    text = memory.get('summary', '').strip()
                    print(f"🔍 DEBUG [utils.py]: Memory summary: {text}")
                    if text:
                        sem_context.append(text)
                        print(f"🔍 DEBUG [utils.py]: Added text to context: {text[:100]}...")

            context['semantics'] = sem_context
            print(f"🔍 DEBUG [utils.py]: Final semantic context: {sem_context}")

        except Exception as e:
            logger.warning(f"Failed to retrieve semantics: {e}")
            print(f"🔍 DEBUG [utils.py]: Exception in semantic retrieval: {e}")
            import traceback
            traceback.print_exc()

        logger.info(f"Retrieved {len(context['preferences'])} preferences, "
                   f"{len(context['semantics'])} semantics, "
                   f"{len(context['summaries'])} summaries")

        return context

    except Exception as e:
        logger.error(f"Failed to retrieve memory context: {e}")
        return {'preferences': [], 'semantics': [], 'summaries': []}


import re
from typing import Dict, Any, Optional, List

STOPWORDS = {
    "a","an","the","and","or","of","for","to","in","on","with","by","is","are","be","as","at","from","this","that","it"
}

def _tokens(s: str) -> List[str]:
    s = re.sub(r"[^\w\s]", " ", s.lower())  # strip punctuation (hyphens etc.)
    toks = [t for t in s.split() if t and t not in STOPWORDS]
    return toks

def _quality_gate(text: str, min_chars: int = 15, min_tokens: int = 3, max_punct_ratio: float = 0.15) -> bool:
    if not text:
        return False
    punct = sum(1 for c in text if not c.isalnum() and not c.isspace())
    punct_ratio = punct / max(1, len(text))
    toks = _tokens(text)
    if len(text.strip()) < min_chars: return False
    if len(toks) < min_tokens: return False
    if len(set(toks)) < 2: return False
    if punct_ratio > max_punct_ratio: return False
    return True

def _lexical_overlap_ok(user_text: str, agent_text: str, agent_tags: List[str], min_overlap: int = 1) -> bool:
    u = set(_tokens(user_text))
    a = set(_tokens(agent_text))
    for t in agent_tags or []:
        a.update(_tokens(t))
    return len(u & a) >= min_overlap