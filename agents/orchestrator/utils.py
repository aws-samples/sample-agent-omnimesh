# this is the file that will be used to contain utility functions for the agents
import boto3
import json
import time
import base64
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
from langchain_community.embeddings import BedrockEmbeddings
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

def extract_prompt(task) -> str:
    """
    Flatten whatever the graph gives you into one prompt string.
    - If it's already a string, return it.
    - If it's a dict with 'text', return that.
    - If it's a list, recurse and join.
    - Else, str() fallback.
    """
    if isinstance(task, str):
        return task
    if isinstance(task, dict) and "text" in task:
        return task["text"]
    if isinstance(task, list):
        parts = []
        for elem in task:
            parts.append(extract_prompt(elem))
        return "".join(parts)
    return str(task)

def save_verdict_to_file(self, verdict_data: Dict[str, Any], file_name_prefix: str) -> str:
        """Save verdict and response to a JSON file with timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"{file_name_prefix}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(verdict_data, f, indent=2)
        
        print(f"Verdict=yes response saved to: {filename}")
        return str(filename)
    
def extract_json_quick(task):
    """Extract JSON from task"""
    # collapse list of dicts like [{'text': '...'}] to one string
    txt = "\n".join(d.get("text", str(d)) if isinstance(d, dict) else str(d)
                   for d in (task if isinstance(task, list) else [task]))

    # Try to find JSON with "Agent:" prefix first (backward compatibility)
    m = re.search(r'Agent:\s*(\{.*\})', txt, re.DOTALL)
    if m:
        return json.loads(m.group(1))

    # If no "Agent:" prefix, look for any JSON object in the text
    m = re.search(r'(\{.*\})', txt, re.DOTALL)
    if m:
        return json.loads(m.group(1))

    # If no JSON found, try to parse the entire text as JSON
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        raise ValueError(f"JSON block not found in task: {txt}")

# Utility function for consistent JSON handling
def format_output(data):
    """
    Format output consistently - JSON objects as pretty-printed JSON, strings as strings.
    
    Args:
        data: The data to format (dict, list, str, or any other type)
        
    Returns:
        tuple: (formatted_string, is_json_data)
    """
    if isinstance(data, (dict, list)):
        # It's JSON data - pretty print it
        return json.dumps(data, indent=2, ensure_ascii=False), True
    elif isinstance(data, str):
        # Try to parse as JSON first
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2, ensure_ascii=False), True
        except json.JSONDecodeError:
            # It's a plain string - return as is
            return data, False
    else:
        # Other types - convert to string
        return str(data), False

def extract_user_response_message(gateway_response: Any) -> str:
    """
    Extract the clean response message from the nested gateway response structure.

    Args:
        gateway_response: The response from the gateway tool invocation

    Returns:
        str: The clean response message for the user
    """
    try:
        logger.info(f"Extracting user response from gateway response...")

        # Handle the full jsonrpc response structure
        if isinstance(gateway_response, dict):
            # Check for jsonrpc response format
            if 'result' in gateway_response:
                result = gateway_response['result']
                if isinstance(result, dict) and 'content' in result:
                    content = result['content']
                    if isinstance(content, list) and len(content) > 0:
                        first_content = content[0]
                        if isinstance(first_content, dict) and 'text' in first_content:
                            text_content = first_content['text']
                            # Parse the JSON string to extract response_message
                            try:
                                parsed_content = json.loads(text_content)
                                response_message = parsed_content.get('response_message')
                                if response_message:
                                    logger.info(f"Successfully extracted response message")
                                    return response_message
                                else:
                                    logger.warning("No response_message found in parsed content")
                                    return text_content
                            except json.JSONDecodeError as e:
                                logger.warning(f"Could not parse text content as JSON: {e}")
                                return text_content
                        else:
                            return str(first_content)
                    else:
                        return str(content)
                else:
                    return str(result)
            else:
                return str(gateway_response)

        # Handle list format (backward compatibility)
        elif isinstance(gateway_response, list) and len(gateway_response) > 0:
            content = gateway_response[0]
            if isinstance(content, dict) and 'text' in content:
                text_content = content['text']
                try:
                    parsed_content = json.loads(text_content)
                    response_message = parsed_content.get('response_message', text_content)
                    return response_message
                except json.JSONDecodeError:
                    return text_content
            else:
                return str(content)

        # Fallback to string conversion
        return str(gateway_response)

    except Exception as e:
        logger.error(f"Error extracting response message: {e}")
        return str(gateway_response)


def extract_response_data(gateway_response: Any) -> Tuple[str, str]:
    """
    Extract both response_message and response_type from gateway response.

    Args:
        gateway_response: The response from the gateway tool invocation

    Returns:
        Tuple[str, str]: (response_message, response_type)
    """
    response_type = 'out_of_scope'  # Default fallback
    response_message = str(gateway_response)  # Default fallback

    try:
        # Navigate through JSON-RPC structure: gateway_response['result']['content'][0]['text']
        if isinstance(gateway_response, dict) and 'result' in gateway_response:
            result = gateway_response.get('result', {})
            content_array = result.get('content', [])
            if content_array and len(content_array) > 0:
                first_content = content_array[0]
                if isinstance(first_content, dict) and 'text' in first_content:
                    inner_json_str = first_content['text']
                    # Parse the inner JSON to get the actual response_type
                    inner_json = json.loads(inner_json_str)
                    response_type = inner_json.get('response_type', 'text')
                    response_message = inner_json.get('response_message', inner_json_str)
        # Fallback for old format (if gateway_response is directly the content array)
        elif isinstance(gateway_response, list) and len(gateway_response) > 0:
            content = gateway_response[0]
            if isinstance(content, dict) and 'text' in content:
                text_content = content['text']
                parsed_content = json.loads(text_content)
                response_message = parsed_content.get('response_message', text_content)
                response_type = parsed_content.get('response_type', 'text')
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        logger.warning(f"Error extracting response data from JSON structure: {e}")
        # Keep default values

    return response_message, response_type


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
                print(f"🧠 REASONING: {reasoning_text}")
                
            if "reasoning_signature" in kwargs:
                print(f"🔍 REASONING SIGNATURE: {kwargs['reasoning_signature']}")
        
        # === TEXT GENERATION EVENTS ===
        elif "data" in kwargs:
            # Log streamed text chunks from the model (reduce logging)
            if kwargs.get("complete", False):
                print("Text generation completed")
        
        # === TOOL EVENTS ===
        elif "current_tool_use" in kwargs:
            tool = kwargs["current_tool_use"]
            tool_use_id = tool.get("toolUseId")
            
            if tool_use_id and tool_use_id not in tool_use_ids:
                tool_name = tool.get('name', 'unknown_tool')
                tool_input = tool.get('input', {})
                
                print(f"🔧 USING TOOL: {tool_name}")
                if tool_input and logger.level <= logging.DEBUG:
                    print(f"📥 TOOL INPUT: {tool_input}")
                tool_use_ids.append(tool_use_id)
        
        # === TOOL RESULTS ===
        elif "tool_result" in kwargs:
            tool_result = kwargs["tool_result"]
            result_content = tool_result.get("content", [])
            
            if logger.level <= logging.DEBUG:
                print(f"📤 TOOL RESULT: {result_content}")
        
        # === LIFECYCLE EVENTS ===
        elif kwargs.get("init_event_loop", False):
            print("🔄 Event loop initialized")
            
        elif kwargs.get("start_event_loop", False):
            print("▶️ Event loop cycle starting")
            
        elif kwargs.get("start", False):
            logger.debug("📝 New cycle started")
            
        elif kwargs.get("complete", False):
            logger.debug("✅ Cycle completed")
            
        elif kwargs.get("force_stop", False):
            reason = kwargs.get("force_stop_reason", "unknown reason")
            print(f"🛑 Event loop force-stopped: {reason}")
        
        # === MESSAGE EVENTS ===
        elif "message" in kwargs:
            message = kwargs["message"]
            role = message.get("role", "unknown")
            print(f"📬 New message created: {role}")
        
        # === ERROR EVENTS ===
        elif "error" in kwargs:
            error_info = kwargs["error"]
            print(f"❌ ERROR: {error_info}")

        # === RAW EVENTS (for debugging) ===
        elif "event" in kwargs:
            # Only log raw events in debug mode to prevent spam
            if logger.level <= logging.DEBUG:
                print(f"🔍 RAW EVENT: {kwargs['event']}")
        
        # === DELTA EVENTS ===
        elif "delta" in kwargs:
            # Only show deltas in debug mode
            if logger.level <= logging.DEBUG:
                print(f"📊 DELTA: {kwargs['delta']}")
        
        # === CATCH-ALL FOR DEBUGGING ===
        else:
            # Only log unknown events in debug mode
            if logger.level <= logging.DEBUG:
                print(f"❓ OTHER EVENT: {kwargs}")
    
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


def save_config(config_data: Dict, config_file: Union[Path, str]) -> bool:
    """
    Save configuration to a local file.

    :param config_data: Dictionary with the configuration data
    :param config_file: Path to the local file
    :return: True if successful, False otherwise
    """
    try:
        logger.info(f"Saving config to local file system: {config_file}")
        content = yaml.safe_dump(config_data, default_flow_style=False, indent=2)
        Path(config_file).write_text(content)
        logger.info(f"Successfully saved config to: {config_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving config to local file system: {e}")
        return False

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

def get_access_token(client_credentials: Dict) -> Optional[str]:
    """
    This function uses the client credentials (discovery URL, client secret and client id) to
    fetch an access token using OAuth2 client credentials flow
    """
    try:
        # In this case, we use the gateway inbound authentication information
        # to get details to access the agents through gateway -> the outbound authentication information
        # is already configured within agentcore
        discovery_url = client_credentials.get('discovery_url')
        client_id = client_credentials.get('client_id')
        client_secret = client_credentials.get('client_secret')
        custom_scope = client_credentials.get('custom_scope')

        if not all([discovery_url, client_id, client_secret]):
            raise ValueError("Missing required client credentials: discovery_url, client_id, or client_secret")

        # OAuth2 client credentials flow
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        auth_header = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        token_url = discovery_url.replace("/.well-known/openid-configuration", "/oauth2/token")

        data = {
            "grant_type": "client_credentials",
        }

        if custom_scope:
            data["scope"] = custom_scope

        response = requests.post(token_url, data=data, headers=auth_header)
        response.raise_for_status()

        token_data = response.json()
        access_token = token_data.get("access_token")
        print(f"Access token response data: {access_token}")

        if not access_token:
            raise ValueError(f"access_token not found in response. Available keys: {list(token_data.keys())}")
        return access_token

    except Exception as e:
        print(f"An error occurred while getting the access token: {e}")
        raise e

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
    Fetch user metadata from config file instead of Cognito.
    This function reads the user_metadata section from config.yaml.

    Args:
        access_token: Access token (not used, kept for compatibility)
        region: AWS region (not used, kept for compatibility)

    Returns:
        Dictionary containing user metadata from config file
    """
    try:
        logger.info("Fetching user metadata from config file")

        # Load config file
        config_path = Path(__file__).parent / "config.yaml"
        config_data = load_config(config_path)

        if not config_data or "user_metadata" not in config_data:
            logger.warning("No user_metadata found in config file")
            return {
                "username": "enterprisetestuser",
                "provided_context": {
                    "product": {"name": "Unknown"}
                }
            }

        user_metadata = config_data["user_metadata"]

        # Add username for compatibility with Streamlit app
        user_metadata["username"] = "enterprisetestuser"

        logger.info(f"Successfully loaded user metadata from config")
        logger.debug(f"User metadata: {user_metadata}")

        return user_metadata

    except Exception as e:
        logger.error(f"Error fetching user metadata from config: {e}")
        # Return fallback metadata
        return {
            "username": "testuser",
            "provided_context": {
                "product": {"name": "Unknown"}
            }
        }


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
            PoolName='agent_identity_directory',
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
            ClientName='ServerPoolClient',
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
            Username='enterprisetestuser',
            TemporaryPassword='Temp123!',
            MessageAction='SUPPRESS'
        )
        # Set Permanent Password
        cognito_client.admin_set_user_password(
            UserPoolId=pool_id,
            Username='enterprisetestuser',
            Password='MyPassword123!',
            Permanent=True
        )
        # Authenticate User and get Access Token
        auth_response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'enterprisetestuser',
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

        for i, message in enumerate(conversation_messages):
            # Validate message structure
            if not isinstance(message, dict):
                logger.warning(f"Skipping invalid message {i}: {type(message)}")
                continue

            role = message.get('role', 'USER').upper()
            content = message.get('content', '')

            # Handle nested content structures
            if isinstance(content, list) and len(content) > 0:
                content = content[0].get('text', '') if isinstance(content[0], dict) else str(content[0])
            elif isinstance(content, dict):
                content = content.get('text', '')

            # Convert to string and strip whitespace
            content = str(content).strip()

            # More robust validation - check for minimum content length
            if not content or len(content) == 0 or len(content.strip()) == 0:
                logger.warning(f"Skipping empty message {i} with role: {role}")
                continue

            # Additional validation to ensure content meets minimum requirements
            if len(content.strip()) < 1:
                logger.warning(f"Skipping message {i} with insufficient content length: {len(content)} chars")
                continue

            logger.info(f"Processing message {i} - Role: {role}, Content length: {len(content)}")
            logger.debug(f"Content preview: '{content[:50]}...'")

            print(f"Creating a memory event using the content: {content} with memory id {memory_id}")

            # Convert to the new messages format with additional safety check
            try:
                memory_client.create_event(
                    memory_id=memory_id,
                    actor_id=actor_id,
                    session_id=session_id,
                    messages=[(content, role)]
                )
            except Exception as event_error:
                logger.error(f"Failed to create memory event for message {i}: {event_error}")
                # Don't fail the entire process for one bad message, just skip it
                continue
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
    user_id: str = None,
    tool_name: str = None
) -> Dict[str, List[str]]:
    """
    Retrieve relevant context from different memory strategies.
    
    Args:
        memory_client: MemoryClient instance
        memory_id: ID of the memory instance
        actor_id: Actor ID (for backward compatibility)
        query: Search query
        session_id: Session ID for summary retrieval
        max_results: Maximum results per strategy
        user_id: User ID for memory namespaces (preferred over actor_id)
        tool_name: Tool name for tool-specific preferences namespace

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
        # Build namespaces using the sanitized user_id
        # Global preferences namespace
        global_pref_namespace = f"/{sanitize(effective_user_id)}/preferences/global"
        # Tool-specific preferences namespace (only if tool_name is provided)
        tool_pref_namespace = f"/{sanitize(effective_user_id)}/preferences/{sanitize(tool_name)}" if tool_name else None
        sem_namespace = f"/{sanitize(effective_user_id)}/semantics"
        # For summaries: single session or all sessions
        if session_id:
            summary_namespace = f"/{sanitize(effective_user_id)}/{sanitize(session_id)}/summaries"
        else:
            summary_namespace = f"/{sanitize(effective_user_id)}/*/summaries"
        
        logger.info(f"Using namespaces - Global Pref: {global_pref_namespace}, Tool Pref: {tool_pref_namespace}, Sem: {sem_namespace}, Sum: {summary_namespace}")
        # Strip quotes from query if present
        clean_query = query.strip('\'"')
        # Retrieve user preferences (global + tool-specific)
        pref_context = []

        # 1. Always retrieve global preferences
        try:
            print(f"Going to retrieve global preferences from namespace: {global_pref_namespace}")
            global_pref_resp = memory_client.retrieve_memories(
                memory_id=memory_id,
                namespace=global_pref_namespace,
                query=clean_query
            )
            for memory in global_pref_resp:
                if isinstance(memory, dict):
                    content = memory.get('content', {})
                    if isinstance(content, dict):
                        text = content.get('text', '').strip()
                        if text:
                            pref_context.append(text)
            print(f"Retrieved {len(pref_context)} global preferences from LTM")
        except Exception as e:
            logger.warning(f"Failed to retrieve global preferences: {e}")

        # 2. Retrieve tool-specific preferences if tool_name is provided
        if tool_pref_namespace:
            try:
                print(f"Going to retrieve tool-specific preferences from namespace: {tool_pref_namespace}")
                tool_pref_resp = memory_client.retrieve_memories(
                    memory_id=memory_id,
                    namespace=tool_pref_namespace,
                    query=clean_query
                )
                tool_pref_count = 0
                for memory in tool_pref_resp:
                    if isinstance(memory, dict):
                        content = memory.get('content', {})
                        if isinstance(content, dict):
                            text = content.get('text', '').strip()
                            if text:
                                pref_context.append(text)
                                tool_pref_count += 1
                print(f"Retrieved {tool_pref_count} tool-specific preferences from LTM")
            except Exception as e:
                logger.warning(f"Failed to retrieve tool-specific preferences: {e}")

        context['preferences'] = pref_context
        # Retrieve session summaries
        try:
            print(f"Going to retrieve session summaries from namespace: {summary_namespace}")
            summary_resp = memory_client.retrieve_memories(
                memory_id=memory_id,
                namespace=summary_namespace, 
                query=clean_query
            )
            summary_context = []
            for memory in summary_resp:
                if isinstance(memory, dict):
                    content = memory.get('content', {})
                    if isinstance(content, dict):
                        text = content.get('text', '').strip()
                        if text:
                            summary_context.append(text)
            context['summaries'] = summary_context
            print(f"Retrieved {len(summary_context)} session summaries from LTM")
        except Exception as e:
            logger.warning(f"Failed to retrieve summaries: {e}")
        # Retrieve semantic memories
        try:
            print(f"🔍 DEBUG [utils.py]: Retrieving from semantic namespace: {sem_namespace}")
            print(f"🔍 DEBUG [utils.py]: Using clean query: '{clean_query}'")
            
            sem_resp = memory_client.retrieve_memories(
                memory_id=memory_id,
                namespace=sem_namespace, 
                query=clean_query
            )
            
            print(f"🔍 DEBUG [utils.py]: Raw semantic response type: {type(sem_resp)}")
            print(f"🔍 DEBUG [utils.py]: Raw semantic response: {json.dumps(sem_resp, indent=2, default=str)}")
            # Extract memory content  
            sem_context = []
            if isinstance(sem_resp, list):
                print(f"🔍 DEBUG [utils.py]: Processing {len(sem_resp)} semantic memories")
                for i, memory in enumerate(sem_resp):
                    print(f"🔍 DEBUG [utils.py]: Processing semantic memory {i+1}: {json.dumps(memory, indent=2, default=str)}")
                    if isinstance(memory, dict):
                        content = memory.get('content', {})
                        print(f"🔍 DEBUG [utils.py]: Memory content: {content}")
                        if isinstance(content, dict):
                            text = content.get('text', '').strip()
                            if text:
                                sem_context.append(text)
                                print(f"🔍 DEBUG [utils.py]: Added text to context: {text[:100]}...")
                        elif isinstance(content, str):
                            # Handle case where content is directly a string
                            if content.strip():
                                sem_context.append(content.strip())
                                print(f"🔍 DEBUG [utils.py]: Added direct string to context: {content[:100]}...")
            else:
                print(f"🔍 DEBUG [utils.py]: Semantic response is not a list: {sem_resp}")
                
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

def load_agent_mapping_from_policy_table(table_name: str) -> List[Tuple[str, List[str]]]:
    """
    Load agent mappings from a DynamoDB table.

    Args:
        table_name: Name of the DynamoDB table containing agent mappings
        region: AWS region for DynamoDB client

    Returns:
        List of tuples containing (user_agent, [enabled_agents])
    """
    try:
        # this is the dynamo db table that contains the users and the list of enabled agents for the users
        # this function provides of list of those.
        dynamodb = boto3.resource('dynamodb', region_name=boto3.session.Session().region_name)
        table = dynamodb.Table(table_name)
        print(f"Loading agent mappings from table: {table_name}")
        # Scanning the elements in the table and getting the items from the table
        response = table.scan()
        items = response.get('Items', [])
        # Handle pagination if needed
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response.get('Items', []))
        print(f"Initializing the agent mappings, going to fetch the agents and the enabled agents from the routing policy table...")
        agent_mappings = []
        for item in items:
            # this is the agent that can be available
            user_id = item.get('user_id', '')
            enabled_agents = item.get('enabled_agents', [])
            if user_id and enabled_agents:
                agent_mappings.append((user_id, enabled_agents))
        print(f"Successfully loaded {len(agent_mappings)} agent mappings")
        return agent_mappings
    except Exception as e:
        print(f"An error occurred while loading the agents from {table_name}: {e}")
        raise e

def perform_user_contextual_matching(
    user_metadata: Dict[str, Any],
    agent_mappings: List[Tuple[str, List[str]]]
) -> Optional[str]:
    """
    Perform contextual matching between user metadata and agent mappings using cosine similarity.
    Args:
        user_metadata: Dictionary containing user metadata with product information
        agent_mappings: List of tuples containing (user_agent, [enabled_sub_agents])

    Returns:
        The best matching sub-agent name, or None if no good match found
    """
    try:
        print(f"\n🔍 DEBUG: Starting perform_user_contextual_matching")
        print(f"🔍 DEBUG: user_metadata = {json.dumps(user_metadata, indent=2, default=str)}")
        print(f"🔍 DEBUG: agent_mappings = {agent_mappings}")

        if not user_metadata or not agent_mappings:
            logger.warning("Empty user metadata or agent mappings provided")
            print(f"🔍 DEBUG: Returning None - empty inputs")
            return None

        # Extract product name from user_metadata for contextual matching
        # Support both 'product' and 'service' keys for backward compatibility
        provided_context = user_metadata.get('provided_context', {})
        product_info = provided_context.get('product') or provided_context.get('service', {})
        product_name = product_info.get('name') if isinstance(product_info, dict) else None
        print(f"🔍 DEBUG: Extracted product_name = {product_name}")

        if not product_name:
            logger.warning("No product name found in user metadata")
            print(f"🔍 DEBUG: Returning None - no product name")
            return None

        user_context = str(product_name)
        print(f"🔍 DEBUG: user_context = {user_context}")

        # fetch information about the config file
        config_data: Dict = load_config('config.yaml')
        embeddings_model: str = config_data['agent_registry']['embeddings_model_info_semantic_search'].get('model_id')
        print(f"🔍 DEBUG: embeddings_model = {embeddings_model}")

        # Initialize embeddings model
        embeddings = BedrockEmbeddings(
            model_id=embeddings_model,
            region_name=boto3.session.Session().region_name
        )

        # Get embedding for user context
        user_embedding = embeddings.embed_query(user_context)
        print(f"🔍 DEBUG: Generated user_embedding (shape: {len(user_embedding)})")

        best_match = None
        best_score = -1.0

        print(f"🔍 DEBUG: Iterating through {len(agent_mappings)} agent mappings")
        for user_agent, sub_agents in agent_mappings:
            print(f"🔍 DEBUG: Checking user_agent='{user_agent}' with sub_agents={sub_agents}")

            # Check if the user context (product name) matches any sub-agent
            for sub_agent in sub_agents:
                print(f"🔍 DEBUG: Checking if '{user_context.lower()}' in '{sub_agent.lower()}'")

                if user_context.lower() in sub_agent.lower():
                    print(f"🔍 DEBUG: ✅ Match found! '{user_context}' is in '{sub_agent}'")
                    # Compute similarity between user context and this sub-agent
                    print(f"🔍 DEBUG: Computing similarity for sub_agent='{sub_agent}'")
                    # Get embedding for sub-agent name
                    sub_agent_embedding = embeddings.embed_query(sub_agent)
                    # Calculate cosine similarity
                    similarity = cosine_similarity(
                        [user_embedding],
                        [sub_agent_embedding]
                    )[0][0]
                    print(f"🔍 DEBUG: Similarity between '{user_context}' and '{sub_agent}': {similarity:.4f}")
                    logger.debug(f"Similarity between '{user_context[:50]}...' and '{sub_agent}': {similarity:.4f}")
                    if similarity > best_score:
                        print(f"🔍 DEBUG: New best score! {similarity:.4f} > {best_score:.4f}")
                        best_score = similarity
                        best_match = sub_agent
                else:
                    print(f"🔍 DEBUG: ❌ No match - '{user_context.lower()}' not in '{sub_agent.lower()}'")

        print(f"\n🔍 DEBUG: Final results:")
        print(f"🔍 DEBUG: best_match = {best_match}")
        print(f"🔍 DEBUG: best_score = {best_score:.4f}")

        if best_match:
            print(f"Best match found: '{best_match}' with similarity score: {best_score:.4f}")
        else:
            print("No suitable match found above threshold")
        return best_match
    except Exception as e:
        print(f"Error in contextual matching: {e}")
        raise e

def list_tools_from_gateway(gateway_url: str, access_token: str) -> Dict[str, Any]:
    """
    List available tools from the MCP gateway using direct HTTP calls.

    Args:
        gateway_url: URL of the MCP gateway
        access_token: Access token for authentication

    Returns:
        Dictionary containing the tools list response
    """
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        # We are going to list all of the tools/agent from the gateway
        payload = {
            "jsonrpc": "2.0",
            "id": "list-tools-request",
            "method": "tools/list"
        }
        print(f"Listing tools from gateway: {gateway_url}")
        response = requests.post(gateway_url, headers=headers, json=payload)
        response.raise_for_status()
        tools_response = response.json()
        print(f"Successfully retrieved tools from gateway")
        return tools_response
    except Exception as e:
        logger.error(f"Error listing tools from gateway: {e}")
        raise

# first get the product name from the user context
def _get_product_name(md: Dict[str, Any]) -> str:
    """
    Pull just the product name from common locations in user metadata.
    This is the function which will get the metadata from the user context that
    will be used to do some matching to get the tool from the gateway
    """
    if not isinstance(md, dict):
        return ""
    # 1) Direct: {"service": {"name": "AWS Infrastructure"}}
    if isinstance(md.get("service"), dict):
        name = md["service"].get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    # 2) Provided context: {"provided_context": {"service": {"name": "AWS Infrastructure"}}}
    pc = md.get("provided_context")
    if isinstance(pc, dict) and isinstance(pc.get("service"), dict):
        name = pc["service"].get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    # 3) Raw config path: {"raw_config": {"service": {"name": "AWS Infrastructure"}}}
    rc = md.get("raw_config")
    if isinstance(rc, dict) and isinstance(rc.get("service"), dict):
        name = rc["service"].get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    # 4) Fallback: {"name": "AWS Infrastructure"} (least preferred)
    if isinstance(md.get("name"), str) and md["name"].strip():
        return md["name"].strip()
    return ""

def match_user_context_with_gateway_tools(user_metadata: Dict[str, Any],
                                          tools_response: Dict[str, Any]) -> Optional[str]:
    """
    Simple keyword match:
    If the (case-insensitive) product name appears anywhere in a tool's name,
    return that tool's name. Otherwise return None.

    This function handles tool names in the format "prefix___ProductName" or just "ProductName".
    """
    try:
        if not user_metadata or not tools_response:
            logger.warning("Empty user metadata or tools response provided")
            return None

        # Navigate to the tools array in the response structure
        result = tools_response.get("result")
        if not result:
            logger.warning("No result found in tools response")
            return None

        tools = result.get("tools")
        if not tools:
            logger.warning("No tools found in gateway response")
            return None

        # Extract product name from user metadata
        product_name = _get_product_name(user_metadata)
        if not product_name:
            # Fallback: try to get from provided_context.product.name
            provided_context = user_metadata.get('provided_context', {})
            product = provided_context.get('product', {})
            product_name = product.get('name', '')

        if not product_name:
            logger.warning("No product name found in user metadata")
            return None

        needle = product_name.lower()
        logger.info(f"Keyword matching product '{product_name}' against {len(tools)} tools")

        # Strategy 1: Exact match (case-insensitive)
        for t in tools:
            tool_name = str(t.get("name", "")).strip()
            if not tool_name:
                continue
            if tool_name.lower() == needle:
                print(f"Found exact match: {needle} == {tool_name}")
                return tool_name

        # Strategy 2: Check if tool name contains "___ProductName" format
        for t in tools:
            tool_name = str(t.get("name", "")).strip()
            if not tool_name:
                continue
            # Split on "___" separator
            if "___" in tool_name:
                parts = tool_name.split("___")
                # Check if any part matches the product name
                for part in parts:
                    if part.lower() == needle:
                        print(f"Found match in segmented tool name: {needle} in {tool_name}")
                        return tool_name

        # Strategy 3: Simple substring match
        for t in tools:
            tool_name = str(t.get("name", "")).strip()
            if not tool_name:
                continue
            if needle in tool_name.lower():
                print(f"Found substring match: {needle} in {tool_name}")
                return tool_name

        logger.warning(f"No tool matched for product name: {product_name}")
        return None
    except Exception as e:
        logger.exception("Error in keyword-based tool matching")
        raise e

def invoke_gateway_tool_direct(tool_name: str, query: str, gateway_url: str, access_token: str) -> Dict[str, Any]:
    """
    Invoke a specific tool from the gateway directly using HTTP calls.

    Args:
        tool_name: Name of the tool to invoke
        query: User query to send to the tool
        gateway_url: URL of the MCP gateway
        access_token: Access token for authentication

    Returns:
        Tool response dictionary
    """
    try:
        print(f"🔧 Invoking gateway tool: {tool_name} with query: {query}")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }

        payload = {
            "jsonrpc": "2.0",
            "id": f"tool-call-{tool_name}",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"prompt": query}
            }
        }

        response = requests.post(gateway_url, headers=headers, json=payload)
        response.raise_for_status()

        tool_response = response.json()

        print(f"✅ Gateway tool {tool_name} responded successfully")
        return {
            "tool_name": tool_name,
            "response": tool_response,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error invoking gateway tool {tool_name}: {e}")
        return {
            "error": f"Gateway tool invocation failed: {str(e)}",
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat()
        }