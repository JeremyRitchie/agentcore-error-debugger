# ===== API Proxy for AgentCore =====
# Required because AWS APIs don't support CORS for browser access
# Browser → Lambda Function URL (CORS) → Lambda → AgentCore Runtime
# Using Lambda Function URL instead of API Gateway for 15 min timeout support

# Lambda function to proxy requests to AgentCore
resource "aws_lambda_function" "api_proxy" {
  function_name = "${local.resource_prefix}-api-proxy"
  role          = aws_iam_role.api_proxy.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 900  # 15 minutes max for long agent operations
  memory_size   = 512  # More memory for processing

  filename         = data.archive_file.api_proxy.output_path
  source_code_hash = data.archive_file.api_proxy.output_base64sha256

  environment {
    variables = {
      AGENT_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
      AWS_REGION_NAME   = local.region
    }
  }

  tags = {
    Name = "${local.resource_prefix}-api-proxy"
  }
}

# Lambda code
data "archive_file" "api_proxy" {
  type        = "zip"
  output_path = "${path.module}/lambda_zips/api_proxy.zip"

  source {
    content = <<-PYTHON
import json
import os
import boto3
import logging
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get agent runtime ARN (not the endpoint ARN)
# ARN format: arn:aws:bedrock-agentcore:region:account:agent-runtime/runtime_id
AGENT_RUNTIME_ARN = os.environ.get('AGENT_RUNTIME_ARN', '')
REGION = os.environ.get('AWS_REGION_NAME', os.environ.get('AWS_REGION', 'us-east-1'))

logger.info(f"Agent Runtime ARN: {AGENT_RUNTIME_ARN}")
logger.info(f"Region: {REGION}")

# Initialize the bedrock-agentcore client
# Docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-agentcore.html
agentcore_client = None
try:
    agentcore_client = boto3.client('bedrock-agentcore', region_name=REGION)
    logger.info("✅ bedrock-agentcore client initialized")
except Exception as e:
    logger.error(f"Failed to init bedrock-agentcore client: {e}")

def handler(event, context):
    """Proxy requests to AgentCore Runtime via invoke_agent_runtime"""
    logger.info(f"Received event: {json.dumps(event)[:500]}")
    
    # CORS headers for all responses
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Content-Type': 'application/json'
    }
    
    # Handle preflight
    http_method = event.get('requestContext', {}).get('http', {}).get('method', '')
    if http_method == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors_headers, 'body': ''}
    
    if not agentcore_client:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'error': 'AgentCore client not initialized'})
        }
    
    try:
        # Parse request body
        body = event.get('body', '{}')
        if event.get('isBase64Encoded'):
            import base64
            body = base64.b64decode(body).decode('utf-8')
        
        request = json.loads(body) if isinstance(body, str) else body
        error_text = request.get('error_text', request.get('inputText', ''))
        github_repo = request.get('github_repo', '')
        
        # runtimeSessionId requires minimum 33 characters
        # Generate a proper UUID-based session ID
        client_session = request.get('sessionId', '')
        session_id = f"session-{uuid.uuid4().hex}"  # 40 chars total (8 + 32)
        logger.info(f"Client session: {client_session} -> Runtime session: {session_id}")
        
        if not error_text:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({'error': 'Missing error_text'})
            }
        
        logger.info(f"Invoking AgentCore runtime: {AGENT_RUNTIME_ARN}")
        logger.info(f"Session ID: {session_id}")
        
        # Build the input for the agent supervisor
        # The supervisor expects: prompt (the error text), session_id, mode
        input_payload = json.dumps({
            'prompt': error_text,  # Agent expects "prompt" not "error_text"
            'session_id': session_id,
            'mode': 'comprehensive',
            'github_repo': github_repo
        })
        
        # Call invoke_agent_runtime
        logger.info("Calling invoke_agent_runtime...")
        response = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=AGENT_RUNTIME_ARN,
            payload=input_payload.encode('utf-8'),
            runtimeSessionId=session_id,
            contentType='application/json',
            accept='application/json'
        )
        logger.info("✅ invoke_agent_runtime returned")
        
        # Log the full response structure for debugging
        response_keys = list(response.keys()) if response else []
        logger.info(f"AgentCore response keys: {response_keys}")
        
        content_type = response.get('contentType', '')
        logger.info(f"Content-Type: {content_type}")
        
        # The actual data is in response["response"], not "payload" or "responseStream"
        result_chunks = []
        
        if "text/event-stream" in content_type:
            # Handle streaming response (SSE format)
            logger.info("Processing streaming response (text/event-stream)...")
            response_body = response.get('response')
            if response_body:
                try:
                    for line in response_body.iter_lines(chunk_size=1024):
                        if line:
                            line_text = line.decode('utf-8') if isinstance(line, bytes) else line
                            logger.info(f"Stream line: {line_text[:200]}")
                            # Strip "data: " prefix from SSE format
                            if line_text.startswith('data: '):
                                line_text = line_text[6:]
                            result_chunks.append(line_text)
                except Exception as stream_err:
                    logger.error(f"Error reading stream: {stream_err}")
        
        elif content_type == "application/json":
            # Handle standard JSON response
            logger.info("Processing JSON response...")
            response_body = response.get('response')
            if response_body:
                try:
                    for chunk in response_body:
                        chunk_text = chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk
                        result_chunks.append(chunk_text)
                        logger.info(f"JSON chunk: {len(chunk_text)} bytes")
                except Exception as json_err:
                    logger.error(f"Error reading JSON response: {json_err}")
        
        else:
            # Fallback - try to read response directly
            logger.info(f"Unknown content type: {content_type}, trying direct read...")
            response_body = response.get('response', response.get('payload'))
            if response_body:
                if hasattr(response_body, 'read'):
                    data = response_body.read()
                    result_chunks.append(data.decode('utf-8') if isinstance(data, bytes) else str(data))
                elif hasattr(response_body, 'iter_lines'):
                    for line in response_body.iter_lines():
                        if line:
                            line_text = line.decode('utf-8') if isinstance(line, bytes) else line
                            if line_text.startswith('data: '):
                                line_text = line_text[6:]
                            result_chunks.append(line_text)
                elif isinstance(response_body, bytes):
                    result_chunks.append(response_body.decode('utf-8'))
                else:
                    result_chunks.append(str(response_body))
        
        result_text = ''.join(result_chunks)
        
        logger.info(f"Total response length: {len(result_text)}")
        logger.info(f"Response (first 1000 chars): {result_text[:1000]}")
        
        # Check for empty response
        if not result_text or result_text.strip() == '':
            logger.warning("Empty response from AgentCore!")
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': 'Empty response from AgentCore runtime',
                    'debug': {
                        'responseKeys': response_keys,
                        'runtimeArn': AGENT_RUNTIME_ARN,
                        'sessionId': session_id,
                        'inputPayloadLength': len(input_payload)
                    }
                })
            }
        
        # The stream often contains multiple JSON objects or text chunks
        # Try to extract the final result - often the last complete JSON object
        result_json = None
        
        # First try parsing the whole thing as JSON
        try:
            result_json = json.loads(result_text)
            logger.info(f"Parsed as single JSON: {list(result_json.keys()) if isinstance(result_json, dict) else 'not a dict'}")
        except json.JSONDecodeError:
            # Try to find JSON objects in the streamed text
            # The agent often yields multiple JSON objects or text lines
            logger.info("Not single JSON, looking for embedded JSON...")
            
            # Split by newlines and look for JSON
            for line in result_text.strip().split('\n'):
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try:
                        candidate = json.loads(line)
                        # Keep the last/most complete JSON
                        if isinstance(candidate, dict):
                            if 'result' in candidate or 'parsed_info' in candidate or 'root_cause' in candidate:
                                result_json = candidate
                                logger.info(f"Found result JSON: {list(candidate.keys())}")
                    except:
                        pass
            
            if not result_json:
                # Just wrap the raw text
                result_json = {'rawResult': result_text}
        
        # Return the full response for debugging
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'success': True,
                'result': result_json.get('result', result_json) if isinstance(result_json, dict) else result_text,
                'fullResponse': result_json,
                'rawText': result_text[:5000],  # First 5000 chars for debugging
                'chunkCount': len(result_chunks),
                'traces': result_json.get('traces', []) if isinstance(result_json, dict) else [],
                'sessionId': session_id
            })
        }
        
    except agentcore_client.exceptions.ValidationException as ve:
        logger.error(f"Validation error: {ve}")
        return {
            'statusCode': 400,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': f"Validation error: {str(ve)}",
                'runtimeArn': AGENT_RUNTIME_ARN
            })
        }
    except Exception as e:
        logger.error(f"Error invoking AgentCore: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': str(e),
                'message': 'Failed to invoke AgentCore Runtime',
                'runtimeArn': AGENT_RUNTIME_ARN
            })
        }
PYTHON
    filename = "index.py"
  }
}

# IAM Role for API Proxy Lambda
resource "aws_iam_role" "api_proxy" {
  name = "${local.resource_prefix}-api-proxy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${local.resource_prefix}-api-proxy-role"
  }
}

# IAM Policy for API Proxy
resource "aws_iam_policy" "api_proxy" {
  name = "${local.resource_prefix}-api-proxy-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Sid    = "InvokeAgentCore"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeAgent",
          "bedrock:InvokeAgentWithResponseStream",
          "bedrock-agentcore:InvokeAgentRuntime",
          "bedrock-agentcore:InvokeAgentRuntimeWithResponseStream"
        ]
        Resource = [
          aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn,
          aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn,
          "${aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_proxy" {
  role       = aws_iam_role.api_proxy.name
  policy_arn = aws_iam_policy.api_proxy.arn
}

# Lambda Function URL - supports up to 15 min timeout (no API Gateway 30s limit)
resource "aws_lambda_function_url" "api_proxy" {
  function_name      = aws_lambda_function.api_proxy.function_name
  authorization_type = "NONE"  # Public access

  cors {
    allow_origins     = ["*"]
    allow_methods     = ["POST", "OPTIONS"]
    allow_headers     = ["Content-Type", "Authorization"]
    allow_credentials = false
    max_age           = 300
  }
}

# Output the Lambda Function URL
output "api_endpoint" {
  value       = trimsuffix(aws_lambda_function_url.api_proxy.function_url, "/")
  description = "Lambda Function URL for AgentCore proxy (15 min timeout)"
}

