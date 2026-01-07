# ===== API Proxy for AgentCore =====
# Required because AWS APIs don't support CORS for browser access
# Browser → API Gateway (CORS) → Lambda → AgentCore Runtime

# Lambda function to proxy requests to AgentCore
resource "aws_lambda_function" "api_proxy" {
  function_name = "${local.resource_prefix}-api-proxy"
  role          = aws_iam_role.api_proxy.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 300  # 5 minutes for long agent operations
  memory_size   = 256

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
        
        # Call invoke_agent_runtime with correct parameter names
        # Valid params: contentType, accept, mcpSessionId, runtimeSessionId, mcpProtocolVersion,
        #               runtimeUserId, traceId, traceParent, traceState, baggage, agentRuntimeArn, qualifier, payload
        response = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=AGENT_RUNTIME_ARN,
            payload=input_payload.encode('utf-8'),
            runtimeSessionId=session_id,
            contentType='application/json',
            accept='application/json'
        )
        
        # Log the full response structure for debugging
        response_keys = list(response.keys())
        logger.info(f"AgentCore response keys: {response_keys}")
        
        # Read the response payload (may be a StreamingBody)
        result_bytes = response.get('payload', b'')
        if hasattr(result_bytes, 'read'):
            result_bytes = result_bytes.read()
        
        result_text = result_bytes.decode('utf-8') if isinstance(result_bytes, bytes) else str(result_bytes)
        
        logger.info(f"Response length: {len(result_text)}")
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
        
        # Try to parse as JSON
        try:
            result_json = json.loads(result_text)
            logger.info(f"Parsed JSON keys: {list(result_json.keys()) if isinstance(result_json, dict) else 'not a dict'}")
        except json.JSONDecodeError as jde:
            logger.warning(f"Response is not JSON: {jde}")
            result_json = {'result': result_text}
        
        # Return the full response for debugging
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'success': True,
                'result': result_json.get('result', result_text) if isinstance(result_json, dict) else result_text,
                'fullResponse': result_json,
                'rawText': result_text[:2000],  # First 2000 chars for debugging
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

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "api_proxy" {
  name          = "${local.resource_prefix}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }

  tags = {
    Name = "${local.resource_prefix}-api"
  }
}

# Lambda integration
resource "aws_apigatewayv2_integration" "api_proxy" {
  api_id                 = aws_apigatewayv2_api.api_proxy.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_proxy.invoke_arn
  payload_format_version = "2.0"
}

# Route for analyze endpoint
resource "aws_apigatewayv2_route" "analyze" {
  api_id    = aws_apigatewayv2_api.api_proxy.id
  route_key = "POST /analyze"
  target    = "integrations/${aws_apigatewayv2_integration.api_proxy.id}"
}

# Default stage with auto-deploy
resource "aws_apigatewayv2_stage" "api_proxy" {
  api_id      = aws_apigatewayv2_api.api_proxy.id
  name        = "$default"
  auto_deploy = true

  tags = {
    Name = "${local.resource_prefix}-api-stage"
  }
}

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_proxy" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api_proxy.execution_arn}/*/*"
}

# Output the API endpoint
output "api_endpoint" {
  value       = aws_apigatewayv2_api.api_proxy.api_endpoint
  description = "API Gateway endpoint for AgentCore proxy"
}

