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
      RUNTIME_ENDPOINT_ARN = aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn
      AWS_REGION_NAME      = local.region
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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Parse endpoint ID from ARN
# ARN format: arn:aws:bedrock-agentcore:region:account:agent-runtime-endpoint/id
RUNTIME_ENDPOINT_ARN = os.environ.get('RUNTIME_ENDPOINT_ARN', '')
ENDPOINT_ID = RUNTIME_ENDPOINT_ARN.split('/')[-1] if RUNTIME_ENDPOINT_ARN else ''

# Initialize AgentCore client
agentcore_client = None
try:
    agentcore_client = boto3.client('bedrock-agent-runtime')
    logger.info(f"AgentCore client initialized for endpoint: {ENDPOINT_ID}")
except Exception as e:
    logger.error(f"Failed to init AgentCore client: {e}")

def handler(event, context):
    """Proxy requests to AgentCore Runtime"""
    logger.info(f"Received event: {json.dumps(event)[:500]}")
    
    # CORS headers for all responses
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Content-Type': 'application/json'
    }
    
    # Handle preflight
    if event.get('requestContext', {}).get('http', {}).get('method') == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors_headers, 'body': ''}
    
    try:
        # Parse request body
        body = event.get('body', '{}')
        if event.get('isBase64Encoded'):
            import base64
            body = base64.b64decode(body).decode('utf-8')
        
        request = json.loads(body) if isinstance(body, str) else body
        input_text = request.get('inputText', request.get('error_text', ''))
        session_id = request.get('sessionId', 'default')
        
        if not input_text:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({'error': 'Missing inputText or error_text'})
            }
        
        logger.info(f"Invoking AgentCore endpoint {ENDPOINT_ID} with session {session_id}")
        
        # Call AgentCore Runtime
        # Note: The exact API depends on how AgentCore exposes the runtime
        # This uses the bedrock-agent-runtime client which may need adjustment
        response = agentcore_client.invoke_agent(
            agentId=ENDPOINT_ID,
            agentAliasId='TSTALIASID',  # Default test alias
            sessionId=session_id,
            inputText=input_text,
            enableTrace=True
        )
        
        # Collect streaming response
        result_text = ""
        traces = []
        
        for event_chunk in response.get('completion', []):
            if 'chunk' in event_chunk:
                chunk_data = event_chunk['chunk']
                if 'bytes' in chunk_data:
                    result_text += chunk_data['bytes'].decode('utf-8')
            if 'trace' in event_chunk:
                traces.append(event_chunk['trace'])
        
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'success': True,
                'result': result_text,
                'traces': traces,
                'sessionId': session_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error invoking AgentCore: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': str(e),
                'message': 'Failed to invoke AgentCore Runtime'
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

