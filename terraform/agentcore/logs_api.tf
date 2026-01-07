# ===== CloudWatch Logs API =====
# Lambda function to fetch logs from CloudWatch for the frontend

# IAM Role for Logs Lambda
resource "aws_iam_role" "logs_lambda" {
  name               = "${local.resource_prefix}-logs-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Name = "${local.resource_prefix}-logs-lambda-role" }
}

resource "aws_iam_policy" "logs_lambda" {
  name = "${local.resource_prefix}-logs-lambda-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Sid    = "ReadCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/*",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/*:*",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.resource_prefix}-*",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.resource_prefix}-*:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "logs_lambda" {
  role       = aws_iam_role.logs_lambda.name
  policy_arn = aws_iam_policy.logs_lambda.arn
}

resource "aws_lambda_function" "logs" {
  function_name    = "${local.resource_prefix}-logs"
  role             = aws_iam_role.logs_lambda.arn
  package_type     = "Zip"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.logs_placeholder.output_path
  source_code_hash = data.archive_file.logs_placeholder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT        = var.environment
      LOG_LEVEL          = "INFO"
      RUNTIME_LOG_GROUP  = aws_cloudwatch_log_group.agentcore.name
      GATEWAY_LOG_GROUP  = aws_cloudwatch_log_group.gateway.name
      MEMORY_LOG_GROUP   = var.feature_part >= 2 ? aws_cloudwatch_log_group.memory[0].name : ""
      # API_LOG_GROUP removed - browser calls AgentCore via Lambda proxy
      PARSER_LOG_GROUP   = aws_cloudwatch_log_group.parser.name
      SECURITY_LOG_GROUP = aws_cloudwatch_log_group.security.name
      CONTEXT_LOG_GROUP  = aws_cloudwatch_log_group.context.name
      STATS_LOG_GROUP    = aws_cloudwatch_log_group.stats.name
    }
  }

  tags = { Name = "${local.resource_prefix}-logs" }
  depends_on = [aws_iam_role_policy_attachment.logs_lambda, aws_cloudwatch_log_group.logs_lambda]
}

data "archive_file" "logs_placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/logs_placeholder.zip"
  source {
    content  = <<-EOF
import json
import os
import boto3
from datetime import datetime, timedelta

logs_client = boto3.client('logs')

# Log group configuration from environment
LOG_GROUPS = {
    'runtime': os.environ.get('RUNTIME_LOG_GROUP', ''),
    'gateway': os.environ.get('GATEWAY_LOG_GROUP', ''),
    'memory': os.environ.get('MEMORY_LOG_GROUP', ''),
    'parser': os.environ.get('PARSER_LOG_GROUP', ''),
    'security': os.environ.get('SECURITY_LOG_GROUP', ''),
    'context': os.environ.get('CONTEXT_LOG_GROUP', ''),
    'stats': os.environ.get('STATS_LOG_GROUP', ''),
}

def lambda_handler(event, context):
    """Fetch CloudWatch logs for the Error Debugger frontend."""
    
    # Handle CORS preflight
    if event.get('httpMethod') == 'OPTIONS':
        return cors_response(200, {})
    
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        components = body.get('components', list(LOG_GROUPS.keys()))
        limit = min(body.get('limit', 100), 500)  # Cap at 500
        start_time = body.get('startTime', int((datetime.utcnow() - timedelta(hours=1)).timestamp() * 1000))
        end_time = body.get('endTime', int(datetime.utcnow().timestamp() * 1000))
        
        all_logs = []
        errors = []
        
        for component in components:
            log_group = LOG_GROUPS.get(component, '')
            if not log_group:
                continue
            
            try:
                # Filter log events from the log group
                response = logs_client.filter_log_events(
                    logGroupName=log_group,
                    startTime=start_time,
                    endTime=end_time,
                    limit=limit,
                )
                
                for event in response.get('events', []):
                    all_logs.append({
                        'timestamp': event['timestamp'],
                        'message': event['message'],
                        'logGroup': log_group,
                        'component': component,
                        'logStreamName': event.get('logStreamName', ''),
                    })
                    
            except logs_client.exceptions.ResourceNotFoundException:
                errors.append({'component': component, 'error': 'Log group not found'})
            except Exception as e:
                errors.append({'component': component, 'error': str(e)})
        
        # Sort by timestamp descending (newest first)
        all_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limit total results
        all_logs = all_logs[:limit]
        
        return cors_response(200, {
            'success': True,
            'logs': all_logs,
            'count': len(all_logs),
            'errors': errors if errors else None,
            'logGroups': {k: v for k, v in LOG_GROUPS.items() if v},
        })
        
    except Exception as e:
        print(f"Error fetching logs: {str(e)}")
        return cors_response(500, {
            'success': False,
            'error': str(e),
        })


def cors_response(status_code, body):
    """Return a response with CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
        'body': json.dumps(body),
    }
EOF
    filename = "handler.py"
  }
}

resource "aws_cloudwatch_log_group" "logs_lambda" {
  name              = "/aws/lambda/${local.resource_prefix}-logs"
  retention_in_days = 14
  tags              = { Name = "${local.resource_prefix}-logs-logs" }
}

# API Gateway HTTP API for logs
resource "aws_apigatewayv2_api" "logs" {
  name          = "${local.resource_prefix}-logs-api"
  protocol_type = "HTTP"
  
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }

  tags = { Name = "${local.resource_prefix}-logs-api" }
}

resource "aws_apigatewayv2_stage" "logs" {
  api_id      = aws_apigatewayv2_api.logs.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.logs_api.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      ip               = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      path             = "$context.path"
      status           = "$context.status"
      responseLength   = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_cloudwatch_log_group" "logs_api" {
  name              = "/aws/apigateway/${local.resource_prefix}-logs-api"
  retention_in_days = 7
  tags              = { Name = "${local.resource_prefix}-logs-api-logs" }
}

resource "aws_apigatewayv2_integration" "logs" {
  api_id                 = aws_apigatewayv2_api.logs.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.logs.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "logs_post" {
  api_id    = aws_apigatewayv2_api.logs.id
  route_key = "POST /logs"
  target    = "integrations/${aws_apigatewayv2_integration.logs.id}"
}

resource "aws_apigatewayv2_route" "logs_get" {
  api_id    = aws_apigatewayv2_api.logs.id
  route_key = "GET /logs"
  target    = "integrations/${aws_apigatewayv2_integration.logs.id}"
}

resource "aws_lambda_permission" "logs_api" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.logs.execution_arn}/*/*"
}

# Output the logs API URL
output "logs_api_url" {
  description = "URL for the CloudWatch logs API"
  value       = aws_apigatewayv2_api.logs.api_endpoint
}

