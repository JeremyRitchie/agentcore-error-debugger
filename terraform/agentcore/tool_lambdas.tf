# ===== MCP Tool Lambdas =====
# Separate Lambda functions for Error Debugger tools

# ============================================================================
# Shared IAM for Lambda Execution
# ============================================================================
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ============================================================================
# PARSER LAMBDA - Extract stack frames, detect language, classify error
# ============================================================================
resource "aws_iam_role" "parser_lambda" {
  name               = "${local.resource_prefix}-parser-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Name = "${local.resource_prefix}-parser-lambda-role" }
}

resource "aws_iam_policy" "parser_lambda" {
  name = "${local.resource_prefix}-parser-lambda-policy"
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
        Sid      = "Comprehend"
        Effect   = "Allow"
        Action   = ["comprehend:DetectDominantLanguage"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "parser_lambda" {
  role       = aws_iam_role.parser_lambda.name
  policy_arn = aws_iam_policy.parser_lambda.arn
}

resource "aws_lambda_function" "parser" {
  function_name    = "${local.resource_prefix}-parser"
  role             = aws_iam_role.parser_lambda.arn
  package_type     = "Zip"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.parser_placeholder.output_path
  source_code_hash = data.archive_file.parser_placeholder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  tags = { Name = "${local.resource_prefix}-parser" }
  depends_on = [aws_iam_role_policy_attachment.parser_lambda, aws_cloudwatch_log_group.parser]
}

data "archive_file" "parser_placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/parser_placeholder.zip"
  source {
    content  = <<-EOF
import json
import re
import boto3

comprehend = boto3.client('comprehend')

def lambda_handler(event, context):
    """Parse error message and extract structured information."""
    body = json.loads(event.get('body', '{}'))
    error_text = body.get('error_text', '')
    
    # Extract stack frames using regex
    frames = []
    file_paths = []
    
    # Python pattern
    for match in re.finditer(r'File "(.+)", line (\d+), in (\w+)', error_text):
        frames.append({'file': match.group(1), 'line': int(match.group(2)), 'function': match.group(3)})
        file_paths.append(match.group(1))
    
    # JavaScript/TypeScript pattern
    for match in re.finditer(r'at\s+(\w+)\s+\(([^:]+):(\d+):(\d+)\)', error_text):
        frames.append({'file': match.group(2), 'line': int(match.group(3)), 'function': match.group(1)})
        file_paths.append(match.group(2))
    
    # Detect programming language
    language = 'unknown'
    language_confidence = 0
    
    lang_patterns = [
        ('terraform', r'on\s+\w+\.tf\s+line\s+\d+|\.tf\s+line\s+\d+|Unsupported block type', 95),
        ('python', r'Traceback \(most recent call last\)|File ".*\.py"|\.py:', 90),
        ('javascript', r'at\s+\w+\s+\([^)]*\.js:\d+:\d+\)|\.js:\d+', 85),
        ('typescript', r'\.ts:\d+|\.tsx:\d+|error TS\d+:', 90),
        ('java', r'at\s+[\w.]+\([\w]+\.java:\d+\)|\.java:\d+', 85),
        ('go', r'panic:|goroutine \d+|\.go:\d+', 85),
        ('rust', r'error\[E\d+\]:|\.rs:\d+', 85),
    ]
    
    for lang, pattern, confidence in lang_patterns:
        if re.search(pattern, error_text, re.IGNORECASE):
            if confidence > language_confidence:
                language = lang
                language_confidence = confidence
    
    # Extract core error message (first line or key error)
    core_message = ''
    lines = error_text.strip().splitlines()
    if lines:
        # Look for common error patterns
        for line in lines:
            if any(x in line for x in ['Error:', 'Exception:', 'error:', 'failed', 'Failed']):
                core_message = line.strip()[:200]
                break
        if not core_message:
            core_message = lines[0].strip()[:200]
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'language': language,
            'language_confidence': language_confidence,
            'stack_frames': frames,
            'frame_count': len(frames),
            'file_paths': list(set(file_paths)),
            'core_message': core_message,
            'error_type': 'unknown',  # Let LLM classify this
            'raw_error': error_text[:500]
        })
    }
EOF
    filename = "handler.py"
  }
}

resource "aws_cloudwatch_log_group" "parser" {
  name              = "/aws/lambda/${local.resource_prefix}-parser"
  retention_in_days = 14
  tags              = { Name = "${local.resource_prefix}-parser-logs" }
}

resource "aws_lambda_permission" "parser_gateway" {
  statement_id  = "AllowAgentCoreGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.parser.function_name
  principal     = "bedrock.amazonaws.com"
  source_arn    = aws_bedrockagentcore_gateway.main.gateway_arn
}

# ============================================================================
# SECURITY LAMBDA - PII detection, secret scanning
# ============================================================================
resource "aws_iam_role" "security_lambda" {
  name               = "${local.resource_prefix}-security-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Name = "${local.resource_prefix}-security-lambda-role" }
}

resource "aws_iam_policy" "security_lambda" {
  name = "${local.resource_prefix}-security-lambda-policy"
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
        Sid      = "Comprehend"
        Effect   = "Allow"
        Action   = ["comprehend:DetectPiiEntities"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_lambda" {
  role       = aws_iam_role.security_lambda.name
  policy_arn = aws_iam_policy.security_lambda.arn
}

resource "aws_lambda_function" "security" {
  function_name    = "${local.resource_prefix}-security"
  role             = aws_iam_role.security_lambda.arn
  package_type     = "Zip"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.security_placeholder.output_path
  source_code_hash = data.archive_file.security_placeholder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  tags = { Name = "${local.resource_prefix}-security" }
  depends_on = [aws_iam_role_policy_attachment.security_lambda, aws_cloudwatch_log_group.security]
}

data "archive_file" "security_placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/security_placeholder.zip"
  source {
    content  = <<-EOF
import json
import re
import boto3

comprehend = boto3.client('comprehend')

def lambda_handler(event, context):
    """Scan text for PII and secrets."""
    body = json.loads(event.get('body', '{}'))
    text = body.get('text', '')
    
    pii_entities = []
    secrets_detected = []
    
    # Detect PII using Comprehend
    try:
        pii_response = comprehend.detect_pii_entities(Text=text[:5000], LanguageCode='en')
        pii_entities = [
            {'type': e['Type'], 'score': e['Score']}
            for e in pii_response.get('Entities', [])
        ]
    except Exception as e:
        pii_entities = [{'error': str(e)}]
    
    # Detect secrets using regex
    secret_patterns = {
        'AWS_ACCESS_KEY': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
        'AWS_SECRET_KEY': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
        'API_KEY': r'(api_key|token|secret|password)=[\'"]?([a-zA-Z0-9_-]{16,64})[\'"]?',
        'GENERIC_PASSWORD': r'(password|passwd|pwd)=[\'"]?([a-zA-Z0-9!@#$%^&*_-]{8,})[\'"]?',
    }
    
    for secret_type, pattern in secret_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            secrets_detected.append(secret_type)
    
    has_secrets = bool(secrets_detected)
    has_pii = bool(pii_entities)
    
    # Determine risk level
    if has_secrets:
        risk_level = 'high'
    elif has_pii:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'risk_level': risk_level,
            'secrets_found': len(secrets_detected),
            'secrets_detected': secrets_detected,
            'pii_found': len(pii_entities),
            'pii_entities': pii_entities,
            'safe_to_store': not has_secrets,
            'recommendations': ['Review and redact sensitive data.'] if has_secrets or has_pii else []
        })
    }
EOF
    filename = "handler.py"
  }
}

resource "aws_cloudwatch_log_group" "security" {
  name              = "/aws/lambda/${local.resource_prefix}-security"
  retention_in_days = 14
  tags              = { Name = "${local.resource_prefix}-security-logs" }
}

resource "aws_lambda_permission" "security_gateway" {
  statement_id  = "AllowAgentCoreGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security.function_name
  principal     = "bedrock.amazonaws.com"
  source_arn    = aws_bedrockagentcore_gateway.main.gateway_arn
}

# ============================================================================
# CONTEXT LAMBDA - GitHub Issues, Stack Overflow search
# ============================================================================
resource "aws_iam_role" "context_lambda" {
  name               = "${local.resource_prefix}-context-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Name = "${local.resource_prefix}-context-lambda-role" }
}

resource "aws_iam_policy" "context_lambda" {
  name = "${local.resource_prefix}-context-lambda-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "context_lambda" {
  role       = aws_iam_role.context_lambda.name
  policy_arn = aws_iam_policy.context_lambda.arn
}

resource "aws_lambda_function" "context" {
  function_name    = "${local.resource_prefix}-context"
  role             = aws_iam_role.context_lambda.arn
  package_type     = "Zip"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.context_placeholder.output_path
  source_code_hash = data.archive_file.context_placeholder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT       = var.environment
      LOG_LEVEL         = "INFO"
      GITHUB_TOKEN      = var.github_token       # For GitHub API (5000 req/hr vs 60 req/hr)
      STACKOVERFLOW_KEY = var.stackoverflow_api_key  # For Stack Overflow API
    }
  }

  tags = { Name = "${local.resource_prefix}-context" }
  depends_on = [aws_iam_role_policy_attachment.context_lambda, aws_cloudwatch_log_group.context]
}

data "archive_file" "context_placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/context_placeholder.zip"
  source {
    content  = <<-EOF
import json
import urllib.request
import urllib.parse
import re
import os

GITHUB_API = 'https://api.github.com'
SO_API = 'https://api.stackexchange.com/2.3'

def lambda_handler(event, context):
    """Search GitHub Issues and Stack Overflow for error context."""
    body = json.loads(event.get('body', '{}'))
    error_text = body.get('error_text', '')
    language = body.get('language', '')
    
    # Extract search terms
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', error_text)
    noise = {'the', 'a', 'an', 'is', 'are', 'was', 'in', 'on', 'for', 'to', 'of'}
    terms = [w for w in words if w.lower() not in noise and len(w) > 2][:5]
    query = ' '.join(terms)
    
    github_issues = []
    so_questions = []
    
    # Search GitHub Issues
    try:
        gh_url = f"{GITHUB_API}/search/issues?q={urllib.parse.quote(query + ' is:issue')}&per_page=5"
        headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'ErrorDebugger/1.0'}
        gh_token = os.environ.get('GITHUB_TOKEN')
        if gh_token:
            headers['Authorization'] = f'Bearer {gh_token}'
        
        req = urllib.request.Request(gh_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            for item in data.get('items', [])[:5]:
                github_issues.append({
                    'title': item.get('title', ''),
                    'url': item.get('html_url', ''),
                    'state': item.get('state', ''),
                    'comments': item.get('comments', 0)
                })
    except Exception as e:
        github_issues = [{'error': str(e)}]
    
    # Search Stack Overflow
    try:
        so_url = f"{SO_API}/search/advanced?order=desc&sort=relevance&q={urllib.parse.quote(query)}&site=stackoverflow&pagesize=5"
        req = urllib.request.Request(so_url, headers={'User-Agent': 'ErrorDebugger/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            for item in data.get('items', [])[:5]:
                so_questions.append({
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'score': item.get('score', 0),
                    'is_answered': item.get('is_answered', False),
                    'answer_count': item.get('answer_count', 0)
                })
    except Exception as e:
        so_questions = [{'error': str(e)}]
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'query': query,
            'github_issues': github_issues,
            'stackoverflow_questions': so_questions,
            'total_results': len(github_issues) + len(so_questions)
        })
    }
EOF
    filename = "handler.py"
  }
}

resource "aws_cloudwatch_log_group" "context" {
  name              = "/aws/lambda/${local.resource_prefix}-context"
  retention_in_days = 14
  tags              = { Name = "${local.resource_prefix}-context-logs" }
}

resource "aws_lambda_permission" "context_gateway" {
  statement_id  = "AllowAgentCoreGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.context.function_name
  principal     = "bedrock.amazonaws.com"
  source_arn    = aws_bedrockagentcore_gateway.main.gateway_arn
}

# ============================================================================
# STATS LAMBDA - Error frequency, trends, recording
# ============================================================================
resource "aws_iam_role" "stats_lambda" {
  name               = "${local.resource_prefix}-stats-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Name = "${local.resource_prefix}-stats-lambda-role" }
}

resource "aws_iam_policy" "stats_lambda" {
  name = "${local.resource_prefix}-stats-lambda-policy"
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
        Sid      = "DynamoDB"
        Effect   = "Allow"
        Action   = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${local.resource_prefix}-stats*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "stats_lambda" {
  role       = aws_iam_role.stats_lambda.name
  policy_arn = aws_iam_policy.stats_lambda.arn
}

# DynamoDB table for stats
resource "aws_dynamodb_table" "stats" {
  name         = "${local.resource_prefix}-stats"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = { Name = "${local.resource_prefix}-stats" }
}

resource "aws_lambda_function" "stats" {
  function_name    = "${local.resource_prefix}-stats"
  role             = aws_iam_role.stats_lambda.arn
  package_type     = "Zip"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.stats_placeholder.output_path
  source_code_hash = data.archive_file.stats_placeholder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
      STATS_TABLE = aws_dynamodb_table.stats.name
    }
  }

  tags = { Name = "${local.resource_prefix}-stats" }
  depends_on = [aws_iam_role_policy_attachment.stats_lambda, aws_cloudwatch_log_group.stats]
}

data "archive_file" "stats_placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/stats_placeholder.zip"
  source {
    content  = <<-EOF
import json
import os
import boto3
from datetime import datetime, timedelta
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ.get('STATS_TABLE', 'error-debugger-stats'))

def lambda_handler(event, context):
    """Record and query error statistics."""
    body = json.loads(event.get('body', '{}'))
    action = body.get('action', 'record')
    
    if action == 'record':
        # Record an error occurrence
        error_type = body.get('error_type', 'unknown')
        language = body.get('language', 'unknown')
        timestamp = datetime.utcnow().isoformat()
        
        table.put_item(Item={
            'pk': f"ERROR#{error_type}",
            'sk': timestamp,
            'error_type': error_type,
            'language': language,
            'resolved': body.get('resolved', False),
            'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
        })
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'action': 'record',
                'error_type': error_type,
                'timestamp': timestamp
            })
        }
    
    elif action == 'get_frequency':
        # Get error frequency for a type
        error_type = body.get('error_type', '')
        days = body.get('days', 30)
        
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        if error_type:
            response = table.query(
                KeyConditionExpression='pk = :pk AND sk >= :cutoff',
                ExpressionAttributeValues={':pk': f"ERROR#{error_type}", ':cutoff': cutoff}
            )
        else:
            response = table.scan(
                FilterExpression='sk >= :cutoff',
                ExpressionAttributeValues={':cutoff': cutoff}
            )
        
        count = len(response.get('Items', []))
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'error_type': error_type or 'all',
                'period_days': days,
                'count': count,
                'frequency_per_day': round(count / days, 2)
            })
        }
    
    elif action == 'get_trend':
        # Get trend (comparing current vs previous period)
        error_type = body.get('error_type', '')
        window = body.get('window_days', 7)
        
        now = datetime.utcnow()
        current_start = (now - timedelta(days=window)).isoformat()
        previous_start = (now - timedelta(days=window*2)).isoformat()
        
        pk = f"ERROR#{error_type}" if error_type else None
        
        # This is simplified - production would use proper queries
        current_count = 5  # Placeholder
        previous_count = 3  # Placeholder
        
        if previous_count == 0:
            change = 100 if current_count > 0 else 0
        else:
            change = ((current_count - previous_count) / previous_count) * 100
        
        trend = 'increasing' if change > 20 else 'decreasing' if change < -20 else 'stable'
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'error_type': error_type or 'all',
                'window_days': window,
                'current_count': current_count,
                'previous_count': previous_count,
                'change_percent': round(change, 1),
                'trend': trend
            })
        }
    
    return {
        'statusCode': 400,
        'body': json.dumps({'error': f"Unknown action: {action}"})
    }
EOF
    filename = "handler.py"
  }
}

resource "aws_cloudwatch_log_group" "stats" {
  name              = "/aws/lambda/${local.resource_prefix}-stats"
  retention_in_days = 14
  tags              = { Name = "${local.resource_prefix}-stats-logs" }
}

resource "aws_lambda_permission" "stats_gateway" {
  statement_id  = "AllowAgentCoreGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.stats.function_name
  principal     = "bedrock.amazonaws.com"
  source_arn    = aws_bedrockagentcore_gateway.main.gateway_arn
}

# ============================================================================
# Outputs
# ============================================================================
output "parser_lambda_arn" {
  description = "Parser Lambda ARN"
  value       = aws_lambda_function.parser.arn
}

output "security_lambda_arn" {
  description = "Security Lambda ARN"
  value       = aws_lambda_function.security.arn
}

output "context_lambda_arn" {
  description = "Context Lambda ARN"
  value       = aws_lambda_function.context.arn
}

output "stats_lambda_arn" {
  description = "Stats Lambda ARN"
  value       = aws_lambda_function.stats.arn
}

output "stats_table_name" {
  description = "Stats DynamoDB table name"
  value       = aws_dynamodb_table.stats.name
}

