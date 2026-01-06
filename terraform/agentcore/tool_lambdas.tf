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
    patterns = [
        r'File "(.+)", line (\d+), in (.+)',  # Python
        r'at (.+) \((.+):(\d+):(\d+)\)',       # JavaScript
        r'at (.+)\((.+):(\d+)\)',              # Java
    ]
    
    for line in error_text.splitlines():
        for pattern in patterns:
            match = re.match(pattern.strip(), line.strip())
            if match:
                frames.append({'raw': line.strip(), 'groups': match.groups()})
                break
    
    # Classify error type
    error_type = 'GenericError'
    error_lower = error_text.lower()
    if 'typeerror' in error_lower:
        error_type = 'TypeError'
    elif 'valueerror' in error_lower:
        error_type = 'ValueError'
    elif 'keyerror' in error_lower:
        error_type = 'KeyError'
    elif 'network' in error_lower or 'connection' in error_lower:
        error_type = 'NetworkError'
    elif 'database' in error_lower or 'sql' in error_lower:
        error_type = 'DatabaseError'
    
    # Detect language using Comprehend
    try:
        lang_response = comprehend.detect_dominant_language(Text=error_text[:500])
        detected_lang = lang_response['Languages'][0]['LanguageCode'] if lang_response['Languages'] else 'unknown'
    except Exception:
        detected_lang = 'unknown'
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'error_type': error_type,
            'stack_frames': frames,
            'detected_language': detected_lang,
            'raw_lines': len(error_text.splitlines())
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
    
    has_sensitive = bool(pii_entities) or bool(secrets_detected)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'has_sensitive_data': has_sensitive,
            'pii_entities': pii_entities,
            'secrets_detected': secrets_detected,
            'recommendation': 'Review and redact sensitive data.' if has_sensitive else 'No sensitive data detected.'
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

