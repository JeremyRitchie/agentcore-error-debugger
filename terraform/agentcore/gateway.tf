# ===== AgentCore Gateway =====
# Gateway with MCP protocol for tool access

# IAM Role for Gateway
data "aws_iam_policy_document" "gateway_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "agentcore_gateway" {
  name               = "${local.resource_prefix}-gateway-role"
  assume_role_policy = data.aws_iam_policy_document.gateway_assume.json

  tags = {
    Name = "${local.resource_prefix}-gateway-role"
  }
}

# Gateway execution policy
resource "aws_iam_policy" "agentcore_gateway" {
  name        = "${local.resource_prefix}-gateway-policy"
  description = "Policy for Error Debugger AgentCore Gateway"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeRuntime"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeAgent",
          "bedrock-agentcore:InvokeAgentRuntime"
        ]
        Resource = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
      },
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.parser.arn,
          aws_lambda_function.security.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agentcore_gateway" {
  role       = aws_iam_role.agentcore_gateway.name
  policy_arn = aws_iam_policy.agentcore_gateway.arn
}

# AgentCore Gateway
resource "aws_bedrockagentcore_gateway" "main" {
  name            = "${local.resource_prefix}-gateway"
  description     = "Error Debugger - MCP Gateway"
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  role_arn        = aws_iam_role.agentcore_gateway.arn

  tags = {
    Name        = "${local.resource_prefix}-gateway"
    Environment = var.environment
  }
}

# Gateway Target - Parser Tool (extract stack frames, detect language, classify error)
resource "aws_bedrockagentcore_gateway_target" "parser" {
  name               = "${local.resource_prefix}-parser"
  gateway_identifier = aws_bedrockagentcore_gateway.main.gateway_id
  description        = "Error parsing and classification tool"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.parser.arn

        tool_schema {
          inline_payload {
            name        = "parse_error"
            description = "Parse error message and stack trace to extract structured information"

            input_schema {
              type        = "object"
              description = "Input for error parsing"

              property {
                name        = "error_text"
                type        = "string"
                description = "Raw error message and stack trace"
                required    = true
              }
            }

            output_schema {
              type = "object"

              property {
                name     = "error_type"
                type     = "string"
                required = true
              }

              property {
                name = "stack_frames"
                type = "array"
                items {
                  type = "object"
                }
              }

              property {
                name = "detected_language"
                type = "string"
              }
            }
          }
        }
      }
    }
  }

  depends_on = [aws_lambda_function.parser]
}

# Gateway Target - Security Tool (PII detection, secret scanning)
resource "aws_bedrockagentcore_gateway_target" "security" {
  name               = "${local.resource_prefix}-security"
  gateway_identifier = aws_bedrockagentcore_gateway.main.gateway_id
  description        = "Security analysis tool for PII and secret detection"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.security.arn

        tool_schema {
          inline_payload {
            name        = "scan_security"
            description = "Scan error message for sensitive data (PII and secrets)"

            input_schema {
              type        = "object"
              description = "Input for security scanning"

              property {
                name        = "text"
                type        = "string"
                description = "Text to scan for sensitive data"
                required    = true
              }
            }

            output_schema {
              type = "object"

              property {
                name     = "has_sensitive_data"
                type     = "boolean"
                required = true
              }

              property {
                name = "pii_entities"
                type = "array"
                items {
                  type = "object"
                }
              }

              property {
                name = "secrets_detected"
                type = "array"
                items {
                  type = "string"
                }
              }
            }
          }
        }
      }
    }
  }

  depends_on = [aws_lambda_function.security]
}

output "gateway_id" {
  description = "AgentCore Gateway ID"
  value       = aws_bedrockagentcore_gateway.main.gateway_id
}

output "gateway_arn" {
  description = "AgentCore Gateway ARN"
  value       = aws_bedrockagentcore_gateway.main.gateway_arn
}

output "gateway_url" {
  description = "AgentCore Gateway URL"
  value       = aws_bedrockagentcore_gateway.main.gateway_url
}

