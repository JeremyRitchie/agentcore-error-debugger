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
          aws_lambda_function.security.arn,
          aws_lambda_function.context.arn,
          aws_lambda_function.stats.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agentcore_gateway" {
  role       = aws_iam_role.agentcore_gateway.name
  policy_arn = aws_iam_policy.agentcore_gateway.arn
}

# CloudWatch Log Group for Gateway (for manual logging configuration in AWS Console)
resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/bedrock-agentcore/${local.resource_prefix}-gateway"
  retention_in_days = 14

  tags = {
    Name = "${local.resource_prefix}-gateway-logs"
  }
}

# AgentCore Gateway
# Note: Logging must be configured manually in AWS Console pointing to the log group above
# Note: Using NONE authorizer for internal Runtime->Gateway calls
#       The Runtime already authenticates callers via Lambda proxy at the API Gateway level
resource "aws_bedrockagentcore_gateway" "main" {
  name            = "${local.resource_prefix}-gateway"
  description     = "Error Debugger - MCP Gateway"
  protocol_type   = "MCP"
  authorizer_type = "NONE"
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

# ============================================================================
# Context Tool Target (GitHub/StackOverflow search)
# ============================================================================
resource "aws_bedrockagentcore_gateway_target" "context" {
  name               = "${local.resource_prefix}-context"
  gateway_identifier = aws_bedrockagentcore_gateway.main.gateway_id
  description        = "Search GitHub Issues and Stack Overflow for error context"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.context.arn

        tool_schema {
          inline_payload {
            name        = "search_error_context"
            description = "Search GitHub Issues and Stack Overflow for similar errors and solutions"

            input_schema {
              type = "object"

              property {
                name        = "error_text"
                type        = "string"
                description = "The error message to search for"
                required    = true
              }

              property {
                name        = "language"
                type        = "string"
                description = "Programming language (optional filter)"
              }
            }

            output_schema {
              type = "object"

              property {
                name = "query"
                type = "string"
              }

              property {
                name = "github_issues"
                type = "array"
                items {
                  type = "object"
                }
              }

              property {
                name = "stackoverflow_questions"
                type = "array"
                items {
                  type = "object"
                }
              }

              property {
                name = "total_results"
                type = "number"
              }
            }
          }
        }
      }
    }
  }

  depends_on = [aws_lambda_function.context]
}

# ============================================================================
# Stats Tool Target (Error tracking and trends)
# ============================================================================
resource "aws_bedrockagentcore_gateway_target" "stats" {
  name               = "${local.resource_prefix}-stats"
  gateway_identifier = aws_bedrockagentcore_gateway.main.gateway_id
  description        = "Record and query error statistics and trends"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.stats.arn

        tool_schema {
          inline_payload {
            name        = "manage_error_stats"
            description = "Record error occurrences and query frequency/trends"

            input_schema {
              type = "object"

              property {
                name        = "action"
                type        = "string"
                description = "Action: record, get_frequency, or get_trend"
                required    = true
              }

              property {
                name        = "error_type"
                type        = "string"
                description = "Type of error (e.g., null_reference, type_error)"
              }

              property {
                name        = "language"
                type        = "string"
                description = "Programming language"
              }

              property {
                name        = "days"
                type        = "number"
                description = "Number of days for frequency calculation"
              }

              property {
                name        = "window_days"
                type        = "number"
                description = "Window size for trend detection"
              }
            }

            output_schema {
              type = "object"

              property {
                name = "success"
                type = "boolean"
              }

              property {
                name = "error_type"
                type = "string"
              }

              property {
                name = "count"
                type = "number"
              }

              property {
                name = "trend"
                type = "string"
              }

              property {
                name = "frequency_per_day"
                type = "number"
              }
            }
          }
        }
      }
    }
  }

  depends_on = [aws_lambda_function.stats]
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

