# ===== AgentCore Memory =====
# Native AgentCore Memory resource (AWS Provider 6.26.0+)
# Stores error patterns and session context for learning

# AgentCore Memory
# Note: name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ - no hyphens allowed
# event_expiry_duration is in days (7-365), not seconds
resource "aws_bedrockagentcore_memory" "main" {
  name = replace("${local.resource_prefix}_memory", "-", "_")

  event_expiry_duration = 30 # days - keeps error patterns for a month

  depends_on = [aws_kms_key.agentcore]
}

# KMS Key for Memory encryption
resource "aws_kms_key" "agentcore" {
  description             = "KMS key for Error Debugger AgentCore encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Bedrock Service"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name = "${local.resource_prefix}-kms"
  }
}

resource "aws_kms_alias" "agentcore" {
  name          = "alias/${local.resource_prefix}"
  target_key_id = aws_kms_key.agentcore.key_id
}

output "memory_id" {
  description = "AgentCore Memory ID"
  value       = aws_bedrockagentcore_memory.main.id
}

output "memory_arn" {
  description = "AgentCore Memory ARN"
  value       = aws_bedrockagentcore_memory.main.arn
}

