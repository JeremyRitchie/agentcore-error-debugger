# ===== AgentCore Memory =====
# Native AgentCore Memory resource (AWS Provider 6.26.0+)
# Stores error patterns and session context for learning
# Part 2 Feature - only created when feature_part >= 2

# AgentCore Memory
# Note: name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ - no hyphens allowed
# event_expiry_duration is in days (7-365), not seconds
resource "aws_bedrockagentcore_memory" "main" {
  count = var.feature_part >= 2 ? 1 : 0
  
  name = replace("${local.resource_prefix}_memory", "-", "_")

  event_expiry_duration = 30 # days - keeps error patterns for a month

  depends_on = [aws_kms_key.agentcore]
}

# KMS Key for Memory encryption (Part 2 only)
resource "aws_kms_key" "agentcore" {
  count = var.feature_part >= 2 ? 1 : 0
  
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
  count = var.feature_part >= 2 ? 1 : 0
  
  name          = "alias/${local.resource_prefix}"
  target_key_id = aws_kms_key.agentcore[0].key_id
}

output "memory_id" {
  description = "AgentCore Memory ID (Part 2 only)"
  value       = var.feature_part >= 2 ? aws_bedrockagentcore_memory.main[0].id : null
}

output "memory_arn" {
  description = "AgentCore Memory ARN (Part 2 only)"
  value       = var.feature_part >= 2 ? aws_bedrockagentcore_memory.main[0].arn : null
}

