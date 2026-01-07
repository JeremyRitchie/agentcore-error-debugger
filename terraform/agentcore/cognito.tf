# ===== Cognito Identity Pool =====
# Allows browser to get temporary AWS credentials for direct AgentCore access
# No user authentication required - unauthenticated access for simplicity

# Identity Pool - allows unauthenticated access
resource "aws_cognito_identity_pool" "main" {
  identity_pool_name               = "${local.resource_prefix}-identity-pool"
  allow_unauthenticated_identities = true
  allow_classic_flow               = false

  tags = {
    Name = "${local.resource_prefix}-identity-pool"
  }
}

# IAM Role for unauthenticated users
resource "aws_iam_role" "cognito_unauthenticated" {
  name = "${local.resource_prefix}-cognito-unauth-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "cognito-identity.amazonaws.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.main.id
          }
          "ForAnyValue:StringLike" = {
            "cognito-identity.amazonaws.com:amr" = "unauthenticated"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${local.resource_prefix}-cognito-unauth-role"
  }
}

# Policy allowing unauthenticated users to invoke AgentCore
resource "aws_iam_policy" "cognito_unauthenticated" {
  name = "${local.resource_prefix}-cognito-unauth-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeAgentCoreRuntime"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:InvokeAgentRuntime",
          "bedrock-agentcore:InvokeAgentRuntimeStreaming",
          "bedrock-agentcore:InvokeAgentRuntimeEndpoint",
          "bedrock-agentcore:InvokeAgentRuntimeEndpointStreaming"
        ]
        Resource = [
          aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn,
          aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cognito_unauthenticated" {
  role       = aws_iam_role.cognito_unauthenticated.name
  policy_arn = aws_iam_policy.cognito_unauthenticated.arn
}

# Attach role to identity pool
resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.main.id

  roles = {
    unauthenticated = aws_iam_role.cognito_unauthenticated.arn
  }
}

# Outputs
output "cognito_identity_pool_id" {
  description = "Cognito Identity Pool ID for browser AWS credentials"
  value       = aws_cognito_identity_pool.main.id
}

