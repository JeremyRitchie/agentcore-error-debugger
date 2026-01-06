# ===== AgentCore Identity =====
# Native AgentCore Workload Identity resource (AWS Provider 6.26.0+)

# Workload Identity Provider
resource "aws_bedrockagentcore_workload_identity" "main" {
  name = "${local.resource_prefix}-identity"
}

output "identity_arn" {
  description = "AgentCore Workload Identity ARN"
  value       = aws_bedrockagentcore_workload_identity.main.workload_identity_arn
}

