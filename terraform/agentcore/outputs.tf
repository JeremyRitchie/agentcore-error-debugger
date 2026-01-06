# ===== Consolidated Outputs =====

output "agentcore_config" {
  description = "AgentCore configuration for multi-agent Error Debugger system"
  value = {
    runtime_id       = aws_bedrockagentcore_agent_runtime.main.agent_runtime_id
    runtime_arn      = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
    runtime_endpoint = aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn
    gateway_id       = aws_bedrockagentcore_gateway.main.gateway_id
    gateway_arn      = aws_bedrockagentcore_gateway.main.gateway_arn
    gateway_url      = aws_bedrockagentcore_gateway.main.gateway_url
    memory_id        = aws_bedrockagentcore_memory.main.id
    memory_arn       = aws_bedrockagentcore_memory.main.arn
    tool_lambdas = {
      parser   = aws_lambda_function.parser.arn
      security = aws_lambda_function.security.arn
    }
  }
}

output "deployment_info" {
  description = "Deployment information"
  value = {
    website_url    = "https://${var.domain_name}"
    ecr_repository = data.aws_ecr_repository.agent.repository_url
    s3_bucket      = aws_s3_bucket.frontend.id
    cloudfront_id  = aws_cloudfront_distribution.frontend.id
    log_group      = aws_cloudwatch_log_group.agentcore.name
  }
}

# Convenience outputs for CI/CD
output "gateway_endpoint" {
  description = "Gateway endpoint URL for frontend configuration"
  value       = aws_bedrockagentcore_gateway.main.gateway_url
}

