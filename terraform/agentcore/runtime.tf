# ===== AgentCore Runtime =====
# Native AgentCore Agent Runtime resource (AWS Provider 6.26.0+)
# Runs the multi-agent Error Debugger system

# IAM Role for AgentCore Runtime
resource "aws_iam_role" "agentcore_runtime" {
  name = "${local.resource_prefix}-runtime-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "bedrock-agentcore.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name = "${local.resource_prefix}-runtime-role"
  }
}

# Runtime execution policy
resource "aws_iam_policy" "agentcore_runtime" {
  name        = "${local.resource_prefix}-runtime-policy"
  description = "Policy for Error Debugger AgentCore Runtime execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchCheckLayerAvailability"
        ]
        Resource = data.aws_ecr_repository.agent.arn
      },
      {
        Sid    = "ECRAuth"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.agentcore.arn}",
          "${aws_cloudwatch_log_group.agentcore.arn}:*"
        ]
      },
      {
        Sid    = "BedrockModels"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Converse",
          "bedrock:ConverseStream"
        ]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/*",
          "arn:aws:bedrock:*:${local.account_id}:inference-profile/*"
        ]
      },
      {
        Sid    = "Comprehend"
        Effect = "Allow"
        Action = [
          "comprehend:DetectSentiment",
          "comprehend:DetectKeyPhrases",
          "comprehend:DetectEntities",
          "comprehend:DetectPiiEntities",
          "comprehend:DetectDominantLanguage",
          "comprehend:BatchDetectSentiment",
          "comprehend:BatchDetectKeyPhrases",
          "comprehend:BatchDetectEntities"
        ]
        Resource = "*"
      },
      {
        Sid    = "XRay"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      },
      {
        Sid    = "AgentCoreMemory"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:CreateMemoryEvent",
          "bedrock-agentcore:GetMemoryEvents",
          "bedrock-agentcore:SearchMemory"
        ]
        Resource = aws_bedrockagentcore_memory.main.arn
      },
      {
        Sid    = "AgentCoreGateway"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:InvokeGateway"
        ]
        Resource = aws_bedrockagentcore_gateway.main.gateway_arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agentcore_runtime" {
  role       = aws_iam_role.agentcore_runtime.name
  policy_arn = aws_iam_policy.agentcore_runtime.arn
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "agentcore" {
  name              = "/aws/bedrock-agentcore/${local.resource_prefix}"
  retention_in_days = 14

  tags = {
    Name = "${local.resource_prefix}-agentcore-logs"
  }
}

# AgentCore Agent Runtime
# Note: agent_runtime_name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ - no hyphens allowed
resource "aws_bedrockagentcore_agent_runtime" "main" {
  agent_runtime_name = replace("${local.resource_prefix}_runtime", "-", "_")
  description        = "Error Debugger - Multi-Agent AgentCore Runtime"
  role_arn           = aws_iam_role.agentcore_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${data.aws_ecr_repository.agent.repository_url}:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  # Environment variables for the Strands agents
  environment_variables = {
    AWS_REGION         = local.region
    AWS_DEFAULT_REGION = local.region
    MEMORY_ID          = aws_bedrockagentcore_memory.main.id
    GATEWAY_ID         = aws_bedrockagentcore_gateway.main.gateway_id
    LLM_MODEL_ID       = var.llm_model_id
    ENVIRONMENT        = var.environment
    LOG_LEVEL          = "INFO"
  }

  tags = {
    Name        = "${local.resource_prefix}-runtime"
    Environment = var.environment
  }

  depends_on = [
    aws_iam_role_policy_attachment.agentcore_runtime,
    aws_cloudwatch_log_group.agentcore,
  ]
}

# AgentCore Runtime Endpoint
# Note: name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ - no hyphens allowed
resource "aws_bedrockagentcore_agent_runtime_endpoint" "main" {
  agent_runtime_id = aws_bedrockagentcore_agent_runtime.main.agent_runtime_id
  name             = replace("${local.resource_prefix}_endpoint", "-", "_")
  description      = "Error Debugger Runtime Endpoint"

  tags = {
    Name = "${local.resource_prefix}-endpoint"
  }
}

output "runtime_id" {
  description = "AgentCore Runtime ID"
  value       = aws_bedrockagentcore_agent_runtime.main.agent_runtime_id
}

output "runtime_arn" {
  description = "AgentCore Runtime ARN"
  value       = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
}

output "runtime_endpoint_arn" {
  description = "AgentCore Runtime Endpoint ARN"
  value       = aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn
}

