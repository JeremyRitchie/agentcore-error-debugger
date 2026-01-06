# ===== ECR Repository for Agent Container =====
# Repository is created by GitHub Actions before Terraform runs

data "aws_ecr_repository" "agent" {
  name = "${local.resource_prefix}-agent"
}

# Lifecycle policy to clean up old images
resource "aws_ecr_lifecycle_policy" "agent" {
  repository = data.aws_ecr_repository.agent.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

output "ecr_repository_url" {
  description = "ECR repository URL for agent container"
  value       = data.aws_ecr_repository.agent.repository_url
}

