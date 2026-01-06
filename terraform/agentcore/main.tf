# ===== Error Debugger - AgentCore Native Infrastructure =====
# Using Terraform AWS Provider 6.26.0+ with native AgentCore resources

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.27.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Application = "error-debugger"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  resource_prefix = "${var.project_name}-${var.environment}"
  account_id      = data.aws_caller_identity.current.account_id
  region          = data.aws_region.current.id
}

