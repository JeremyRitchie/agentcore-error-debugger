# ===== Variables =====

# Blog Post Feature Flag
variable "feature_part" {
  description = "Blog series part (1 = basic, 2 = advanced with memory/github)"
  type        = number
  default     = 2
  
  validation {
    condition     = var.feature_part >= 1 && var.feature_part <= 2
    error_message = "feature_part must be 1 or 2"
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "error-debugger"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# Domain configuration
variable "domain_name" {
  description = "Custom domain name for the frontend"
  type        = string
  default     = "error-debugger.jeremyritchie.com"
}

variable "hosted_zone_name" {
  description = "Route53 hosted zone name"
  type        = string
  default     = "jeremyritchie.com"
}

# Model configuration
variable "llm_model_id" {
  description = "Bedrock LLM model ID for code generation and analysis"
  type        = string
  default     = "anthropic.claude-haiku-4-5-2025-1001-v1:0"
}

variable "embedding_model_id" {
  description = "Bedrock embedding model ID for semantic memory"
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

# Agent configuration
variable "agent_memory_mb" {
  description = "Memory allocation for tools Lambda (MB)"
  type        = number
  default     = 1024
}

variable "agent_timeout_seconds" {
  description = "Timeout for tools Lambda (seconds)"
  type        = number
  default     = 300
}

# Session memory TTL
variable "session_memory_ttl_hours" {
  description = "Session memory TTL in hours"
  type        = number
  default     = 24
}

# Container image tag (git SHA for versioning)
variable "container_tag" {
  description = "Container image tag - use git SHA to force updates"
  type        = string
  default     = "latest"
}

# GitHub API Token (optional but recommended for higher rate limits)
# Without a token: 60 requests/hour
# With a token: 5000 requests/hour
variable "github_token" {
  description = "GitHub Personal Access Token for API calls (optional but recommended)"
  type        = string
  default     = ""
  sensitive   = true
}

# Stack Overflow API Key (optional)
variable "stackoverflow_api_key" {
  description = "Stack Overflow API key for higher rate limits (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

