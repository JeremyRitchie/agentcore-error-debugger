# ===== Variables =====

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
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
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

