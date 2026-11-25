variable "confirm_sandbox_account" {
  type        = bool
  default     = false
  description = "Safety guardrail: must be explicitly set to true to confirm you are targeting a non-production sandbox AWS account."

  validation {
    condition     = var.confirm_sandbox_account == true
    error_message = "Set -var=\"confirm_sandbox_account=true\" to confirm you are deploying deliberately weak fixtures only to a sandbox AWS account."
  }
}

variable "expected_account_id" {
  type        = string
  default     = ""
  description = "Optional 12-digit sandbox AWS account ID. When set, Terraform refuses to apply if the active AWS credentials resolve to any other account."

  validation {
    condition     = var.expected_account_id == "" || can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for the sandbox provider."
}

variable "aws_profile" {
  type        = string
  default     = null
  description = "Optional AWS shared config/credentials profile name."
}

variable "name_prefix" {
  type        = string
  default     = "nhilens-sandbox-"
  description = "Prefix applied to all fixture IAM roles, policies, and users for easy identification and cleanup."
}

variable "github_oidc_provider_arn" {
  type        = string
  default     = ""
  description = "Optional ARN of an existing token.actions.githubusercontent.com OIDC provider in the sandbox account. Leave empty to create one."
}
