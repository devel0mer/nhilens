terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_caller_identity" "current" {}

# Guardrail: optionally lock execution to an explicit sandbox AWS account ID.
resource "terraform_data" "sandbox_account_guard" {
  lifecycle {
    precondition {
      condition     = var.expected_account_id == "" || data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "Refusing to apply: active AWS account (${data.aws_caller_identity.current.account_id}) does not match expected_account_id (${var.expected_account_id})."
    }
  }
}
