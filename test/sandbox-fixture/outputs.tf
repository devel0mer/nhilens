# Note: aws_iam_access_key.r4_ci_bot_key.secret is deliberately NOT output.

output "sandbox_account_id" {
  description = "AWS account ID where the sandbox fixture was deployed."
  value       = data.aws_caller_identity.current.account_id
}

output "r1_wildcard_agent_arn" {
  description = "Role ARN targeting R1 (wildcard-permissions)."
  value       = aws_iam_role.r1_wildcard_agent.arn
}

output "r2_unused_agent_arn" {
  description = "Role ARN targeting R2 (unused-permissions)."
  value       = aws_iam_role.r2_unused_agent.arn
}

output "r3_no_owner_arn" {
  description = "Role ARN targeting R3 (no-owner)."
  value       = aws_iam_role.r3_no_owner.arn
}

output "r4_ci_bot_user_arn" {
  description = "Programmatic IAM user ARN targeting R4 (stale-or-shared-key)."
  value       = aws_iam_user.r4_ci_bot.arn
}

output "r4_ci_bot_access_key_id" {
  description = "Access key ID (non-secret) created for the R4 fixture user."
  value       = aws_iam_access_key.r4_ci_bot_key.id
}

output "r5_loose_trust_arn" {
  description = "Role ARN targeting R5 (loose-trust)."
  value       = aws_iam_role.r5_loose_trust.arn
}
