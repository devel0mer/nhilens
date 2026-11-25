locals {
  account_id = data.aws_caller_identity.current.account_id
  common_tags = {
    managed-by    = "terraform"
    nhilens-fixture = "true"
  }
  github_oidc_arn = var.github_oidc_provider_arn != "" ? var.github_oidc_provider_arn : aws_iam_openid_connect_provider.github[0].arn
}

# Defense-in-depth permissions boundary used on the R1 admin fixture so that even in a sandbox
# account, the test role cannot perform mutating AWS actions while still triggering R1 and
# exercising nhilens's permissions-boundary visibility.
resource "aws_iam_policy" "sandbox_safety_boundary" {
  name        = "${var.name_prefix}safety-boundary"
  description = "Restricts nhilens sandbox fixture roles to sts:GetCallerIdentity only."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowIdentityCheckOnly"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
  tags       = local.common_tags
  depends_on = [terraform_data.sandbox_account_guard]
}

# ------------------------------------------------------------------------------
# Fixture 1 — R1 (wildcard-permissions) + likely AI agent
# ------------------------------------------------------------------------------
resource "aws_iam_role" "r1_wildcard_agent" {
  name                 = "${var.name_prefix}bedrock-admin-agent"
  permissions_boundary = aws_iam_policy.sandbox_safety_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
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

  tags = merge(local.common_tags, {
    owner         = "nhilens-sandbox"
    agent         = "true"
    nhilens-rule    = "R1"
  })
}

resource "aws_iam_role_policy_attachment" "r1_admin" {
  role       = aws_iam_role.r1_wildcard_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ------------------------------------------------------------------------------
# Fixture 2 — R2 (unused-permissions) + likely AI agent
# ------------------------------------------------------------------------------
resource "aws_iam_role" "r2_unused_agent" {
  name = "${var.name_prefix}unused-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
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

  tags = merge(local.common_tags, {
    owner      = "nhilens-sandbox"
    agent      = "true"
    nhilens-rule = "R2"
  })

  depends_on = [terraform_data.sandbox_account_guard]
}

resource "aws_iam_role_policy_attachment" "r2_s3_ro" {
  role       = aws_iam_role.r2_unused_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "r2_ec2_ro" {
  role       = aws_iam_role.r2_unused_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

# ------------------------------------------------------------------------------
# Fixture 3 — R3 (no-owner) + likely AI agent (intentionally omits owner tag)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "r3_no_owner" {
  name = "${var.name_prefix}orphan-bot-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
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

  tags = merge(local.common_tags, {
    nhilens-rule = "R3"
  })

  depends_on = [terraform_data.sandbox_account_guard]
}

resource "aws_iam_role_policy" "r3_minimal" {
  name = "sts-identity-only"
  role = aws_iam_role.r3_no_owner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Fixture 4 — R4 (stale-or-shared-key) + programmatic IAM user (no login profile)
# ------------------------------------------------------------------------------
resource "aws_iam_user" "r4_ci_bot" {
  name          = "${var.name_prefix}ci-bot-user"
  force_destroy = true

  tags = merge(local.common_tags, {
    owner      = "nhilens-sandbox"
    nhilens-rule = "R4"
  })

  depends_on = [terraform_data.sandbox_account_guard]
}

resource "aws_iam_user_policy" "r4_minimal" {
  name = "sts-identity-only"
  user = aws_iam_user.r4_ci_bot.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "r4_ci_bot_key" {
  user = aws_iam_user.r4_ci_bot.name
}

# ------------------------------------------------------------------------------
# Fixture 5 — R5 (loose-trust: GitHub Actions OIDC wildcard sub) + likely agent
# ------------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.github_oidc_provider_arn == "" ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  tags           = local.common_tags

  depends_on = [terraform_data.sandbox_account_guard]
}

resource "aws_iam_role" "r5_loose_trust" {
  name = "${var.name_prefix}gh-wildcard-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = local.github_oidc_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:nhilens-sandbox-nonexistent-org/*:*"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    owner      = "nhilens-sandbox"
    nhilens-rule = "R5"
  })

  depends_on = [terraform_data.sandbox_account_guard]
}

resource "aws_iam_role_policy" "r5_minimal" {
  name = "sts-identity-only"
  role = aws_iam_role.r5_loose_trust.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}
