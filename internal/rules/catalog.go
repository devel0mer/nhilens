package rules

import (
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// Metadata describes a risk rule for `nhilens explain`, reports, and SARIF metadata.
type Metadata struct {
	ID               string
	Name             string
	DefaultSeverity  model.Severity
	Summary          string
	Description      string
	Guardrails       string
	ConfigKnobs      []string
	Remediation      string
	ExampleCLI       string
	ExampleTerraform string
}

// Catalog returns canonical documentation metadata for every built-in rule (R1–R8).
func Catalog() []Metadata {
	return []Metadata{
		{
			ID:              "R1",
			Name:            "wildcard-permissions",
			DefaultSeverity: model.SeverityCritical,
			Summary:         "AdministratorAccess or Action:*, Allow NotAction, iam:* on Resource:*",
			Description:     "Flags non-human roles and users granted full or admin-equivalent wildcard permissions (AdministratorAccess, unconditioned Action:*, Allow NotAction, or iam:* on Resource:*). Conditioned statements are downgraded from critical to high with condition keys listed.",
			Guardrails:      "Console-only human IAM users and AWS /aws-service-role/ roles (by default) are skipped. Attached permissions boundaries are noted in evidence.",
			ConfigKnobs:     []string{"rules.enabled.R1", "rules.include_service_linked_roles"},
			Remediation:     "Replace wildcard/admin policies with least-privilege permissions scoped to exact actions and ARNs, and attach a permissions boundary where appropriate.",
			ExampleCLI:      "# Inspect and detach AdministratorAccess (review workload requirements first!)\naws iam list-attached-role-policies --role-name <ROLE_NAME>\naws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
			ExampleTerraform: `resource "aws_iam_role_policy" "least_priv" {
  name = "scoped-agent-policy"
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.*"
    }]
  })
}`,
		},
		{
			ID:              "R2",
			Name:            "unused-permissions",
			DefaultSeverity: model.SeverityMedium,
			Summary:         "Granted AWS services unused within the stale window (default 90d)",
			Description:     "Uses IAM Access Advisor (GenerateServiceLastAccessedDetails) to identify AWS services granted to a non-human role or user with no authenticated usage within rules.stale_days.",
			Guardrails:      "Skipped cleanly without false positives when --skip-service-last-accessed is passed or Access Advisor data is unavailable. Newly created identities include an age-context note.",
			ConfigKnobs:     []string{"rules.enabled.R2", "rules.stale_days"},
			Remediation:     "Remove unused service permissions from attached managed and inline policies to reduce blast radius.",
			ExampleCLI:      "# Review attached policies before removing unused services\naws iam list-attached-role-policies --role-name <ROLE_NAME>\naws iam list-role-policies --role-name <ROLE_NAME>",
			ExampleTerraform: "# Remove unused aws_iam_role_policy_attachment blocks and narrow inline statements to observed services.",
		},
		{
			ID:              "R3",
			Name:            "no-owner",
			DefaultSeverity: model.SeverityMedium,
			Summary:         "Taggable non-human identity lacks an owner/sponsor tag",
			Description:     "Flags non-human IAM roles and users missing all configured owner_tag_keys (default: owner, sponsor, team, maintainer, created-by). Establishing ownership is critical for AI agent lifecycle governance and incident response.",
			Guardrails:      "IAM access keys cannot carry tags independently in AWS, so R3 evaluates roles and parent users only. Service-linked roles are excluded by default.",
			ConfigKnobs:     []string{"rules.enabled.R3", "agent_detection.owner_tag_keys"},
			Remediation:     "Attach an owner or team tag to the IAM role or user.",
			ExampleCLI:      "aws iam tag-role --role-name <ROLE_NAME> --tags Key=owner,Value=<team-or-email>\n# Or for an IAM user:\naws iam tag-user --user-name <USER_NAME> --tags Key=owner,Value=<team-or-email>",
			ExampleTerraform: `tags = {
  owner = "ai-platform-team"
  agent = "true"
}`,
		},
		{
			ID:              "R4",
			Name:            "stale-or-shared-key",
			DefaultSeverity: model.SeverityHigh,
			Summary:         "Static access key older than threshold or used from multiple IPs (best-effort)",
			Description:     "Flags static IAM access keys exceeding rules.key_max_age_days (default 90d) and/or observed from >= rules.min_shared_key_ips distinct valid IPv4/IPv6 addresses in CloudTrail management events.",
			Guardrails:      "Multi-IP attribution is explicitly labeled best-effort (NAT gateways, proxies, or ephemeral CI runners can produce multiple IPs). Non-IP CloudTrail strings like 'AWS Internal' are filtered out.",
			ConfigKnobs:     []string{"rules.enabled.R4", "rules.key_max_age_days", "rules.min_shared_key_ips"},
			Remediation:     "Migrate to short-lived STS credentials via IAM roles (OIDC, EC2/ECS/Lambda roles), or rotate and dedicate one key per workload.",
			ExampleCLI:      "# Rotate static key (create new -> update workload -> deactivate -> delete old)\naws iam update-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID> --status Inactive\naws iam delete-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID>",
			ExampleTerraform: "# Prefer OIDC or workload IAM roles over aws_iam_access_key resources.",
		},
		{
			ID:              "R5",
			Name:            "loose-trust",
			DefaultSeverity: model.SeverityHigh,
			Summary:         "Wildcard principal, cross-account without ExternalId, loose OIDC/Cognito/SAML, or confused-deputy service trust",
			Description:     "Audits role AssumeRolePolicyDocument Allow statements for Principal:*, cross-account AWS trust without sts:ExternalId, GitHub/GitLab/EKS OIDC missing or wildcard sub/aud, Cognito missing aud/authenticated amr, SAML missing SAML:aud, and confused-deputy-prone service principals missing aws:SourceArn/aws:SourceAccount.",
			Guardrails:      "Org-scoped wildcards (aws:PrincipalOrgID) and same-account trusts are allowed. Service confused-deputy checks apply only to configured high-risk service principals at medium severity.",
			ConfigKnobs:     []string{"rules.enabled.R5", "rules.confused_deputy_service_principals"},
			Remediation:     "Pin exact trust principals, add sts:ExternalId for external accounts, pin OIDC sub & aud (sts.amazonaws.com), enforce Cognito aud/amr and SAML:aud, and add aws:SourceAccount/aws:SourceArn on service trusts.",
			ExampleCLI:      "# Inspect current trust policy\naws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument'",
			ExampleTerraform: `assume_role_policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect    = "Allow"
    Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
    Action    = "sts:AssumeRoleWithWebIdentity"
    Condition = {
      StringEquals = {
        "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub" = "repo:org/repo:ref:refs/heads/main"
      }
    }
  }]
})`,
		},
		{
			ID:              "R6",
			Name:            "privilege-escalation-path",
			DefaultSeverity: model.SeverityHigh,
			Summary:         "Explicit IAM self-escalation actions, unbounded iam:PassRole, or sts:AssumeRole on *",
			Description:     "Flags explicit IAM write/escalation permissions (iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreatePolicyVersion, iam:CreateAccessKey, iam:UpdateAssumeRolePolicy, etc.) on Resource:*, iam:PassRole on Resource:* without iam:PassedToService (critical when paired with compute/AI launch permissions), and sts:AssumeRole on Resource:*.",
			Guardrails:      "Ignores full Action:* and iam:* statements already reported by R1 to prevent duplicate scoring. Conditioned escalation statements are reduced from critical to high with condition keys listed.",
			ConfigKnobs:     []string{"rules.enabled.R6"},
			Remediation:     "Remove IAM mutation permissions from workload roles, scope iam:PassRole to exact role ARNs plus iam:PassedToService, and restrict sts:AssumeRole to explicit target role ARNs.",
			ExampleCLI:      "# Inspect inline and managed policies granting escalation actions\naws iam list-role-policies --role-name <ROLE_NAME>\naws iam list-attached-role-policies --role-name <ROLE_NAME>",
			ExampleTerraform: `Statement = [{
  Effect    = "Allow"
  Action    = ["iam:PassRole"]
  Resource  = aws_iam_role.bedrock_execution.arn
  Condition = {
    StringEquals = { "iam:PassedToService" = "bedrock.amazonaws.com" }
  }
}]`,
		},
		{
			ID:              "R7",
			Name:            "sensitive-service-wildcard",
			DefaultSeverity: model.SeverityHigh,
			Summary:         "Broad Resource:* access to KMS, Secrets Manager, SSM Parameter Store, Bedrock, or SageMaker",
			Description:     "Flags unconditioned Resource:* permissions for high-value secret stores (kms:*, kms:Decrypt, secretsmanager:*, secretsmanager:GetSecretValue, ssm:*, ssm:GetParameter*) and full AI control planes (bedrock:*, sagemaker:*). Conditioned statements are downgraded from high to medium.",
			Guardrails:      "Ignores full Action:* statements already owned by R1 to prevent duplicate findings.",
			ConfigKnobs:     []string{"rules.enabled.R7"},
			Remediation:     "Scope KMS, Secrets Manager, and SSM permissions to specific ARNs or path prefixes, and replace bedrock:*/sagemaker:* with explicit invoke actions on approved model/endpoint ARNs.",
			ExampleCLI:      "# Review policy documents for broad kms/secretsmanager/ssm/bedrock wildcards\naws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY_NAME>",
			ExampleTerraform: `Statement = [{
  Effect   = "Allow"
  Action   = ["secretsmanager:GetSecretValue"]
  Resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-agent/*"
}]`,
		},
		{
			ID:              "R8",
			Name:            "key-hygiene",
			DefaultSeverity: model.SeverityMedium,
			Summary:         "User holds two active keys simultaneously, or an active key (>7d old) was never used",
			Description:     "Detects static access-key hygiene risks complementary to R4: IAM users with two or more Active access keys at the same time, and Active keys created more than 7 days ago with zero recorded usage.",
			Guardrails:      "Newly provisioned active keys younger than 7 days are given a grace window; Inactive keys are not flagged as unused-active.",
			ConfigKnobs:     []string{"rules.enabled.R8"},
			Remediation:     "Deactivate and delete unused or redundant static access keys, or replace static keys with short-lived STS roles.",
			ExampleCLI:      "aws iam list-access-keys --user-name <USER_NAME>\naws iam update-access-key --user-name <USER_NAME> --access-key-id <KEY_ID> --status Inactive\naws iam delete-access-key --user-name <USER_NAME> --access-key-id <KEY_ID>",
			ExampleTerraform: "# Keep at most one active aws_iam_access_key per programmatic user during planned rotations only.",
		},
	}
}

// LookupMetadata finds a rule's Metadata by ID (e.g. "R5") or Name (e.g. "loose-trust"), case-insensitively.
func LookupMetadata(query string) (Metadata, bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return Metadata{}, false
	}
	for _, m := range Catalog() {
		if strings.ToLower(m.ID) == q || strings.ToLower(m.Name) == q {
			return m, true
		}
	}
	return Metadata{}, false
}
