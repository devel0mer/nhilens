package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

type sensitiveActionCheck struct {
	pattern string
	label   string
}

var sensitiveWildcardChecks = []sensitiveActionCheck{
	{pattern: "kms:*", label: "kms:* (unrestricted KMS key management/decryption)"},
	{pattern: "kms:decrypt", label: "kms:Decrypt on Resource:*"},
	{pattern: "secretsmanager:*", label: "secretsmanager:* (all Secrets Manager operations)"},
	{pattern: "secretsmanager:getsecretvalue", label: "secretsmanager:GetSecretValue on Resource:*"},
	{pattern: "ssm:*", label: "ssm:* (all Systems Manager & Parameter Store operations)"},
	{pattern: "ssm:getparameter", label: "ssm:GetParameter* on Resource:*"},
	{pattern: "ssm:getparameters", label: "ssm:GetParameters on Resource:*"},
	{pattern: "ssm:getparametersbypath", label: "ssm:GetParametersByPath on Resource:*"},
	{pattern: "bedrock:*", label: "bedrock:* (unrestricted Bedrock model/agent/guardrail control)"},
	{pattern: "sagemaker:*", label: "sagemaker:* (unrestricted SageMaker training/endpoint/notebook control)"},
}

// R7SensitiveServiceWildcard flags non-human identities with broad Resource:"*" permissions over
// high-value secrets/key stores (KMS, Secrets Manager, SSM Parameter Store) or AI control planes
// (bedrock:*, sagemaker:*). Full Action:"*" policies are handled by R1 to avoid duplicate findings.
type R7SensitiveServiceWildcard struct{}

func (R7SensitiveServiceWildcard) ID() string                      { return "R7" }
func (R7SensitiveServiceWildcard) Name() string                    { return "sensitive-service-wildcard" }
func (R7SensitiveServiceWildcard) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r R7SensitiveServiceWildcard) Evaluate(ident *model.Identity, _ Context) *model.Finding {
	if ident == nil || !IsNonHuman(ident) {
		return nil
	}
	if ident.Type != model.TypeRole && ident.Type != model.TypeUser {
		return nil
	}

	var (
		evidence   []string
		highestSev model.Severity
	)
	seen := make(map[string]struct{})
	addEvidence := func(sev model.Severity, msg string) {
		if model.SeverityRank(sev) > model.SeverityRank(highestSev) {
			highestSev = sev
		}
		if _, ok := seen[msg]; !ok {
			seen[msg] = struct{}{}
			evidence = append(evidence, msg)
		}
	}

	for _, att := range ident.Policies {
		if policy.IsAdministratorAccessARN(att.ARN) {
			continue
		}
		parsed := parsePolicyLazy(att)
		if parsed == nil {
			continue
		}

		label := formatPolicyLabel(att)
		for _, stmt := range parsed.Statements {
			if stmt.Effect != "Allow" || !policy.ContainsWildcardResource(stmt.Resources) {
				continue
			}
			// Skip Action:"*" already covered by R1.
			if policy.ContainsWildcardAction(stmt.Actions) {
				continue
			}

			condKeys := collectConditionKeys(stmt.Conditions)
			conditioned := len(condKeys) > 0
			stmtTag := formatStmtTag(label, stmt.SID)

			matchedLabels := make(map[string]struct{})
			// Check service-level wildcards first so kms:* doesn't also emit kms:Decrypt redundantly.
			hasKMSAll := matchesActionPattern(stmt.Actions, "kms:*")
			hasSMAll := matchesActionPattern(stmt.Actions, "secretsmanager:*")
			hasSSMAll := matchesActionPattern(stmt.Actions, "ssm:*")

			for _, chk := range sensitiveWildcardChecks {
				if hasKMSAll && chk.pattern == "kms:decrypt" {
					continue
				}
				if hasSMAll && chk.pattern == "secretsmanager:getsecretvalue" {
					continue
				}
				if hasSSMAll && strings.HasPrefix(chk.pattern, "ssm:getparameter") {
					continue
				}
				if matchesActionPattern(stmt.Actions, chk.pattern) {
					matchedLabels[chk.label] = struct{}{}
				}
			}

			if len(matchedLabels) == 0 {
				continue
			}

			items := make([]string, 0, len(matchedLabels))
			for l := range matchedLabels {
				items = append(items, l)
			}
			sort.Strings(items)

			if conditioned {
				addEvidence(model.SeverityMedium, fmt.Sprintf("%s grants broad sensitive-service access [%s] (conditioned on %s; severity reduced from high to medium)", stmtTag, strings.Join(items, ", "), strings.Join(condKeys, ", ")))
			} else {
				addEvidence(model.SeverityHigh, fmt.Sprintf("%s grants unconditioned broad access to [%s]", stmtTag, strings.Join(items, ", ")))
			}
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    highestSev,
		Title:       "Non-human identity has broad wildcard access to secrets, KMS, or AI control plane",
		Explanation: "This non-human identity can read or manage secrets/keys (KMS, Secrets Manager, SSM Parameter Store) or full AI control planes (bedrock:*, sagemaker:*) across Resource \"*\". Compromised AI agents with unrestricted secret or AI-service wildcards can exfiltrate credentials or invoke/reconfigure arbitrary foundation models.",
		Remediation: "Scope KMS, Secrets Manager, and SSM Parameter Store policies to specific secret/key/parameter ARNs or path prefixes, and replace bedrock:*/sagemaker:* with explicit runtime invocation actions scoped to approved model/endpoint ARNs. Run `nhilens explain R7` for examples.",
		Evidence:    evidence,
	}
}
