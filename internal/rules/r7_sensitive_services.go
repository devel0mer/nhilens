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
	probes  []string
	label   string
}

var sensitiveWildcardChecks = []sensitiveActionCheck{
	{pattern: "kms:*", probes: []string{"kms:decrypt", "kms:creategrant", "kms:putkeypolicy"}, label: "kms:* (unrestricted KMS key management/decryption)"},
	{pattern: "kms:decrypt", probes: []string{"kms:decrypt"}, label: "kms:Decrypt on Resource:*"},
	{pattern: "secretsmanager:*", probes: []string{"secretsmanager:getsecretvalue", "secretsmanager:putsecretvalue"}, label: "secretsmanager:* (all Secrets Manager operations)"},
	{pattern: "secretsmanager:getsecretvalue", probes: []string{"secretsmanager:getsecretvalue"}, label: "secretsmanager:GetSecretValue on Resource:*"},
	{pattern: "ssm:*", probes: []string{"ssm:getparameter", "ssm:putparameter"}, label: "ssm:* (all Systems Manager & Parameter Store operations)"},
	{pattern: "ssm:getparameter", probes: []string{"ssm:getparameter"}, label: "ssm:GetParameter* on Resource:*"},
	{pattern: "ssm:getparameters", probes: []string{"ssm:getparameters"}, label: "ssm:GetParameters on Resource:*"},
	{pattern: "ssm:getparametersbypath", probes: []string{"ssm:getparametersbypath"}, label: "ssm:GetParametersByPath on Resource:*"},
	{pattern: "bedrock:*", probes: []string{"bedrock:invokemodel", "bedrock:createagent"}, label: "bedrock:* (unrestricted Bedrock model/agent/guardrail control)"},
	{pattern: "sagemaker:*", probes: []string{"sagemaker:createnotebookinstance", "sagemaker:invokeendpoint"}, label: "sagemaker:* (unrestricted SageMaker training/endpoint/notebook control)"},
}

// R7SensitiveServiceWildcard flags non-human identities with broad Resource:"*" permissions over
// high-value secrets/key stores (KMS, Secrets Manager, SSM Parameter Store) or AI control planes
// (bedrock:*, sagemaker:*). Full Action:"*" policies are handled by R1 to avoid duplicate findings.
// Action-level explicit Denies, attached Permissions Boundaries, and optional SCPs are intersected
// so blocked sensitive wildcards do not emit false-positive alerts.
type R7SensitiveServiceWildcard struct{}

func (R7SensitiveServiceWildcard) ID() string                      { return "R7" }
func (R7SensitiveServiceWildcard) Name() string                    { return "sensitive-service-wildcard" }
func (R7SensitiveServiceWildcard) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r R7SensitiveServiceWildcard) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
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
			stmtTag := formatStmtTag(label, stmt.SID)

			uncondLabels := make(map[string]struct{})
			condLabels := make(map[string]struct{})
			allCondKeys := make(map[string]struct{})
			for _, k := range condKeys {
				allCondKeys[k] = struct{}{}
			}

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
				if !matchesActionPattern(stmt.Actions, chk.pattern) {
					continue
				}

				dec := policy.EvaluateEffectiveAnyAction(ident, rctx.SCPPolicies, chk.probes, "*")
				if !dec.Allowed {
					// Effectively blocked by explicit Deny, attached Permissions Boundary, or SCP.
					continue
				}
				if len(condKeys) > 0 || dec.Conditioned {
					condLabels[chk.label] = struct{}{}
					for _, k := range dec.ConditionKeys {
						allCondKeys[k] = struct{}{}
					}
				} else {
					uncondLabels[chk.label] = struct{}{}
				}
			}

			if len(uncondLabels) > 0 {
				items := sortedStringSet(uncondLabels)
				addEvidence(model.SeverityHigh, fmt.Sprintf("%s grants unconditioned broad access to [%s]", stmtTag, strings.Join(items, ", ")))
			}
			if len(condLabels) > 0 {
				items := sortedStringSet(condLabels)
				cKeys := sortedStringSet(allCondKeys)
				addEvidence(model.SeverityMedium, fmt.Sprintf("%s grants broad sensitive-service access [%s] (conditioned on %s; severity reduced from high to medium)", stmtTag, strings.Join(items, ", "), strings.Join(cKeys, ", ")))
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
		Explanation: "This non-human identity effectively retains read or administrative access to secrets/keys (KMS, Secrets Manager, SSM Parameter Store) or full AI control planes (bedrock:*, sagemaker:*) across Resource \"*\" after intersecting explicit Denies, permissions boundaries, and provided SCPs.",
		Remediation: "Scope KMS, Secrets Manager, and SSM Parameter Store policies to specific secret/key/parameter ARNs or path prefixes, and replace bedrock:*/sagemaker:* with explicit runtime invocation actions scoped to approved model/endpoint ARNs. Run `nhilens explain R7` for examples.",
		Evidence:    evidence,
	}
}

func sortedStringSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
