package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// R1WildcardPermissions flags non-human roles/users with full or admin-equivalent wildcard permissions:
//   - Critical: AdministratorAccess, or unconditioned Allow with Action:"*" / NotAction / iam:* on Resource:"*"
//   - High: conditioned versions of the above (condition keys listed in evidence so conditioned wildcards
//     do not emit blind critical findings)
//
// Specific IAM privilege-escalation paths (iam:PassRole, sts:AssumeRole, iam:AttachRolePolicy, etc.)
// are evaluated separately by R6 (privilege-escalation-path) to avoid duplicate scoring.
type R1WildcardPermissions struct{}

func (R1WildcardPermissions) ID() string                      { return "R1" }
func (R1WildcardPermissions) Name() string                    { return "wildcard-permissions" }
func (R1WildcardPermissions) DefaultSeverity() model.Severity { return model.SeverityCritical }

func (r R1WildcardPermissions) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
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
		label := formatPolicyLabel(att)

		if policy.IsAdministratorAccessARN(att.ARN) {
			addEvidence(model.SeverityCritical, fmt.Sprintf("%s grants full AWS AdministratorAccess (%s)", label, att.ARN))
			continue
		}

		parsed := parsePolicyLazy(att)
		if parsed == nil {
			continue
		}

		for _, stmt := range parsed.Statements {
			if stmt.Effect != "Allow" || !policy.ContainsWildcardResource(stmt.Resources) {
				continue
			}

			condKeys := collectConditionKeys(stmt.Conditions)
			conditioned := len(condKeys) > 0
			stmtTag := formatStmtTag(label, stmt.SID)

			// 1. Full wildcard Action:"*" or "*:*" on Resource:"*"
			if policy.ContainsWildcardAction(stmt.Actions) {
				if conditioned {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows Action:* on Resource:* (conditioned on %s; severity reduced from critical to high — verify conditions prevent abuse)", stmtTag, strings.Join(condKeys, ", ")))
				} else {
					addEvidence(model.SeverityCritical, fmt.Sprintf("%s allows unconditioned Action:* on Resource:*", stmtTag))
				}
				continue
			}

			// 2. Allow NotAction on Resource:"*"
			if len(stmt.NotActions) > 0 && len(stmt.Actions) == 0 {
				if conditioned {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s uses Allow NotAction on Resource:* (conditioned on %s; severity reduced from critical to high)", stmtTag, strings.Join(condKeys, ", ")))
				} else {
					addEvidence(model.SeverityCritical, fmt.Sprintf("%s uses unconditioned Allow NotAction on Resource:* (grants broad admin-equivalent access outside excluded actions)", stmtTag))
				}
				continue
			}

			// 3. Full IAM control (iam:*) on Resource:"*"
			if matchesActionPattern(stmt.Actions, "iam:*") {
				if conditioned {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows iam:* on Resource:* (conditioned on %s; severity reduced from critical to high)", stmtTag, strings.Join(condKeys, ", ")))
				} else {
					addEvidence(model.SeverityCritical, fmt.Sprintf("%s allows unconditioned iam:* on Resource:* (direct privilege-escalation path to full admin)", stmtTag))
				}
			}
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	// If an identity-level explicit Deny unconditionally blocks both wildcard admin and IAM control,
	// cap R1 down to medium while noting the explicit Deny in evidence.
	cappedByGuardrail := false
	adminProbe := policy.EvaluateEffectiveAnyAction(ident, nil, []string{"iam:attachrolepolicy", "sts:assumerole", "s3:putobject", "kms:decrypt"}, "*")
	if !adminProbe.Allowed && adminProbe.BlockedBy == "identity_deny" {
		cappedByGuardrail = true
		evidence = append(evidence, "effective access restricted by an explicit identity Deny statement (severity reduced to medium)")
	}

	// Evaluate effective-permission guardrails (attached Permissions Boundary + optional SCPs).
	if ident.PermissionsBoundaryARN != "" {
		if strings.TrimSpace(ident.PermissionsBoundaryDoc) != "" {
			if parsedBoundary, err := policy.ParseDocument(ident.PermissionsBoundaryDoc); err == nil {
				if capped, why := policy.GuardrailCapsAdminWildcard(parsedBoundary); capped {
					cappedByGuardrail = true
					evidence = append(evidence, fmt.Sprintf("effective access capped by permissions boundary %s (%s; severity reduced to medium)", ident.PermissionsBoundaryARN, why))
				} else {
					evidence = append(evidence, fmt.Sprintf("note: permissions boundary %s is attached but still permits Action:* on Resource:*", ident.PermissionsBoundaryARN))
				}
			} else {
				evidence = append(evidence, fmt.Sprintf("note: permissions boundary %s is attached and may restrict effective access", ident.PermissionsBoundaryARN))
			}
		} else {
			evidence = append(evidence, fmt.Sprintf("note: permissions boundary %s is attached and may restrict effective access", ident.PermissionsBoundaryARN))
		}
	}

	for _, scp := range rctx.SCPPolicies {
		if capped, why := policy.GuardrailCapsAdminWildcard(scp.Parsed); capped {
			cappedByGuardrail = true
			evidence = append(evidence, fmt.Sprintf("effective access capped by SCP %q (%s; severity reduced to medium)", scp.Name, why))
		}
	}

	if cappedByGuardrail && model.SeverityRank(highestSev) > model.SeverityRank(model.SeverityMedium) {
		highestSev = model.SeverityMedium
	}

	title := "Non-human identity has wildcard administrator permissions"
	explanation := "This non-human identity is granted full or admin-equivalent wildcard permissions (AdministratorAccess, Action \"*\", Allow NotAction, or iam:* on Resource \"*\"), giving any compromised agent, prompt injection, or leaked credential broad control over the AWS account unless externally restricted."
	if cappedByGuardrail {
		title = "Non-human identity has wildcard policy capped by permissions boundary or SCP"
		explanation = "Identity policies grant wildcard administrator permissions, but an attached permissions boundary or provided SCP caps effective access below full wildcard admin. Severity is reduced to medium; keep identity policies least-privilege so security does not rely solely on guardrails."
	} else if highestSev == model.SeverityHigh {
		title = "Non-human identity has conditioned wildcard permissions"
		explanation = "This non-human identity has wildcard administrator statements constrained by IAM Condition keys. Severity is reduced from critical to high, but conditions should be reviewed carefully to ensure they cannot be bypassed."
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    highestSev,
		Title:       title,
		Explanation: explanation,
		Remediation: "Replace AdministratorAccess, NotAction, iam:*, or wildcard Action/Resource statements with least-privilege policies scoped to specific actions and ARNs, and attach a permissions boundary where appropriate. Run `nhilens explain R1` for remediation templates.",
		Evidence:    evidence,
	}
}

func parsePolicyLazy(att model.PolicyAttachment) *model.ParsedPolicy {
	if att.Parsed != nil {
		return att.Parsed
	}
	if strings.TrimSpace(att.RawDocument) == "" {
		return nil
	}
	parsed, err := policy.ParseDocument(att.RawDocument)
	if err != nil {
		return nil
	}
	return parsed
}

func formatPolicyLabel(att model.PolicyAttachment) string {
	name := att.Name
	if name == "" {
		name = att.ARN
	}
	if att.SourceGroup != "" {
		return fmt.Sprintf("%s policy %q (via group %q)", att.Kind, name, att.SourceGroup)
	}
	return fmt.Sprintf("%s policy %q", att.Kind, name)
}

func formatStmtTag(label, sid string) string {
	if sid != "" {
		return fmt.Sprintf("%s (statement %q)", label, sid)
	}
	return label
}

// matchesActionPattern checks whether any action in actions grants targetAction (lowercase "svc:op"),
// supporting exact match and IAM action wildcards (e.g., "iam:*", "iam:pass*", "sts:assume*").
func matchesActionPattern(actions []string, targetAction string) bool {
	target := strings.ToLower(strings.TrimSpace(targetAction))
	targetSvc, targetOp, _ := strings.Cut(target, ":")

	for _, raw := range actions {
		a := strings.ToLower(strings.TrimSpace(raw))
		if a == "" {
			continue
		}
		if a == target {
			return true
		}
		if targetOp == "*" {
			if a == targetSvc+":*" {
				return true
			}
			continue
		}
		svc, op, ok := strings.Cut(a, ":")
		if !ok || svc != targetSvc {
			continue
		}
		if iamWildcardMatch(op, targetOp) {
			return true
		}
	}
	return false
}

// iamWildcardMatch matches simple IAM glob patterns ('*' and '?') against text.
func iamWildcardMatch(pattern, text string) bool {
	p, t := 0, 0
	starIdx, matchIdx := -1, 0
	for t < len(text) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == text[t]) {
			p++
			t++
		} else if p < len(pattern) && pattern[p] == '*' {
			starIdx = p
			matchIdx = t
			p++
		} else if starIdx != -1 {
			p = starIdx + 1
			matchIdx++
			t = matchIdx
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func collectConditionKeys(conditions map[string]map[string][]string) []string {
	if len(conditions) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	for _, inner := range conditions {
		for k := range inner {
			if tk := strings.TrimSpace(k); tk != "" {
				seen[tk] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
