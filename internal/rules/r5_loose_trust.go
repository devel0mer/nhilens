package rules

import (
	"fmt"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// R5LooseTrust flags IAM roles with overly permissive or under-constrained assume-role trust policies:
//   - Wildcard Principal "*" (or AWS "*") without aws:PrincipalOrgID / aws:PrincipalAccount (critical)
//   - Cross-account AWS principal without sts:ExternalId or aws:PrincipalOrgID (high)
//   - GitHub Actions, GitLab, and EKS IRSA OIDC with missing sub (critical), wildcard sub (high), or missing/loose aud (high)
//   - Cognito Identity federation without aud (critical) or authenticated amr restriction (high)
//   - SAML federation (:saml-provider/) without SAML:aud condition (high)
//   - Confused-deputy-prone AWS service principals without aws:SourceArn / aws:SourceAccount / aws:SourceOrgID (medium)
type R5LooseTrust struct{}

func (R5LooseTrust) ID() string                      { return "R5" }
func (R5LooseTrust) Name() string                    { return "loose-trust" }
func (R5LooseTrust) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r R5LooseTrust) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil || ident.Type != model.TypeRole {
		return nil
	}

	principals := ident.TrustPrincipals
	if len(principals) == 0 && strings.TrimSpace(ident.TrustPolicyRaw) != "" {
		parsed, err := policy.ParseTrustPolicy(ident.TrustPolicyRaw)
		if err != nil {
			return nil
		}
		principals = parsed
	}
	if len(principals) == 0 {
		return nil
	}

	deputyServices := make(map[string]struct{})
	if rctx.Config != nil {
		for _, svc := range rctx.Config.Rules.ConfusedDeputyServicePrincipals {
			if s := strings.ToLower(strings.TrimSpace(svc)); s != "" {
				deputyServices[s] = struct{}{}
			}
		}
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

	for _, tp := range principals {
		lowerVal := strings.ToLower(strings.TrimSpace(tp.Value))

		switch {
		case tp.Type == "wildcard" || strings.TrimSpace(tp.Value) == "*":
			if !hasConcreteCondition(tp.Conditions, "aws:principalorgid", "aws:principalaccount") {
				addEvidence(model.SeverityCritical, "trust policy allows wildcard Principal \"*\" without an aws:PrincipalOrgID or aws:PrincipalAccount condition")
			}

		case tp.Type == "account":
			targetAcct := policy.ExtractAccountID(tp.Value)
			if targetAcct != "" && ident.Account != "" && targetAcct != ident.Account {
				if !hasConcreteCondition(tp.Conditions, "sts:externalid", "aws:principalorgid") {
					addEvidence(model.SeverityHigh, fmt.Sprintf("cross-account trust to %s (account %s != %s) has no sts:ExternalId condition", tp.Value, targetAcct, ident.Account))
				}
			}

		case (tp.Type == "oidc" || tp.Type == "federated") && strings.Contains(lowerVal, "token.actions.githubusercontent.com"):
			checkOIDCSubAndAud(tp, "GitHub Actions", "token.actions.githubusercontent.com", addEvidence)

		case (tp.Type == "oidc" || tp.Type == "federated") && strings.Contains(lowerVal, "gitlab"):
			host := extractOIDCProviderHost(tp.Value, "gitlab.com")
			checkOIDCSubAndAud(tp, "GitLab", host, addEvidence)

		case (tp.Type == "oidc" || tp.Type == "federated") && strings.Contains(lowerVal, "oidc.eks."):
			host := extractOIDCProviderHost(tp.Value, "")
			if host != "" {
				checkOIDCSubAndAud(tp, "EKS IRSA", host, addEvidence)
			}

		case (tp.Type == "oidc" || tp.Type == "federated") && lowerVal == "cognito-identity.amazonaws.com":
			audValues := findConditionValues(tp.Conditions, "cognito-identity.amazonaws.com:aud")
			if len(audValues) == 0 || !hasConcreteCondition(tp.Conditions, "cognito-identity.amazonaws.com:aud") {
				addEvidence(model.SeverityCritical, "Cognito Identity federation trust lacks a concrete cognito-identity.amazonaws.com:aud identity pool ID condition")
			}
			amrValues := findConditionValues(tp.Conditions, "cognito-identity.amazonaws.com:amr")
			if !containsCaseInsensitive(amrValues, "authenticated") {
				addEvidence(model.SeverityHigh, "Cognito Identity federation trust does not restrict cognito-identity.amazonaws.com:amr to \"authenticated\" (may allow unauthenticated guest access)")
			}

		case tp.Type == "federated" && strings.Contains(lowerVal, ":saml-provider/"):
			if !hasConcreteCondition(tp.Conditions, "saml:aud") {
				addEvidence(model.SeverityHigh, fmt.Sprintf("SAML federation trust (%s) lacks a concrete SAML:aud condition (expected https://signin.aws.amazon.com/saml)", tp.Value))
			}

		case tp.Type == "service":
			if _, checkDeputy := deputyServices[lowerVal]; checkDeputy {
				if !hasSourceRestriction(tp.Conditions) {
					addEvidence(model.SeverityMedium, fmt.Sprintf("service principal trust (%s) lacks aws:SourceArn, aws:SourceAccount, or aws:SourceOrgID condition (cross-service confused-deputy risk)", tp.Value))
				}
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
		Title:       "Role has an overly permissive or under-constrained trust policy",
		Explanation: "This IAM role's trust policy permits broad assumption or omits standard anti-spoofing/confused-deputy conditions (wildcard principal, cross-account trust without ExternalId, loose GitHub/GitLab/EKS OIDC sub/aud, unconstrained Cognito/SAML federation, or missing aws:SourceArn/aws:SourceAccount on a service principal).",
		Remediation: "Restrict Principal to specific trusted ARNs/services; require sts:ExternalId on external cross-account trusts; pin both sub and aud (sts.amazonaws.com) for GitHub/GitLab/EKS OIDC; enforce aud/amr for Cognito and SAML:aud for SAML; and add aws:SourceAccount or aws:SourceArn to confused-deputy-prone service trusts. Run `nhilens explain R5` for templates.",
		Evidence:    evidence,
	}
}

func checkOIDCSubAndAud(tp model.TrustPrincipal, providerLabel, host string, addEvidence func(model.Severity, string)) {
	subKey := host + ":sub"
	audKey := host + ":aud"

	subValues := findConditionValues(tp.Conditions, subKey)
	if len(subValues) == 0 {
		addEvidence(model.SeverityCritical, fmt.Sprintf("%s OIDC trust (%s) has no %s condition; any subject from this provider can assume this role", providerLabel, tp.Value, subKey))
	} else {
		for _, sub := range subValues {
			if isWildcardOIDCSub(sub) {
				addEvidence(model.SeverityHigh, fmt.Sprintf("%s OIDC trust (%s) uses wildcard sub claim %q", providerLabel, tp.Value, sub))
			}
		}
	}

	audValues := findConditionValues(tp.Conditions, audKey)
	if len(audValues) == 0 {
		addEvidence(model.SeverityHigh, fmt.Sprintf("%s OIDC trust (%s) has no %s condition (should pin to \"sts.amazonaws.com\")", providerLabel, tp.Value, audKey))
	} else {
		for _, aud := range audValues {
			ta := strings.TrimSpace(aud)
			if ta == "" || strings.ContainsAny(ta, "*?") {
				addEvidence(model.SeverityHigh, fmt.Sprintf("%s OIDC trust (%s) uses loose/wildcard aud claim %q", providerLabel, tp.Value, aud))
			}
		}
	}
}

func extractOIDCProviderHost(principalARN, fallback string) string {
	const marker = ":oidc-provider/"
	if idx := strings.Index(strings.ToLower(principalARN), marker); idx >= 0 {
		return strings.TrimSpace(principalARN[idx+len(marker):])
	}
	if !strings.HasPrefix(strings.ToLower(principalARN), "arn:") {
		return strings.TrimSpace(principalARN)
	}
	return fallback
}

// hasSourceRestriction checks for aws:SourceAccount, aws:SourceOrgID, aws:SourceOrgPaths (strict non-wildcard),
// or aws:SourceArn (accepts scoped ARN patterns like arn:aws:bedrock:us-east-1:123456789012:*, rejecting bare "*").
func hasSourceRestriction(conditions map[string]map[string][]string) bool {
	if hasConcreteCondition(conditions, "aws:sourceaccount", "aws:sourceorgid", "aws:sourceorgpaths") {
		return true
	}
	for _, val := range findConditionValues(conditions, "aws:sourcearn") {
		tv := strings.TrimSpace(val)
		if tv != "" && tv != "*" && strings.HasPrefix(strings.ToLower(tv), "arn:") {
			return true
		}
	}
	return false
}

// hasConcreteCondition reports whether any positive condition operator constrains one of targetKeys
// (case-insensitive) to at least one non-empty, non-wildcard value.
func hasConcreteCondition(conditions map[string]map[string][]string, targetKeys ...string) bool {
	if len(conditions) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(targetKeys))
	for _, k := range targetKeys {
		want[strings.ToLower(k)] = struct{}{}
	}
	for op, keys := range conditions {
		lowerOp := strings.ToLower(op)
		if strings.Contains(lowerOp, "not") || lowerOp == "null" {
			continue
		}
		for k, vals := range keys {
			if _, ok := want[strings.ToLower(strings.TrimSpace(k))]; !ok {
				continue
			}
			for _, v := range vals {
				tv := strings.TrimSpace(v)
				if tv != "" && !strings.ContainsAny(tv, "*?") {
					return true
				}
			}
		}
	}
	return false
}

func findConditionValues(conditions map[string]map[string][]string, targetKey string) []string {
	if len(conditions) == 0 {
		return nil
	}
	want := strings.ToLower(strings.TrimSpace(targetKey))
	var out []string
	for op, keys := range conditions {
		lowerOp := strings.ToLower(op)
		if strings.Contains(lowerOp, "not") || lowerOp == "null" {
			continue
		}
		for k, vals := range keys {
			if strings.ToLower(strings.TrimSpace(k)) == want {
				out = append(out, vals...)
			}
		}
	}
	return out
}

func containsCaseInsensitive(vals []string, want string) bool {
	lw := strings.ToLower(strings.TrimSpace(want))
	for _, v := range vals {
		if strings.ToLower(strings.TrimSpace(v)) == lw {
			return true
		}
	}
	return false
}

func isWildcardOIDCSub(sub string) bool {
	trimmed := strings.TrimSpace(sub)
	if trimmed == "" {
		return true
	}
	return strings.ContainsAny(trimmed, "*?")
}
