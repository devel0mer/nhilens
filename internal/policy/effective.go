package policy

import (
	"fmt"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// ActionDecision captures the result of intersecting identity policies with explicit Denies,
// an optional attached IAM Permissions Boundary, and optional AWS Organizations SCPs.
type ActionDecision struct {
	Allowed       bool
	IdentityAllow bool
	Conditioned   bool
	ConditionKeys []string
	BlockedBy     string // "", "identity_deny", "permissions_boundary", "scp:<name>"
	BlockedReason string
}

// WildcardMatch matches simple IAM glob patterns ('*' and '?') against text.
func WildcardMatch(pattern, text string) bool {
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

// ActionMatchesPattern reports whether an IAM action pattern (e.g. "*", "iam:*", "iam:Pass*")
// matches a concrete or service-wildcard target action (case-insensitive "svc:op").
func ActionMatchesPattern(pattern, targetAction string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	target := strings.ToLower(strings.TrimSpace(targetAction))
	if pat == "" || target == "" {
		return false
	}
	if pat == "*" || pat == "*:*" || pat == target {
		return true
	}
	targetSvc, targetOp, targetHasColon := strings.Cut(target, ":")
	patSvc, patOp, patHasColon := strings.Cut(pat, ":")
	if !targetHasColon || !patHasColon {
		return WildcardMatch(pat, target)
	}
	if !WildcardMatch(patSvc, targetSvc) {
		return false
	}
	if targetOp == "*" {
		return patOp == "*"
	}
	return WildcardMatch(patOp, targetOp)
}

// ResourceMatchesPattern reports whether an IAM resource pattern matches targetResource.
// When targetResource is "*", only a wildcard resource pattern ("*") matches.
func ResourceMatchesPattern(pattern, targetResource string) bool {
	pat := strings.TrimSpace(pattern)
	target := strings.TrimSpace(targetResource)
	if pat == "" || target == "" {
		return false
	}
	if pat == "*" {
		return true
	}
	if target == "*" {
		return false
	}
	return WildcardMatch(pat, target)
}

// StatementMatchesAction reports whether stmt applies to action via Action or NotAction.
func StatementMatchesAction(stmt model.PolicyStatement, action string) bool {
	if len(stmt.Actions) > 0 {
		for _, a := range stmt.Actions {
			if ActionMatchesPattern(a, action) {
				return true
			}
		}
		return false
	}
	if len(stmt.NotActions) > 0 {
		for _, na := range stmt.NotActions {
			if ActionMatchesPattern(na, action) {
				return false
			}
		}
		return true
	}
	return false
}

// StatementMatchesResource reports whether stmt applies to resource via Resource or NotResource.
func StatementMatchesResource(stmt model.PolicyStatement, resource string) bool {
	if len(stmt.Resources) > 0 {
		for _, r := range stmt.Resources {
			if ResourceMatchesPattern(r, resource) {
				return true
			}
		}
		return false
	}
	if len(stmt.NotResources) > 0 {
		for _, nr := range stmt.NotResources {
			if ResourceMatchesPattern(nr, resource) {
				return false
			}
		}
		return true
	}
	return false
}

// StatementMatchesActionResource reports whether stmt matches both action and resource.
func StatementMatchesActionResource(stmt model.PolicyStatement, action, resource string) bool {
	return StatementMatchesAction(stmt, action) && StatementMatchesResource(stmt, resource)
}

type policySetOutcome struct {
	allowed         bool
	explicitDeny    bool
	conditionedOnly bool
	condKeys        []string
}

func evalPolicyDocs(docs []*model.ParsedPolicy, action, resource string) policySetOutcome {
	var (
		hasUncondAllow bool
		hasCondAllow   bool
		condKeySet     = make(map[string]struct{})
	)

	for _, doc := range docs {
		if doc == nil {
			continue
		}
		for _, stmt := range doc.Statements {
			if !StatementMatchesActionResource(stmt, action, resource) {
				continue
			}
			keys := extractStatementConditionKeys(stmt.Conditions)
			switch stmt.Effect {
			case "Deny":
				// Only an unconditioned explicit Deny unconditionally blocks the action.
				// Conditioned Denies may still be bypassed when their condition is not satisfied.
				if len(keys) == 0 {
					return policySetOutcome{explicitDeny: true}
				}
			case "Allow":
				if len(keys) == 0 {
					hasUncondAllow = true
				} else {
					hasCondAllow = true
					for _, k := range keys {
						condKeySet[k] = struct{}{}
					}
				}
			}
		}
	}

	if hasUncondAllow {
		return policySetOutcome{allowed: true}
	}
	if hasCondAllow {
		return policySetOutcome{
			allowed:         true,
			conditionedOnly: true,
			condKeys:        sortedKeys(condKeySet),
		}
	}
	return policySetOutcome{}
}

// EvaluateEffectiveAction evaluates whether an identity can effectively perform (action, resource)
// after intersecting all identity policies (managed, inline, group) with explicit Denies,
// any resolved Permissions Boundary, and any provided AWS Organizations SCPs.
func EvaluateEffectiveAction(ident *model.Identity, scps []NamedPolicy, action, resource string) ActionDecision {
	if ident == nil {
		return ActionDecision{}
	}

	identDocs := collectIdentityPolicyDocs(ident)
	idOutcome := evalPolicyDocs(identDocs, action, resource)
	if idOutcome.explicitDeny {
		return ActionDecision{
			Allowed:       false,
			BlockedBy:     "identity_deny",
			BlockedReason: fmt.Sprintf("explicitly denied for %s on %s by identity policy", action, resource),
		}
	}
	if !idOutcome.allowed {
		return ActionDecision{Allowed: false}
	}

	dec := ActionDecision{
		Allowed:       true,
		IdentityAllow: true,
		Conditioned:   idOutcome.conditionedOnly,
		ConditionKeys: append([]string(nil), idOutcome.condKeys...),
	}

	// Intersect attached IAM Permissions Boundary when document is available.
	if boundaryDoc := parseBoundaryLazy(ident); boundaryDoc != nil {
		bOut := evalPolicyDocs([]*model.ParsedPolicy{boundaryDoc}, action, resource)
		if bOut.explicitDeny {
			dec.Allowed = false
			dec.BlockedBy = "permissions_boundary"
			dec.BlockedReason = fmt.Sprintf("explicitly denied by permissions boundary %s", ident.PermissionsBoundaryARN)
			return dec
		}
		if !bOut.allowed {
			dec.Allowed = false
			dec.BlockedBy = "permissions_boundary"
			dec.BlockedReason = fmt.Sprintf("not allowed by permissions boundary %s", ident.PermissionsBoundaryARN)
			return dec
		}
		if bOut.conditionedOnly {
			dec.Conditioned = true
			dec.ConditionKeys = mergeSortedStrings(dec.ConditionKeys, bOut.condKeys)
		}
	}

	// Intersect every provided AWS Organizations SCP (all SCPs must allow without explicit Deny).
	for _, scp := range scps {
		if scp.Parsed == nil || len(scp.Parsed.Statements) == 0 {
			continue
		}
		sOut := evalPolicyDocs([]*model.ParsedPolicy{scp.Parsed}, action, resource)
		if sOut.explicitDeny {
			dec.Allowed = false
			dec.BlockedBy = "scp:" + scp.Name
			dec.BlockedReason = fmt.Sprintf("explicitly denied by SCP %q", scp.Name)
			return dec
		}
		if !sOut.allowed {
			dec.Allowed = false
			dec.BlockedBy = "scp:" + scp.Name
			dec.BlockedReason = fmt.Sprintf("not allowed by SCP %q", scp.Name)
			return dec
		}
		if sOut.conditionedOnly {
			dec.Conditioned = true
			dec.ConditionKeys = mergeSortedStrings(dec.ConditionKeys, sOut.condKeys)
		}
	}

	return dec
}

// EvaluateEffectiveAnyAction checks whether at least one probe action in probeActions is effectively
// allowed on resource after identity + boundary + SCP intersection.
func EvaluateEffectiveAnyAction(ident *model.Identity, scps []NamedPolicy, probeActions []string, resource string) ActionDecision {
	var (
		bestAllowed *ActionDecision
		lastBlocked ActionDecision
	)
	for _, act := range probeActions {
		d := EvaluateEffectiveAction(ident, scps, act, resource)
		if d.Allowed {
			if !d.Conditioned {
				return d
			}
			if bestAllowed == nil {
				copyD := d
				bestAllowed = &copyD
			} else {
				bestAllowed.ConditionKeys = mergeSortedStrings(bestAllowed.ConditionKeys, d.ConditionKeys)
			}
		} else if d.BlockedBy != "" {
			lastBlocked = d
		}
	}
	if bestAllowed != nil {
		return *bestAllowed
	}
	return lastBlocked
}

func collectIdentityPolicyDocs(ident *model.Identity) []*model.ParsedPolicy {
	docs := make([]*model.ParsedPolicy, 0, len(ident.Policies))
	for _, att := range ident.Policies {
		if att.Parsed != nil {
			docs = append(docs, att.Parsed)
			continue
		}
		if strings.TrimSpace(att.RawDocument) != "" {
			if parsed, err := ParseDocument(att.RawDocument); err == nil {
				docs = append(docs, parsed)
				continue
			}
		}
		if IsAdministratorAccessARN(att.ARN) {
			docs = append(docs, &model.ParsedPolicy{
				Version: "2012-10-17",
				Statements: []model.PolicyStatement{
					{
						Effect:    "Allow",
						Actions:   []string{"*"},
						Resources: []string{"*"},
					},
				},
			})
		}
	}
	return docs
}

func parseBoundaryLazy(ident *model.Identity) *model.ParsedPolicy {
	if ident == nil || strings.TrimSpace(ident.PermissionsBoundaryDoc) == "" {
		return nil
	}
	parsed, err := ParseDocument(ident.PermissionsBoundaryDoc)
	if err != nil || len(parsed.Statements) == 0 {
		return nil
	}
	return parsed
}

func extractStatementConditionKeys(conditions map[string]map[string][]string) []string {
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
	return sortedKeys(seen)
}

func mergeSortedStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, s := range b {
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return sortedKeys(seen)
}
