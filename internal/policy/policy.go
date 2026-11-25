package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// rawPolicyDocument reflects the flexible JSON structure of AWS IAM policies,
// where Statement, Action, Resource, and Condition values may be single items or arrays.
type rawPolicyDocument struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

type rawStatement struct {
	SID          string                                 `json:"Sid"`
	Effect       string                                 `json:"Effect"`
	Action       json.RawMessage                        `json:"Action"`
	NotAction    json.RawMessage                        `json:"NotAction"`
	Resource     json.RawMessage                        `json:"Resource"`
	NotResource  json.RawMessage                        `json:"NotResource"`
	Condition    map[string]map[string]json.RawMessage  `json:"Condition"`
	Principal    json.RawMessage                        `json:"Principal"`
	NotPrincipal json.RawMessage                        `json:"NotPrincipal"`
}

// ParseDocument parses a raw (or URL-encoded) IAM permission policy JSON document.
func ParseDocument(raw string) (*model.ParsedPolicy, error) {
	decoded := decodeIfURLEncoded(raw)
	if decoded == "" {
		return nil, fmt.Errorf("empty policy document")
	}

	var doc rawPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("unmarshal policy document: %w", err)
	}

	rawStmts, err := parseStatements(doc.Statement)
	if err != nil {
		return nil, err
	}

	stmts := make([]model.PolicyStatement, 0, len(rawStmts))
	for i, rs := range rawStmts {
		actions, err := parseStringOrSlice(rs.Action)
		if err != nil {
			return nil, fmt.Errorf("statement[%d] Action: %w", i, err)
		}
		notActions, err := parseStringOrSlice(rs.NotAction)
		if err != nil {
			return nil, fmt.Errorf("statement[%d] NotAction: %w", i, err)
		}
		resources, err := parseStringOrSlice(rs.Resource)
		if err != nil {
			return nil, fmt.Errorf("statement[%d] Resource: %w", i, err)
		}
		notResources, err := parseStringOrSlice(rs.NotResource)
		if err != nil {
			return nil, fmt.Errorf("statement[%d] NotResource: %w", i, err)
		}
		conditions, err := parseConditions(rs.Condition)
		if err != nil {
			return nil, fmt.Errorf("statement[%d] Condition: %w", i, err)
		}

		stmts = append(stmts, model.PolicyStatement{
			SID:          rs.SID,
			Effect:       normalizeEffect(rs.Effect),
			Actions:      actions,
			NotActions:   notActions,
			Resources:    resources,
			NotResources: notResources,
			Conditions:   conditions,
		})
	}

	return &model.ParsedPolicy{
		Version:    doc.Version,
		Statements: stmts,
	}, nil
}

// ParseAndSummarize parses all policy documents and trust policy on an Identity,
// populating PolicyAttachment.Parsed, TrustPrincipals, and EffectiveActions.
// Malformed individual documents return non-fatal warnings rather than aborting analysis.
func ParseAndSummarize(ident *model.Identity) []string {
	if ident == nil {
		return nil
	}

	var warnings []string

	if strings.TrimSpace(ident.TrustPolicyRaw) != "" {
		principals, err := ParseTrustPolicy(ident.TrustPolicyRaw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s %s: parse trust policy: %v", ident.Type, ident.Name, err))
		} else {
			ident.TrustPrincipals = principals
		}
	}

	var (
		summary          model.AllowedActionsSummary
		serviceSet       = make(map[string]struct{})
		wildcardSvcSet   = make(map[string]struct{})
	)

	for i := range ident.Policies {
		att := &ident.Policies[i]

		if IsAdministratorAccessARN(att.ARN) {
			summary.HasAdminWildcard = true
		}

		if att.Parsed == nil && strings.TrimSpace(att.RawDocument) != "" {
			parsed, err := ParseDocument(att.RawDocument)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s %s: parse policy %q: %v", ident.Type, ident.Name, att.Name, err))
				continue
			}
			att.Parsed = parsed
		}

		if att.Parsed == nil {
			continue
		}

		for _, stmt := range att.Parsed.Statements {
			summary.TotalStatements++
			if len(stmt.Conditions) > 0 {
				summary.ConditionedStatements++
			}

			switch stmt.Effect {
			case "Allow":
				summary.AllowStatements++
				hasWildcardRes := ContainsWildcardResource(stmt.Resources)
				for _, act := range stmt.Actions {
					normAct := strings.ToLower(strings.TrimSpace(act))
					if normAct == "" {
						continue
					}
					if normAct == "*" || normAct == "*:*" {
						wildcardSvcSet["*"] = struct{}{}
						if hasWildcardRes {
							summary.HasAdminWildcard = true
						}
						continue
					}
					svc, op, hasColon := strings.Cut(normAct, ":")
					if !hasColon {
						continue
					}
					if svc == "*" {
						wildcardSvcSet["*"] = struct{}{}
						if op == "*" && hasWildcardRes {
							summary.HasAdminWildcard = true
						}
						continue
					}
					serviceSet[svc] = struct{}{}
					if op == "*" {
						wildcardSvcSet[svc] = struct{}{}
					}
				}
			case "Deny":
				summary.DenyStatements++
			}
		}
	}

	summary.Services = sortedKeys(serviceSet)
	summary.WildcardServices = sortedKeys(wildcardSvcSet)
	ident.EffectiveActions = summary

	return warnings
}

// ParseAll parses and summarizes policies and trust relationships across all identities.
func ParseAll(identities []model.Identity) []string {
	var warnings []string
	for i := range identities {
		warnings = append(warnings, ParseAndSummarize(&identities[i])...)
	}
	return warnings
}

// IsAdministratorAccessARN reports whether an ARN refers to the AWS-managed AdministratorAccess policy
// across standard, GovCloud, and China partitions.
func IsAdministratorAccessARN(arn string) bool {
	switch strings.TrimSpace(arn) {
	case "arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
		"arn:aws-cn:iam::aws:policy/AdministratorAccess":
		return true
	default:
		return false
	}
}

// ContainsWildcardResource reports whether any resource entry is "*".
func ContainsWildcardResource(resources []string) bool {
	for _, r := range resources {
		if strings.TrimSpace(r) == "*" {
			return true
		}
	}
	return false
}

// ContainsWildcardAction reports whether any action entry grants all actions ("*" or "*:*").
func ContainsWildcardAction(actions []string) bool {
	for _, a := range actions {
		norm := strings.TrimSpace(a)
		if norm == "*" || norm == "*:*" {
			return true
		}
	}
	return false
}

func parseStatements(raw json.RawMessage) ([]rawStatement, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []rawStatement
		if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
			return nil, fmt.Errorf("unmarshal Statement array: %w", err)
		}
		return list, nil
	}
	var single rawStatement
	if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
		return nil, fmt.Errorf("unmarshal Statement object: %w", err)
	}
	return []rawStatement{single}, nil
}

func parseConditions(raw map[string]map[string]json.RawMessage) (map[string]map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]map[string][]string, len(raw))
	for op, keys := range raw {
		inner := make(map[string][]string, len(keys))
		for k, valRaw := range keys {
			vals, err := parseStringOrSlice(valRaw)
			if err != nil {
				return nil, fmt.Errorf("condition %s/%s: %w", op, k, err)
			}
			inner[k] = vals
		}
		out[op] = inner
	}
	return out, nil
}

// parseStringOrSlice decodes a JSON scalar (string, bool, number) or array of scalars into []string.
func parseStringOrSlice(raw json.RawMessage) ([]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var elems []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &elems); err != nil {
			return nil, err
		}
		out := make([]string, 0, len(elems))
		for _, elem := range elems {
			s, err := parseScalar(elem)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	s, err := parseScalar([]byte(trimmed))
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func parseScalar(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b), nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("expected string/bool/number scalar, got %s", string(raw))
}

func decodeIfURLEncoded(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "{") {
		return trimmed
	}
	decoded, err := url.QueryUnescape(trimmed)
	if err != nil {
		return trimmed
	}
	return strings.TrimSpace(decoded)
}

func normalizeEffect(effect string) string {
	switch strings.ToLower(strings.TrimSpace(effect)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return strings.TrimSpace(effect)
	}
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
