package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// ParseTrustPolicy parses an IAM role's AssumeRolePolicyDocument JSON into normalized TrustPrincipals.
// Only statements with Effect == "Allow" produce granted trust principals.
func ParseTrustPolicy(raw string) ([]model.TrustPrincipal, error) {
	decoded := decodeIfURLEncoded(raw)
	if decoded == "" {
		return nil, nil
	}

	var doc rawPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("unmarshal trust policy: %w", err)
	}

	rawStmts, err := parseStatements(doc.Statement)
	if err != nil {
		return nil, err
	}

	var principals []model.TrustPrincipal
	for i, rs := range rawStmts {
		if normalizeEffect(rs.Effect) != "Allow" {
			continue
		}

		actions, err := parseStringOrSlice(rs.Action)
		if err != nil {
			return nil, fmt.Errorf("trust statement[%d] Action: %w", i, err)
		}
		sort.Strings(actions)

		conditions, err := parseConditions(rs.Condition)
		if err != nil {
			return nil, fmt.Errorf("trust statement[%d] Condition: %w", i, err)
		}

		parsed, err := parsePrincipalBlock(rs.Principal, actions, conditions)
		if err != nil {
			return nil, fmt.Errorf("trust statement[%d] Principal: %w", i, err)
		}
		principals = append(principals, parsed...)
	}

	sort.Slice(principals, func(i, j int) bool {
		if principals[i].Type != principals[j].Type {
			return principals[i].Type < principals[j].Type
		}
		return principals[i].Value < principals[j].Value
	})

	return principals, nil
}

func parsePrincipalBlock(raw json.RawMessage, actions []string, conditions map[string]map[string][]string) ([]model.TrustPrincipal, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	// Form 1: "Principal": "*"
	var wildcardStr string
	if err := json.Unmarshal([]byte(trimmed), &wildcardStr); err == nil {
		val := strings.TrimSpace(wildcardStr)
		kind := "unknown"
		if val == "*" {
			kind = "wildcard"
		}
		return []model.TrustPrincipal{{
			Type:       kind,
			Value:      val,
			Actions:    cloneSlice(actions),
			Conditions: cloneConditions(conditions),
		}}, nil
	}

	// Form 2: "Principal": { "AWS": ..., "Service": ..., "Federated": ..., "CanonicalUser": ... }
	var block map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &block); err != nil {
		return nil, fmt.Errorf("unmarshal Principal object: %w", err)
	}

	var out []model.TrustPrincipal
	for key, valRaw := range block {
		values, err := parseStringOrSlice(valRaw)
		if err != nil {
			return nil, fmt.Errorf("principal.%s: %w", key, err)
		}
		for _, val := range values {
			v := strings.TrimSpace(val)
			if v == "" {
				continue
			}
			out = append(out, model.TrustPrincipal{
				Type:       classifyPrincipalType(key, v),
				Value:      v,
				Actions:    cloneSlice(actions),
				Conditions: cloneConditions(conditions),
			})
		}
	}
	return out, nil
}

func classifyPrincipalType(principalKey, value string) string {
	if value == "*" {
		return "wildcard"
	}
	switch strings.ToLower(strings.TrimSpace(principalKey)) {
	case "service":
		return "service"
	case "aws":
		return "account"
	case "federated":
		if isOIDCPrincipal(value) {
			return "oidc"
		}
		return "federated"
	case "canonicaluser":
		return "canonical_user"
	default:
		return "unknown"
	}
}

func isOIDCPrincipal(val string) bool {
	lower := strings.ToLower(val)
	if strings.Contains(lower, ":oidc-provider/") {
		return true
	}
	switch lower {
	case "accounts.google.com",
		"cognito-identity.amazonaws.com",
		"www.amazon.com",
		"graph.facebook.com",
		"appleid.apple.com",
		"token.actions.githubusercontent.com":
		return true
	default:
		return false
	}
}

// ExtractAccountID extracts a 12-digit AWS account ID from an IAM principal string
// (either a bare 12-digit account ID or an ARN such as arn:aws:iam::123456789012:root).
// Returns "" if no 12-digit AWS account ID can be determined.
func ExtractAccountID(principal string) string {
	p := strings.TrimSpace(principal)
	if isTwelveDigits(p) {
		return p
	}
	if strings.HasPrefix(p, "arn:") {
		parts := strings.Split(p, ":")
		// arn:partition:service:region:account-id:resource
		if len(parts) >= 5 && isTwelveDigits(parts[4]) {
			return parts[4]
		}
	}
	return ""
}

func isTwelveDigits(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func cloneSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneConditions(in map[string]map[string][]string) map[string]map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]map[string][]string, len(in))
	for op, inner := range in {
		innerCopy := make(map[string][]string, len(inner))
		for k, vals := range inner {
			innerCopy[k] = cloneSlice(vals)
		}
		out[op] = innerCopy
	}
	return out
}
