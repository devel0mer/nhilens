package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// NamedPolicy associates an optional human-readable name with a parsed IAM/SCP policy document.
type NamedPolicy struct {
	Name   string
	Parsed *model.ParsedPolicy
}

// LoadSCPFile reads optional AWS Organizations Service Control Policies from a local JSON file.
// Supported JSON shapes:
//   - Single SCP policy document: {"Version":"2012-10-17","Statement":[...]}
//   - Array of SCP policy documents: [{"Version":...}, ...]
//   - Wrapper object: {"policies":[{"name":"...","document":{...}}]} or {"Policies":[{"Name":"...","Content":"{...}"}]}
func LoadSCPFile(filePath string) ([]NamedPolicy, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read SCP file %q: %w", filePath, err)
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}

	// Shape 1: JSON array of policy documents.
	if strings.HasPrefix(trimmed, "[") {
		var docs []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &docs); err != nil {
			return nil, fmt.Errorf("parse SCP array %q: %w", filePath, err)
		}
		out := make([]NamedPolicy, 0, len(docs))
		for i, d := range docs {
			parsed, err := ParseDocument(string(d))
			if err != nil {
				return nil, fmt.Errorf("parse SCP[%d] in %q: %w", i, filePath, err)
			}
			out = append(out, NamedPolicy{
				Name:   fmt.Sprintf("scp[%d]", i),
				Parsed: parsed,
			})
		}
		return out, nil
	}

	// Shape 2: Wrapper object with "policies" or "Policies".
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return nil, fmt.Errorf("parse SCP JSON %q: %w", filePath, err)
	}
	for _, key := range []string{"policies", "Policies"} {
		if listRaw, ok := probe[key]; ok {
			var items []struct {
				Name     string          `json:"name"`
				NameCap  string          `json:"Name"`
				Content  string          `json:"Content"`
				Document json.RawMessage `json:"document"`
			}
			if err := json.Unmarshal(listRaw, &items); err != nil {
				return nil, fmt.Errorf("parse SCP %s list in %q: %w", key, filePath, err)
			}
			out := make([]NamedPolicy, 0, len(items))
			for i, item := range items {
				name := strings.TrimSpace(item.Name)
				if name == "" {
					name = strings.TrimSpace(item.NameCap)
				}
				if name == "" {
					name = fmt.Sprintf("scp[%d]", i)
				}
				docStr := strings.TrimSpace(item.Content)
				if docStr == "" && len(item.Document) > 0 {
					docStr = strings.TrimSpace(string(item.Document))
				}
				parsed, err := ParseDocument(docStr)
				if err != nil {
					return nil, fmt.Errorf("parse SCP %q in %q: %w", name, filePath, err)
				}
				out = append(out, NamedPolicy{Name: name, Parsed: parsed})
			}
			return out, nil
		}
	}

	// Shape 3: Single policy document object.
	parsed, err := ParseDocument(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse SCP document %q: %w", filePath, err)
	}
	return []NamedPolicy{{Name: "scp", Parsed: parsed}}, nil
}

// GuardrailCapsAdminWildcard evaluates whether a permissions boundary or SCP prevents an identity
// from achieving unrestricted full administrator access (Action:"*" on Resource:"*").
//
// Per AWS IAM evaluation logic:
//   - An effective permission requires BOTH the identity policy AND the guardrail (boundary / SCP)
//     to Allow the action without an explicit Deny.
//   - Therefore, a guardrail caps full admin wildcard if it does NOT allow unconditioned Action:"*"
//     (or NotAction) on Resource:"*", OR if it explicitly Denies "*" or "iam:*".
func GuardrailCapsAdminWildcard(doc *model.ParsedPolicy) (bool, string) {
	if doc == nil || len(doc.Statements) == 0 {
		return false, ""
	}

	allowsWildcardAdmin := false
	for _, stmt := range doc.Statements {
		switch stmt.Effect {
		case "Deny":
			if len(stmt.Conditions) == 0 && ContainsWildcardResource(stmt.Resources) {
				if ContainsWildcardAction(stmt.Actions) {
					return true, "explicitly denies Action:* on Resource:*"
				}
				for _, a := range stmt.Actions {
					if strings.EqualFold(strings.TrimSpace(a), "iam:*") {
						return true, "explicitly denies iam:* on Resource:*"
					}
				}
			}
		case "Allow":
			if ContainsWildcardResource(stmt.Resources) {
				if ContainsWildcardAction(stmt.Actions) || (len(stmt.NotActions) > 0 && len(stmt.Actions) == 0) {
					allowsWildcardAdmin = true
				}
			}
		}
	}

	if !allowsWildcardAdmin {
		return true, "does not allow Action:* on Resource:*"
	}
	return false, ""
}
