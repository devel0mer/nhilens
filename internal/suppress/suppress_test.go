package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestLoadValidationAndExample(t *testing.T) {
	example := filepath.Join("..", "..", "docs", "nhilens-ignore.example.yaml")
	f, err := Load(example)
	if err != nil {
		t.Fatalf("Load(%q) unexpected error: %v", example, err)
	}
	if len(f.Suppressions) != 2 {
		t.Fatalf("expected 2 example suppressions, got %d", len(f.Suppressions))
	}

	dir := t.TempDir()
	invalidCases := []struct {
		name string
		yaml string
	}{
		{name: "missing reason", yaml: "suppressions:\n  - rule_id: R3\n    identity: my-role\n"},
		{name: "missing rule_id", yaml: "suppressions:\n  - identity: my-role\n    reason: ok\n"},
		{name: "missing identity", yaml: "suppressions:\n  - rule_id: R3\n    reason: ok\n"},
		{name: "bad expires", yaml: "suppressions:\n  - rule_id: R3\n    identity: my-role\n    reason: ok\n    expires: not-a-date\n"},
		{name: "bad glob", yaml: "suppressions:\n  - rule_id: R3\n    identity: \"[unclosed\"\n    reason: ok\n"},
		{name: "unknown field", yaml: "extra_key: true\n"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestApplySuppressionsAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	ignorePath := filepath.Join(dir, ".nhilens-ignore.yaml")
	yamlContent := `
suppressions:
  - rule_id: R3
    identity: "arn:aws:iam::123456789012:role/legacy-*"
    reason: "Scheduled retirement Q1"
    expires: "2027-03-01"
  - rule_id: R1
    identity: "expired-admin"
    reason: "Temporary migration waiver"
    expires: "2026-10-01"
`
	if err := os.WriteFile(ignorePath, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	sf, err := Load(ignorePath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	run := &model.ScanRun{
		Identities: []model.Identity{
			{
				ID:   "arn:aws:iam::123456789012:role/legacy-sync",
				ARN:  "arn:aws:iam::123456789012:role/legacy-sync",
				Type: model.TypeRole,
				Name: "legacy-sync",
				Findings: []model.Finding{
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium},
					{RuleID: "R2", RuleName: "unused-permissions", Severity: model.SeverityMedium},
				},
			},
			{
				ID:   "arn:aws:iam::123456789012:role/expired-admin",
				ARN:  "arn:aws:iam::123456789012:role/expired-admin",
				Type: model.TypeRole,
				Name: "expired-admin",
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
				},
			},
		},
	}

	count, expiredWarns := Apply(run, sf, now)
	if count != 1 || run.SuppressedFindingCount != 1 {
		t.Fatalf("expected 1 active suppression, got %d (run=%d)", count, run.SuppressedFindingCount)
	}
	if len(run.Identities[0].Findings) != 1 || run.Identities[0].Findings[0].RuleID != "R2" {
		t.Errorf("expected only R2 remaining on legacy-sync, got %+v", run.Identities[0].Findings)
	}
	if len(run.Identities[0].SuppressedFindings) != 1 || run.Identities[0].SuppressedFindings[0].Reason != "Scheduled retirement Q1" {
		t.Errorf("expected R3 moved to SuppressedFindings with reason, got %+v", run.Identities[0].SuppressedFindings)
	}

	// Expired suppression must NOT suppress R1 and must emit a clear warning.
	if len(run.Identities[1].Findings) != 1 || run.Identities[1].Findings[0].RuleID != "R1" {
		t.Errorf("expired suppression must not hide R1, got %+v", run.Identities[1].Findings)
	}
	if len(expiredWarns) != 1 || !strings.Contains(expiredWarns[0], "suppression expired on 2026-10-01") {
		t.Errorf("expected expired suppression warning, got %v", expiredWarns)
	}
}
