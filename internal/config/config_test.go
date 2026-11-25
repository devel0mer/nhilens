package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate() unexpected error: %v", err)
	}
	if cfg.Rules.StaleDays != 90 {
		t.Errorf("expected default stale_days=90, got %d", cfg.Rules.StaleDays)
	}
	if cfg.Scoring.MaxScore != 10.0 {
		t.Errorf("expected default max_score=10.0, got %v", cfg.Scoring.MaxScore)
	}
	if len(cfg.CompiledRolePatterns()) == 0 {
		t.Errorf("expected compiled role name patterns to be populated")
	}
	if len(cfg.CompiledAINameTokens()) == 0 {
		t.Errorf("expected compiled AI name tokens to be populated")
	}
	if len(cfg.CompiledAINameExclusions()) == 0 {
		t.Errorf("expected compiled AI name exclusions to be populated")
	}
	for _, id := range []string{"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"} {
		if !cfg.IsRuleEnabled(id) {
			t.Errorf("expected rule %s enabled by default", id)
		}
	}
}

func TestLoadEmptyPathReturnsDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") unexpected error: %v", err)
	}
	if cfg.AWS.Region != "us-east-1" {
		t.Errorf("expected default region us-east-1, got %q", cfg.AWS.Region)
	}
}

func TestLoadExampleYAML(t *testing.T) {
	examplePath := filepath.Join("..", "..", "docs", "nhilens.example.yaml")
	cfg, err := Load(examplePath)
	if err != nil {
		t.Fatalf("Load(%q) unexpected error: %v", examplePath, err)
	}
	if cfg.Rules.StaleDays != 90 {
		t.Errorf("expected stale_days=90, got %d", cfg.Rules.StaleDays)
	}
	if len(cfg.CompiledRolePatterns()) == 0 {
		t.Errorf("expected compiled regexes from example yaml")
	}
	if len(cfg.CompiledAINameTokens()) == 0 {
		t.Errorf("expected compiled AI name tokens from example yaml")
	}
	if len(cfg.CompiledAINameExclusions()) == 0 {
		t.Errorf("expected compiled AI name exclusions from example yaml")
	}
}

func TestLoadOverridesAndValidation(t *testing.T) {
	dir := t.TempDir()

	validFile := filepath.Join(dir, "valid.yaml")
	validContent := `
aws:
  region: eu-west-1
agent_detection:
  ai_name_tokens:
    - assistant
    - support-agent
  ai_name_exclusions:
    - jenkins
    - acme-backup
rules:
  stale_days: 60
  enabled:
    R2: false
scoring:
  agent_likely_bonus: 2.0
`
	if err := os.WriteFile(validFile, []byte(validContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(validFile)
	if err != nil {
		t.Fatalf("Load valid yaml failed: %v", err)
	}
	if cfg.AWS.Region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %q", cfg.AWS.Region)
	}
	if cfg.Rules.StaleDays != 60 {
		t.Errorf("expected stale_days=60, got %d", cfg.Rules.StaleDays)
	}
	if cfg.IsRuleEnabled("R2") {
		t.Errorf("expected R2 disabled")
	}
	if !cfg.IsRuleEnabled("R1") {
		t.Errorf("expected R1 to remain enabled via defaults")
	}
	if cfg.Scoring.AgentLikelyBonus != 2.0 {
		t.Errorf("expected agent_likely_bonus=2.0, got %v", cfg.Scoring.AgentLikelyBonus)
	}
	if len(cfg.CompiledAINameTokens()) != 2 || cfg.CompiledAINameTokens()[0].Token != "assistant" {
		t.Errorf("expected 2 custom compiled AI name tokens starting with assistant, got %+v", cfg.CompiledAINameTokens())
	}
	if len(cfg.CompiledAINameExclusions()) != 2 || cfg.CompiledAINameExclusions()[1].Token != "acme-backup" {
		t.Errorf("expected 2 custom compiled AI name exclusions ending with acme-backup, got %+v", cfg.CompiledAINameExclusions())
	}

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "invalid regex",
			yaml: "agent_detection:\n  role_name_patterns:\n    - \"[unclosed\"\n",
		},
		{
			name: "non-positive stale_days",
			yaml: "rules:\n  stale_days: 0\n",
		},
		{
			name: "negative scoring weight",
			yaml: "scoring:\n  weights:\n    high: -1.0\n",
		},
		{
			name: "unknown top-level field",
			yaml: "unknown_section: true\n",
		},
		{
			name: "min_shared_key_ips below 2",
			yaml: "rules:\n  min_shared_key_ips: 1\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
