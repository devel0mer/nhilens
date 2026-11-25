package rules

import (
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

func TestEvaluateAllRespectsRuleTogglesAndServiceLinkedRoles(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	makeIdentities := func() []model.Identity {
		return []model.Identity{
			{
				ID:                  "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
				Type:                model.TypeRole,
				Name:                "AWSServiceRoleForSupport",
				Path:                "/aws-service-role/support.amazonaws.com/",
				IsServiceLinkedRole: true,
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
			{
				ID:   "arn:aws:iam::123456789012:role/bedrock-agent",
				Type: model.TypeRole,
				Name: "bedrock-agent",
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
		}
	}

	// Default config: service-linked roles are excluded from findings; R1 and R3 both enabled.
	cfg := config.Default()
	idents := makeIdentities()
	EvaluateAll(idents, cfg, now)

	if len(idents[0].Findings) != 0 {
		t.Errorf("expected service-linked role excluded by default, got %+v", idents[0].Findings)
	}
	if len(idents[1].Findings) != 2 {
		t.Errorf("expected R1 + R3 findings on bedrock-agent, got %+v", idents[1].Findings)
	}

	// Opt-in service-linked roles + disable R3.
	cfg.Rules.IncludeServiceLinkedRoles = true
	cfg.Rules.Enabled["R3"] = false
	idents2 := makeIdentities()
	EvaluateAll(idents2, cfg, now)

	if len(idents2[0].Findings) != 1 || idents2[0].Findings[0].RuleID != "R1" {
		t.Errorf("expected only R1 on included SLR when R3 disabled, got %+v", idents2[0].Findings)
	}
	if len(idents2[1].Findings) != 1 || idents2[1].Findings[0].RuleID != "R1" {
		t.Errorf("expected only R1 on bedrock-agent when R3 disabled, got %+v", idents2[1].Findings)
	}
}

func TestIsNonHuman(t *testing.T) {
	tests := []struct {
		name  string
		ident model.Identity
		want  bool
	}{
		{name: "role is non-human", ident: model.Identity{Type: model.TypeRole}, want: true},
		{name: "key is non-human", ident: model.Identity{Type: model.TypeKey}, want: true},
		{name: "console-only human user excluded", ident: model.Identity{Type: model.TypeUser, HasConsoleLogin: boolPtr(true), AgentLikelihood: model.LikelihoodNone}, want: false},
		{name: "console user with access key is non-human", ident: model.Identity{Type: model.TypeUser, HasConsoleLogin: boolPtr(true), AccessKeyIDs: []string{"AKIA123"}}, want: true},
		{name: "user without console login is non-human", ident: model.Identity{Type: model.TypeUser, HasConsoleLogin: boolPtr(false)}, want: true},
		{name: "user with unknown console login is audited", ident: model.Identity{Type: model.TypeUser, HasConsoleLogin: nil}, want: true},
		{name: "console user with agent signal is audited", ident: model.Identity{Type: model.TypeUser, HasConsoleLogin: boolPtr(true), AgentLikelihood: model.LikelihoodPossible}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNonHuman(&tc.ident); got != tc.want {
				t.Errorf("IsNonHuman() = %v, want %v", got, tc.want)
			}
		})
	}
}
