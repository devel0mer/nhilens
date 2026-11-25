package score

import (
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestScoreIdentitySaturatingCurveTable(t *testing.T) {
	defaultCfg := config.Default()

	customCfg := config.Default()
	customCfg.Scoring.Weights["high"] = 5.0
	customCfg.Scoring.AgentLikelyBonus = 2.0
	customCfg.Scoring.MaxScore = 10.0
	customCfg.Scoring.SaturationScale = 6.5

	tests := []struct {
		name         string
		cfg          *config.Config
		ident        model.Identity
		wantRaw      float64
		wantScore    float64
		wantContribs int
	}{
		{
			name: "likely agent with zero findings scores 0.0",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "clean-agent",
				AgentLikelihood: model.LikelihoodLikely,
			},
			wantRaw:      0.0,
			wantScore:    0.0,
			wantContribs: 0,
		},
		{
			name: "non-agent with one critical finding (raw 4.0 -> 4.6)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "admin-role",
				AgentLikelihood: model.LikelihoodNone,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
				},
			},
			wantRaw:      4.0,
			wantScore:    4.6,
			wantContribs: 1,
		},
		{
			name: "likely agent with critical + medium gets bonus (raw 7.5 -> 6.8)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "risky-agent",
				AgentLikelihood: model.LikelihoodLikely,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium},
				},
			},
			wantRaw:      7.5,
			wantScore:    6.8,
			wantContribs: 3,
		},
		{
			name: "possible agent does not receive likely bonus (raw 3.0 -> 3.7)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "possible-agent",
				AgentLikelihood: model.LikelihoodPossible,
				Findings: []model.Finding{
					{RuleID: "R4", RuleName: "stale-or-shared-key", Severity: model.SeverityHigh},
				},
			},
			wantRaw:      3.0,
			wantScore:    3.7,
			wantContribs: 1,
		},
		{
			name: "two criticals (R1+R5) + compound exposure (+2.0) + agent bonus preserves upper-end headroom (raw 11.5 -> 8.3)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "two-crit-agent",
				AgentLikelihood: model.LikelihoodLikely,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical},
				},
			},
			wantRaw:      11.5,
			wantScore:    8.3,
			wantContribs: 4,
		},
		{
			name: "four findings (R1+R5+R2+R3) + compound + agent bonus strictly outranks two criticals (raw 15.5 -> 9.1)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "worst-case-agent",
				AgentLikelihood: model.LikelihoodLikely,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical},
					{RuleID: "R2", RuleName: "unused-permissions", Severity: model.SeverityMedium},
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium},
				},
			},
			wantRaw:      15.5,
			wantScore:    9.1,
			wantContribs: 6,
		},
		{
			name: "R6 privesc + R5 high triggers compound exposure bonus (3+3+2=8.0 -> 7.1)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "escalate-plus-trust",
				AgentLikelihood: model.LikelihoodNone,
				Findings: []model.Finding{
					{RuleID: "R6", RuleName: "privilege-escalation-path", Severity: model.SeverityHigh},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityHigh},
				},
			},
			wantRaw:      8.0,
			wantScore:    7.1,
			wantContribs: 3,
		},
		{
			name: "R1 + medium-only R5 confused deputy does NOT add compound external trust bonus (4+2=6.0 -> 6.0)",
			cfg:  defaultCfg,
			ident: model.Identity{
				Name:            "admin-plus-medium-r5",
				AgentLikelihood: model.LikelihoodNone,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityMedium},
				},
			},
			wantRaw:      6.0,
			wantScore:    6.0,
			wantContribs: 2,
		},
		{
			name: "custom config weights and bonus apply cleanly (raw 7.0 -> 6.6)",
			cfg:  customCfg,
			ident: model.Identity{
				Name:            "custom-scored-agent",
				AgentLikelihood: model.LikelihoodLikely,
				Findings: []model.Finding{
					{RuleID: "R4", RuleName: "stale-or-shared-key", Severity: model.SeverityHigh},
				},
			},
			wantRaw:      7.0,
			wantScore:    6.6,
			wantContribs: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.ident
			ScoreIdentity(&id, tc.cfg)
			if id.RawRiskPoints != tc.wantRaw {
				t.Errorf("RawRiskPoints = %.1f, want %.1f", id.RawRiskPoints, tc.wantRaw)
			}
			if id.RiskScore != tc.wantScore {
				t.Errorf("RiskScore = %.1f, want %.1f (raw=%.1f contribs=%+v)", id.RiskScore, tc.wantScore, id.RawRiskPoints, id.ScoreContributions)
			}
			if len(id.ScoreContributions) != tc.wantContribs {
				t.Errorf("len(ScoreContributions) = %d, want %d (%+v)", len(id.ScoreContributions), tc.wantContribs, id.ScoreContributions)
			}
		})
	}
}

func TestScoreAllRankingAndExceedsFailOn(t *testing.T) {
	idents := []model.Identity{
		{
			ID:   "role-low",
			Type: model.TypeRole,
			Name: "low-risk",
			Findings: []model.Finding{
				{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium},
			},
		},
		{
			ID:              "role-two-crit",
			Type:            model.TypeRole,
			Name:            "two-crit-agent",
			AgentLikelihood: model.LikelihoodLikely,
			Findings: []model.Finding{
				{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
				{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical},
			},
		},
		{
			ID:              "role-worst",
			Type:            model.TypeRole,
			Name:            "worst-agent",
			AgentLikelihood: model.LikelihoodLikely,
			Findings: []model.Finding{
				{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical},
				{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical},
				{RuleID: "R2", RuleName: "unused-permissions", Severity: model.SeverityMedium},
				{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium},
			},
		},
		{
			ID:   "role-clean",
			Type: model.TypeRole,
			Name: "clean-role",
		},
	}

	ScoreAll(idents, config.Default())

	// Upper-end differentiation: worst-agent (8.7) strictly outranks two-crit-agent (7.7).
	if idents[0].Name != "worst-agent" || idents[1].Name != "two-crit-agent" || idents[2].Name != "low-risk" || idents[3].Name != "clean-role" {
		t.Fatalf("unexpected ranking order: %s (%.1f), %s (%.1f), %s (%.1f), %s (%.1f)",
			idents[0].Name, idents[0].RiskScore,
			idents[1].Name, idents[1].RiskScore,
			idents[2].Name, idents[2].RiskScore,
			idents[3].Name, idents[3].RiskScore,
		)
	}
	if idents[0].RiskScore <= idents[1].RiskScore {
		t.Errorf("expected worst-agent (%.1f) strictly > two-crit-agent (%.1f)", idents[0].RiskScore, idents[1].RiskScore)
	}

	if exceeded, cnt := ExceedsFailOn(idents, ""); exceeded || cnt != 0 {
		t.Errorf("empty failOn: got (%v, %d), want (false, 0)", exceeded, cnt)
	}
	if exceeded, cnt := ExceedsFailOn(idents, "critical"); !exceeded || cnt != 4 {
		t.Errorf("failOn=critical: got (%v, %d), want (true, 4)", exceeded, cnt)
	}
	if exceeded, cnt := ExceedsFailOn(idents, "medium"); !exceeded || cnt != 7 {
		t.Errorf("failOn=medium: got (%v, %d), want (true, 7)", exceeded, cnt)
	}
}
