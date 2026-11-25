package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR2UnusedPermissionsTable(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-10 * 24 * time.Hour)
	stale := now.Add(-120 * 24 * time.Hour)
	oldCreated := now.Add(-200 * 24 * time.Hour)
	youngCreated := now.Add(-15 * 24 * time.Hour)

	r := R2UnusedPermissions{}
	rctx := Context{Config: config.Default(), Now: now}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantEvidenceSub string
	}{
		{
			name: "role with never-accessed and stale services triggers R2",
			ident: model.Identity{
				Type:    model.TypeRole,
				Name:    "overprivileged-agent",
				Created: &oldCreated,
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "s3", LastAuthenticated: &recent},
					{ServiceNamespace: "ec2", LastAuthenticated: &stale},
					{ServiceNamespace: "iam", LastAuthenticated: nil},
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "2 of 3 granted service(s) unused",
		},
		{
			name: "newly created role still flags unused services with age context note",
			ident: model.Identity{
				Type:    model.TypeRole,
				Name:    "new-sandbox-agent",
				Created: &youngCreated,
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "dynamodb", LastAuthenticated: nil},
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "younger than the 90d stale window",
		},
		{
			name: "all granted services recently accessed does not trigger R2",
			ident: model.Identity{
				Type:    model.TypeRole,
				Name:    "least-priv-agent",
				Created: &oldCreated,
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "bedrock", LastAuthenticated: &recent},
					{ServiceNamespace: "s3", LastAuthenticated: &recent},
				},
			},
			wantTriggered: false,
		},
		{
			name: "missing Access Advisor data does not emit false finding",
			ident: model.Identity{
				Type:                     model.TypeRole,
				Name:                     "skipped-sla-role",
				ServicesLastAccessed:     nil,
				ServiceLastAccessedError: "timed out",
			},
			wantTriggered: false,
		},
		{
			name: "console-only human user is skipped by R2",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "human-user",
				HasConsoleLogin: boolPtr(true),
				AgentLikelihood: model.LikelihoodNone,
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "ec2", LastAuthenticated: nil},
				},
			},
			wantTriggered: false,
		},
		{
			name: "key identity is skipped by R2",
			ident: model.Identity{
				Type: model.TypeKey,
				Name: "AKIA1234567890123456",
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R2 finding, got nil")
				}
				if f.RuleID != "R2" || f.Severity != model.SeverityMedium {
					t.Errorf("unexpected rule metadata: %+v", f)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R2 finding, got %+v", f)
			}
		})
	}
}
