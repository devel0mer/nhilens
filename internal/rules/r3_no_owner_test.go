package rules

import (
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR3NoOwnerTable(t *testing.T) {
	r := R3NoOwner{}
	rctx := Context{Config: config.Default()}

	tests := []struct {
		name          string
		ident         model.Identity
		wantTriggered bool
		wantRemedSub  string
	}{
		{
			name: "unowned role triggers R3 with tag-role remediation",
			ident: model.Identity{
				Type:  model.TypeRole,
				Name:  "orphan-agent-role",
				Owner: nil,
				Tags:  map[string]string{"env": "sandbox"},
			},
			wantTriggered: true,
			wantRemedSub:  "tag-role",
		},
		{
			name: "unowned programmatic user triggers R3 with tag-user remediation",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "orphan-bot",
				Owner:           nil,
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA111"},
			},
			wantTriggered: true,
			wantRemedSub:  "tag-user",
		},
		{
			name: "role with owner tag does not trigger R3",
			ident: model.Identity{
				Type:  model.TypeRole,
				Name:  "owned-agent-role",
				Owner: strPtr("ml-platform"),
				Tags:  map[string]string{"owner": "ml-platform"},
			},
			wantTriggered: false,
		},
		{
			name: "blank whitespace owner still triggers R3",
			ident: model.Identity{
				Type:  model.TypeRole,
				Name:  "blank-owner-role",
				Owner: strPtr("   "),
			},
			wantTriggered: true,
			wantRemedSub:  "tag-role",
		},
		{
			name: "console-only human user is skipped by R3",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "jane",
				Owner:           nil,
				HasConsoleLogin: boolPtr(true),
				AgentLikelihood: model.LikelihoodNone,
			},
			wantTriggered: false,
		},
		{
			name: "access key identity is skipped by R3 (keys cannot be tagged in AWS)",
			ident: model.Identity{
				Type:  model.TypeKey,
				Name:  "AKIA111",
				Owner: nil,
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R3 finding, got nil")
				}
				if f.RuleID != "R3" || f.Severity != model.SeverityMedium {
					t.Errorf("unexpected rule metadata: %+v", f)
				}
				if tc.wantRemedSub != "" && !strings.Contains(f.Remediation, tc.wantRemedSub) {
					t.Errorf("expected remediation containing %q, got %q", tc.wantRemedSub, f.Remediation)
				}
			} else if f != nil {
				t.Fatalf("expected no R3 finding, got %+v", f)
			}
		})
	}
}
