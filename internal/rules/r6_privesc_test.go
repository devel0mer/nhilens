package rules

import (
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR6PrivilegeEscalationTable(t *testing.T) {
	r := R6PrivilegeEscalation{}
	rctx := Context{Config: config.Default()}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantSeverity    model.Severity
		wantEvidenceSub string
	}{
		{
			name: "unconditioned iam:AttachRolePolicy on Resource:* triggers critical",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "escalating-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "iam-attach",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "iam:attachrolepolicy",
		},
		{
			name: "conditioned iam:CreateAccessKey downgrades from critical to high",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "cond-key-creator",
				Policies: []model.PolicyAttachment{
					{
						Name:        "cond-create-key",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/env":"sandbox"}}}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "aws:PrincipalTag/env",
		},
		{
			name: "iam:PassRole on * alone triggers high",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "passrole-only",
				Policies: []model.PolicyAttachment{
					{
						Name:        "passrole",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "iam:PassRole",
		},
		{
			name: "iam:PassRole on * combined with lambda:CreateFunction escalates to critical",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "passrole-plus-lambda",
				Policies: []model.PolicyAttachment{
					{
						Name:        "passrole-lambda",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "lambda:createfunction",
		},
		{
			name: "iam:PassRole on * constrained by iam:PassedToService does not trigger R6",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "scoped-passrole",
				Policies: []model.PolicyAttachment{
					{
						Name:        "scoped",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"bedrock.amazonaws.com"}}}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "sts:AssumeRole on Resource:* triggers high",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "lateral-chainer",
				Policies: []model.PolicyAttachment{
					{
						Name:        "assume-any",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "sts:AssumeRole",
		},
		{
			name: "AdministratorAccess and iam:* are skipped by R6 (already owned by R1)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "full-admin",
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
					{Name: "iam-all", Kind: "inline", RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`},
				},
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R6 finding, got nil")
				}
				if f.RuleID != "R6" || f.Severity != tc.wantSeverity {
					t.Errorf("got (%s, %s), want (R6, %s) evidence=%v", f.RuleID, f.Severity, tc.wantSeverity, f.Evidence)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R6 finding, got %+v", f)
			}
		})
	}
}
