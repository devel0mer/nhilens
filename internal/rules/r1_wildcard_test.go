package rules

import (
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

func TestR1WildcardPermissionsTable(t *testing.T) {
	r := R1WildcardPermissions{}
	rctx := Context{Config: config.Default()}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantSeverity    model.Severity
		wantEvidenceSub string
	}{
		{
			name: "role with AWS AdministratorAccess managed policy triggers critical",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "agent-admin",
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "AdministratorAccess",
		},
		{
			name: "role with unconditioned inline Action:* Resource:* triggers critical and notes permissions boundary",
			ident: model.Identity{
				Type:                   model.TypeRole,
				Name:                   "bounded-agent",
				PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/dev-boundary",
				Policies: []model.PolicyAttachment{
					{
						Name:        "wildcard-inline",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Sid":"FullAccess","Effect":"Allow","Action":"*","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "permissions boundary",
		},
		{
			name: "conditioned Action:* Resource:* downgrades from critical to high and lists condition keys",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "cond-admin-role",
				Policies: []model.PolicyAttachment{
					{
						Name:        "cond-wildcard",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "aws:RequestedRegion",
		},
		{
			name: "unconditioned Allow NotAction on Resource:* triggers critical",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "notaction-admin",
				Policies: []model.PolicyAttachment{
					{
						Name:        "notaction-policy",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:DeleteUser"],"Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "NotAction",
		},
		{
			name: "unconditioned iam:* on Resource:* triggers critical",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "iam-wildcard-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "iam-all",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "iam:*",
		},
		{
			name: "iam:PassRole on Resource:* is owned by R6 and does not duplicate R1",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "passrole-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "pass-any-role",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "sts:AssumeRole on Resource:* is owned by R6 and does not duplicate R1",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "assume-any-role",
				Policies: []model.PolicyAttachment{
					{
						Name:        "assume-wildcard",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "programmatic user with group-inherited Action:*:* Resource:* triggers critical",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "bot-user",
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA1234567890123456"},
				Policies: []model.PolicyAttachment{
					{
						Name:        "group-wildcard",
						Kind:        "group_inline",
						SourceGroup: "admins",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*:*"],"Resource":["*"]}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: `via group "admins"`,
		},
		{
			name: "scoped service wildcard s3:* does not trigger R1",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "s3-worker",
				Policies: []model.PolicyAttachment{
					{
						Name:        "s3-all",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "Action:* on specific resource ARN does not trigger R1",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "bucket-admin",
				Policies: []model.PolicyAttachment{
					{
						Name:        "scoped-res",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::one-bucket/*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "Deny statement with Action:* Resource:* does not trigger R1",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "deny-all",
				Policies: []model.PolicyAttachment{
					{
						Name:        "explicit-deny",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "console-only human user is skipped by R1",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "human-admin",
				HasConsoleLogin: boolPtr(true),
				AgentLikelihood: model.LikelihoodNone,
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
			wantTriggered: false,
		},
		{
			name: "role with restrictive permissions boundary doc caps AdministratorAccess to medium",
			ident: model.Identity{
				Type:                   model.TypeRole,
				Name:                   "sandbox-bounded-admin",
				PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/sts-only-boundary",
				PermissionsBoundaryDoc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}`,
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityMedium,
			wantEvidenceSub: "effective access capped by permissions boundary",
		},
		{
			name: "role with permissive Action:* boundary does NOT cap AdministratorAccess",
			ident: model.Identity{
				Type:                   model.TypeRole,
				Name:                   "unbounded-admin",
				PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/allow-all-boundary",
				PermissionsBoundaryDoc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "still permits Action:* on Resource:*",
		},
		{
			name: "access key identity is not double-flagged by R1",
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
					t.Fatalf("expected R1 finding, got nil")
				}
				if f.RuleID != "R1" {
					t.Errorf("RuleID = %q, want R1", f.RuleID)
				}
				if f.Severity != tc.wantSeverity {
					t.Errorf("Severity = %q, want %q (evidence=%v)", f.Severity, tc.wantSeverity, f.Evidence)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R1 finding, got %+v", f)
			}
		})
	}

	// Verify SCP guardrail capping via Context.SCPPolicies.
	scpDoc, err := policy.ParseDocument(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	scpCtx := Context{
		Config:      config.Default(),
		SCPPolicies: []policy.NamedPolicy{{Name: "DenyIAMMutation", Parsed: scpDoc}},
	}
	adminRole := model.Identity{
		Type: model.TypeRole,
		Name: "scp-capped-admin",
		Policies: []model.PolicyAttachment{
			{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
		},
	}
	f := r.Evaluate(&adminRole, scpCtx)
	if f == nil || f.Severity != model.SeverityMedium || !strings.Contains(strings.Join(f.Evidence, " | "), `capped by SCP "DenyIAMMutation"`) {
		t.Fatalf("expected SCP-capped medium finding, got %+v", f)
	}
}
