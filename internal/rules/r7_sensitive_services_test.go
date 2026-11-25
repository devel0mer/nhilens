package rules

import (
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR7SensitiveServiceWildcardTable(t *testing.T) {
	r := R7SensitiveServiceWildcard{}
	rctx := Context{Config: config.Default()}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantSeverity    model.Severity
		wantEvidenceSub string
	}{
		{
			name: "unconditioned secretsmanager:GetSecretValue on * triggers high",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "secret-reader-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "all-secrets",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "secretsmanager:GetSecretValue",
		},
		{
			name: "bedrock:* on * triggers high",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "broad-bedrock-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "bedrock-all",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"bedrock:*","Resource":"*"}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "bedrock:*",
		},
		{
			name: "conditioned kms:* on * downgrades from high to medium",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "cond-kms",
				Policies: []model.PolicyAttachment{
					{
						Name:        "kms-cond",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}}}]}`,
					},
				},
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityMedium,
			wantEvidenceSub: "kms:ViaService",
		},
		{
			name: "scoped secret ARN and scoped bedrock:InvokeModel do not trigger R7",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "scoped-agent",
				Policies: []model.PolicyAttachment{
					{
						Name:        "scoped",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:agent/*"},{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"arn:aws:bedrock:us-east-1::foundation-model/*"}]}`,
					},
				},
			},
			wantTriggered: false,
		},
		{
			name: "AdministratorAccess and Action:* are skipped by R7 (owned by R1)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "admin-role",
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
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
					t.Fatalf("expected R7 finding, got nil")
				}
				if f.RuleID != "R7" || f.Severity != tc.wantSeverity {
					t.Errorf("got (%s, %s), want (R7, %s)", f.RuleID, f.Severity, tc.wantSeverity)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R7 finding, got %+v", f)
			}
		})
	}
}
