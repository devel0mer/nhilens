package rules

import (
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR5LooseTrustTable(t *testing.T) {
	r := R5LooseTrust{}
	rctx := Context{Config: config.Default()}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantSeverity    model.Severity
		wantEvidenceSub string
	}{
		{
			name: "unconditioned Principal:* escalates to critical",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "public-role",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: `wildcard Principal "*"`,
		},
		{
			name: "Principal AWS:* constrained by aws:PrincipalOrgID does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "org-shared-role",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc1234567"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "cross-account trust without sts:ExternalId triggers R5 high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "vendor-agent-role",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "no sts:ExternalId",
		},
		{
			name: "cross-account trust WITH concrete sts:ExternalId does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "vendor-safe-role",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"ext-9f8e7d6c"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "same-account trust without ExternalId does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "internal-role",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "GitHub OIDC with wildcard sub triggers R5 high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gh-actions-wildcard",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*:*"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "wildcard sub claim",
		},
		{
			name: "GitHub OIDC with pinned sub but missing aud triggers R5 high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gh-actions-no-aud",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/nhilens:ref:refs/heads/main"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "no token.actions.githubusercontent.com:aud",
		},
		{
			name: "GitHub OIDC with missing sub escalates to critical",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gh-actions-open",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "no token.actions.githubusercontent.com:sub",
		},
		{
			name: "GitHub OIDC pinned to exact repo/branch AND aud does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gh-actions-pinned",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/nhilens:ref:refs/heads/main"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "Cognito federation without aud escalates to critical",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "cognito-open",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityCritical,
			wantEvidenceSub: "cognito-identity.amazonaws.com:aud",
		},
		{
			name: "Cognito federation with aud but allowing unauthenticated triggers high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "cognito-guest",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:11111111-2222-3333-4444-555555555555"},"ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "authenticated",
		},
		{
			name: "Cognito federation pinned to aud and authenticated does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "cognito-safe",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:11111111-2222-3333-4444-555555555555"},"ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"authenticated"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "SAML federation missing SAML:aud triggers high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "saml-no-aud",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML"}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "SAML:aud",
		},
		{
			name: "SAML federation with SAML:aud does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "saml-safe",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "Bedrock service principal without aws:SourceAccount/SourceArn triggers medium confused-deputy finding",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "bedrock-no-source-cond",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityMedium,
			wantEvidenceSub: "confused-deputy",
		},
		{
			name: "Bedrock service principal WITH scoped aws:SourceArn does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "bedrock-scoped",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:bedrock:us-east-1:123456789012:agent/*"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "GitLab OIDC with wildcard sub triggers R5 high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gitlab-wildcard",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"https://gitlab.com"},"StringLike":{"gitlab.com:sub":"project_path:mygroup/*:ref_type:branch:ref:*"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "GitLab OIDC",
		},
		{
			name: "GitLab OIDC pinned sub and aud does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "gitlab-pinned",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"sts.amazonaws.com","gitlab.com:sub":"project_path:mygroup/myproj:ref_type:branch:ref:main"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "EKS IRSA OIDC with wildcard serviceaccount sub triggers R5 high",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "eks-wildcard-sa",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890:aud":"sts.amazonaws.com"},"StringLike":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890:sub":"system:serviceaccount:default:*"}}}]}`,
			},
			wantTriggered:   true,
			wantSeverity:    model.SeverityHigh,
			wantEvidenceSub: "EKS IRSA OIDC",
		},
		{
			name: "EKS IRSA OIDC pinned to exact namespace/sa and aud does not trigger R5",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "eks-pinned-sa",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890:aud":"sts.amazonaws.com","oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890:sub":"system:serviceaccount:ai-prod:agent-sa"}}}]}`,
			},
			wantTriggered: false,
		},
		{
			name: "standard lambda service principal is not flagged for confused deputy by default",
			ident: model.Identity{
				Type:           model.TypeRole,
				Name:           "lambda-worker",
				Account:        "123456789012",
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R5 finding, got nil")
				}
				if f.RuleID != "R5" {
					t.Errorf("RuleID = %q, want R5", f.RuleID)
				}
				if f.Severity != tc.wantSeverity {
					t.Errorf("Severity = %q, want %q (evidence=%v)", f.Severity, tc.wantSeverity, f.Evidence)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R5 finding, got %+v", f)
			}
		})
	}
}
