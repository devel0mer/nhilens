package policy

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestParseDocumentTable(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantStmts int
		wantErr   bool
		check     func(t *testing.T, p *model.ParsedPolicy)
	}{
		{
			name: "single statement object with scalar action and resource",
			raw: `{
				"Version": "2012-10-17",
				"Statement": {
					"Sid": "SingleAllow",
					"Effect": "allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::my-bucket/*"
				}
			}`,
			wantStmts: 1,
			check: func(t *testing.T, p *model.ParsedPolicy) {
				s := p.Statements[0]
				if s.Effect != "Allow" {
					t.Errorf("Effect = %q, want Allow", s.Effect)
				}
				if !reflect.DeepEqual(s.Actions, []string{"s3:GetObject"}) {
					t.Errorf("Actions = %v", s.Actions)
				}
				if !reflect.DeepEqual(s.Resources, []string{"arn:aws:s3:::my-bucket/*"}) {
					t.Errorf("Resources = %v", s.Resources)
				}
			},
		},
		{
			name: "array statements with conditions of bool, number, and string slice",
			raw: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:PutObject"],
						"Resource": "*",
						"Condition": {
							"Bool": {"aws:SecureTransport": true},
							"NumericLessThanEquals": {"s3:max-keys": 100},
							"StringEquals": {"aws:PrincipalTag/env": ["dev", "sandbox"]}
						}
					},
					{
						"Effect": "Deny",
						"NotAction": "sts:GetCallerIdentity",
						"NotResource": "arn:aws:s3:::safe/*"
					}
				]
			}`,
			wantStmts: 2,
			check: func(t *testing.T, p *model.ParsedPolicy) {
				cond := p.Statements[0].Conditions
				if !reflect.DeepEqual(cond["Bool"]["aws:SecureTransport"], []string{"true"}) {
					t.Errorf("unexpected Bool condition: %v", cond["Bool"])
				}
				if !reflect.DeepEqual(cond["NumericLessThanEquals"]["s3:max-keys"], []string{"100"}) {
					t.Errorf("unexpected Numeric condition: %v", cond["NumericLessThanEquals"])
				}
				if !reflect.DeepEqual(cond["StringEquals"]["aws:PrincipalTag/env"], []string{"dev", "sandbox"}) {
					t.Errorf("unexpected StringEquals condition: %v", cond["StringEquals"])
				}
				if !reflect.DeepEqual(p.Statements[1].NotActions, []string{"sts:GetCallerIdentity"}) {
					t.Errorf("unexpected NotActions: %v", p.Statements[1].NotActions)
				}
			},
		},
		{
			name:      "url encoded policy document",
			raw:       url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			wantStmts: 1,
			check: func(t *testing.T, p *model.ParsedPolicy) {
				if !ContainsWildcardAction(p.Statements[0].Actions) || !ContainsWildcardResource(p.Statements[0].Resources) {
					t.Errorf("expected wildcard action & resource")
				}
			},
		},
		{
			name:    "malformed json fails cleanly",
			raw:     `{"Version": "2012-10-17", "Statement": [`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDocument(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got.Statements) != tc.wantStmts {
				t.Fatalf("got %d statements, want %d", len(got.Statements), tc.wantStmts)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestParseTrustPolicyTable(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantCount int
		check     func(t *testing.T, principals []model.TrustPrincipal)
	}{
		{
			name: "wildcard string principal",
			raw: `{
				"Version": "2012-10-17",
				"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
			}`,
			wantCount: 1,
			check: func(t *testing.T, ps []model.TrustPrincipal) {
				if ps[0].Type != "wildcard" || ps[0].Value != "*" {
					t.Errorf("got %+v, want wildcard *", ps[0])
				}
			},
		},
		{
			name: "AWS wildcard principal",
			raw: `{
				"Version": "2012-10-17",
				"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]
			}`,
			wantCount: 1,
			check: func(t *testing.T, ps []model.TrustPrincipal) {
				if ps[0].Type != "wildcard" || ps[0].Value != "*" {
					t.Errorf("got %+v, want wildcard *", ps[0])
				}
			},
		},
		{
			name: "github actions OIDC trust with sub condition and deny ignored",
			raw: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
						"Action": "sts:AssumeRoleWithWebIdentity",
						"Condition": {
							"StringLike": {
								"token.actions.githubusercontent.com:sub": "repo:acme/*:*"
							}
						}
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantCount: 1,
			check: func(t *testing.T, ps []model.TrustPrincipal) {
				if ps[0].Type != "oidc" {
					t.Errorf("Type = %q, want oidc", ps[0].Type)
				}
				gotSub := ps[0].Conditions["StringLike"]["token.actions.githubusercontent.com:sub"]
				if !reflect.DeepEqual(gotSub, []string{"repo:acme/*:*"}) {
					t.Errorf("unexpected sub condition: %v", gotSub)
				}
			},
		},
		{
			name: "multi-service and cross-account with external id",
			raw: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"Service": ["lambda.amazonaws.com", "bedrock.amazonaws.com"]},
						"Action": "sts:AssumeRole"
					},
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
						"Action": "sts:AssumeRole",
						"Condition": {"StringEquals": {"sts:ExternalId": "secret-ext-id"}}
					}
				]
			}`,
			wantCount: 3,
			check: func(t *testing.T, ps []model.TrustPrincipal) {
				// Sorted by Type, Value: account first, then service.
				if ps[0].Type != "account" || ExtractAccountID(ps[0].Value) != "999999999999" {
					t.Errorf("unexpected account principal: %+v", ps[0])
				}
				if ps[1].Type != "service" || ps[1].Value != "bedrock.amazonaws.com" {
					t.Errorf("unexpected service[0]: %+v", ps[1])
				}
				if ps[2].Type != "service" || ps[2].Value != "lambda.amazonaws.com" {
					t.Errorf("unexpected service[1]: %+v", ps[2])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTrustPolicy(tc.raw)
			if err != nil {
				t.Fatalf("ParseTrustPolicy error: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Fatalf("got %d principals, want %d (%+v)", len(got), tc.wantCount, got)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestParseAndSummarizeIdentity(t *testing.T) {
	ident := &model.Identity{
		ID:             "arn:aws:iam::123456789012:role/agent-runner",
		Type:           model.TypeRole,
		Name:           "agent-runner",
		TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		Policies: []model.PolicyAttachment{
			{
				Name:        "scoped-inline",
				Kind:        "inline",
				RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","dynamodb:*"],"Resource":"*"}]}`,
			},
			{
				Name:        "corrupt-inline",
				Kind:        "inline",
				RawDocument: `{bad json`,
			},
		},
	}

	warnings := ParseAndSummarize(ident)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 non-fatal parse warning, got %v", warnings)
	}
	if len(ident.TrustPrincipals) != 1 || ident.TrustPrincipals[0].Value != "ecs-tasks.amazonaws.com" {
		t.Errorf("unexpected TrustPrincipals: %+v", ident.TrustPrincipals)
	}
	if ident.EffectiveActions.HasAdminWildcard {
		t.Errorf("expected HasAdminWildcard=false for scoped policy")
	}
	if !reflect.DeepEqual(ident.EffectiveActions.Services, []string{"dynamodb", "s3"}) {
		t.Errorf("Services = %v, want [dynamodb s3]", ident.EffectiveActions.Services)
	}
	if !reflect.DeepEqual(ident.EffectiveActions.WildcardServices, []string{"dynamodb"}) {
		t.Errorf("WildcardServices = %v, want [dynamodb]", ident.EffectiveActions.WildcardServices)
	}

	// Attaching AdministratorAccess flips HasAdminWildcard to true even without RawDocument.
	ident.Policies = append(ident.Policies, model.PolicyAttachment{
		Name: "AdministratorAccess",
		ARN:  "arn:aws:iam::aws:policy/AdministratorAccess",
		Kind: "managed",
	})
	_ = ParseAndSummarize(ident)
	if !ident.EffectiveActions.HasAdminWildcard {
		t.Errorf("expected HasAdminWildcard=true when AdministratorAccess is attached")
	}
}

func TestExtractAccountID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"123456789012", "123456789012"},
		{"arn:aws:iam::123456789012:root", "123456789012"},
		{"arn:aws-us-gov:iam::999988887777:role/external", "999988887777"},
		{"*", ""},
		{"lambda.amazonaws.com", ""},
		{"12345", ""},
	}
	for _, tc := range cases {
		if got := ExtractAccountID(tc.in); got != tc.want {
			t.Errorf("ExtractAccountID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
