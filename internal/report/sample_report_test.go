package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/detect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
	"github.com/devel0mer/nhilens/internal/report"
	"github.com/devel0mer/nhilens/internal/rules"
	"github.com/devel0mer/nhilens/internal/score"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// TestSampleReportHTML verifies docs/sample-report.html is present and CDN-free.
// Set NHILENS_UPDATE_SAMPLE=1 to regenerate docs/sample-report.html from synthetic data.
func TestSampleReportHTML(t *testing.T) {
	samplePath := filepath.Join("..", "..", "docs", "sample-report.html")

	if os.Getenv("NHILENS_UPDATE_SAMPLE") == "1" {
		run := buildSyntheticSampleRun()
		var buf bytes.Buffer
		if err := report.WriteHTML(&buf, run); err != nil {
			t.Fatalf("WriteHTML synthetic sample: %v", err)
		}
		if err := os.WriteFile(samplePath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", samplePath, err)
		}
	}

	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read %s: %v (run with NHILENS_UPDATE_SAMPLE=1 to generate)", samplePath, err)
	}
	html := string(raw)
	if !strings.Contains(html, "111122223333") {
		t.Errorf("expected synthetic account 111122223333 in sample report")
	}
	if strings.Contains(html, "<script src=") || strings.Contains(html, "cdn.jsdelivr.net") {
		t.Errorf("sample report must not reference external CDNs")
	}
}

func buildSyntheticSampleRun() *model.ScanRun {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	oldCreated := now.Add(-180 * 24 * time.Hour)
	midCreated := now.Add(-110 * 24 * time.Hour)
	recentUsed := now.Add(-2 * 24 * time.Hour)
	staleUsed := now.Add(-140 * 24 * time.Hour)

	run := &model.ScanRun{
		ID:                   "scan-111122223333-sample",
		AccountID:            "111122223333",
		CallerARN:            "arn:aws:iam::111122223333:role/nhilens-readonly-auditor",
		Region:               "us-east-1",
		Profile:              "sandbox-demo",
		StartedAt:            now,
		CompletedAt:          now.Add(6 * time.Second),
		SinceWindow:          "90d",
		CloudTrailStatus:     model.CloudTrailStatusOK,
		CloudTrailEventCount: 318,
		Identities: []model.Identity{
			{
				ID:                     "arn:aws:iam::111122223333:role/bedrock-support-agent",
				ARN:                    "arn:aws:iam::111122223333:role/bedrock-support-agent",
				Type:                   model.TypeRole,
				Name:                   "bedrock-support-agent",
				Path:                   "/",
				Account:                "111122223333",
				Created:                &oldCreated,
				LastUsed:               &recentUsed,
				PermissionsBoundaryARN: "arn:aws:iam::111122223333:policy/sandbox-boundary",
				Tags:                   map[string]string{"agent": "true", "env": "sandbox"},
				Owner:                  nil,
				TrustPolicyRaw:         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "bedrock", LastAuthenticated: &recentUsed},
					{ServiceNamespace: "ec2", LastAuthenticated: &staleUsed},
					{ServiceNamespace: "iam", LastAuthenticated: nil},
					{ServiceNamespace: "rds", LastAuthenticated: nil},
				},
				RecentEventNames:   []string{"bedrock:InvokeModel", "s3:GetObject"},
				ObservedUserAgents: []string{"langchain-aws/0.2.1 Boto3/1.35.0"},
				Activity30d: &model.ActivitySummary{
					WindowDays:  30,
					TotalEvents: 148,
					TopServices: []model.ActivityCount{{Name: "bedrock", Count: 112}, {Name: "s3", Count: 36}},
					TopAPIs:     []model.ActivityCount{{Name: "bedrock:InvokeModel", Count: 112}, {Name: "s3:GetObject", Count: 36}},
				},
				CloudTrailStatus: model.CloudTrailStatusOK,
			},
			{
				ID:             "arn:aws:iam::111122223333:role/gh-wildcard-deploy",
				ARN:            "arn:aws:iam::111122223333:role/gh-wildcard-deploy",
				Type:           model.TypeRole,
				Name:           "gh-wildcard-deploy",
				Path:           "/",
				Account:        "111122223333",
				Created:        &midCreated,
				LastUsed:       &recentUsed,
				Tags:           map[string]string{"owner": "devops-team"},
				Owner:          strPtr("devops-team"),
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example-org/*:*"}}}]}`,
				Policies: []model.PolicyAttachment{
					{
						Name:        "deploy-inline",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","ecr:GetAuthorizationToken"],"Resource":"*"}]}`,
					},
				},
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "s3", LastAuthenticated: &recentUsed},
					{ServiceNamespace: "ecr", LastAuthenticated: &recentUsed},
				},
				RecentEventNames: []string{"sts:AssumeRoleWithWebIdentity", "s3:PutObject"},
				CloudTrailStatus: model.CloudTrailStatusOK,
			},
			{
				ID:               "arn:aws:iam::111122223333:user/ci-bot-user",
				ARN:              "arn:aws:iam::111122223333:user/ci-bot-user",
				Type:             model.TypeUser,
				Name:             "ci-bot-user",
				Path:             "/",
				Account:          "111122223333",
				Created:          &oldCreated,
				LastUsed:         &recentUsed,
				HasConsoleLogin:  boolPtr(false),
				AccessKeyIDs:     []string{"AKIAEXAMPLE111111111"},
				Tags:             map[string]string{"owner": "platform-team"},
				Owner:            strPtr("platform-team"),
				Policies: []model.PolicyAttachment{
					{
						Name:        "ci-read-s3",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`,
					},
				},
				CloudTrailStatus: model.CloudTrailStatusOK,
			},
			{
				ID:        "arn:aws:iam::111122223333:user/ci-bot-user/access-key/AKIAEXAMPLE111111111",
				ARN:       "arn:aws:iam::111122223333:user/ci-bot-user",
				Type:      model.TypeKey,
				Name:      "AKIAEXAMPLE111111111",
				Account:   "111122223333",
				Created:   &oldCreated,
				LastUsed:  &recentUsed,
				Tags:      map[string]string{"owner": "platform-team"},
				Owner:     strPtr("platform-team"),
				SourceIPs: []string{"198.51.100.14", "203.0.113.88"},
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:     "AKIAEXAMPLE111111111",
					ParentUserName:  "ci-bot-user",
					ParentUserARN:   "arn:aws:iam::111122223333:user/ci-bot-user",
					Status:          "Active",
					LastUsedService: "s3",
					LastUsedRegion:  "us-east-1",
				},
				RecentEventNames: []string{"s3:ListBuckets", "sts:GetCallerIdentity"},
				CloudTrailStatus: model.CloudTrailStatusOK,
			},
			{
				ID:             "arn:aws:iam::111122223333:role/lambda-doc-summarizer-agent",
				ARN:            "arn:aws:iam::111122223333:role/lambda-doc-summarizer-agent",
				Type:           model.TypeRole,
				Name:           "lambda-doc-summarizer-agent",
				Path:           "/",
				Account:        "111122223333",
				Created:        &midCreated,
				LastUsed:       &recentUsed,
				Tags:           map[string]string{"owner": "ai-platform", "agent": "true"},
				Owner:          strPtr("ai-platform"),
				TrustPolicyRaw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
				Policies: []model.PolicyAttachment{
					{
						Name:        "bedrock-invoke-scoped",
						Kind:        "inline",
						RawDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"arn:aws:bedrock:us-east-1::foundation-model/*"}]}`,
					},
				},
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "bedrock", LastAuthenticated: &recentUsed},
				},
				CloudTrailStatus: model.CloudTrailStatusOK,
			},
			{
				ID:                  "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
				ARN:                 "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
				Type:                model.TypeRole,
				Name:                "AWSServiceRoleForSupport",
				Path:                "/aws-service-role/support.amazonaws.com/",
				IsServiceLinkedRole: true,
				Account:             "111122223333",
				CloudTrailStatus:    model.CloudTrailStatusOK,
			},
		},
	}

	cfg := config.Default()
	_ = policy.ParseAll(run.Identities)
	detect.ClassifyAll(run.Identities, cfg)
	rules.EvaluateAll(run.Identities, cfg, now)
	score.ScoreAll(run.Identities, cfg)

	return run
}
