package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/store"
)

type goldenIdentityExpectation struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	AgentLikelihood string   `json:"agent_likelihood"`
	AgentConfidence int      `json:"agent_confidence"`
	WorkloadKind    string   `json:"workload_kind,omitempty"`
	AgentProfile    string   `json:"agent_profile,omitempty"`
	RiskScore       float64  `json:"risk_score"`
	RawRiskPoints   float64  `json:"raw_risk_points"`
	Findings        []string `json:"findings,omitempty"`
}

// TestGoldenAnonymizedAccountRegression verifies deterministic end-to-end classification,
// rule evaluation (R1–R8 + permissions boundary intersection), and scoring against a checked-in
// golden snapshot (internal/cli/testdata/golden_summary.json).
func TestGoldenAnonymizedAccountRegression(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	old := now.Add(-120 * 24 * time.Hour)
	unused := now.Add(-20 * 24 * time.Hour)

	boundaryARN := "arn:aws:iam::999900001111:policy/sts-only-boundary"
	boundaryDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}`

	iamMock := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			Policies: []iamtypes.ManagedPolicyDetail{
				{
					Arn:              aws.String(boundaryARN),
					PolicyName:       aws.String("sts-only-boundary"),
					DefaultVersionId: aws.String("v1"),
					PolicyVersionList: []iamtypes.PolicyVersion{
						{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: aws.String(url.QueryEscape(boundaryDoc))},
					},
				},
			},
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:                      aws.String("arn:aws:iam::999900001111:role/bedrock-privesc-agent"),
					RoleName:                 aws.String("bedrock-privesc-agent"),
					Path:                     aws.String("/"),
					CreateDate:               &old,
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)),
					RolePolicyList: []iamtypes.PolicyDetail{
						{
							PolicyName:     aws.String("escalate-and-secrets"),
							PolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction","secretsmanager:GetSecretValue","bedrock:InvokeModel"],"Resource":"*"}]}`)),
						},
					},
				},
				{
					Arn:                      aws.String("arn:aws:iam::999900001111:role/bounded-admin-worker"),
					RoleName:                 aws.String("bounded-admin-worker"),
					Path:                     aws.String("/"),
					CreateDate:               &old,
					PermissionsBoundary:      &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(boundaryARN)},
					Tags:                     []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("secops")}},
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{
						{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
					},
				},
			},
			UserDetailList: []iamtypes.UserDetail{
				{
					Arn:        aws.String("arn:aws:iam::999900001111:user/ci-dual-key-bot"),
					UserName:   aws.String("ci-dual-key-bot"),
					CreateDate: &old,
					Tags:       []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("devops")}},
				},
			},
		},
		keysByUser: map[string][]iamtypes.AccessKeyMetadata{
			"ci-dual-key-bot": {
				{AccessKeyId: aws.String("AKIA1111111111111111"), UserName: aws.String("ci-dual-key-bot"), Status: iamtypes.StatusTypeActive, CreateDate: &unused},
				{AccessKeyId: aws.String("AKIA2222222222222222"), UserName: aws.String("ci-dual-key-bot"), Status: iamtypes.StatusTypeActive, CreateDate: &unused},
			},
		},
	}

	deps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "999900001111", arn: "arn:aws:iam::999900001111:role/nhilens-ro"}, iamMock, &fakeCloudTrail{}, nil
		},
		Now: func() time.Time { return now },
		CollectorHooks: func(opts *collect.Options) {
			opts.Sleep = func(_ context.Context, _ time.Duration) error { return nil }
		},
	}

	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := ExecuteWithDeps([]string{"scan", "--out", outDir, "--max-events", "0", "--skip-service-last-accessed", "--format", "json"}, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("golden scan failed (code=%d): %s", code, stderr.String())
	}

	var run model.ScanRun
	if err := json.Unmarshal(stdout.Bytes(), &run); err != nil {
		t.Fatalf("unmarshal golden scan JSON: %v", err)
	}

	got := make([]goldenIdentityExpectation, 0, len(run.Identities))
	for _, id := range run.Identities {
		fids := make([]string, 0, len(id.Findings))
		for _, f := range id.Findings {
			fids = append(fids, fmt.Sprintf("%s:%s", f.RuleID, f.Severity))
		}
		got = append(got, goldenIdentityExpectation{
			Name:            id.Name,
			Type:            string(id.Type),
			AgentLikelihood: string(id.AgentLikelihood),
			AgentConfidence: id.AgentConfidence,
			WorkloadKind:    id.WorkloadKind,
			AgentProfile:    id.AgentProfile,
			RiskScore:       id.RiskScore,
			RawRiskPoints:   id.RawRiskPoints,
			Findings:        fids,
		})
	}

	goldenPath := filepath.Join("testdata", "golden_summary.json")
	if os.Getenv("NHILENS_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatal(err)
		}
		enc, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(goldenPath, append(enc, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	wantRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file %s: %v", goldenPath, err)
	}
	var want []goldenIdentityExpectation
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatalf("parse golden file: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("golden regression mismatch!\nGOT:\n%s\nWANT:\n%s", string(gotJSON), string(wantRaw))
	}
}

type paginatedScaleIAM struct {
	pages []*iam.GetAccountAuthorizationDetailsOutput
}

func (p *paginatedScaleIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	idx := 0
	if in != nil && in.Marker != nil {
		_, _ = fmt.Sscanf(*in.Marker, "page-%d", &idx)
	}
	return p.pages[idx], nil
}

func (p *paginatedScaleIAM) GetLoginProfile(_ context.Context, _ *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	return nil, &iamtypes.NoSuchEntityException{Message: aws.String("not found")}
}

func (p *paginatedScaleIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}

func (p *paginatedScaleIAM) GetAccessKeyLastUsed(_ context.Context, _ *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{}, nil
}

func (p *paginatedScaleIAM) GenerateServiceLastAccessedDetails(_ context.Context, _ *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("unused")}, nil
}

func (p *paginatedScaleIAM) GetServiceLastAccessedDetails(_ context.Context, _ *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted}, nil
}

// TestLargeAccountPaginationAndScale exercises 600 paginated IAM roles through the full scan + SQLite pipeline.
func TestLargeAccountPaginationAndScale(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	const (
		numPages     = 6
		rolesPerPage = 100
	)

	pages := make([]*iam.GetAccountAuthorizationDetailsOutput, numPages)
	trustDoc := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	inlineDoc := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::demo/*"}]}`)

	for p := 0; p < numPages; p++ {
		roles := make([]iamtypes.RoleDetail, rolesPerPage)
		for i := 0; i < rolesPerPage; i++ {
			idx := p*rolesPerPage + i
			name := fmt.Sprintf("workload-role-%04d", idx)
			arn := fmt.Sprintf("arn:aws:iam::123456789012:role/%s", name)
			roles[i] = iamtypes.RoleDetail{
				Arn:                      aws.String(arn),
				RoleName:                 aws.String(name),
				Path:                     aws.String("/"),
				CreateDate:               &now,
				AssumeRolePolicyDocument: aws.String(trustDoc),
				RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: aws.String("read-s3"), PolicyDocument: aws.String(inlineDoc)}},
			}
		}
		out := &iam.GetAccountAuthorizationDetailsOutput{RoleDetailList: roles}
		if p < numPages-1 {
			out.IsTruncated = true
			out.Marker = aws.String(fmt.Sprintf("page-%d", p+1))
		}
		pages[p] = out
	}

	deps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "123456789012", arn: "arn:aws:iam::123456789012:role/nhilens-ro"}, &paginatedScaleIAM{pages: pages}, &fakeCloudTrail{}, nil
		},
		Now: func() time.Time { return now },
	}

	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := ExecuteWithDeps([]string{"scan", "--out", outDir, "--max-events", "0", "--skip-service-last-accessed", "--format", "sarif"}, &stdout, &stderr, deps)
	elapsed := time.Since(start)
	if code != 0 {
		t.Fatalf("large account scan failed (code=%d): %s", code, stderr.String())
	}

	st, err := store.Open(filepath.Join(outDir, "nhilens.db"))
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer func() { _ = st.Close() }()

	saved, err := st.LoadLatestScan(context.Background())
	if err != nil {
		t.Fatalf("LoadLatestScan: %v", err)
	}
	if len(saved.Identities) != numPages*rolesPerPage {
		t.Fatalf("expected %d roles persisted, got %d", numPages*rolesPerPage, len(saved.Identities))
	}
	t.Logf("600 paginated roles scanned, scored, persisted to SQLite, and exported to SARIF in %s", elapsed)
}
