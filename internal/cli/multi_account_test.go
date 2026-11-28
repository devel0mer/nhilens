package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/store"
)

type fakeOrgClient struct {
	orgID            string
	masterAccountID  string
	accounts         []orgtypes.Account
	parents          map[string][]string
	policiesByTarget map[string][]orgtypes.PolicySummary
	policyContent    map[string]string
}

func (f *fakeOrgClient) DescribeOrganization(_ context.Context, _ *organizations.DescribeOrganizationInput, _ ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{
		Organization: &orgtypes.Organization{
			Id:              aws.String(f.orgID),
			MasterAccountId: aws.String(f.masterAccountID),
		},
	}, nil
}

func (f *fakeOrgClient) ListAccounts(_ context.Context, _ *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	return &organizations.ListAccountsOutput{Accounts: f.accounts}, nil
}

func (f *fakeOrgClient) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	ids := f.parents[aws.ToString(in.ChildId)]
	out := make([]orgtypes.Parent, 0, len(ids))
	for _, id := range ids {
		out = append(out, orgtypes.Parent{Id: aws.String(id)})
	}
	return &organizations.ListParentsOutput{Parents: out}, nil
}

func (f *fakeOrgClient) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	return &organizations.ListPoliciesForTargetOutput{Policies: f.policiesByTarget[aws.ToString(in.TargetId)]}, nil
}

func (f *fakeOrgClient) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	return &organizations.DescribePolicyOutput{
		Policy: &orgtypes.Policy{Content: aws.String(f.policyContent[aws.ToString(in.PolicyId)])},
	}, nil
}

func TestScanOrgAutoSCPPartialAccountFailureAndSQLiteReload(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	old := now.Add(-120 * 24 * time.Hour)

	// Management account (111111111111): has a clean owned role.
	mgmtIAM := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:        aws.String("arn:aws:iam::111111111111:role/org-auditor"),
					RoleName:   aws.String("org-auditor"),
					Path:       aws.String("/"),
					CreateDate: &old,
					Tags:       []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("secops")}},
				},
			},
		},
	}

	// Member account (222222222222): has an AdministratorAccess Bedrock agent,
	// BUT its OU attaches an SCP denying iam:* — auto SCP discovery must downgrade R1 from critical to medium!
	prodIAM := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:                      aws.String("arn:aws:iam::222222222222:role/bedrock-prod-agent"),
					RoleName:                 aws.String("bedrock-prod-agent"),
					Path:                     aws.String("/"),
					CreateDate:               &old,
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{
						{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
					},
				},
			},
		},
	}

	orgMock := &fakeOrgClient{
		orgID:           "o-testorg123",
		masterAccountID: "111111111111",
		accounts: []orgtypes.Account{
			{Id: aws.String("111111111111"), Name: aws.String("management"), Status: orgtypes.AccountStatusActive},
			{Id: aws.String("222222222222"), Name: aws.String("prod-ai"), Status: orgtypes.AccountStatusActive},
			{Id: aws.String("333333333333"), Name: aws.String("staging-denied"), Status: orgtypes.AccountStatusActive},
			{Id: aws.String("444444444444"), Name: aws.String("sandbox-excluded"), Status: orgtypes.AccountStatusActive},
		},
		parents: map[string][]string{
			"222222222222": {"ou-prod"},
			"ou-prod":      {"r-root"},
		},
		policiesByTarget: map[string][]orgtypes.PolicySummary{
			"r-root":  {{Id: aws.String("p-full"), Name: aws.String("FullAWSAccess")}},
			"ou-prod": {{Id: aws.String("p-full"), Name: aws.String("FullAWSAccess")}, {Id: aws.String("p-deny-iam"), Name: aws.String("DenyIAM")}},
		},
		policyContent: map[string]string{
			"p-full":     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			"p-deny-iam": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`,
		},
	}

	var selfAssumeCalls atomic.Int32
	deps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "111111111111", arn: "arn:aws:iam::111111111111:role/nhilens-org-auditor"}, mgmtIAM, &fakeCloudTrail{}, nil
		},
		NewCloudTrailClient: func(_ context.Context, _, _ string) (collect.CloudTrailClient, error) {
			return &fakeCloudTrail{}, nil
		},
		NewOrganizationsClient: func(_ context.Context, _, _ string) (collect.OrganizationsClient, error) {
			return orgMock, nil
		},
		AssumeAccount: func(_ context.Context, _, _, targetAccountID string, aOpts collect.AssumeRoleOptions) (*collect.AccountClients, error) {
			if aOpts.RoleName != "nhilens-readonly" {
				t.Errorf("unexpected assume role name %q", aOpts.RoleName)
			}
			switch targetAccountID {
			case "111111111111":
				selfAssumeCalls.Add(1)
				return nil, errors.New("should not assume role into caller's own account")
			case "222222222222":
				return &collect.AccountClients{
					STS:               &fakeSTS{account: "222222222222", arn: "arn:aws:sts::222222222222:assumed-role/nhilens-readonly/s"},
					IAM:               prodIAM,
					PrimaryCloudTrail: &fakeCloudTrail{},
					CloudTrailForRegion: func(_ context.Context, _ string) (collect.CloudTrailClient, error) {
						return &fakeCloudTrail{}, nil
					},
				}, nil
			case "333333333333":
				return nil, errors.New("AccessDenied: User is not authorized to perform sts:AssumeRole")
			default:
				t.Errorf("unexpected excluded account assumed: %s", targetAccountID)
				return nil, errors.New("unexpected account")
			}
		},
		Now: func() time.Time { return now },
		CollectorHooks: func(opts *collect.Options) {
			opts.Sleep = func(_ context.Context, _ time.Duration) error { return nil }
		},
		CloudTrailHooks: func(opts *collect.CloudTrailOptions) {
			opts.MinRequestInterval = -1
			opts.Sleep = func(_ context.Context, _ time.Duration) error { return nil }
		},
	}

	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := ExecuteWithDeps(
		[]string{
			"scan", "--org",
			"--assume-role-name", "nhilens-readonly",
			"--exclude-accounts", "444444444444",
			"--regions", "us-east-1,eu-west-1",
			"--skip-service-last-accessed",
			"--format", "json",
			"--out", outDir,
		},
		&stdout, &stderr, deps,
	)
	if code != 0 {
		t.Fatalf("org scan failed (code=%d): %s", code, stderr.String())
	}
	if selfAssumeCalls.Load() != 0 {
		t.Errorf("expected 0 self-AssumeRole calls for caller account, got %d", selfAssumeCalls.Load())
	}

	var run model.ScanRun
	if err := json.Unmarshal(stdout.Bytes(), &run); err != nil {
		t.Fatalf("unmarshal org scan JSON: %v", err)
	}
	if run.OrganizationID != "o-testorg123" || run.AccountID != "org:o-testorg123" {
		t.Errorf("unexpected org identity: org=%q account=%q", run.OrganizationID, run.AccountID)
	}
	if run.Coverage == nil || run.Coverage.AccountsScanned != 2 || run.Coverage.AccountsFailed != 1 || run.Coverage.Status != model.CoverageStatusPartial {
		t.Fatalf("expected 2 scanned, 1 failed, partial coverage; got %+v", run.Coverage)
	}
	if run.Coverage.SCPPoliciesLoaded != 2 {
		t.Errorf("expected 2 auto-discovered org SCPs loaded, got %d", run.Coverage.SCPPoliciesLoaded)
	}

	// Verify R1 on prod-ai's AdministratorAccess role was downgraded from critical to medium by the auto-discovered DenyIAM SCP!
	var prodAgent *model.Identity
	for i := range run.Identities {
		if run.Identities[i].Name == "bedrock-prod-agent" {
			prodAgent = &run.Identities[i]
			break
		}
	}
	if prodAgent == nil {
		t.Fatalf("expected bedrock-prod-agent in rollup identities")
	}
	if prodAgent.AccountName != "prod-ai" {
		t.Errorf("expected AccountName=prod-ai, got %q", prodAgent.AccountName)
	}
	r1Found := false
	for _, f := range prodAgent.Findings {
		if f.RuleID == "R1" {
			r1Found = true
			if f.Severity != model.SeverityMedium {
				t.Errorf("expected R1 downgraded to medium by auto-discovered org SCP, got %q (evidence=%v)", f.Severity, f.Evidence)
			}
		}
	}
	if !r1Found {
		t.Errorf("expected R1 finding on bedrock-prod-agent, got %+v", prodAgent.Findings)
	}

	// Verify SQLite persistence reloads multi-account metadata cleanly.
	st, err := store.Open(filepath.Join(outDir, "nhilens.db"))
	if err != nil {
		t.Fatalf("open SQLite DB: %v", err)
	}
	defer func() { _ = st.Close() }()

	loaded, err := st.LoadLatestScan(context.Background())
	if err != nil {
		t.Fatalf("LoadLatestScan: %v", err)
	}
	if loaded.OrganizationID != "o-testorg123" || len(loaded.Accounts) != 3 || !loaded.IsMultiAccount() {
		t.Errorf("expected reloaded org metadata & 3 account summaries, got org=%q accounts=%d", loaded.OrganizationID, len(loaded.Accounts))
	}
}

func TestScanExplicitAccountsAndFlagValidation(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	iam1 := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{Arn: aws.String("arn:aws:iam::111111111111:role/r1"), RoleName: aws.String("r1"), Path: aws.String("/"), Tags: []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("team-a")}}},
			},
		},
	}
	iam2 := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{Arn: aws.String("arn:aws:iam::222222222222:role/r2"), RoleName: aws.String("r2"), Path: aws.String("/"), Tags: []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("team-b")}}},
			},
		},
	}

	deps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "111111111111", arn: "arn:aws:iam::111111111111:role/audit"}, iam1, &fakeCloudTrail{}, nil
		},
		AssumeAccount: func(_ context.Context, _, _, targetAccountID string, aOpts collect.AssumeRoleOptions) (*collect.AccountClients, error) {
			if aOpts.ExternalID != "ext-123" {
				t.Errorf("expected ExternalID=ext-123, got %q", aOpts.ExternalID)
			}
			return &collect.AccountClients{
				STS:               &fakeSTS{account: targetAccountID, arn: "arn:aws:sts::" + targetAccountID + ":assumed-role/nhilens-ro/s"},
				IAM:               iam2,
				PrimaryCloudTrail: &fakeCloudTrail{},
			}, nil
		},
		Now: func() time.Time { return now },
	}

	// 1. Valid --accounts scan without Organizations API.
	outDir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := ExecuteWithDeps(
		[]string{"scan", "--accounts", "111111111111,222222222222", "--assume-role-name", "nhilens-ro", "--external-id", "ext-123", "--max-events", "0", "--skip-service-last-accessed", "--format", "json", "--out", outDir},
		&out, &errBuf, deps,
	)
	if code != 0 {
		t.Fatalf("--accounts scan failed (code=%d): %s", code, errBuf.String())
	}
	var run model.ScanRun
	if err := json.Unmarshal(out.Bytes(), &run); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if run.AccountID != "multi-account(2)" || len(run.Identities) != 2 {
		t.Errorf("unexpected multi-account rollup: account=%q identities=%d", run.AccountID, len(run.Identities))
	}

	// 2. Missing --assume-role-name for member account fails clearly.
	var o2, e2 bytes.Buffer
	if c := ExecuteWithDeps([]string{"scan", "--accounts", "111111111111,222222222222", "--max-events", "0", "--out", t.TempDir()}, &o2, &e2, deps); c == 0 || !strings.Contains(e2.String(), "--assume-role-name") {
		t.Errorf("expected error mentioning --assume-role-name, got code=%d stderr=%q", c, e2.String())
	}

	// 3. Invalid account ID, concurrency, and orphan --exclude-accounts fail fast.
	for _, args := range [][]string{
		{"scan", "--accounts", "not-an-id"},
		{"scan", "--accounts", "111111111111", "--account-concurrency", "99"},
		{"scan", "--exclude-accounts", "111111111111"},
	} {
		var o, e bytes.Buffer
		if c := ExecuteWithDeps(args, &o, &e, deps); c == 0 {
			t.Errorf("expected validation failure for args %v", args)
		}
	}
}
