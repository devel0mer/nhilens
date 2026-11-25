package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/store"
)

type fakeSTS struct {
	account string
	arn     string
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Account: aws.String(f.account),
		Arn:     aws.String(f.arn),
	}, nil
}

type fakeIAM struct {
	authOut       *iam.GetAccountAuthorizationDetailsOutput
	loginProfiles map[string]bool
	keysByUser    map[string][]iamtypes.AccessKeyMetadata
	slaByARN      map[string][]iamtypes.ServiceLastAccessed
	slaCalls      atomic.Int32
}

func (f *fakeIAM) GetAccountAuthorizationDetails(_ context.Context, _ *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	return f.authOut, nil
}

func (f *fakeIAM) GetLoginProfile(_ context.Context, in *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	if f.loginProfiles[aws.ToString(in.UserName)] {
		return &iam.GetLoginProfileOutput{LoginProfile: &iamtypes.LoginProfile{UserName: in.UserName}}, nil
	}
	return nil, &iamtypes.NoSuchEntityException{Message: aws.String("not found")}
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: f.keysByUser[aws.ToString(in.UserName)],
	}, nil
}

func (f *fakeIAM) GetAccessKeyLastUsed(_ context.Context, _ *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
			Region:      aws.String("us-east-1"),
			ServiceName: aws.String("s3"),
		},
	}, nil
}

func (f *fakeIAM) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	f.slaCalls.Add(1)
	return &iam.GenerateServiceLastAccessedDetailsOutput{
		JobId: aws.String("job:" + aws.ToString(in.Arn)),
	}, nil
}

func (f *fakeIAM) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	arn := strings.TrimPrefix(aws.ToString(in.JobId), "job:")
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus:            iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: f.slaByARN[arn],
	}, nil
}

type fakeCloudTrail struct {
	events []cttypes.Event
}

func (f *fakeCloudTrail) LookupEvents(_ context.Context, _ *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: f.events}, nil
}

func buildFixtureMockIAM(now time.Time) *fakeIAM {
	oldCreated := now.Add(-180 * 24 * time.Hour)
	freshCreated := now.Add(-10 * 24 * time.Hour)
	agentRoleARN := "arn:aws:iam::123456789012:role/bedrock-support-agent"
	slrARN := "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"
	botUserARN := "arn:aws:iam::123456789012:user/ci-bot"
	humanUserARN := "arn:aws:iam::123456789012:user/alice"

	looseTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`

	return &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:                      aws.String(agentRoleARN),
					RoleName:                 aws.String("bedrock-support-agent"),
					Path:                     aws.String("/"),
					CreateDate:               &oldCreated,
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(looseTrust)),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{
						{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
					},
				},
				{
					Arn:      aws.String(slrARN),
					RoleName: aws.String("AWSServiceRoleForSupport"),
					Path:     aws.String("/aws-service-role/support.amazonaws.com/"),
				},
			},
			UserDetailList: []iamtypes.UserDetail{
				{
					Arn:        aws.String(botUserARN),
					UserName:   aws.String("ci-bot"),
					CreateDate: &oldCreated,
				},
				{
					Arn:        aws.String(humanUserARN),
					UserName:   aws.String("alice"),
					CreateDate: &oldCreated,
					Tags:       []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("alice")}},
				},
			},
		},
		loginProfiles: map[string]bool{
			"alice": true,
		},
		keysByUser: map[string][]iamtypes.AccessKeyMetadata{
			"ci-bot": {
				{
					AccessKeyId: aws.String("AKIAOLD1234567890123"),
					UserName:    aws.String("ci-bot"),
					Status:      iamtypes.StatusTypeActive,
					CreateDate:  &freshCreated, // fresh key: triggers R4 purely via CloudTrail multi-IP attribution!
				},
			},
		},
		slaByARN: map[string][]iamtypes.ServiceLastAccessed{
			agentRoleARN: {
				{ServiceNamespace: aws.String("ec2"), LastAuthenticated: nil},
				{ServiceNamespace: aws.String("iam"), LastAuthenticated: nil},
			},
		},
	}
}

func TestScanEndToEndTableJSONSQLiteAndFailOn(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	evTime := now.Add(-1 * time.Hour)
	mockIAM := buildFixtureMockIAM(now)
	mockCT := &fakeCloudTrail{
		events: []cttypes.Event{
			{
				EventTime:   &evTime,
				EventName:   aws.String("ListBuckets"),
				EventSource: aws.String("s3.amazonaws.com"),
				AccessKeyId: aws.String("AKIAOLD1234567890123"),
				CloudTrailEvent: aws.String(`{"eventSource":"s3.amazonaws.com","eventName":"ListBuckets","sourceIPAddress":"198.51.100.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAOLD1234567890123"}}`),
			},
			{
				EventTime:   &evTime,
				EventName:   aws.String("GetCallerIdentity"),
				EventSource: aws.String("sts.amazonaws.com"),
				AccessKeyId: aws.String("AKIAOLD1234567890123"),
				CloudTrailEvent: aws.String(`{"eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","sourceIPAddress":"203.0.113.9","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAOLD1234567890123"}}`),
			},
		},
	}

	deps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "123456789012", arn: "arn:aws:iam::123456789012:role/nhilens-ro"}, mockIAM, mockCT, nil
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

	// 1. Table format + --fail-on high => exit code 2, DB saved, ranked table printed.
	outDir1 := t.TempDir()
	var stdout1, stderr1 bytes.Buffer
	code := ExecuteWithDeps(
		[]string{"scan", "--region", "us-east-1", "--out", outDir1, "--fail-on", "high"},
		&stdout1, &stderr1, deps,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2 for --fail-on high, got %d (stderr=%q)", code, stderr1.String())
	}

	tableOut := stdout1.String()
	for _, want := range []string{
		"nhilens scan summary",
		"123456789012",
		"bedrock-support-agent",
		"8.9/10",
		"raw 14.5",
		"compound:+2.0",
		"AKIAOLD1234567890123 (ci-bot)",
		"[service-linked]",
		"R1(critical)",
		"R4(high)",
		"R5(high)",
	} {
		if !strings.Contains(tableOut, want) {
			t.Errorf("expected table output to contain %q, got:\n%s", want, tableOut)
		}
	}

	// Reload SQLite DB and verify persistence of scores and findings.
	st, err := store.Open(filepath.Join(outDir1, "nhilens.db"))
	if err != nil {
		t.Fatalf("open saved SQLite DB: %v", err)
	}
	defer func() { _ = st.Close() }()

	saved, err := st.LoadLatestScan(context.Background())
	if err != nil {
		t.Fatalf("LoadLatestScan: %v", err)
	}
	if len(saved.Identities) != 5 {
		t.Fatalf("expected 5 identities saved in SQLite, got %d", len(saved.Identities))
	}
	if saved.Identities[0].Name != "bedrock-support-agent" || saved.Identities[0].RiskScore != 8.9 {
		t.Errorf("expected top-ranked saved identity bedrock-support-agent with 8.9, got %s (%.1f)",
			saved.Identities[0].Name, saved.Identities[0].RiskScore)
	}

	// 2. JSON format + --skip-service-last-accessed + no --fail-on => exit code 0, valid JSON, zero SLA calls.
	mockIAM.slaCalls.Store(0)
	outDir2 := t.TempDir()
	var stdout2, stderr2 bytes.Buffer
	code2 := ExecuteWithDeps(
		[]string{"scan", "--region", "us-east-1", "--out", outDir2, "--format", "json", "--skip-service-last-accessed"},
		&stdout2, &stderr2, deps,
	)
	if code2 != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code2, stderr2.String())
	}
	if mockIAM.slaCalls.Load() != 0 {
		t.Errorf("expected 0 GenerateServiceLastAccessedDetails calls with --skip-service-last-accessed, got %d", mockIAM.slaCalls.Load())
	}

	var decoded model.ScanRun
	if err := json.Unmarshal(stdout2.Bytes(), &decoded); err != nil {
		t.Fatalf("scan --format json produced invalid JSON: %v\n%s", err, stdout2.String())
	}
	if decoded.AccountID != "123456789012" || len(decoded.Identities) != 5 {
		t.Errorf("unexpected decoded JSON scan run: account=%q identities=%d", decoded.AccountID, len(decoded.Identities))
	}
	for _, f := range decoded.Identities[0].Findings {
		if f.RuleID == "R2" {
			t.Errorf("expected R2 skipped when --skip-service-last-accessed is set")
		}
	}
}
