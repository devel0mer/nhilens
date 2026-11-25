package collect

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/devel0mer/nhilens/internal/model"
)

type mockSTSClient struct {
	account string
	arn     string
	err     error
}

func (m *mockSTSClient) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String(m.account),
		Arn:     aws.String(m.arn),
	}, nil
}

type mockIAMClient struct {
	mu sync.Mutex

	authPages          []*iam.GetAccountAuthorizationDetailsOutput
	authThrottleBefore int
	authCalls          int

	loginProfiles map[string]bool // true => has login profile; false/missing => NoSuchEntity

	accessKeysPages map[string][]*iam.ListAccessKeysOutput
	accessKeyLast   map[string]*iam.GetAccessKeyLastUsedOutput

	// service last accessed keyed by ARN
	slaJobs      map[string]string // arn -> jobID
	slaResponses map[string][]*iam.GetServiceLastAccessedDetailsOutput
	slaCallCount map[string]int
}

func (m *mockIAMClient) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.authCalls++
	if m.authCalls <= m.authThrottleBefore {
		return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}

	idx := 0
	if in != nil && in.Marker != nil {
		if *in.Marker == "page2" {
			idx = 1
		}
	}
	return m.authPages[idx], nil
}

func (m *mockIAMClient) GetLoginProfile(_ context.Context, in *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loginProfiles[aws.ToString(in.UserName)] {
		return &iam.GetLoginProfileOutput{
			LoginProfile: &iamtypes.LoginProfile{UserName: in.UserName},
		}, nil
	}
	return nil, &iamtypes.NoSuchEntityException{Message: aws.String("Login Profile for User cannot be found")}
}

func (m *mockIAMClient) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pages := m.accessKeysPages[aws.ToString(in.UserName)]
	if len(pages) == 0 {
		return &iam.ListAccessKeysOutput{}, nil
	}
	idx := 0
	if in.Marker != nil && *in.Marker == "kpage2" {
		idx = 1
	}
	return pages[idx], nil
}

func (m *mockIAMClient) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if out, ok := m.accessKeyLast[aws.ToString(in.AccessKeyId)]; ok {
		return out, nil
	}
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
			Region:      aws.String("N/A"),
			ServiceName: aws.String("N/A"),
		},
	}, nil
}

func (m *mockIAMClient) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	arn := aws.ToString(in.Arn)
	jobID := m.slaJobs[arn]
	if jobID == "" {
		jobID = "job-default-" + arn
	}
	return &iam.GenerateServiceLastAccessedDetailsOutput{
		JobId: aws.String(jobID),
	}, nil
}

func (m *mockIAMClient) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.slaCallCount == nil {
		m.slaCallCount = make(map[string]int)
	}
	jobID := aws.ToString(in.JobId)
	resps := m.slaResponses[jobID]
	if len(resps) == 0 {
		return &iam.GetServiceLastAccessedDetailsOutput{
			JobStatus: iamtypes.JobStatusTypeCompleted,
		}, nil
	}
	idx := m.slaCallCount[jobID]
	m.slaCallCount[jobID] = idx + 1
	if idx >= len(resps) {
		idx = len(resps) - 1
	}
	return resps[idx], nil
}

func TestIAMCollectorFullCollectionAndPagination(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	created := now.Add(-120 * 24 * time.Hour)
	roleUsed := now.Add(-5 * 24 * time.Hour)
	keyUsed := now.Add(-2 * 24 * time.Hour)

	trustDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	adminDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	inlineDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	roleARN := "arn:aws:iam::123456789012:role/bedrock-agent-role"
	slrARN := "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"
	boundaryARN := "arn:aws:iam::123456789012:policy/sandbox-boundary"
	botUserARN := "arn:aws:iam::123456789012:user/ci-agent-bot"
	humanUserARN := "arn:aws:iam::123456789012:user/alice"

	mockIAM := &mockIAMClient{
		authThrottleBefore: 2, // exercises retry backoff on ThrottlingException
		authPages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				IsTruncated: true,
				Marker:      aws.String("page2"),
				RoleDetailList: []iamtypes.RoleDetail{
					{
						Arn:                      aws.String(roleARN),
						RoleName:                 aws.String("bedrock-agent-role"),
						Path:                     aws.String("/"),
						CreateDate:               &created,
						RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: &roleUsed, Region: aws.String("us-east-1")},
						AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustDoc)),
						PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
							PermissionsBoundaryArn: aws.String(boundaryARN),
						},
						Tags: []iamtypes.Tag{
							{Key: aws.String("Owner"), Value: aws.String("ml-platform")},
							{Key: aws.String("agent"), Value: aws.String("true")},
						},
						AttachedManagedPolicies: []iamtypes.AttachedPolicy{
							{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
						},
						RolePolicyList: []iamtypes.PolicyDetail{
							{PolicyName: aws.String("s3-read"), PolicyDocument: aws.String(url.QueryEscape(inlineDoc))},
						},
					},
					{
						Arn:      aws.String(slrARN),
						RoleName: aws.String("AWSServiceRoleForSupport"),
						Path:     aws.String("/aws-service-role/support.amazonaws.com/"),
					},
				},
				Policies: []iamtypes.ManagedPolicyDetail{
					{
						Arn:              aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
						PolicyName:       aws.String("AdministratorAccess"),
						DefaultVersionId: aws.String("v1"),
						PolicyVersionList: []iamtypes.PolicyVersion{
							{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: aws.String(url.QueryEscape(adminDoc))},
						},
					},
				},
			},
			{
				IsTruncated: false,
				GroupDetailList: []iamtypes.GroupDetail{
					{
						GroupName: aws.String("automation-group"),
						AttachedManagedPolicies: []iamtypes.AttachedPolicy{
							{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
						},
						GroupPolicyList: []iamtypes.PolicyDetail{
							{PolicyName: aws.String("group-inline"), PolicyDocument: aws.String(url.QueryEscape(inlineDoc))},
						},
					},
				},
				UserDetailList: []iamtypes.UserDetail{
					{
						Arn:        aws.String(botUserARN),
						UserName:   aws.String("ci-agent-bot"),
						CreateDate: &created,
						GroupList:  []string{"automation-group"},
					},
					{
						Arn:        aws.String(humanUserARN),
						UserName:   aws.String("alice"),
						CreateDate: &created,
						Tags: []iamtypes.Tag{
							{Key: aws.String("owner"), Value: aws.String("alice@example.com")},
						},
					},
				},
			},
		},
		loginProfiles: map[string]bool{
			"alice": true,
		},
		accessKeysPages: map[string][]*iam.ListAccessKeysOutput{
			"ci-agent-bot": {
				{
					IsTruncated: true,
					Marker:      aws.String("kpage2"),
					AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
						{AccessKeyId: aws.String("AKIAOLD1111111111111"), UserName: aws.String("ci-agent-bot"), Status: iamtypes.StatusTypeActive, CreateDate: &created},
					},
				},
				{
					IsTruncated: false,
					AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
						{AccessKeyId: aws.String("AKIANEW2222222222222"), UserName: aws.String("ci-agent-bot"), Status: iamtypes.StatusTypeInactive, CreateDate: &created},
					},
				},
			},
		},
		accessKeyLast: map[string]*iam.GetAccessKeyLastUsedOutput{
			"AKIAOLD1111111111111": {
				AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
					LastUsedDate: &keyUsed,
					ServiceName:  aws.String("s3"),
					Region:       aws.String("us-east-1"),
				},
			},
		},
		slaJobs: map[string]string{
			roleARN:      "job-role",
			botUserARN:   "job-bot",
			humanUserARN: "job-alice",
		},
		slaResponses: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
			"job-role": {
				{JobStatus: iamtypes.JobStatusTypeInProgress},
				{
					JobStatus:   iamtypes.JobStatusTypeCompleted,
					IsTruncated: true,
					Marker:      aws.String("spage2"),
					ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
						{ServiceName: aws.String("Amazon S3"), ServiceNamespace: aws.String("s3"), LastAuthenticated: &roleUsed},
					},
				},
				{
					JobStatus:   iamtypes.JobStatusTypeCompleted,
					IsTruncated: false,
					ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
						{ServiceName: aws.String("Amazon EC2"), ServiceNamespace: aws.String("ec2")},
					},
				},
			},
			"job-bot": {
				{JobStatus: iamtypes.JobStatusTypeCompleted},
			},
			"job-alice": {
				{JobStatus: iamtypes.JobStatusTypeCompleted},
			},
		},
	}

	collector := NewIAMCollector(
		&mockSTSClient{account: "123456789012", arn: "arn:aws:iam::123456789012:role/nhilens-auditor"},
		mockIAM,
		Options{
			OwnerTagKeys:        []string{"owner", "sponsor"},
			MaxConcurrency:      3,
			Retry:               RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond, Sleep: noopSleep},
			PollInitialInterval: time.Millisecond,
			PollMaxInterval:     2 * time.Millisecond,
			LastAccessedTimeout: time.Second,
			Sleep:               noopSleep,
			Now:                 func() time.Time { return now },
		},
	)

	run, err := collector.Collect(context.Background(), "sandbox", "us-east-1", "90d")
	if err != nil {
		t.Fatalf("Collect() unexpected error: %v", err)
	}

	if run.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want 123456789012", run.AccountID)
	}
	if run.CloudTrailStatus != model.CloudTrailStatusUnknown {
		t.Errorf("CloudTrailStatus = %q, want unknown", run.CloudTrailStatus)
	}
	if len(run.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", run.Warnings)
	}
	// Expect 2 roles (incl. 1 SLR) + 2 users + 2 access keys = 6 identities.
	if len(run.Identities) != 6 {
		t.Fatalf("expected 6 normalized identities, got %d", len(run.Identities))
	}

	byID := make(map[string]model.Identity, len(run.Identities))
	for _, id := range run.Identities {
		byID[id.ID] = id
	}

	role := byID[roleARN]
	if role.PermissionsBoundaryARN != boundaryARN {
		t.Errorf("role PermissionsBoundaryARN = %q, want %q", role.PermissionsBoundaryARN, boundaryARN)
	}
	if role.IsServiceLinkedRole {
		t.Errorf("expected bedrock-agent-role IsServiceLinkedRole=false")
	}
	slr := byID[slrARN]
	if !slr.IsServiceLinkedRole {
		t.Errorf("expected AWSServiceRoleForSupport IsServiceLinkedRole=true")
	}
	if role.Owner == nil || *role.Owner != "ml-platform" {
		t.Errorf("role owner = %v, want ml-platform", role.Owner)
	}
	if role.TrustPolicyRaw != trustDoc {
		t.Errorf("role TrustPolicyRaw not URL-decoded cleanly: %q", role.TrustPolicyRaw)
	}
	if len(role.Policies) != 2 {
		t.Fatalf("expected 2 role policies, got %d", len(role.Policies))
	}
	if role.Policies[0].RawDocument != adminDoc {
		t.Errorf("managed policy doc not resolved/decoded: %q", role.Policies[0].RawDocument)
	}
	if len(role.ServicesLastAccessed) != 2 {
		t.Fatalf("expected 2 paginated services last accessed on role, got %d", len(role.ServicesLastAccessed))
	}
	if role.ServicesLastAccessed[0].ServiceNamespace != "ec2" || role.ServicesLastAccessed[1].ServiceNamespace != "s3" {
		t.Errorf("unexpected services last accessed order/content: %+v", role.ServicesLastAccessed)
	}

	bot := byID[botUserARN]
	if bot.Owner != nil {
		t.Errorf("expected nil owner for untagged bot user, got %q", *bot.Owner)
	}
	if bot.HasConsoleLogin == nil || *bot.HasConsoleLogin != false {
		t.Errorf("expected HasConsoleLogin=false for ci-agent-bot, got %v", bot.HasConsoleLogin)
	}
	if len(bot.Policies) != 2 {
		t.Errorf("expected 2 inherited group policies on bot user, got %d", len(bot.Policies))
	}
	if len(bot.AccessKeyIDs) != 2 {
		t.Errorf("expected 2 AccessKeyIDs on bot user, got %v", bot.AccessKeyIDs)
	}
	if bot.LastUsed == nil || !bot.LastUsed.Equal(keyUsed) {
		t.Errorf("expected bot LastUsed propagated from key (%v), got %v", keyUsed, bot.LastUsed)
	}

	alice := byID[humanUserARN]
	if alice.HasConsoleLogin == nil || !*alice.HasConsoleLogin {
		t.Errorf("expected HasConsoleLogin=true for alice, got %v", alice.HasConsoleLogin)
	}

	key1 := byID[botUserARN+"/access-key/AKIAOLD1111111111111"]
	if key1.Type != model.TypeKey || key1.AccessKey == nil {
		t.Fatalf("expected normalized key identity, got %+v", key1)
	}
	if key1.AccessKey.LastUsedService != "s3" || key1.AccessKey.Status != "Active" {
		t.Errorf("unexpected key metadata: %+v", key1.AccessKey)
	}
}

func TestServiceLastAccessedFailureAndTimeoutAreNonFatal(t *testing.T) {
	// Advance a virtual clock on each call so timeout triggers deterministically without sleeping.
	var mu sync.Mutex
	cur := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		cur = cur.Add(10 * time.Second)
		return cur
	}

	failedARN := "arn:aws:iam::123456789012:role/failed-sla"
	timeoutARN := "arn:aws:iam::123456789012:role/timeout-sla"

	dummyPolicy := []iamtypes.AttachedPolicy{{PolicyName: aws.String("ReadOnly"), PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}}
	mockIAM := &mockIAMClient{
		authPages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				RoleDetailList: []iamtypes.RoleDetail{
					{Arn: aws.String(failedARN), RoleName: aws.String("failed-sla"), AttachedManagedPolicies: dummyPolicy},
					{Arn: aws.String(timeoutARN), RoleName: aws.String("timeout-sla"), AttachedManagedPolicies: dummyPolicy},
				},
			},
		},
		slaJobs: map[string]string{
			failedARN:  "job-fail",
			timeoutARN: "job-timeout",
		},
		slaResponses: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
			"job-fail": {
				{
					JobStatus: iamtypes.JobStatusTypeFailed,
					Error:     &iamtypes.ErrorDetails{Message: aws.String("access denied to advisor")},
				},
			},
			"job-timeout": {
				{JobStatus: iamtypes.JobStatusTypeInProgress},
			},
		},
	}

	collector := NewIAMCollector(
		&mockSTSClient{account: "123456789012", arn: "arn:aws:iam::123456789012:role/auditor"},
		mockIAM,
		Options{
			MaxConcurrency:      2,
			PollInitialInterval: time.Millisecond,
			LastAccessedTimeout: 5 * time.Second,
			Sleep:               noopSleep,
			Now:                 nowFn,
		},
	)

	run, err := collector.Collect(context.Background(), "", "us-east-1", "90d")
	if err != nil {
		t.Fatalf("expected non-fatal handling of SLA job errors, got error: %v", err)
	}
	if len(run.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %v", run.Warnings)
	}
	for _, ident := range run.Identities {
		if ident.ServiceLastAccessedError == "" {
			t.Errorf("expected ServiceLastAccessedError recorded on %s", ident.Name)
		}
		if ident.Name == "failed-sla" && !strings.Contains(ident.ServiceLastAccessedError, "access denied") {
			t.Errorf("unexpected error on failed-sla: %q", ident.ServiceLastAccessedError)
		}
		if ident.Name == "timeout-sla" && !strings.Contains(ident.ServiceLastAccessedError, "timed out") {
			t.Errorf("unexpected error on timeout-sla: %q", ident.ServiceLastAccessedError)
		}
		if ident.CoverageStatus != model.CoverageStatusPartial || len(ident.DataGaps) == 0 || ident.DataGaps[0] != "access_advisor_failed" {
			t.Errorf("expected partial coverage with access_advisor_failed on %s, got status=%q gaps=%v", ident.Name, ident.CoverageStatus, ident.DataGaps)
		}
	}
	if run.Coverage == nil || run.Coverage.AccessAdvisorAttempted != 2 || run.Coverage.AccessAdvisorFailed != 2 {
		t.Errorf("expected coverage AccessAdvisorAttempted=2, Failed=2, got %+v", run.Coverage)
	}
}

func TestCollectSkipsAccessAdvisorForSLRsAndZeroPolicyIdentities(t *testing.T) {
	mockIAM := &mockIAMClient{
		authPages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				RoleDetailList: []iamtypes.RoleDetail{
					{
						Arn:      aws.String("arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"),
						RoleName: aws.String("AWSServiceRoleForSupport"),
						Path:     aws.String("/aws-service-role/support.amazonaws.com/"),
						AttachedManagedPolicies: []iamtypes.AttachedPolicy{
							{PolicyName: aws.String("AWSSupportServiceRolePolicy"), PolicyArn: aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy")},
						},
					},
					{
						Arn:      aws.String("arn:aws:iam::123456789012:role/empty-role"),
						RoleName: aws.String("empty-role"),
						Path:     aws.String("/"),
					},
				},
			},
		},
	}

	collector := NewIAMCollector(
		&mockSTSClient{account: "123456789012", arn: "arn:aws:iam::123456789012:role/auditor"},
		mockIAM,
		Options{MaxConcurrency: 2, Sleep: noopSleep},
	)
	run, err := collector.Collect(context.Background(), "", "us-east-1", "90d")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if run.Coverage == nil {
		t.Fatalf("expected non-nil Coverage")
	}
	if run.Coverage.AccessAdvisorAttempted != 0 || run.Coverage.AccessAdvisorSkippedSLR != 1 || run.Coverage.AccessAdvisorSkippedNoPolicy != 1 {
		t.Errorf("unexpected Access Advisor skip counts: %+v", run.Coverage)
	}
}

func noopSleep(_ context.Context, _ time.Duration) error {
	return nil
}
