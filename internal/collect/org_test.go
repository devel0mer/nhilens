package collect

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

type mockOrganizationsClient struct {
	orgID            string
	masterAccountID  string
	accountPages     [][]orgtypes.Account
	parentsByChild   map[string][]string
	policiesByTarget map[string][]orgtypes.PolicySummary
	policyContent    map[string]string

	describePolicyCalls atomic.Int32
	listPoliciesCalls   atomic.Int32
}

func (m *mockOrganizationsClient) DescribeOrganization(_ context.Context, _ *organizations.DescribeOrganizationInput, _ ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{
		Organization: &orgtypes.Organization{
			Id:              aws.String(m.orgID),
			MasterAccountId: aws.String(m.masterAccountID),
		},
	}, nil
}

func (m *mockOrganizationsClient) ListAccounts(_ context.Context, in *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	page := 0
	if in != nil && in.NextToken != nil && *in.NextToken == "page-2" {
		page = 1
	}
	if page >= len(m.accountPages) {
		return &organizations.ListAccountsOutput{}, nil
	}
	out := &organizations.ListAccountsOutput{Accounts: m.accountPages[page]}
	if page+1 < len(m.accountPages) {
		out.NextToken = aws.String("page-2")
	}
	return out, nil
}

func (m *mockOrganizationsClient) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	ids := m.parentsByChild[aws.ToString(in.ChildId)]
	parents := make([]orgtypes.Parent, 0, len(ids))
	for _, id := range ids {
		parents = append(parents, orgtypes.Parent{Id: aws.String(id)})
	}
	return &organizations.ListParentsOutput{Parents: parents}, nil
}

func (m *mockOrganizationsClient) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	m.listPoliciesCalls.Add(1)
	return &organizations.ListPoliciesForTargetOutput{
		Policies: m.policiesByTarget[aws.ToString(in.TargetId)],
	}, nil
}

func (m *mockOrganizationsClient) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	m.describePolicyCalls.Add(1)
	id := aws.ToString(in.PolicyId)
	return &organizations.DescribePolicyOutput{
		Policy: &orgtypes.Policy{
			Content: aws.String(m.policyContent[id]),
		},
	}, nil
}

func TestDiscoverOrgAccountsPaginationFilteringAndStatus(t *testing.T) {
	mockOrg := &mockOrganizationsClient{
		orgID:           "o-abc1234567",
		masterAccountID: "111111111111",
		accountPages: [][]orgtypes.Account{
			{
				{Id: aws.String("222222222222"), Name: aws.String("prod-ai"), Status: orgtypes.AccountStatusActive},
				{Id: aws.String("999999999999"), Name: aws.String("old-suspended"), Status: orgtypes.AccountStatusSuspended},
			},
			{
				{Id: aws.String("111111111111"), Name: aws.String("management"), Status: orgtypes.AccountStatusActive},
				{Id: aws.String("333333333333"), Name: aws.String("sandbox-excluded"), Status: orgtypes.AccountStatusActive},
			},
		},
	}

	res, err := DiscoverOrgAccounts(context.Background(), mockOrg, OrgDiscoveryOptions{
		ExcludeAccounts: []string{"333333333333"},
		Retry:           RetryPolicy{MaxAttempts: 1, Sleep: noopSleep},
	})
	if err != nil {
		t.Fatalf("DiscoverOrgAccounts failed: %v", err)
	}
	if res.OrganizationID != "o-abc1234567" || res.MasterAccountID != "111111111111" {
		t.Errorf("unexpected org metadata: %+v", res)
	}
	if len(res.Accounts) != 2 || res.Accounts[0].ID != "111111111111" || res.Accounts[1].ID != "222222222222" {
		t.Fatalf("expected sorted active accounts [111111111111 222222222222], got %+v", res.Accounts)
	}
	if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "non-ACTIVE") {
		t.Errorf("expected warning for skipped suspended account, got %v", res.Warnings)
	}
}

func TestSCPResolverHierarchyMergingCachingAndMasterExemption(t *testing.T) {
	fullAccess := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	denyIAM := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`

	mockOrg := &mockOrganizationsClient{
		orgID:           "o-abc1234567",
		masterAccountID: "111111111111",
		parentsByChild: map[string][]string{
			"222222222222": {"ou-prod-1"},
			"333333333333": {"ou-prod-1"},
			"ou-prod-1":    {"r-root1"},
		},
		policiesByTarget: map[string][]orgtypes.PolicySummary{
			"r-root1": {
				{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess")},
			},
			"ou-prod-1": {
				{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess")},
				{Id: aws.String("p-DenyIAM"), Name: aws.String("DenyIAMWildcard")},
			},
			"222222222222": {
				{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess")},
			},
			"333333333333": {
				{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess")},
			},
		},
		policyContent: map[string]string{
			"p-FullAWSAccess": fullAccess,
			"p-DenyIAM":       denyIAM,
		},
	}

	resolver := NewSCPResolver(mockOrg, "111111111111", RetryPolicy{MaxAttempts: 1, Sleep: noopSleep})

	// 1. Management account is exempt from SCPs per AWS Organizations rules.
	masterSCPs, masterCount, masterWarns := resolver.ResolveForAccount(context.Background(), "111111111111")
	if len(masterSCPs) != 0 || masterCount != 0 || len(masterWarns) != 0 {
		t.Errorf("expected management account exempt from SCPs, got scps=%d count=%d warns=%v", len(masterSCPs), masterCount, masterWarns)
	}

	// 2. Member account inherits FullAWSAccess + DenyIAMWildcard at ou-prod-1.
	// Within-level union must ALLOW s3:GetObject while DENYING iam:AttachRolePolicy.
	scps, uniqueCount, warns := resolver.ResolveForAccount(context.Background(), "222222222222")
	if len(warns) != 0 {
		t.Fatalf("unexpected SCP warnings: %v", warns)
	}
	if uniqueCount != 2 {
		t.Errorf("expected 2 unique SCPs, got %d", uniqueCount)
	}

	adminRole := &model.Identity{
		Type: model.TypeRole,
		Name: "prod-admin",
		Policies: []model.PolicyAttachment{
			{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
		},
	}
	if dec := policy.EvaluateEffectiveAction(adminRole, scps, "s3:GetObject", "*"); !dec.Allowed {
		t.Errorf("expected s3:GetObject allowed through FullAWSAccess + DenyIAMWildcard level union, got %+v", dec)
	}
	if dec := policy.EvaluateEffectiveAction(adminRole, scps, "iam:AttachRolePolicy", "*"); dec.Allowed || !strings.HasPrefix(dec.BlockedBy, "scp:") {
		t.Errorf("expected iam:AttachRolePolicy blocked by OU SCP, got %+v", dec)
	}

	// 3. Second account in the same OU reuses cached OU/root policies and DescribePolicy results.
	callsBefore := mockOrg.describePolicyCalls.Load()
	_, uniqueCount2, _ := resolver.ResolveForAccount(context.Background(), "333333333333")
	if uniqueCount2 != 2 {
		t.Errorf("expected 2 unique SCPs for sibling account, got %d", uniqueCount2)
	}
	if mockOrg.describePolicyCalls.Load() != callsBefore {
		t.Errorf("expected DescribePolicy calls cached across sibling accounts (before=%d after=%d)", callsBefore, mockOrg.describePolicyCalls.Load())
	}
}

func TestBuildAssumeRoleARNAndPartitionDetection(t *testing.T) {
	if got := PartitionFromARN("arn:aws-us-gov:sts::123456789012:assumed-role/admin/s"); got != "aws-us-gov" {
		t.Errorf("PartitionFromARN gov = %q", got)
	}
	if got := PartitionFromARN("arn:aws-cn:iam::123456789012:user/auditor"); got != "aws-cn" {
		t.Errorf("PartitionFromARN cn = %q", got)
	}
	if got := PartitionFromARN("arn:aws:iam::123456789012:role/audit"); got != "aws" {
		t.Errorf("PartitionFromARN commercial = %q", got)
	}

	arn, err := BuildAssumeRoleARN("aws", "123456789012", "/security/nhilens-readonly")
	if err != nil || arn != "arn:aws:iam::123456789012:role/security/nhilens-readonly" {
		t.Errorf("BuildAssumeRoleARN = (%q, %v)", arn, err)
	}
	if _, err := BuildAssumeRoleARN("aws", "12345", "nhilens-readonly"); err == nil {
		t.Errorf("expected error for non-12-digit account ID")
	}
	if _, err := BuildAssumeRoleARN("aws", "123456789012", ""); err == nil {
		t.Errorf("expected error for empty role name")
	}
}
