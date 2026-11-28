package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSClient defines the strictly read-only STS subset used by nhilens.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// IAMClient defines the strictly read-only IAM subset used by nhilens.
// No mutating IAM APIs may ever be added to this interface.
type IAMClient interface {
	GetAccountAuthorizationDetails(ctx context.Context, params *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	GetLoginProfile(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	GenerateServiceLastAccessedDetails(ctx context.Context, params *iam.GenerateServiceLastAccessedDetailsInput, optFns ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(ctx context.Context, params *iam.GetServiceLastAccessedDetailsInput, optFns ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
}

// CloudTrailClient defines the strictly read-only CloudTrail subset used by nhilens.
type CloudTrailClient interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// OrganizationsClient defines the strictly read-only AWS Organizations subset used by nhilens
// for multi-account discovery and effective SCP guardrail resolution.
// No mutating Organizations APIs may ever be added to this interface.
type OrganizationsClient interface {
	DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListParents(ctx context.Context, params *organizations.ListParentsInput, optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

// Compile-time guarantees that AWS SDK v2 concrete clients satisfy our interfaces.
var (
	_ STSClient           = (*sts.Client)(nil)
	_ IAMClient           = (*iam.Client)(nil)
	_ CloudTrailClient    = (*cloudtrail.Client)(nil)
	_ OrganizationsClient = (*organizations.Client)(nil)
)
