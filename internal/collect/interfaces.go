package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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

// Compile-time guarantees that AWS SDK v2 concrete clients satisfy our interfaces.
var (
	_ STSClient        = (*sts.Client)(nil)
	_ IAMClient        = (*iam.Client)(nil)
	_ CloudTrailClient = (*cloudtrail.Client)(nil)
)
