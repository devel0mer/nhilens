package collect

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DefaultEnabledAWSRegions lists the 17 standard commercial AWS regions that are enabled
// by default without opt-in. Used when `--regions all` is requested so multi-region scans
// stay strictly within nhilens's minimal read-only IAM policy (no ec2:DescribeRegions needed).
var DefaultEnabledAWSRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"ap-south-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-southeast-1",
	"ap-southeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"eu-north-1",
	"sa-east-1",
}

var awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)

// AssumeRoleOptions configures read-only cross-account STS AssumeRole calls.
type AssumeRoleOptions struct {
	RoleName    string
	ExternalID  string
	SessionName string
	Partition   string // aws | aws-us-gov | aws-cn (auto-detected from caller ARN if empty)
}

// AccountClients bundles scoped read-only AWS clients targeting a single account.
type AccountClients struct {
	STS                 STSClient
	IAM                 IAMClient
	PrimaryCloudTrail   CloudTrailClient
	CloudTrailForRegion func(ctx context.Context, region string) (CloudTrailClient, error)
}

// IsValidAccountID reports whether s is a 12-digit AWS account ID.
func IsValidAccountID(s string) bool {
	return awsAccountIDPattern.MatchString(strings.TrimSpace(s))
}

// PartitionFromARN extracts the AWS partition ("aws", "aws-us-gov", "aws-cn") from an ARN,
// defaulting to "aws" when unrecognized.
func PartitionFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if !strings.HasPrefix(trimmed, "arn:") {
		return "aws"
	}
	parts := strings.SplitN(trimmed, ":", 4)
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}
	return "aws"
}

// BuildAssumeRoleARN constructs the target IAM role ARN for cross-account AssumeRole.
// Accepts either a role name / path (e.g. "nhilens-readonly" or "audit/nhilens-readonly")
// or an explicit role ARN.
func BuildAssumeRoleARN(partition, accountID, roleNameOrARN string) (string, error) {
	acct := strings.TrimSpace(accountID)
	if !IsValidAccountID(acct) {
		return "", fmt.Errorf("invalid AWS account ID %q (expected 12 digits)", accountID)
	}
	role := strings.TrimSpace(roleNameOrARN)
	if role == "" {
		return "", fmt.Errorf("assume role name is required for cross-account scan of account %s", acct)
	}
	if strings.HasPrefix(role, "arn:") {
		return role, nil
	}
	role = strings.TrimPrefix(role, "/")
	part := strings.TrimSpace(partition)
	if part == "" {
		part = "aws"
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", part, acct, role), nil
}

// NewAWSClients constructs STS, IAM, and CloudTrail clients using the standard AWS SDK v2
// credential chain (environment variables, shared profile, AWS SSO, or instance/task metadata).
// nhilens never prompts for or stores credentials.
func NewAWSClients(ctx context.Context, profile, region string) (STSClient, IAMClient, CloudTrailClient, error) {
	cfg, err := loadAWSConfig(ctx, profile, region)
	if err != nil {
		return nil, nil, nil, err
	}
	return sts.NewFromConfig(cfg), iam.NewFromConfig(cfg), cloudtrail.NewFromConfig(cfg), nil
}

// NewCloudTrailClientForRegion constructs a regional CloudTrail client using the standard AWS SDK v2
// credential chain, targeting the specified AWS region.
func NewCloudTrailClientForRegion(ctx context.Context, profile, region string) (CloudTrailClient, error) {
	cfg, err := loadAWSConfig(ctx, profile, region)
	if err != nil {
		return nil, fmt.Errorf("load AWS config for region %q: %w", region, err)
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// NewOrganizationsClient constructs a strictly read-only AWS Organizations client.
// AWS Organizations is hosted in us-east-1 (commercial), us-gov-west-1 (GovCloud), or cn-northwest-1 (China).
func NewOrganizationsClient(ctx context.Context, profile, region string) (OrganizationsClient, error) {
	orgRegion := "us-east-1"
	r := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(r, "us-gov-"):
		orgRegion = "us-gov-west-1"
	case strings.HasPrefix(r, "cn-"):
		orgRegion = "cn-northwest-1"
	}
	cfg, err := loadAWSConfig(ctx, profile, orgRegion)
	if err != nil {
		return nil, fmt.Errorf("load AWS Organizations config: %w", err)
	}
	return organizations.NewFromConfig(cfg), nil
}

// AssumeAccountClients assumes a read-only IAM role in targetAccountID via STS AssumeRole
// and returns STS, IAM, and regional CloudTrail clients bound to those temporary credentials.
func AssumeAccountClients(ctx context.Context, profile, primaryRegion, targetAccountID string, opts AssumeRoleOptions) (*AccountClients, error) {
	roleARN, err := BuildAssumeRoleARN(opts.Partition, targetAccountID, opts.RoleName)
	if err != nil {
		return nil, err
	}

	baseCfg, err := loadAWSConfig(ctx, profile, primaryRegion)
	if err != nil {
		return nil, err
	}

	sessionName := strings.TrimSpace(opts.SessionName)
	if sessionName == "" {
		sessionName = "nhilens-readonly"
	}

	baseSTS := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewAssumeRoleProvider(baseSTS, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		if ext := strings.TrimSpace(opts.ExternalID); ext != "" {
			o.ExternalID = aws.String(ext)
		}
	})
	credsCache := aws.NewCredentialsCache(provider)

	assumedCfg := baseCfg.Copy()
	assumedCfg.Credentials = credsCache

	return &AccountClients{
		STS:               sts.NewFromConfig(assumedCfg),
		IAM:               iam.NewFromConfig(assumedCfg),
		PrimaryCloudTrail: cloudtrail.NewFromConfig(assumedCfg),
		CloudTrailForRegion: func(_ context.Context, region string) (CloudTrailClient, error) {
			regCfg := assumedCfg.Copy()
			if r := strings.TrimSpace(region); r != "" {
				regCfg.Region = r
			}
			return cloudtrail.NewFromConfig(regCfg), nil
		},
	}, nil
}

func loadAWSConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	loadOpts := make([]func(*awsconfig.LoadOptions) error, 0, 2)
	if p := strings.TrimSpace(profile); p != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(p))
	}
	if r := strings.TrimSpace(region); r != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(r))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}
