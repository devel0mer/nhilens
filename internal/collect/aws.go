package collect

import (
	"context"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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

// NewAWSClients constructs STS, IAM, and CloudTrail clients using the standard AWS SDK v2
// credential chain (environment variables, shared profile, AWS SSO, or instance/task metadata).
// nhilens never prompts for or stores credentials.
func NewAWSClients(ctx context.Context, profile, region string) (STSClient, IAMClient, CloudTrailClient, error) {
	loadOpts := make([]func(*awsconfig.LoadOptions) error, 0, 2)
	if p := strings.TrimSpace(profile); p != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(p))
	}
	if r := strings.TrimSpace(region); r != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(r))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load AWS config: %w", err)
	}

	return sts.NewFromConfig(cfg), iam.NewFromConfig(cfg), cloudtrail.NewFromConfig(cfg), nil
}

// NewCloudTrailClientForRegion constructs a regional CloudTrail client using the standard AWS SDK v2
// credential chain, targeting the specified AWS region.
func NewCloudTrailClientForRegion(ctx context.Context, profile, region string) (CloudTrailClient, error) {
	loadOpts := make([]func(*awsconfig.LoadOptions) error, 0, 2)
	if p := strings.TrimSpace(profile); p != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(p))
	}
	if r := strings.TrimSpace(region); r != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(r))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config for region %q: %w", region, err)
	}

	return cloudtrail.NewFromConfig(cfg), nil
}
