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
