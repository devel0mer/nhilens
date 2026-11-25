package collect

import (
	"context"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

type apiCallCounters struct {
	authDetails atomic.Int64
	loginProf   atomic.Int64
	listKeys    atomic.Int64
	keyLastUsed atomic.Int64
	genSLA      atomic.Int64
	getSLA      atomic.Int64
	throttled   atomic.Int64
}

type instrumentedScaleIAM struct {
	pages          []*iam.GetAccountAuthorizationDetailsOutput
	throttleEveryN int64
	callSeq        atomic.Int64
	counts         apiCallCounters
}

func (m *instrumentedScaleIAM) maybeThrottle() error {
	if m.throttleEveryN <= 0 {
		return nil
	}
	if m.callSeq.Add(1)%m.throttleEveryN == 0 {
		m.counts.throttled.Add(1)
		return &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	return nil
}

func (m *instrumentedScaleIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	m.counts.authDetails.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	idx := 0
	if in != nil && in.Marker != nil {
		_, _ = fmt.Sscanf(*in.Marker, "page-%d", &idx)
	}
	return m.pages[idx], nil
}

func (m *instrumentedScaleIAM) GetLoginProfile(_ context.Context, _ *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	m.counts.loginProf.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	return nil, &iamtypes.NoSuchEntityException{Message: aws.String("not found")}
}

func (m *instrumentedScaleIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	m.counts.listKeys.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
			{
				AccessKeyId: aws.String("AKIA" + aws.ToString(in.UserName)),
				UserName:    in.UserName,
				Status:      iamtypes.StatusTypeActive,
				CreateDate:  &now,
			},
		},
	}, nil
}

func (m *instrumentedScaleIAM) GetAccessKeyLastUsed(_ context.Context, _ *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	m.counts.keyLastUsed.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{ServiceName: aws.String("s3"), Region: aws.String("us-east-1")},
	}, nil
}

func (m *instrumentedScaleIAM) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	m.counts.genSLA.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("job-" + aws.ToString(in.Arn))}, nil
}

func (m *instrumentedScaleIAM) GetServiceLastAccessedDetails(_ context.Context, _ *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	m.counts.getSLA.Add(1)
	if err := m.maybeThrottle(); err != nil {
		return nil, err
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{ServiceNamespace: aws.String("s3"), LastAuthenticated: &now},
		},
	}, nil
}

// buildSyntheticScalePages generates realistic IAM account pages:
//   - 60% normal roles with policies
//   - 15% AWS service-linked roles (/aws-service-role/)
//   - 15% zero-policy roles
//   - 10% programmatic IAM users with an attached policy + 1 active access key
func buildSyntheticScalePages(totalPrincipals int) []*iam.GetAccountAuthorizationDetailsOutput {
	const pageSize = 100
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	trustDoc := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	inlineDoc := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}`)

	numPages := (totalPrincipals + pageSize - 1) / pageSize
	pages := make([]*iam.GetAccountAuthorizationDetailsOutput, 0, numPages)

	for p := 0; p < numPages; p++ {
		start := p * pageSize
		end := min(start+pageSize, totalPrincipals)
		out := &iam.GetAccountAuthorizationDetailsOutput{}

		for i := start; i < end; i++ {
			mod := i % 20
			switch {
			case mod < 12: // 60%: normal role with policy
				name := fmt.Sprintf("workload-role-%05d", i)
				out.RoleDetailList = append(out.RoleDetailList, iamtypes.RoleDetail{
					Arn:                      aws.String("arn:aws:iam::123456789012:role/" + name),
					RoleName:                 aws.String(name),
					Path:                     aws.String("/"),
					CreateDate:               &now,
					AssumeRolePolicyDocument: aws.String(trustDoc),
					RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: aws.String("read-s3"), PolicyDocument: aws.String(inlineDoc)}},
				})
			case mod < 15: // 15%: excluded service-linked role
				name := fmt.Sprintf("AWSServiceRoleForSvc%05d", i)
				out.RoleDetailList = append(out.RoleDetailList, iamtypes.RoleDetail{
					Arn:                     aws.String("arn:aws:iam::123456789012:role/aws-service-role/svc.amazonaws.com/" + name),
					RoleName:                aws.String(name),
					Path:                    aws.String("/aws-service-role/svc.amazonaws.com/"),
					CreateDate:              &now,
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{{PolicyName: aws.String("SLRPolicy"), PolicyArn: aws.String("arn:aws:iam::aws:policy/aws-service-role/SLRPolicy")}},
				})
			case mod < 18: // 15%: zero-policy role
				name := fmt.Sprintf("unused-empty-role-%05d", i)
				out.RoleDetailList = append(out.RoleDetailList, iamtypes.RoleDetail{
					Arn:        aws.String("arn:aws:iam::123456789012:role/" + name),
					RoleName:   aws.String(name),
					Path:       aws.String("/"),
					CreateDate: &now,
				})
			default: // 10%: IAM user with policy + 1 key
				name := fmt.Sprintf("bot-user-%05d", i)
				out.UserDetailList = append(out.UserDetailList, iamtypes.UserDetail{
					Arn:            aws.String("arn:aws:iam::123456789012:user/" + name),
					UserName:       aws.String(name),
					Path:           aws.String("/"),
					CreateDate:     &now,
					UserPolicyList: []iamtypes.PolicyDetail{{PolicyName: aws.String("read-s3"), PolicyDocument: aws.String(inlineDoc)}},
				})
			}
		}

		if p < numPages-1 {
			out.IsTruncated = true
			out.Marker = aws.String(fmt.Sprintf("page-%d", p+1))
		}
		pages = append(pages, out)
	}
	return pages
}

// TestLargeAccountAPICallsAndThrottling measures API call volume, duration, Access Advisor skip
// savings, and AWS throttling backoff resilience across 100 and 1,000 synthetic principals.
func TestLargeAccountAPICallsAndThrottling(t *testing.T) {
	sizes := []struct {
		name           string
		principals     int
		concurrency    int
		throttleEveryN int64
	}{
		{name: "100-principals-c5-no-throttle", principals: 100, concurrency: 5, throttleEveryN: 0},
		{name: "1000-principals-c10-with-10pct-throttling", principals: 1000, concurrency: 10, throttleEveryN: 10},
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := &instrumentedScaleIAM{
				pages:          buildSyntheticScalePages(tc.principals),
				throttleEveryN: tc.throttleEveryN,
			}
			collector := NewIAMCollector(
				&mockSTSClient{account: "123456789012", arn: "arn:aws:iam::123456789012:role/auditor"},
				mockIAM,
				Options{
					MaxConcurrency: tc.concurrency,
					Retry: RetryPolicy{
						MaxAttempts: 5,
						BaseDelay:   time.Microsecond,
						MaxDelay:    time.Millisecond,
						Sleep:       noopSleep,
					},
					Sleep: noopSleep,
				},
			)

			start := time.Now()
			run, err := collector.Collect(context.Background(), "", "us-east-1", "90d")
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Collect(%d) failed: %v", tc.principals, err)
			}

			// 10% of principals are users, each with 1 access key => total identities = 1.1 * principals.
			wantIdentities := tc.principals + tc.principals/10
			if len(run.Identities) != wantIdentities {
				t.Fatalf("got %d identities, want %d", len(run.Identities), wantIdentities)
			}
			if run.Coverage == nil {
				t.Fatalf("expected non-nil Coverage")
			}

			// 30% of principals (15% SLR + 15% empty roles) must skip Access Advisor automatically.
			wantSLRSkip := (tc.principals * 15) / 100
			wantNoPolSkip := (tc.principals * 15) / 100
			wantAttempted := tc.principals - wantSLRSkip - wantNoPolSkip
			if run.Coverage.AccessAdvisorSkippedSLR != wantSLRSkip || run.Coverage.AccessAdvisorSkippedNoPolicy != wantNoPolSkip || run.Coverage.AccessAdvisorAttempted != wantAttempted {
				t.Errorf("Access Advisor counts = (attempted=%d slr_skip=%d nopol_skip=%d), want (%d, %d, %d)",
					run.Coverage.AccessAdvisorAttempted, run.Coverage.AccessAdvisorSkippedSLR, run.Coverage.AccessAdvisorSkippedNoPolicy,
					wantAttempted, wantSLRSkip, wantNoPolSkip)
			}
			if run.Coverage.AccessAdvisorFailed != 0 || run.Coverage.LoginProfileFailed != 0 {
				t.Errorf("expected zero enrichment failures after retry backoff, got coverage=%+v warnings=%v", run.Coverage, run.Warnings)
			}

			totalCalls := mockIAM.counts.authDetails.Load() + mockIAM.counts.loginProf.Load() +
				mockIAM.counts.listKeys.Load() + mockIAM.counts.keyLastUsed.Load() +
				mockIAM.counts.genSLA.Load() + mockIAM.counts.getSLA.Load()
			t.Logf("%s: %d identities in %s | total IAM calls=%d (auth=%d, login=%d, keys=%d, lastUsed=%d, genSLA=%d, getSLA=%d, throttled_retries=%d) | saved %d Access Advisor jobs",
				tc.name, len(run.Identities), elapsed, totalCalls,
				mockIAM.counts.authDetails.Load(), mockIAM.counts.loginProf.Load(),
				mockIAM.counts.listKeys.Load(), mockIAM.counts.keyLastUsed.Load(),
				mockIAM.counts.genSLA.Load(), mockIAM.counts.getSLA.Load(),
				mockIAM.counts.throttled.Load(), wantSLRSkip+wantNoPolSkip)
		})
	}
}

func BenchmarkCollectScale(b *testing.B) {
	cases := []struct {
		name        string
		principals  int
		concurrency int
		skipSLA     bool
	}{
		{name: "100_c5_full", principals: 100, concurrency: 5, skipSLA: false},
		{name: "1000_c5_full", principals: 1000, concurrency: 5, skipSLA: false},
		{name: "1000_c10_full", principals: 1000, concurrency: 10, skipSLA: false},
		{name: "1000_c10_skip_sla", principals: 1000, concurrency: 10, skipSLA: true},
	}

	for _, tc := range cases {
		pages := buildSyntheticScalePages(tc.principals)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				collector := NewIAMCollector(
					&mockSTSClient{account: "123456789012", arn: "arn:aws:iam::123456789012:role/auditor"},
					&instrumentedScaleIAM{pages: pages},
					Options{
						MaxConcurrency:          tc.concurrency,
						SkipServiceLastAccessed: tc.skipSLA,
						Sleep:                   noopSleep,
					},
				)
				if _, err := collector.Collect(context.Background(), "", "us-east-1", "90d"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
