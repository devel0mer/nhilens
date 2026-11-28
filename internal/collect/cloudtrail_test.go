package collect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
	"github.com/devel0mer/nhilens/internal/model"
)

type mockCloudTrailClient struct {
	pages          []*cloudtrail.LookupEventsOutput
	throttleBefore int
	err            error
	calls          int
}

func (m *mockCloudTrailClient) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	m.calls++
	if m.calls <= m.throttleBefore {
		return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	if m.err != nil {
		return nil, m.err
	}
	idx := 0
	if in != nil && in.NextToken != nil && *in.NextToken == "tok2" {
		idx = 1
	}
	if idx >= len(m.pages) {
		return &cloudtrail.LookupEventsOutput{}, nil
	}
	return m.pages[idx], nil
}

func TestCloudTrailEnrichAttributionPaginationAndRetry(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	evTimeOld := now.Add(-45 * 24 * time.Hour) // outside 30d window
	evTime1 := now.Add(-2 * time.Hour)
	evTime2 := now.Add(-1 * time.Hour)

	roleARN := "arn:aws:iam::123456789012:role/bedrock-agent"
	userARN := "arn:aws:iam::123456789012:user/ci-bot"
	keyID := "AKIAKEY1111111111111"

	run := &model.ScanRun{
		AccountID: "123456789012",
		Identities: []model.Identity{
			{ID: roleARN, ARN: roleARN, Type: model.TypeRole, Name: "bedrock-agent"},
			{ID: userARN, ARN: userARN, Type: model.TypeUser, Name: "ci-bot"},
			{
				ID:   userARN + "/access-key/" + keyID,
				ARN:  userARN,
				Type: model.TypeKey,
				Name: keyID,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    keyID,
					ParentUserName: "ci-bot",
					ParentUserARN:  userARN,
				},
			},
		},
	}

	mockCT := &mockCloudTrailClient{
		throttleBefore: 1,
		pages: []*cloudtrail.LookupEventsOutput{
			{
				NextToken: aws.String("tok2"),
				Events: []cttypes.Event{
					{
						EventTime:   &evTimeOld,
						EventName:   aws.String("ListBuckets"),
						EventSource: aws.String("s3.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource": "s3.amazonaws.com",
							"eventName": "ListBuckets",
							"sourceIPAddress": "198.51.100.10",
							"userAgent": "Boto3/1.35.0 Python/3.12",
							"userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/ci-bot", "accessKeyId": "AKIAKEY1111111111111"}
						}`),
					},
					{
						EventTime:   &evTime1,
						EventName:   aws.String("GetCallerIdentity"),
						EventSource: aws.String("sts.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource": "sts.amazonaws.com",
							"eventName": "GetCallerIdentity",
							"sourceIPAddress": "203.0.113.55",
							"userAgent": "Boto3/1.35.0 Python/3.12",
							"userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/ci-bot", "accessKeyId": "AKIAKEY1111111111111"}
						}`),
					},
				},
			},
			{
				Events: []cttypes.Event{
					{
						EventTime:   &evTime2,
						EventName:   aws.String("InvokeModel"),
						EventSource: aws.String("bedrock.amazonaws.com"),
						CloudTrailEvent: aws.String(`{
							"eventSource": "bedrock.amazonaws.com",
							"eventName": "InvokeModel",
							"sourceIPAddress": "AWS Internal",
							"userAgent": "langchain-aws/0.2.1 Boto3/1.35.0",
							"userIdentity": {
								"type": "AssumedRole",
								"arn": "arn:aws:sts::123456789012:assumed-role/bedrock-agent/session-1",
								"sessionContext": {
									"sessionIssuer": {
										"type": "Role",
										"arn": "arn:aws:iam::123456789012:role/bedrock-agent"
									}
								}
							}
						}`),
					},
				},
			},
		},
	}

	collector := NewCloudTrailCollector(mockCT, CloudTrailOptions{
		Since:              120 * 24 * time.Hour, // > 90d should clamp with warning
		MaxEvents:          100,
		Retry:              RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond, Sleep: noopSleep},
		MinRequestInterval: -1,
		Sleep:              noopSleep,
		Now:                func() time.Time { return now },
	})

	collector.Enrich(context.Background(), run)

	if run.CloudTrailStatus != model.CloudTrailStatusOK {
		t.Fatalf("CloudTrailStatus = %q, want ok (warnings=%v)", run.CloudTrailStatus, run.Warnings)
	}
	if run.CloudTrailEventCount != 3 {
		t.Errorf("CloudTrailEventCount = %d, want 3", run.CloudTrailEventCount)
	}
	if len(run.Warnings) != 1 || !strings.Contains(run.Warnings[0], "clamped --since") {
		t.Errorf("expected 90d clamp warning, got %v", run.Warnings)
	}

	role := run.Identities[0]
	if role.CloudTrailEventCount != 1 {
		t.Errorf("role event count = %d, want 1", role.CloudTrailEventCount)
	}
	if len(role.SourceIPs) != 0 {
		t.Errorf("expected AWS Internal filtered out of role SourceIPs, got %v", role.SourceIPs)
	}
	if !reflect.DeepEqual(role.RecentEventNames, []string{"bedrock:InvokeModel"}) {
		t.Errorf("role RecentEventNames = %v", role.RecentEventNames)
	}
	if role.LastUsed == nil || !role.LastUsed.Equal(evTime2) {
		t.Errorf("role LastUsed = %v, want %v", role.LastUsed, evTime2)
	}
	if !reflect.DeepEqual(role.ObservedUserAgents, []string{"langchain-aws/0.2.1 Boto3/1.35.0"}) {
		t.Errorf("role ObservedUserAgents = %v", role.ObservedUserAgents)
	}
	if role.Activity30d == nil || role.Activity30d.TotalEvents != 1 || len(role.Activity30d.TopAPIs) != 1 || role.Activity30d.TopAPIs[0].Name != "bedrock:InvokeModel" {
		t.Errorf("unexpected role Activity30d: %+v", role.Activity30d)
	}

	key := run.Identities[2]
	if !reflect.DeepEqual(key.SourceIPs, []string{"198.51.100.10", "203.0.113.55"}) {
		t.Errorf("key SourceIPs = %v, want [198.51.100.10 203.0.113.55]", key.SourceIPs)
	}
	if key.CloudTrailEventCount != 2 {
		t.Errorf("key CloudTrailEventCount = %d, want 2", key.CloudTrailEventCount)
	}
	// Only 1 of the 2 key events occurred within the trailing 30 days (the 45d-old event is excluded from Activity30d).
	if key.Activity30d == nil || key.Activity30d.TotalEvents != 1 {
		t.Errorf("expected key Activity30d.TotalEvents = 1 (excluding 45d-old event), got %+v", key.Activity30d)
	}
}

func TestCloudTrailCapDisabledAndAccessDeniedFallback(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. --max-events=0 disables lookup without making API calls.
	mockDisabled := &mockCloudTrailClient{}
	runDisabled := &model.ScanRun{Identities: []model.Identity{{ID: "r1", Type: model.TypeRole, Name: "r1"}}}
	NewCloudTrailCollector(mockDisabled, CloudTrailOptions{MaxEvents: 0, Now: func() time.Time { return now }}).Enrich(context.Background(), runDisabled)
	if runDisabled.CloudTrailStatus != model.CloudTrailStatusDisabled || mockDisabled.calls != 0 {
		t.Errorf("expected disabled with 0 calls, got status=%q calls=%d", runDisabled.CloudTrailStatus, mockDisabled.calls)
	}

	// 2. AccessDenied falls back gracefully to "unknown" with warning.
	mockDenied := &mockCloudTrailClient{err: errors.New("AccessDeniedException: not authorized")}
	runDenied := &model.ScanRun{Identities: []model.Identity{{ID: "r1", Type: model.TypeRole, Name: "r1"}}}
	NewCloudTrailCollector(mockDenied, CloudTrailOptions{MaxEvents: 100, MinRequestInterval: -1, Sleep: noopSleep, Now: func() time.Time { return now }}).Enrich(context.Background(), runDenied)
	if runDenied.CloudTrailStatus != model.CloudTrailStatusUnknown || runDenied.Identities[0].CloudTrailStatus != model.CloudTrailStatusUnknown {
		t.Errorf("expected unknown status on access denied, got run=%q ident=%q", runDenied.CloudTrailStatus, runDenied.Identities[0].CloudTrailStatus)
	}
	if len(runDenied.Warnings) == 0 {
		t.Errorf("expected warning recorded on access denied")
	}

	// 3. Hitting --max-events cap when NextToken remains sets "partial" status.
	mockCapped := &mockCloudTrailClient{
		pages: []*cloudtrail.LookupEventsOutput{
			{
				NextToken: aws.String("tok2"),
				Events:    []cttypes.Event{{EventName: aws.String("ListUsers")}, {EventName: aws.String("ListRoles")}},
			},
		},
	}
	runCapped := &model.ScanRun{}
	NewCloudTrailCollector(mockCapped, CloudTrailOptions{MaxEvents: 1, MinRequestInterval: -1, Sleep: noopSleep, Now: func() time.Time { return now }}).Enrich(context.Background(), runCapped)
	if runCapped.CloudTrailStatus != model.CloudTrailStatusPartial || runCapped.CloudTrailEventCount != 1 {
		t.Errorf("expected partial status capped at 1 event, got status=%q count=%d", runCapped.CloudTrailStatus, runCapped.CloudTrailEventCount)
	}
}

func TestEnrichRegionsAggregatesCrossRegionIPsUserAgentsAndDedupesEvents(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	t1 := now.Add(-3 * time.Hour)
	t2 := now.Add(-1 * time.Hour)

	roleARN := "arn:aws:iam::123456789012:role/eu-bedrock-agent"
	userARN := "arn:aws:iam::123456789012:user/ci-bot"
	keyID := "AKIAKEY2222222222222"

	run := &model.ScanRun{
		AccountID: "123456789012",
		Region:    "us-east-1",
		Identities: []model.Identity{
			{ID: roleARN, ARN: roleARN, Type: model.TypeRole, Name: "eu-bedrock-agent"},
			{ID: userARN, ARN: userARN, Type: model.TypeUser, Name: "ci-bot"},
			{
				ID:   userARN + "/access-key/" + keyID,
				ARN:  userARN,
				Type: model.TypeKey,
				Name: keyID,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    keyID,
					ParentUserName: "ci-bot",
					ParentUserARN:  userARN,
				},
			},
		},
	}

	usEast := &mockCloudTrailClient{
		pages: []*cloudtrail.LookupEventsOutput{
			{
				Events: []cttypes.Event{
					{
						EventId:     aws.String("evt-us-1"),
						EventTime:   &t1,
						EventName:   aws.String("ListBuckets"),
						EventSource: aws.String("s3.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource":"s3.amazonaws.com",
							"eventName":"ListBuckets",
							"sourceIPAddress":"198.51.100.10",
							"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAKEY2222222222222"}
						}`),
					},
					{
						EventId:     aws.String("evt-global-dup"),
						EventTime:   &t1,
						EventName:   aws.String("GetCallerIdentity"),
						EventSource: aws.String("sts.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource":"sts.amazonaws.com",
							"eventName":"GetCallerIdentity",
							"sourceIPAddress":"198.51.100.10",
							"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAKEY2222222222222"}
						}`),
					},
				},
			},
		},
	}

	euWest := &mockCloudTrailClient{
		pages: []*cloudtrail.LookupEventsOutput{
			{
				Events: []cttypes.Event{
					{
						EventId:     aws.String("evt-global-dup"), // duplicate EventId across regions must be deduped
						EventTime:   &t1,
						EventName:   aws.String("GetCallerIdentity"),
						EventSource: aws.String("sts.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource":"sts.amazonaws.com",
							"eventName":"GetCallerIdentity",
							"sourceIPAddress":"198.51.100.10",
							"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAKEY2222222222222"}
						}`),
					},
					{
						EventId:     aws.String("evt-eu-1"),
						EventTime:   &t2,
						EventName:   aws.String("GetObject"),
						EventSource: aws.String("s3.amazonaws.com"),
						AccessKeyId: aws.String(keyID),
						CloudTrailEvent: aws.String(`{
							"eventSource":"s3.amazonaws.com",
							"eventName":"GetObject",
							"sourceIPAddress":"203.0.113.77",
							"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAKEY2222222222222"}
						}`),
					},
					{
						EventId:     aws.String("evt-eu-2"),
						EventTime:   &t2,
						EventName:   aws.String("InvokeModel"),
						EventSource: aws.String("bedrock.amazonaws.com"),
						CloudTrailEvent: aws.String(`{
							"eventSource":"bedrock.amazonaws.com",
							"eventName":"InvokeModel",
							"userAgent":"anthropic-sdk-python/0.49.0 Boto3/1.35.0",
							"userIdentity":{
								"type":"AssumedRole",
								"arn":"arn:aws:sts::123456789012:assumed-role/eu-bedrock-agent/s1",
								"sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/eu-bedrock-agent"}}
							}
						}`),
					},
				},
			},
		},
	}

	EnrichRegions(
		context.Background(),
		[]RegionCloudTrailClient{
			{Region: "us-east-1", Client: usEast},
			{Region: "eu-west-1", Client: euWest},
		},
		CloudTrailOptions{MaxEvents: 100, MaxConcurrency: 2, MinRequestInterval: -1, Sleep: noopSleep, Now: func() time.Time { return now }},
		run,
	)

	if run.CloudTrailStatus != model.CloudTrailStatusOK {
		t.Fatalf("CloudTrailStatus = %q, want ok (warnings=%v)", run.CloudTrailStatus, run.Warnings)
	}
	// 2 unique from us-east-1 + 2 unique from eu-west-1 (1 duplicate deduped) = 4 total.
	if run.CloudTrailEventCount != 4 {
		t.Errorf("CloudTrailEventCount = %d, want 4 (deduped)", run.CloudTrailEventCount)
	}
	if !reflect.DeepEqual(run.Regions, []string{"us-east-1", "eu-west-1"}) {
		t.Errorf("run.Regions = %v, want [us-east-1 eu-west-1]", run.Regions)
	}
	if run.Coverage == nil || len(run.Coverage.CloudTrailRegions) != 2 {
		t.Fatalf("expected 2 per-region coverage entries, got %+v", run.Coverage)
	}

	key := run.Identities[2]
	if !reflect.DeepEqual(key.SourceIPs, []string{"198.51.100.10", "203.0.113.77"}) {
		t.Errorf("cross-region key SourceIPs = %v, want [198.51.100.10 203.0.113.77]", key.SourceIPs)
	}
	if key.CloudTrailEventCount != 3 {
		t.Errorf("key CloudTrailEventCount = %d, want 3 (deduped)", key.CloudTrailEventCount)
	}

	role := run.Identities[0]
	if !reflect.DeepEqual(role.ObservedUserAgents, []string{"anthropic-sdk-python/0.49.0 Boto3/1.35.0"}) {
		t.Errorf("role ObservedUserAgents from eu-west-1 = %v", role.ObservedUserAgents)
	}
	if role.LastUsed == nil || !role.LastUsed.Equal(t2) {
		t.Errorf("role LastUsed = %v, want %v", role.LastUsed, t2)
	}
}

func TestEnrichRegionsPartialFailurePreservesSuccessAndSurfacesGap(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	run := &model.ScanRun{
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Identities: []model.Identity{{ID: "r1", ARN: "arn:aws:iam::123456789012:role/r1", Type: model.TypeRole, Name: "r1"}},
	}

	okCT := &mockCloudTrailClient{
		pages: []*cloudtrail.LookupEventsOutput{
			{Events: []cttypes.Event{{EventId: aws.String("e1"), EventName: aws.String("ListRoles")}}},
		},
	}
	deniedCT := &mockCloudTrailClient{err: errors.New("AccessDeniedException: blocked by SCP")}

	EnrichRegions(
		context.Background(),
		[]RegionCloudTrailClient{
			{Region: "us-east-1", Client: okCT},
			{Region: "eu-west-1", Client: deniedCT},
		},
		CloudTrailOptions{MaxEvents: 100, MaxConcurrency: 2, MinRequestInterval: -1, Sleep: noopSleep, Now: func() time.Time { return now }},
		run,
	)

	if run.CloudTrailStatus != model.CloudTrailStatusPartial {
		t.Fatalf("expected partial status when 1 of 2 regions fails, got %q", run.CloudTrailStatus)
	}
	if len(run.Coverage.CloudTrailRegions) != 2 || run.Coverage.CloudTrailRegions[1].Error == "" {
		t.Errorf("expected eu-west-1 error recorded in CloudTrailRegions, got %+v", run.Coverage.CloudTrailRegions)
	}
	if run.Identities[0].CoverageStatus != model.CoverageStatusPartial {
		t.Errorf("expected identity marked partial when a region fails, got %q (gaps=%v)", run.Identities[0].CoverageStatus, run.Identities[0].DataGaps)
	}
	foundRegionWarn := false
	for _, w := range run.Warnings {
		if strings.Contains(w, "[eu-west-1]") {
			foundRegionWarn = true
			break
		}
	}
	if !foundRegionWarn {
		t.Errorf("expected warning tagged with [eu-west-1], got %v", run.Warnings)
	}
}
