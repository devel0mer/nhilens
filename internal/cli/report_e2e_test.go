package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/report"
)

func TestReportCommandEndToEndFromScanDB(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	evTime := now.Add(-1 * time.Hour)
	mockIAM := buildFixtureMockIAM(now)
	mockCT := &fakeCloudTrail{
		events: []cttypes.Event{
			{
				EventTime:       &evTime,
				EventName:       aws.String("ListBuckets"),
				EventSource:     aws.String("s3.amazonaws.com"),
				AccessKeyId:     aws.String("AKIAOLD1234567890123"),
				CloudTrailEvent: aws.String(`{"eventSource":"s3.amazonaws.com","eventName":"ListBuckets","sourceIPAddress":"198.51.100.1","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-bot","accessKeyId":"AKIAOLD1234567890123"}}`),
			},
			{
				EventTime:       &evTime,
				EventName:       aws.String("GetCallerIdentity"),
				EventSource:     aws.String("sts.amazonaws.com"),
				AccessKeyId:     aws.String("AKIAOLD1234567890123"),
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

	tmpDir := t.TempDir()
	var scanOut, scanErr bytes.Buffer
	if code := ExecuteWithDeps([]string{"scan", "--out", tmpDir}, &scanOut, &scanErr, deps); code != 0 {
		t.Fatalf("scan failed (code=%d): %s", code, scanErr.String())
	}

	dbPath := filepath.Join(tmpDir, "nhilens.db")
	htmlPath := filepath.Join(tmpDir, "reports", "audit.html")
	jsonPath := filepath.Join(tmpDir, "reports", "audit.json")

	// 1. Generate static HTML report.
	var repOut, repErr bytes.Buffer
	if code := Execute([]string{"report", "--in", dbPath, "--out", htmlPath}, &repOut, &repErr); code != 0 {
		t.Fatalf("report html failed (code=%d): %s", code, repErr.String())
	}
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read generated HTML: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "bedrock-support-agent") || !strings.Contains(htmlStr, "nhilens-graph-data") {
		t.Errorf("generated HTML missing expected content")
	}

	// 2. Generate JSON report.
	var repOut2, repErr2 bytes.Buffer
	if code := Execute([]string{"report", "--in", dbPath, "--out", jsonPath, "--format", "json"}, &repOut2, &repErr2); code != 0 {
		t.Fatalf("report json failed (code=%d): %s", code, repErr2.String())
	}
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read generated JSON: %v", err)
	}
	var decoded report.ReportData
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("unmarshal generated report JSON: %v", err)
	}
	if decoded.Summary.AccountID != "123456789012" || len(decoded.TopRisky) == 0 {
		t.Errorf("unexpected JSON report summary=%+v top_risky=%d", decoded.Summary, len(decoded.TopRisky))
	}

	// 3. Missing input DB returns non-zero cleanly.
	var missOut, missErr bytes.Buffer
	if code := Execute([]string{"report", "--in", filepath.Join(tmpDir, "missing.db")}, &missOut, &missErr); code == 0 {
		t.Errorf("expected non-zero exit code for missing input DB")
	}
}
