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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/devel0mer/nhilens/internal/collect"
)

func TestIgnoreSuppressionDiffAndSARIFEndToEnd(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tmpDir := t.TempDir()

	// Scan 1 (base): single owned, clean role.
	baseIAM := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:      aws.String("arn:aws:iam::123456789012:role/clean-worker"),
					RoleName: aws.String("clean-worker"),
					Path:     aws.String("/"),
					Tags:     []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("core")}},
				},
			},
		},
	}
	baseDeps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "123456789012", arn: "arn:aws:iam::123456789012:role/nhilens-ro"}, baseIAM, &fakeCloudTrail{}, nil
		},
		Now: func() time.Time { return t1 },
		CollectorHooks: func(opts *collect.Options) {
			opts.Sleep = func(_ context.Context, _ time.Duration) error { return nil }
		},
	}

	var out1, err1 bytes.Buffer
	if code := ExecuteWithDeps([]string{"scan", "--out", tmpDir, "--max-events", "0"}, &out1, &err1, baseDeps); code != 0 {
		t.Fatalf("base scan failed (code=%d): %s", code, err1.String())
	}

	// Scan 2 (head) into the SAME SQLite DB: adds an unowned admin agent role.
	headIAM := &fakeIAM{
		authOut: &iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{
					Arn:      aws.String("arn:aws:iam::123456789012:role/clean-worker"),
					RoleName: aws.String("clean-worker"),
					Path:     aws.String("/"),
					Tags:     []iamtypes.Tag{{Key: aws.String("owner"), Value: aws.String("core")}},
				},
				{
					Arn:      aws.String("arn:aws:iam::123456789012:role/new-admin-agent"),
					RoleName: aws.String("new-admin-agent"),
					Path:     aws.String("/"),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{
						{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
					},
				},
			},
		},
	}
	headDeps := ScanDeps{
		NewClients: func(_ context.Context, _, _ string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error) {
			return &fakeSTS{account: "123456789012", arn: "arn:aws:iam::123456789012:role/nhilens-ro"}, headIAM, &fakeCloudTrail{}, nil
		},
		Now: func() time.Time { return t2 },
		CollectorHooks: func(opts *collect.Options) {
			opts.Sleep = func(_ context.Context, _ time.Duration) error { return nil }
		},
	}

	var out2, err2 bytes.Buffer
	if code := ExecuteWithDeps([]string{"scan", "--out", tmpDir, "--max-events", "0", "--format", "sarif"}, &out2, &err2, headDeps); code != 0 {
		t.Fatalf("head scan --format sarif failed (code=%d): %s", code, err2.String())
	}
	var sarifCheck map[string]any
	if err := json.Unmarshal(out2.Bytes(), &sarifCheck); err != nil {
		t.Fatalf("scan --format sarif emitted invalid JSON: %v", err)
	}
	if sarifCheck["version"] != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %v", sarifCheck["version"])
	}

	// 1. Run nhilens diff against the single DB (auto-compares previous vs latest) with --fail-on-new critical => exit code 2.
	dbPath := filepath.Join(tmpDir, "nhilens.db")
	var diffOut, diffErr bytes.Buffer
	diffCode := Execute([]string{"diff", "--base", dbPath, "--format", "markdown", "--fail-on-new", "critical"}, &diffOut, &diffErr)
	if diffCode != 2 {
		t.Fatalf("expected exit code 2 from diff --fail-on-new critical, got %d (stderr=%q)", diffCode, diffErr.String())
	}
	if !strings.Contains(diffOut.String(), "new-admin-agent") || !strings.Contains(diffOut.String(), "R1") {
		t.Errorf("unexpected diff markdown output:\n%s", diffOut.String())
	}

	// 2. Suppress R1 via .nhilens-ignore.yaml => --fail-on critical now passes with exit code 0!
	ignorePath := filepath.Join(tmpDir, ".nhilens-ignore.yaml")
	ignoreContent := `
suppressions:
  - rule_id: R1
    identity: "new-admin-agent"
    reason: "Approved temporary sandbox test"
    expires: "2027-01-01"
`
	if err := os.WriteFile(ignorePath, []byte(ignoreContent), 0o600); err != nil {
		t.Fatal(err)
	}

	outDirSup := t.TempDir()
	var supOut, supErr bytes.Buffer
	supCode := ExecuteWithDeps(
		[]string{"scan", "--out", outDirSup, "--max-events", "0", "--ignore", ignorePath, "--fail-on", "critical"},
		&supOut, &supErr, headDeps,
	)
	if supCode != 0 {
		t.Fatalf("expected exit code 0 when critical finding is suppressed, got %d (stderr=%q)", supCode, supErr.String())
	}
	if !strings.Contains(supOut.String(), "Suppressed: 1 finding(s)") {
		t.Errorf("expected table summary to mention suppressed finding, got:\n%s", supOut.String())
	}

	// 3. Report command exports SARIF, Markdown, and CSV from saved SQLite DB.
	supDB := filepath.Join(outDirSup, "nhilens.db")
	for _, fmtName := range []string{"sarif", "markdown", "csv"} {
		outFile := filepath.Join(outDirSup, "out."+fmtName)
		var rOut, rErr bytes.Buffer
		if code := Execute([]string{"report", "--in", supDB, "--out", outFile, "--format", fmtName}, &rOut, &rErr); code != 0 {
			t.Fatalf("report --format %s failed (code=%d): %s", fmtName, code, rErr.String())
		}
		if st, err := os.Stat(outFile); err != nil || st.Size() == 0 {
			t.Errorf("expected non-empty output file %s (err=%v)", outFile, err)
		}
	}
}
