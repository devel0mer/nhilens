package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestStoreSaveAndLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "nested", "nhilens.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", dbPath, err)
	}
	defer func() { _ = st.Close() }()

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(dbPath)
		if statErr != nil {
			t.Fatalf("stat %q: %v", dbPath, statErr)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("SQLite DB file mode = %04o, want 0600", got)
		}
	}

	// Empty database returns ErrNotFound.
	if _, err := st.LoadLatestScan(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on empty DB, got %v", err)
	}

	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	created := t1.Add(-100 * 24 * time.Hour)
	owner := "ai-team"
	hasConsole := false

	scan1 := &model.ScanRun{
		ID:               "scan-1",
		AccountID:        "123456789012",
		CallerARN:        "arn:aws:iam::123456789012:role/auditor",
		Region:           "us-east-1",
		Profile:          "sandbox",
		StartedAt:        t1,
		CompletedAt:      t1.Add(3 * time.Second),
		SinceWindow:      "90d",
		CloudTrailStatus: model.CloudTrailStatusUnknown,
		Coverage: &model.ScanCoverage{
			Status:               model.CoverageStatusPartial,
			AccountID:            "123456789012",
			Region:               "us-east-1",
			SinceWindow:          "90d",
			CloudTrailStatus:     model.CloudTrailStatusUnknown,
			LoginProfileChecked:  1,
			LoginProfileFailed:   1,
			PartialIdentities:    1,
			CollectionErrorCount: 1,
		},
		Warnings: []string{"partial access advisor"},
		Identities: []model.Identity{
			{
				ID:               "arn:aws:iam::123456789012:role/agent-a",
				ARN:              "arn:aws:iam::123456789012:role/agent-a",
				Type:             model.TypeRole,
				Name:             "agent-a",
				Account:          "123456789012",
				Created:          &created,
				Tags:             map[string]string{"owner": "ai-team", "agent": "true"},
				Owner:            &owner,
				AgentLikelihood:  model.LikelihoodLikely,
				AgentReasons:     []string{"tag agent=true"},
				CloudTrailStatus: model.CloudTrailStatusUnknown,
				RiskScore:        8.5,
				Findings: []model.Finding{
					{
						RuleID:      "R1",
						RuleName:    "wildcard-permissions",
						Severity:    model.SeverityCritical,
						Title:       "Wildcard admin permissions",
						Explanation: "Grants Action:* on Resource:*",
						Remediation: "Scope down to least privilege",
						Evidence:    []string{"AdministratorAccess"},
					},
				},
			},
			{
				ID:               "arn:aws:iam::123456789012:user/bot-unowned",
				ARN:              "arn:aws:iam::123456789012:user/bot-unowned",
				Type:             model.TypeUser,
				Name:             "bot-unowned",
				Account:          "123456789012",
				Owner:            nil,
				HasConsoleLogin:  &hasConsole,
				AgentLikelihood:  model.LikelihoodPossible,
				CloudTrailStatus: model.CloudTrailStatusUnknown,
				RiskScore:        3.0,
			},
		},
	}

	if err := st.SaveScan(ctx, scan1); err != nil {
		t.Fatalf("SaveScan(scan1) failed: %v", err)
	}

	// Save a newer scan so LoadLatestScan picks scan-2 while LoadScan("scan-1") still works.
	scan2 := &model.ScanRun{
		ID:               "scan-2",
		AccountID:        "123456789012",
		CallerARN:        "arn:aws:iam::123456789012:role/auditor",
		Region:           "us-east-1",
		StartedAt:        t2,
		CompletedAt:      t2.Add(2 * time.Second),
		SinceWindow:      "90d",
		CloudTrailStatus: model.CloudTrailStatusUnknown,
		Identities:       []model.Identity{},
	}
	if err := st.SaveScan(ctx, scan2); err != nil {
		t.Fatalf("SaveScan(scan2) failed: %v", err)
	}

	latest, err := st.LoadLatestScan(ctx)
	if err != nil {
		t.Fatalf("LoadLatestScan failed: %v", err)
	}
	if latest.ID != "scan-2" {
		t.Errorf("LoadLatestScan ID = %q, want scan-2", latest.ID)
	}

	loaded1, err := st.LoadScan(ctx, "scan-1")
	if err != nil {
		t.Fatalf("LoadScan(scan-1) failed: %v", err)
	}
	if loaded1.AccountID != "123456789012" || len(loaded1.Identities) != 2 {
		t.Fatalf("unexpected loaded scan-1: %+v", loaded1)
	}
	if len(loaded1.Warnings) != 1 || loaded1.Warnings[0] != "partial access advisor" {
		t.Errorf("warnings did not round-trip: %v", loaded1.Warnings)
	}
	if loaded1.Coverage == nil || loaded1.Coverage.Status != model.CoverageStatusPartial || loaded1.Coverage.LoginProfileFailed != 1 {
		t.Errorf("coverage did not round-trip cleanly: %+v", loaded1.Coverage)
	}
	// Identities are ordered by risk_score DESC.
	if loaded1.Identities[0].Name != "agent-a" || loaded1.Identities[0].Owner == nil || *loaded1.Identities[0].Owner != "ai-team" {
		t.Errorf("first identity did not round-trip cleanly: %+v", loaded1.Identities[0])
	}
	if len(loaded1.Identities[0].Findings) != 1 || loaded1.Identities[0].Findings[0].RuleID != "R1" {
		t.Errorf("findings did not round-trip cleanly: %+v", loaded1.Identities[0].Findings)
	}
	if loaded1.Identities[1].Owner != nil {
		t.Errorf("expected nil owner on bot-unowned, got %q", *loaded1.Identities[1].Owner)
	}
	if loaded1.Identities[1].HasConsoleLogin == nil || *loaded1.Identities[1].HasConsoleLogin != false {
		t.Errorf("expected HasConsoleLogin=false on bot-unowned, got %v", loaded1.Identities[1].HasConsoleLogin)
	}

	// Re-saving scan-1 replaces cleanly without duplicating findings.
	if err := st.SaveScan(ctx, scan1); err != nil {
		t.Fatalf("re-saving scan1 failed: %v", err)
	}

	summaries, err := st.ListScans(ctx)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 scan summaries, got %d", len(summaries))
	}
	if summaries[0].ID != "scan-2" || summaries[1].ID != "scan-1" {
		t.Errorf("unexpected summary ordering: %+v", summaries)
	}
	if summaries[1].IdentityCount != 2 || summaries[1].FindingCount != 1 {
		t.Errorf("unexpected scan-1 counts (identity=%d, finding=%d)", summaries[1].IdentityCount, summaries[1].FindingCount)
	}
}

func TestOpenInMemory(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) failed: %v", err)
	}
	defer func() { _ = st.Close() }()
}
