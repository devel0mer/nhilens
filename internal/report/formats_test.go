package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestWriteSARIFMarkdownAndCSV(t *testing.T) {
	run := sampleScanRun()
	run.SuppressedFindingCount = 1
	run.Identities[0].AIServices = []string{"bedrock"}
	run.Identities[0].RawRiskPoints = 11.5
	run.Identities[0].SuppressedFindings = []model.SuppressedFinding{
		{
			Finding: model.Finding{
				RuleID:   "R2",
				RuleName: "unused-permissions",
				Severity: model.SeverityMedium,
				Title:    "Unused services",
				Evidence: []string{"ec2 (never accessed)"},
			},
			Reason:  "Accepted sandbox waiver",
			Expires: "2027-06-30",
		},
	}

	// 1. SARIF 2.1.0 validation.
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, run); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifBuf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") {
		t.Errorf("unexpected SARIF version/schema: %q / %q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "nhilens" || len(log.Runs[0].Tool.Driver.Rules) != 8 {
		t.Fatalf("unexpected SARIF tool driver: %+v", log.Runs)
	}
	// 4 active findings + 1 suppressed finding = 5 SARIF results.
	if len(log.Runs[0].Results) != 5 {
		t.Fatalf("expected 5 SARIF results (4 active + 1 suppressed), got %d", len(log.Runs[0].Results))
	}
	suppressedFound := false
	for _, r := range log.Runs[0].Results {
		if r.PartialFingerprints["nhilensIdentityRule/v1"] == "" {
			t.Errorf("missing partialFingerprint on SARIF result %s", r.RuleID)
		}
		if len(r.Suppressions) > 0 {
			suppressedFound = true
			if !strings.Contains(r.Suppressions[0].Justification, "Accepted sandbox waiver") {
				t.Errorf("unexpected SARIF suppression justification: %+v", r.Suppressions)
			}
		}
	}
	if !suppressedFound {
		t.Errorf("expected native SARIF suppression entry")
	}

	// 2. Markdown validation.
	var mdBuf bytes.Buffer
	if err := WriteMarkdown(&mdBuf, run); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	md := mdBuf.String()
	for _, want := range []string{"# nhilens Audit Report", "## Summary", "Single-region CloudTrail scope:", "region `us-east-1` only", "## Top Risky Identities", "## Findings by Rule", "## Limitations", "Suppressed Findings"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown output missing %q", want)
		}
	}

	// 3. RFC 4180 CSV validation.
	var csvBuf bytes.Buffer
	if err := WriteCSV(&csvBuf, run); err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}
	records, err := csv.NewReader(&csvBuf).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV output: %v", err)
	}
	// Header + 4 active findings = 5 rows.
	if len(records) != 5 {
		t.Fatalf("expected 5 CSV rows (1 header + 4 findings), got %d", len(records))
	}
	if records[0][0] != "account_id" || records[0][11] != "rule_id" {
		t.Errorf("unexpected CSV header: %v", records[0])
	}
}
