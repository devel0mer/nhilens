package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestCompareIdentitiesScoresAndFindings(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	base := &model.ScanRun{
		ID:        "scan-base",
		AccountID: "123456789012",
		Region:    "us-east-1",
		StartedAt: t1,
		Identities: []model.Identity{
			{
				ID:              "arn:aws:iam::123456789012:role/agent-a",
				ARN:             "arn:aws:iam::123456789012:role/agent-a",
				Type:            model.TypeRole,
				Name:            "agent-a",
				AgentLikelihood: model.LikelihoodLikely,
				RiskScore:       4.6,
				Findings: []model.Finding{
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium, Title: "No owner"},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityMedium, Title: "Missing source cond"},
				},
			},
			{
				ID:        "arn:aws:iam::123456789012:role/retired-role",
				ARN:       "arn:aws:iam::123456789012:role/retired-role",
				Type:      model.TypeRole,
				Name:      "retired-role",
				RiskScore: 3.7,
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityHigh, Title: "PassRole"},
				},
			},
		},
	}

	head := &model.ScanRun{
		ID:        "scan-head",
		AccountID: "123456789012",
		Region:    "us-east-1",
		StartedAt: t2,
		Identities: []model.Identity{
			{
				ID:              "arn:aws:iam::123456789012:role/agent-a",
				ARN:             "arn:aws:iam::123456789012:role/agent-a",
				Type:            model.TypeRole,
				Name:            "agent-a",
				AgentLikelihood: model.LikelihoodLikely,
				RiskScore:       7.7,
				Findings: []model.Finding{
					// R3 resolved; R5 escalated from medium -> critical; R1 newly introduced.
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical, Title: "Wildcard admin"},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical, Title: "Principal *"},
				},
			},
			{
				ID:              "arn:aws:iam::123456789012:role/new-mcp-agent",
				ARN:             "arn:aws:iam::123456789012:role/new-mcp-agent",
				Type:            model.TypeRole,
				Name:            "new-mcp-agent",
				AgentLikelihood: model.LikelihoodPossible,
				RiskScore:       2.6,
				Findings: []model.Finding{
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium, Title: "No owner"},
				},
			},
		},
	}

	res := Compare(base, head)

	if res.Summary.AddedIdentities != 1 || res.Summary.RemovedIdentities != 1 {
		t.Fatalf("unexpected identity delta summary: %+v", res.Summary)
	}
	if res.Summary.ScoreIncreased != 1 || res.Summary.ScoreDecreased != 0 {
		t.Errorf("unexpected score delta summary: %+v", res.Summary)
	}
	// New findings: agent-a R1 (new), agent-a R5 (escalated medium->critical), new-mcp-agent R3 (new).
	if res.Summary.NewFindings != 3 {
		t.Errorf("NewFindings = %d, want 3 (%+v)", res.Summary.NewFindings, res.NewFindings)
	}
	// Resolved findings: agent-a R3, retired-role R1.
	if res.Summary.ResolvedFindings != 2 {
		t.Errorf("ResolvedFindings = %d, want 2 (%+v)", res.Summary.ResolvedFindings, res.ResolvedFindings)
	}

	if exceeded, cnt := ExceedsFailOnNew(res, "critical"); !exceeded || cnt != 2 {
		t.Errorf("ExceedsFailOnNew(critical) = (%v, %d), want (true, 2)", exceeded, cnt)
	}

	var tableBuf, mdBuf, jsonBuf bytes.Buffer
	if err := WriteTable(&tableBuf, res); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(tableBuf.String(), "medium->critical") || !strings.Contains(tableBuf.String(), "new-mcp-agent") {
		t.Errorf("unexpected table diff output:\n%s", tableBuf.String())
	}

	if err := WriteMarkdown(&mdBuf, res); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if !strings.Contains(mdBuf.String(), "## nhilens Scan Diff") || !strings.Contains(mdBuf.String(), "### New / Escalated Findings") {
		t.Errorf("unexpected markdown diff output:\n%s", mdBuf.String())
	}

	if err := WriteJSON(&jsonBuf, res); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded Result
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("WriteJSON invalid JSON: %v", err)
	}
}
