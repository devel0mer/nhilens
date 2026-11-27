package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

func sampleScanRun() *model.ScanRun {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	created := now.Add(-120 * 24 * time.Hour)
	owner := "platform-team"
	xssPayload := `<script>alert("xss")</script>`

	return &model.ScanRun{
		ID:                   "scan-123456789012-20261125",
		AccountID:            "123456789012",
		CallerARN:            "arn:aws:iam::123456789012:role/nhilens-ro",
		Region:               "us-east-1",
		StartedAt:            now,
		CompletedAt:          now.Add(4 * time.Second),
		SinceWindow:          "90d",
		CloudTrailStatus:     model.CloudTrailStatusOK,
		CloudTrailEventCount: 42,
		Warnings:             []string{"test non-fatal warning"},
		Identities: []model.Identity{
			{
				ID:                     "arn:aws:iam::123456789012:role/bedrock-agent",
				ARN:                    "arn:aws:iam::123456789012:role/bedrock-agent",
				Type:                   model.TypeRole,
				Name:                   "bedrock-agent-" + xssPayload,
				Account:                "123456789012",
				Created:                &created,
				PermissionsBoundaryARN: "arn:aws:iam::123456789012:policy/sandbox-boundary",
				Tags:                   map[string]string{"note": xssPayload},
				Owner:                  nil,
				AgentLikelihood:        model.LikelihoodLikely,
				AgentConfidence:        85,
				AgentProfile:           "bedrock-agent",
				ObservedUserAgents:     []string{"langchain-aws/0.2 Boto3/1.35"},
				Activity30d: &model.ActivitySummary{
					WindowDays:  30,
					TotalEvents: 42,
					TopServices: []model.ActivityCount{{Name: "bedrock", Count: 30}, {Name: "s3", Count: 12}},
					TopAPIs:     []model.ActivityCount{{Name: "bedrock:InvokeModel", Count: 30}},
				},
				ScoreExplanation: "8.9/10 (raw 14.5): R1 critical (+4.0) + R5 critical (+4.0) + compound (+2.0)",
				AgentReasons:     []string{"trust policy allows automation service principal bedrock.amazonaws.com", "name matches pattern"},
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "bedrock.amazonaws.com", Actions: []string{"sts:AssumeRole"}},
					{Type: "wildcard", Value: "*", Actions: []string{"sts:AssumeRole"}},
				},
				Policies: []model.PolicyAttachment{
					{Name: "AdministratorAccess", ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "managed"},
				},
				RecentEventNames: []string{"bedrock:InvokeModel"},
				RiskScore:        10.0,
				ScoreContributions: []model.ScoreContribution{
					{Source: "R1 wildcard-permissions (critical)", Points: 4.0},
					{Source: "R5 loose-trust (critical)", Points: 4.0},
					{Source: "R3 no-owner (medium)", Points: 2.0},
					{Source: "agent_likelihood=likely bonus", Points: 1.5},
				},
				Findings: []model.Finding{
					{RuleID: "R1", RuleName: "wildcard-permissions", Severity: model.SeverityCritical, Title: "Wildcard admin", Explanation: "Full admin", Remediation: "Scope down", Evidence: []string{"AdministratorAccess"}},
					{RuleID: "R5", RuleName: "loose-trust", Severity: model.SeverityCritical, Title: "Wildcard trust", Explanation: "Principal *", Remediation: "Restrict principal", Evidence: []string{"Principal *"}},
					{RuleID: "R3", RuleName: "no-owner", Severity: model.SeverityMedium, Title: "No owner", Explanation: "Missing owner tag", Remediation: "Tag role", Evidence: []string{"no owner tag"}},
				},
			},
			{
				ID:              "arn:aws:iam::123456789012:user/ci-bot",
				ARN:             "arn:aws:iam::123456789012:user/ci-bot",
				Type:            model.TypeUser,
				Name:            "ci-bot",
				Account:         "123456789012",
				Owner:           &owner,
				AgentLikelihood: model.LikelihoodPossible,
				AccessKeyIDs:    []string{"AKIA1111111111111111"},
				RiskScore:       0.0,
			},
			{
				ID:              "arn:aws:iam::123456789012:user/ci-bot/access-key/AKIA1111111111111111",
				ARN:             "arn:aws:iam::123456789012:user/ci-bot",
				Type:            model.TypeKey,
				Name:            "AKIA1111111111111111",
				Account:         "123456789012",
				Owner:           &owner,
				AgentLikelihood: model.LikelihoodPossible,
				SourceIPs:       []string{"198.51.100.1", "203.0.113.2"},
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIA1111111111111111",
					ParentUserName: "ci-bot",
					ParentUserARN:  "arn:aws:iam::123456789012:user/ci-bot",
					Status:         "Active",
				},
				RiskScore: 3.0,
				Findings: []model.Finding{
					{RuleID: "R4", RuleName: "stale-or-shared-key", Severity: model.SeverityHigh, Title: "Shared key", Evidence: []string{"best-effort: 2 distinct IPs"}},
				},
			},
			{
				ID:                  "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
				ARN:                 "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
				Type:                model.TypeRole,
				Name:                "AWSServiceRoleForSupport",
				Path:                "/aws-service-role/support.amazonaws.com/",
				IsServiceLinkedRole: true,
				AgentLikelihood:     model.LikelihoodNone,
			},
		},
	}
}

func TestWriteHTMLNoCDNAndXSSSafe(t *testing.T) {
	run := sampleScanRun()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, run); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	html := buf.String()

	// Must embed Cytoscape.js inline and have zero external CDN references.
	if len(cytoscapeJS) < 50000 {
		t.Fatalf("expected vendored cytoscape.min.js to be embedded, got only %d bytes", len(cytoscapeJS))
	}
	for _, forbidden := range []string{
		"<script src=",
		"cdn.jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
		"fonts.googleapis.com",
		`<script>alert("xss")</script>`,
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("HTML report must not contain %q", forbidden)
		}
	}

	// Required report sections must all be present.
	for _, want := range []string{
		"Review before sharing:",
		"Single-region CloudTrail scope:",
		"Summary",
		"Scan Coverage &amp; Data Completeness",
		"Top Risky Identities",
		"Findings by Rule",
		"Identity, Trust &amp; Policy Relationship Graph",
		"Limitations &amp; Methodology",
		"Heuristic AI agent vs. automation classification",
		"CloudTrail single-region, window, volume, and IP attribution limits",
		"IAM Access Advisor (last-accessed) data gaps",
		"Effective permissions scope",
		"123456789012",
		"nhilens-graph-data",
		"1 unflagged AWS service-linked roles omitted",
		"Who can assume this role?",
		"table-filters",
		"Why 10.0/10?",
		"bedrock:InvokeModel (30)",
		"bedrock-agent",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected HTML report to contain %q", want)
		}
	}
}

func TestBuildGraphAndWriteJSON(t *testing.T) {
	run := sampleScanRun()
	graph := BuildGraph(run)

	if graph.OmittedServiceLinked != 1 {
		t.Errorf("OmittedServiceLinked = %d, want 1", graph.OmittedServiceLinked)
	}

	kinds := make(map[string]int)
	for _, n := range graph.Nodes {
		kinds[n.Data.Kind]++
	}
	for _, wantKind := range []string{"role", "user", "key", "trust", "policy", "boundary"} {
		if kinds[wantKind] == 0 {
			t.Errorf("expected at least one graph node of kind %q, got counts %v", wantKind, kinds)
		}
	}

	edgeKinds := make(map[string]int)
	for _, e := range graph.Edges {
		edgeKinds[e.Data.EdgeKind]++
	}
	for _, wantEdge := range []string{"trusts", "has_policy", "bounded_by", "has_key"} {
		if edgeKinds[wantEdge] == 0 {
			t.Errorf("expected at least one graph edge of kind %q, got counts %v", wantEdge, edgeKinds)
		}
	}

	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, run); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var decoded ReportData
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("WriteJSON produced invalid JSON: %v", err)
	}
	if decoded.Summary.AccountID != "123456789012" || len(decoded.RuleGroups) != 8 || len(decoded.Limitations) < 4 {
		t.Errorf("unexpected JSON report structure: summary=%+v rules=%d limitations=%d",
			decoded.Summary, len(decoded.RuleGroups), len(decoded.Limitations))
	}
}
