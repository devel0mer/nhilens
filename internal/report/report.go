package report

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/rules"
	"github.com/devel0mer/nhilens/internal/score"
	"github.com/devel0mer/nhilens/internal/version"
)

//go:embed assets/cytoscape.min.js
var cytoscapeJS string

//go:embed templates/report.html.tmpl
var reportHTMLTemplate string

// SummaryStats holds high-level KPI metrics displayed at the top of the report.
type SummaryStats struct {
	ScanID               string    `json:"scan_id"`
	AccountID            string    `json:"account_id"`
	CallerARN            string    `json:"caller_arn"`
	Region               string    `json:"region"`
	Profile              string    `json:"profile,omitempty"`
	StartedAt            time.Time `json:"started_at"`
	CompletedAt          time.Time `json:"completed_at"`
	SinceWindow          string    `json:"since_window"`
	TotalIdentities      int       `json:"total_identities"`
	Roles                int       `json:"roles"`
	Users                int       `json:"users"`
	Keys                 int       `json:"keys"`
	ServiceLinkedRoles   int       `json:"service_linked_roles"`
	AgentLikely          int       `json:"agent_likely"`
	AgentPossible        int       `json:"agent_possible"`
	UnownedNonHuman      int       `json:"unowned_non_human"`
	TotalFindings        int       `json:"total_findings"`
	CriticalFindings     int       `json:"critical_findings"`
	HighFindings         int       `json:"high_findings"`
	MediumFindings       int       `json:"medium_findings"`
	LowFindings          int       `json:"low_findings"`
	CloudTrailStatus     string    `json:"cloudtrail_status"`
	CloudTrailEventCount int       `json:"cloudtrail_event_count"`
}

// RuleGroup aggregates findings across identities for one rule (R1..R5).
type RuleGroup struct {
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	HighestSeverity model.Severity    `json:"highest_severity"`
	Count           int               `json:"count"`
	Explanation     string            `json:"explanation"`
	Remediation     string            `json:"remediation"`
	Items           []RuleFindingItem `json:"items"`
}

// RuleFindingItem links one finding to its affected identity.
type RuleFindingItem struct {
	IdentityID      string                `json:"identity_id"`
	IdentityARN     string                `json:"identity_arn"`
	IdentityName    string                `json:"identity_name"`
	IdentityType    model.IdentityType    `json:"identity_type"`
	AgentLikelihood model.AgentLikelihood `json:"agent_likelihood"`
	RiskScore       float64               `json:"risk_score"`
	Severity        model.Severity        `json:"severity"`
	Title           string                `json:"title"`
	Evidence        []string              `json:"evidence,omitempty"`
}

// Limitation documents an explicit methodological or AWS data boundary.
type Limitation struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// ReportData is the complete structured model rendered to static HTML or JSON.
type ReportData struct {
	GeneratedAt time.Time        `json:"generated_at"`
	ToolVersion string           `json:"tool_version"`
	Summary     SummaryStats     `json:"summary"`
	TopRisky    []model.Identity `json:"top_risky"`
	RuleGroups  []RuleGroup      `json:"rule_groups"`
	Graph       GraphData        `json:"graph"`
	Warnings    []string         `json:"warnings,omitempty"`
	Limitations []Limitation     `json:"limitations"`
	Scan        *model.ScanRun   `json:"scan"`
}

type htmlTemplateData struct {
	Report      *ReportData
	GraphJSON   template.JS
	CytoscapeJS template.JS
}

var parsedHTMLTmpl = template.Must(
	template.New("report.html.tmpl").Funcs(template.FuncMap{
		"join": strings.Join,
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"fmtTimePtr": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "never / unknown"
			}
			return t.UTC().Format("2006-01-02")
		},
		"ownerOrNone": func(owner *string) string {
			if owner == nil || strings.TrimSpace(*owner) == "" {
				return "<none>"
			}
			return *owner
		},
		"scoreFmt": func(v float64) string {
			return fmt.Sprintf("%.1f", v)
		},
		"riskClass": func(v float64) string {
			switch {
			case v >= 7.0:
				return "sev-critical"
			case v >= 4.0:
				return "sev-high"
			case v >= 2.0:
				return "sev-medium"
			case v > 0:
				return "sev-low"
			default:
				return "sev-clean"
			}
		},
		"sevClass": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "sev-critical"
			case model.SeverityHigh:
				return "sev-high"
			case model.SeverityMedium:
				return "sev-medium"
			case model.SeverityLow:
				return "sev-low"
			default:
				return "sev-info"
			}
		},
		"agentClass": func(a model.AgentLikelihood) string {
			switch a {
			case model.LikelihoodLikely:
				return "agent-likely"
			case model.LikelihoodPossible:
				return "agent-possible"
			default:
				return "agent-none"
			}
		},
		"shortARN": shortARNName,
		"maxSev": func(findings []model.Finding) string {
			var best model.Severity
			for _, f := range findings {
				if model.SeverityRank(f.Severity) > model.SeverityRank(best) {
					best = f.Severity
				}
			}
			if best == "" {
				return "none"
			}
			return string(best)
		},
		"fmtActivity30d": formatActivitySummary,
	}).Parse(reportHTMLTemplate),
)

// Build constructs the complete ReportData view model from a persisted or freshly collected ScanRun.
func Build(run *model.ScanRun, generatedAt time.Time) *ReportData {
	if run == nil {
		return nil
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	sevCounts := score.SummarizeSeverities(run.Identities)
	summary := SummaryStats{
		ScanID:               run.ID,
		AccountID:            run.AccountID,
		CallerARN:            run.CallerARN,
		Region:               run.Region,
		Profile:              run.Profile,
		StartedAt:            run.StartedAt,
		CompletedAt:          run.CompletedAt,
		SinceWindow:          run.SinceWindow,
		TotalIdentities:      len(run.Identities),
		CriticalFindings:     sevCounts[model.SeverityCritical],
		HighFindings:         sevCounts[model.SeverityHigh],
		MediumFindings:       sevCounts[model.SeverityMedium],
		LowFindings:          sevCounts[model.SeverityLow],
		CloudTrailStatus:     run.CloudTrailStatus,
		CloudTrailEventCount: run.CloudTrailEventCount,
	}
	summary.TotalFindings = summary.CriticalFindings + summary.HighFindings + summary.MediumFindings + summary.LowFindings + sevCounts[model.SeverityInfo]

	for _, id := range run.Identities {
		switch id.Type {
		case model.TypeRole:
			summary.Roles++
		case model.TypeUser:
			summary.Users++
		case model.TypeKey:
			summary.Keys++
		}
		if id.IsServiceLinkedRole {
			summary.ServiceLinkedRoles++
		}
		switch id.AgentLikelihood {
		case model.LikelihoodLikely:
			summary.AgentLikely++
		case model.LikelihoodPossible:
			summary.AgentPossible++
		}
		if (id.Type == model.TypeRole || id.Type == model.TypeUser) && !id.IsServiceLinkedRole && (id.Owner == nil || strings.TrimSpace(*id.Owner) == "") {
			summary.UnownedNonHuman++
		}
	}

	// Copy and rank identities for Top 10 Risky Identities section.
	ranked := make([]model.Identity, len(run.Identities))
	copy(ranked, run.Identities)
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].RiskScore != ranked[j].RiskScore {
			return ranked[i].RiskScore > ranked[j].RiskScore
		}
		if len(ranked[i].Findings) != len(ranked[j].Findings) {
			return len(ranked[i].Findings) > len(ranked[j].Findings)
		}
		return ranked[i].Name < ranked[j].Name
	})

	topRisky := make([]model.Identity, 0, min(10, len(ranked)))
	for _, id := range ranked {
		if len(topRisky) >= 10 {
			break
		}
		if id.RiskScore > 0 || len(id.Findings) > 0 {
			topRisky = append(topRisky, id)
		}
	}

	ruleGroups := buildRuleGroups(ranked)
	graph := BuildGraph(run)

	return &ReportData{
		GeneratedAt: generatedAt.UTC(),
		ToolVersion: version.String(),
		Summary:     summary,
		TopRisky:    topRisky,
		RuleGroups:  ruleGroups,
		Graph:       graph,
		Warnings:    run.Warnings,
		Limitations: defaultLimitations(run),
		Scan:        run,
	}
}

// WriteHTML renders a standalone static HTML report with embedded Cytoscape.js (no CDN at view time).
func WriteHTML(w io.Writer, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}
	data := Build(run, time.Now().UTC())

	graphBytes, err := json.Marshal(data.Graph)
	if err != nil {
		return fmt.Errorf("marshal graph JSON: %w", err)
	}
	// encoding/json escapes <, >, & as \u003c, \u003e, \u0026; also neutralize Unicode line separators.
	safeGraphJSON := strings.ReplaceAll(string(graphBytes), "\u2028", `\u2028`)
	safeGraphJSON = strings.ReplaceAll(safeGraphJSON, "\u2029", `\u2029`)

	return parsedHTMLTmpl.Execute(w, htmlTemplateData{
		Report:      data,
		GraphJSON:   template.JS(safeGraphJSON),
		CytoscapeJS: template.JS(cytoscapeJS),
	})
}

// WriteJSON writes the structured ReportData as indented JSON.
func WriteJSON(w io.Writer, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}
	data := Build(run, time.Now().UTC())
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func buildRuleGroups(ranked []model.Identity) []RuleGroup {
	catalog := rules.Catalog()
	order := make([]string, 0, len(catalog))
	groupMap := make(map[string]*RuleGroup, len(catalog))
	for _, meta := range catalog {
		order = append(order, meta.ID)
		groupMap[meta.ID] = &RuleGroup{
			RuleID:          meta.ID,
			RuleName:        meta.Name,
			HighestSeverity: meta.DefaultSeverity,
			Explanation:     meta.Description,
			Remediation:     meta.Remediation,
			Items:           []RuleFindingItem{},
		}
	}

	var extraIDs []string
	for _, ident := range ranked {
		for _, f := range ident.Findings {
			grp, ok := groupMap[f.RuleID]
			if !ok {
				grp = &RuleGroup{
					RuleID:          f.RuleID,
					RuleName:        f.RuleName,
					HighestSeverity: f.Severity,
					Explanation:     f.Explanation,
					Remediation:     f.Remediation,
				}
				groupMap[f.RuleID] = grp
				extraIDs = append(extraIDs, f.RuleID)
			}
			if model.SeverityRank(f.Severity) > model.SeverityRank(grp.HighestSeverity) {
				grp.HighestSeverity = f.Severity
			}
			if f.Explanation != "" {
				grp.Explanation = f.Explanation
			}
			if f.Remediation != "" {
				grp.Remediation = f.Remediation
			}
			grp.Count++
			grp.Items = append(grp.Items, RuleFindingItem{
				IdentityID:      ident.ID,
				IdentityARN:     ident.ARN,
				IdentityName:    ident.Name,
				IdentityType:    ident.Type,
				AgentLikelihood: ident.AgentLikelihood,
				RiskScore:       ident.RiskScore,
				Severity:        f.Severity,
				Title:           f.Title,
				Evidence:        f.Evidence,
			})
		}
	}

	sort.Strings(extraIDs)
	allIDs := append(order, extraIDs...)
	out := make([]RuleGroup, 0, len(allIDs))
	for _, id := range allIDs {
		out = append(out, *groupMap[id])
	}
	return out
}

func formatActivitySummary(a *model.ActivitySummary) string {
	if a == nil || a.TotalEvents == 0 {
		return ""
	}
	parts := make([]string, 0, len(a.TopAPIs))
	for _, item := range a.TopAPIs {
		parts = append(parts, fmt.Sprintf("%s (%d)", item.Name, item.Count))
	}
	if len(parts) == 0 {
		for _, item := range a.TopServices {
			parts = append(parts, fmt.Sprintf("%s (%d)", item.Name, item.Count))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d events in %dd", a.TotalEvents, a.WindowDays)
	}
	return fmt.Sprintf("%d calls in %dd: %s", a.TotalEvents, a.WindowDays, strings.Join(parts, ", "))
}

func defaultLimitations(run *model.ScanRun) []Limitation {
	ctNote := fmt.Sprintf("CloudTrail LookupEvents is regional (queries only --region=%s): API calls made in other AWS regions—including cross-region key sharing (R4) and userAgent/30d signals—are not visible unless scanned per region. LookupEvents inspects management events only (not S3/Lambda data events), is retained for at most 90 days in Event History, and is subject to --max-events caps. Multi-IP key detection (R4) is best-effort (NAT gateways, proxies, or ephemeral runners can emit multiple IPs). Current scan CloudTrail status: %s (%d events analyzed).",
		run.Region, run.CloudTrailStatus, run.CloudTrailEventCount)

	return []Limitation{
		{
			Title:  "Heuristic AI agent vs. automation classification",
			Detail: "No universal AWS attribute identifies an AI agent. nhilens separates AI-specific signals (AI tags/names, Bedrock/SageMaker trusts, AI/LLM policy permissions or runtime usage, AI framework userAgents) from generic automation signals (programmatic keys, CI/OIDC trusts, generic SDK userAgents). Automation-only identities are labeled workload_kind=automation and capped at 45% (possible) so ordinary CI/CD bots do not false-positive as likely AI agents.",
		},
		{
			Title:  "CloudTrail single-region, window, volume, and IP attribution limits",
			Detail: ctNote,
		},
		{
			Title:  "IAM Access Advisor (last-accessed) data gaps",
			Detail: "Service last-accessed data (R2) covers only the trailing 400 days, may lag by up to several hours, and can be unavailable if --skip-service-last-accessed was passed or an async job failed/timed out. Newly created identities may show unused services simply because they have not been active for the full stale window.",
		},
		{
			Title:  "Identity-policy upper bound (permissions boundaries, SCPs, resource & session policies)",
			Detail: "Permission summaries reflect attached managed, inline, and group identity policies. Attached permissions boundaries (when resolved in IAM authorization details) and optional --scp-file JSON guardrails are intersected for R1 admin-wildcard capping, but full action-level SCP/boundary intersections, resource-based policies (e.g., S3/KMS), and STS session policies are not evaluated.",
		},
		{
			Title:  "Service-linked roles & point-in-time snapshot",
			Detail: "AWS-managed service-linked roles (/aws-service-role/) are inventoried and labeled but excluded from risk findings and unflagged graph clutter by default unless opted in. This report reflects a point-in-time read-only snapshot of a single AWS account.",
		},
	}
}
