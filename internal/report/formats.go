package report

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

// WriteMarkdown renders a clean GitHub-Flavored Markdown audit report suitable for
// GitHub Actions Job Summaries ($GITHUB_STEP_SUMMARY), PR comments, or documentation.
func WriteMarkdown(w io.Writer, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}
	data := Build(run, time.Now().UTC())
	s := data.Summary

	_, _ = fmt.Fprintf(w, "# nhilens Audit Report — Account `%s`\n\n", s.AccountID)
	_, _ = fmt.Fprintf(w, "> **Review before sharing:** Contains AWS account IDs, IAM ARNs, tag values, policy details, and best-effort CloudTrail source IPs.\n\n")

	_, _ = fmt.Fprintf(w, "## Summary\n\n")
	_, _ = fmt.Fprintf(w, "| Metric | Value |\n|---|---|\n")
	_, _ = fmt.Fprintf(w, "| Account / Region | `%s` (`%s`) |\n", s.AccountID, s.Region)
	_, _ = fmt.Fprintf(w, "| Scan ID | `%s` |\n", s.ScanID)
	_, _ = fmt.Fprintf(w, "| Identities | %d total (%d roles, %d users, %d keys; %d service-linked) |\n",
		s.TotalIdentities, s.Roles, s.Users, s.Keys, s.ServiceLinkedRoles)
	_, _ = fmt.Fprintf(w, "| Heuristic AI / Automation | %d likely, %d possible |\n", s.AgentLikely, s.AgentPossible)
	_, _ = fmt.Fprintf(w, "| Active Findings | %d total (%d critical, %d high, %d medium, %d low) |\n",
		s.TotalFindings, s.CriticalFindings, s.HighFindings, s.MediumFindings, s.LowFindings)
	if run.SuppressedFindingCount > 0 {
		_, _ = fmt.Fprintf(w, "| Suppressed Findings | %d (via baseline ignore file) |\n", run.SuppressedFindingCount)
	}
	_, _ = fmt.Fprintf(w, "| CloudTrail Attribution | `%s` (%d events, `%s` window) |\n\n", s.CloudTrailStatus, s.CloudTrailEventCount, s.SinceWindow)

	_, _ = fmt.Fprintf(w, "## Top 10 Risky Identities\n\n")
	if len(data.TopRisky) == 0 {
		_, _ = fmt.Fprintln(w, "No risky findings recorded in this scan.")
		_, _ = fmt.Fprintln(w)
	} else {
		_, _ = fmt.Fprintln(w, "| Score | Type | Identity | Agent | AI Services | Owner | Findings |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
		for _, id := range data.TopRisky {
			owner := "<none>"
			if id.Owner != nil && strings.TrimSpace(*id.Owner) != "" {
				owner = *id.Owner
			}
			aiSvc := "-"
			if len(id.AIServices) > 0 {
				aiSvc = strings.Join(id.AIServices, ", ")
			}
			fList := make([]string, 0, len(id.Findings))
			for _, f := range id.Findings {
				fList = append(fList, fmt.Sprintf("`%s`(%s)", f.RuleID, f.Severity))
			}
			_, _ = fmt.Fprintf(w, "| **%.1f/10** (raw %.1f) | %s | `%s` | %s | %s | `%s` | %s |\n",
				id.RiskScore, id.RawRiskPoints, id.Type, id.Name, id.AgentLikelihood, aiSvc, owner, strings.Join(fList, ", "))
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "## Findings by Rule\n\n")
	for _, rg := range data.RuleGroups {
		_, _ = fmt.Fprintf(w, "### %s — `%s` (%d finding(s))\n\n", rg.RuleID, rg.RuleName, rg.Count)
		_, _ = fmt.Fprintf(w, "%s\n\n", rg.Explanation)
		_, _ = fmt.Fprintf(w, "**Remediation hint:** %s\n\n", rg.Remediation)
		if len(rg.Items) > 0 {
			_, _ = fmt.Fprintln(w, "| Identity | Type | Severity | Score | Evidence |")
			_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
			for _, item := range rg.Items {
				_, _ = fmt.Fprintf(w, "| `%s` | %s | %s | %.1f/10 | %s |\n",
					item.IdentityName, item.IdentityType, item.Severity, item.RiskScore, strings.Join(item.Evidence, "; "))
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	_, _ = fmt.Fprintf(w, "## Limitations\n\n")
	for _, lim := range data.Limitations {
		_, _ = fmt.Fprintf(w, "- **%s:** %s\n", lim.Title, lim.Detail)
	}
	return nil
}

// WriteCSV writes one RFC 4180 CSV row per active finding (plus identity metadata) for spreadsheet/BI analysis.
func WriteCSV(w io.Writer, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}

	cw := csv.NewWriter(w)
	header := []string{
		"account_id",
		"region",
		"scan_id",
		"identity_type",
		"identity_name",
		"identity_arn",
		"owner",
		"agent_likelihood",
		"ai_services",
		"risk_score",
		"raw_risk_points",
		"rule_id",
		"rule_name",
		"severity",
		"title",
		"evidence",
		"remediation",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, id := range run.Identities {
		owner := ""
		if id.Owner != nil {
			owner = *id.Owner
		}
		aiServices := strings.Join(id.AIServices, "; ")

		for _, f := range id.Findings {
			row := []string{
				run.AccountID,
				run.Region,
				run.ID,
				string(id.Type),
				id.Name,
				id.ARN,
				owner,
				string(id.AgentLikelihood),
				aiServices,
				fmt.Sprintf("%.1f", id.RiskScore),
				fmt.Sprintf("%.1f", id.RawRiskPoints),
				f.RuleID,
				f.RuleName,
				string(f.Severity),
				f.Title,
				strings.Join(f.Evidence, "; "),
				f.Remediation,
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}
