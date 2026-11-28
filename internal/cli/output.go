package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/score"
)

// WriteScanJSON writes the full ScanRun as indented JSON.
func WriteScanJSON(w io.Writer, run *model.ScanRun) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(run)
}

// WriteScanTable writes a concise scan summary and ranked table of identities.
func WriteScanTable(w io.Writer, run *model.ScanRun, dbPath string) error {
	var roles, users, keys, likely, possible, slrs int
	for _, id := range run.Identities {
		switch id.Type {
		case model.TypeRole:
			roles++
		case model.TypeUser:
			users++
		case model.TypeKey:
			keys++
		}
		switch id.AgentLikelihood {
		case model.LikelihoodLikely:
			likely++
		case model.LikelihoodPossible:
			possible++
		}
		if id.IsServiceLinkedRole {
			slrs++
		}
	}

	sevCounts := score.SummarizeSeverities(run.Identities)
	totalFindings := sevCounts[model.SeverityCritical] +
		sevCounts[model.SeverityHigh] +
		sevCounts[model.SeverityMedium] +
		sevCounts[model.SeverityLow] +
		sevCounts[model.SeverityInfo]

	regions := run.EffectiveRegions()
	accounts := run.EffectiveAccounts()
	isMultiAcct := run.IsMultiAccount()

	_, _ = fmt.Fprintf(w, "nhilens scan summary\n")
	if isMultiAcct {
		if run.OrganizationID != "" {
			_, _ = fmt.Fprintf(w, "  Org:        %s (%d account(s))\n", run.OrganizationID, len(accounts))
		} else {
			_, _ = fmt.Fprintf(w, "  Accounts:   %d targeted\n", len(accounts))
		}
		if len(regions) > 1 {
			_, _ = fmt.Fprintf(w, "  Regions:    %s\n", strings.Join(regions, ", "))
		} else {
			_, _ = fmt.Fprintf(w, "  Region:     %s\n", run.Region)
		}
	} else if len(regions) > 1 {
		_, _ = fmt.Fprintf(w, "  Account:    %s (regions: %s)\n", run.AccountID, strings.Join(regions, ", "))
	} else {
		_, _ = fmt.Fprintf(w, "  Account:    %s (region: %s)\n", run.AccountID, run.Region)
	}
	_, _ = fmt.Fprintf(w, "  Scan ID:    %s\n", run.ID)
	_, _ = fmt.Fprintf(w, "  Identities: %d total (%d roles, %d users, %d keys; %d likely AI agent, %d automation/possible; %d service-linked)\n",
		len(run.Identities), roles, users, keys, likely, possible, slrs)
	_, _ = fmt.Fprintf(w, "  Findings:   %d total (critical: %d, high: %d, medium: %d, low: %d)\n",
		totalFindings,
		sevCounts[model.SeverityCritical],
		sevCounts[model.SeverityHigh],
		sevCounts[model.SeverityMedium],
		sevCounts[model.SeverityLow],
	)
	if run.SuppressedFindingCount > 0 {
		_, _ = fmt.Fprintf(w, "  Suppressed: %d finding(s) via baseline ignore file\n", run.SuppressedFindingCount)
	}
	regionLabel := strings.TrimSpace(run.Region)
	if regionLabel == "" {
		regionLabel = "default"
	}
	switch {
	case run.CloudTrailStatus == model.CloudTrailStatusDisabled:
		_, _ = fmt.Fprintf(w, "  CloudTrail: disabled (--max-events=0; userAgent traces and R4 multi-IP skipped)\n")
	case len(regions) > 1:
		detail := formatRegionCloudTrailBrief(run.Coverage)
		if detail != "" {
			_, _ = fmt.Fprintf(w, "  CloudTrail: %s (%d events analyzed across %d regions: %s)\n", run.CloudTrailStatus, run.CloudTrailEventCount, len(regions), detail)
		} else {
			_, _ = fmt.Fprintf(w, "  CloudTrail: %s (%d events analyzed across %d regions)\n", run.CloudTrailStatus, run.CloudTrailEventCount, len(regions))
		}
	case run.CloudTrailEventCount > 0:
		_, _ = fmt.Fprintf(w, "  CloudTrail: %s (%d events analyzed; region %s only)\n", run.CloudTrailStatus, run.CloudTrailEventCount, regionLabel)
	default:
		_, _ = fmt.Fprintf(w, "  CloudTrail: %s (region %s only)\n", run.CloudTrailStatus, regionLabel)
	}
	if run.Coverage != nil {
		_, _ = fmt.Fprintf(w, "  Coverage:   %s\n", formatCoverageLine(run.Coverage))
	}
	if dbPath != "" {
		_, _ = fmt.Fprintf(w, "  Saved DB:   %s\n", dbPath)
	}
	_, _ = fmt.Fprintln(w)

	if isMultiAcct && len(accounts) > 0 {
		_, _ = fmt.Fprintln(w, "Account breakdown:")
		atw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(atw, "ACCOUNT\tNAME\tSTATUS\tIDENTITIES\tAI AGENTS\tFINDINGS\tSCPS")
		_, _ = fmt.Fprintln(atw, "-------\t----\t------\t----------\t---------\t--------\t----")
		for _, a := range accounts {
			acctName := a.AccountName
			if acctName == "" {
				acctName = "-"
			}
			findingsSummary := fmt.Sprintf("%d (crit:%d high:%d)", a.FindingsTotal, a.CriticalCount, a.HighCount)
			if a.Status == "failed" {
				findingsSummary = "error: " + a.Error
			}
			_, _ = fmt.Fprintf(atw, "%s\t%s\t%s\t%d\t%d\t%s\t%d\n",
				a.AccountID, acctName, a.Status, a.Identities, a.AgentLikely, findingsSummary, a.SCPCount)
		}
		if err := atw.Flush(); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(run.Identities) == 0 {
		_, _ = fmt.Fprintln(w, "No identities found.")
		writeCloudTrailScopeNotice(w, run)
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if isMultiAcct {
		_, _ = fmt.Fprintln(tw, "SCORE\tACCOUNT\tTYPE\tNAME\tAGENT\tOWNER\tFINDINGS\tBREAKDOWN")
		_, _ = fmt.Fprintln(tw, "-----\t-------\t----\t----\t-----\t-----\t--------\t---------")
	} else {
		_, _ = fmt.Fprintln(tw, "SCORE\tTYPE\tNAME\tAGENT\tOWNER\tFINDINGS\tBREAKDOWN")
		_, _ = fmt.Fprintln(tw, "-----\t----\t----\t-----\t-----\t--------\t---------")
	}

	for _, id := range run.Identities {
		name := id.Name
		if id.Type == model.TypeKey && id.AccessKey != nil && id.AccessKey.ParentUserName != "" {
			name = fmt.Sprintf("%s (%s)", id.Name, id.AccessKey.ParentUserName)
		}

		owner := "<none>"
		if id.Owner != nil && strings.TrimSpace(*id.Owner) != "" {
			owner = *id.Owner
		}

		findingsCol := formatFindingsSummary(id)
		breakdownCol := formatScoreBreakdown(id)

		agentCol := string(id.AgentLikelihood)
		if id.AgentConfidence > 0 {
			if id.WorkloadKind == "automation" {
				agentCol = fmt.Sprintf("auto(%d%%)", id.AgentConfidence)
			} else {
				agentCol = fmt.Sprintf("%s(%d%%)", id.AgentLikelihood, id.AgentConfidence)
			}
		}

		if isMultiAcct {
			acctCol := id.Account
			if id.AccountName != "" {
				acctCol = fmt.Sprintf("%s (%s)", id.AccountName, id.Account)
			}
			_, _ = fmt.Fprintf(tw, "%.1f/10\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				id.RiskScore,
				acctCol,
				id.Type,
				name,
				agentCol,
				owner,
				findingsCol,
				breakdownCol,
			)
		} else {
			_, _ = fmt.Fprintf(tw, "%.1f/10\t%s\t%s\t%s\t%s\t%s\t%s\n",
				id.RiskScore,
				id.Type,
				name,
				agentCol,
				owner,
				findingsCol,
				breakdownCol,
			)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(run.Warnings) > 0 {
		_, _ = fmt.Fprintf(w, "\nWarnings (%d):\n", len(run.Warnings))
		limit := min(len(run.Warnings), 10)
		for i := 0; i < limit; i++ {
			_, _ = fmt.Fprintf(w, "  - %s\n", run.Warnings[i])
		}
		if len(run.Warnings) > limit {
			_, _ = fmt.Fprintf(w, "  - ... and %d more warning(s)\n", len(run.Warnings)-limit)
		}
	}

	writeCloudTrailScopeNotice(w, run)
	return nil
}

func writeCloudTrailScopeNotice(w io.Writer, run *model.ScanRun) {
	if run == nil {
		return
	}
	if run.CloudTrailStatus == model.CloudTrailStatusDisabled {
		_, _ = fmt.Fprintln(w, "\nScope note: CloudTrail lookup was disabled (--max-events=0). Agent userAgent traces, 30d activity, and R4 multi-IP key checks were skipped.")
		return
	}
	regions := run.EffectiveRegions()
	if len(regions) > 1 {
		_, _ = fmt.Fprintf(w, "\nScope note: CloudTrail signals (userAgent traces, 30d activity, R4 multi-IP keys) aggregated across %d regions (%s) — activity in unqueried AWS regions is not included.\n", len(regions), strings.Join(regions, ", "))
		return
	}
	regionLabel := strings.TrimSpace(run.Region)
	if regionLabel == "" {
		regionLabel = "default"
	}
	_, _ = fmt.Fprintf(w, "\nScope note: CloudTrail signals (userAgent traces, 30d activity, R4 multi-IP keys) cover region %s only — activity in other AWS regions is not included.\n", regionLabel)
}

func formatRegionCloudTrailBrief(cov *model.ScanCoverage) string {
	if cov == nil || len(cov.CloudTrailRegions) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cov.CloudTrailRegions))
	for _, rc := range cov.CloudTrailRegions {
		switch {
		case rc.Error != "":
			parts = append(parts, fmt.Sprintf("%s=%s(%d, err)", rc.Region, rc.Status, rc.EventsAnalyzed))
		case rc.Truncated:
			parts = append(parts, fmt.Sprintf("%s=%d(capped)", rc.Region, rc.EventsAnalyzed))
		default:
			parts = append(parts, fmt.Sprintf("%s=%d", rc.Region, rc.EventsAnalyzed))
		}
	}
	return strings.Join(parts, ", ")
}

func formatFindingsSummary(id model.Identity) string {
	suffix := ""
	if id.CoverageStatus == model.CoverageStatusPartial || len(id.DataGaps) > 0 {
		suffix = " [partial]"
	}
	if len(id.Findings) == 0 {
		if id.IsServiceLinkedRole {
			return "[service-linked]"
		}
		return "none" + suffix
	}
	parts := make([]string, 0, len(id.Findings))
	for _, f := range id.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.RuleID, f.Severity))
	}
	return strings.Join(parts, ", ") + suffix
}

func formatCoverageLine(cov *model.ScanCoverage) string {
	if cov == nil {
		return "unknown"
	}
	status := strings.ToUpper(cov.Status)
	if status == "" {
		status = "COMPLETE"
	}
	var details []string
	if cov.AccountsScanned > 0 || cov.AccountsFailed > 0 {
		details = append(details, fmt.Sprintf("accounts %d ok/%d failed", cov.AccountsScanned, cov.AccountsFailed))
	}
	if cov.LoginProfileChecked > 0 {
		okCount := cov.LoginProfileChecked - cov.LoginProfileFailed
		details = append(details, fmt.Sprintf("login_profile %d/%d ok", okCount, cov.LoginProfileChecked))
	}
	if cov.AccessAdvisorSkipped {
		details = append(details, "access_advisor skipped")
	} else if cov.AccessAdvisorAttempted > 0 {
		details = append(details, fmt.Sprintf("access_advisor %d/%d ok", cov.AccessAdvisorSucceeded, cov.AccessAdvisorAttempted))
	}
	if cov.CloudTrailTruncated {
		details = append(details, fmt.Sprintf("cloudtrail capped at %d events", cov.CloudTrailEventLimit))
	}
	if cov.SCPPoliciesLoaded > 0 {
		details = append(details, fmt.Sprintf("%d SCP(s)", cov.SCPPoliciesLoaded))
	}
	if cov.PartialIdentities > 0 {
		details = append(details, fmt.Sprintf("%d partial identity(ies) — missing data is not zero risk", cov.PartialIdentities))
	}
	if len(details) == 0 {
		return status
	}
	return fmt.Sprintf("%s (%s)", status, strings.Join(details, "; "))
}

func formatScoreBreakdown(id model.Identity) string {
	if len(id.ScoreContributions) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(id.ScoreContributions))
	for _, c := range id.ScoreContributions {
		label := c.Source
		if idx := strings.IndexByte(label, ' '); idx > 0 && strings.HasPrefix(label, "R") {
			label = label[:idx]
		} else if strings.HasPrefix(label, "agent_likelihood=") {
			label = "agent-bonus"
		} else if strings.HasPrefix(label, "compound ") {
			label = "compound"
		}
		parts = append(parts, fmt.Sprintf("%s:+%.1f", label, c.Points))
	}
	if id.RawRiskPoints > 0 {
		return fmt.Sprintf("raw %.1f (%s)", id.RawRiskPoints, strings.Join(parts, ", "))
	}
	return strings.Join(parts, ", ")
}
