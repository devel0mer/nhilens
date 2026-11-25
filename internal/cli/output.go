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

	fmt.Fprintf(w, "nhilens scan summary\n")
	fmt.Fprintf(w, "  Account:    %s (region: %s)\n", run.AccountID, run.Region)
	fmt.Fprintf(w, "  Scan ID:    %s\n", run.ID)
	fmt.Fprintf(w, "  Identities: %d total (%d roles, %d users, %d keys; %d likely AI agent, %d automation/possible; %d service-linked)\n",
		len(run.Identities), roles, users, keys, likely, possible, slrs)
	fmt.Fprintf(w, "  Findings:   %d total (critical: %d, high: %d, medium: %d, low: %d)\n",
		totalFindings,
		sevCounts[model.SeverityCritical],
		sevCounts[model.SeverityHigh],
		sevCounts[model.SeverityMedium],
		sevCounts[model.SeverityLow],
	)
	if run.SuppressedFindingCount > 0 {
		fmt.Fprintf(w, "  Suppressed: %d finding(s) via baseline ignore file\n", run.SuppressedFindingCount)
	}
	if run.CloudTrailEventCount > 0 {
		fmt.Fprintf(w, "  CloudTrail: %s (%d events analyzed)\n", run.CloudTrailStatus, run.CloudTrailEventCount)
	} else {
		fmt.Fprintf(w, "  CloudTrail: %s\n", run.CloudTrailStatus)
	}
	if dbPath != "" {
		fmt.Fprintf(w, "  Saved DB:   %s\n", dbPath)
	}
	fmt.Fprintln(w)

	if len(run.Identities) == 0 {
		fmt.Fprintln(w, "No identities found.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCORE\tTYPE\tNAME\tAGENT\tOWNER\tFINDINGS\tBREAKDOWN")
	fmt.Fprintln(tw, "-----\t----\t----\t-----\t-----\t--------\t---------")

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

		fmt.Fprintf(tw, "%.1f/10\t%s\t%s\t%s\t%s\t%s\t%s\n",
			id.RiskScore,
			id.Type,
			name,
			agentCol,
			owner,
			findingsCol,
			breakdownCol,
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(run.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d):\n", len(run.Warnings))
		limit := min(len(run.Warnings), 10)
		for i := 0; i < limit; i++ {
			fmt.Fprintf(w, "  - %s\n", run.Warnings[i])
		}
		if len(run.Warnings) > limit {
			fmt.Fprintf(w, "  - ... and %d more warning(s)\n", len(run.Warnings)-limit)
		}
	}

	return nil
}

func formatFindingsSummary(id model.Identity) string {
	if len(id.Findings) == 0 {
		if id.IsServiceLinkedRole {
			return "[service-linked]"
		}
		return "none"
	}
	parts := make([]string, 0, len(id.Findings))
	for _, f := range id.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.RuleID, f.Severity))
	}
	return strings.Join(parts, ", ")
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
