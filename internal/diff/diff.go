package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

// ScanRef summarizes one side (base or head) of a scan comparison.
type ScanRef struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Region    string    `json:"region"`
	StartedAt time.Time `json:"started_at"`
}

// DiffSummary aggregates high-level change counts between two scans.
type DiffSummary struct {
	AddedIdentities   int `json:"added_identities"`
	RemovedIdentities int `json:"removed_identities"`
	ScoreIncreased    int `json:"score_increased"`
	ScoreDecreased    int `json:"score_decreased"`
	NewFindings       int `json:"new_findings"`
	ResolvedFindings  int `json:"resolved_findings"`
}

// ScoreDelta records a risk score change for an identity present in both scans.
type ScoreDelta struct {
	IdentityID      string                `json:"identity_id"`
	IdentityARN     string                `json:"identity_arn"`
	IdentityName    string                `json:"identity_name"`
	IdentityType    model.IdentityType    `json:"identity_type"`
	AgentLikelihood model.AgentLikelihood `json:"agent_likelihood"`
	BaseScore       float64               `json:"base_score"`
	HeadScore       float64               `json:"head_score"`
	Delta           float64               `json:"delta"`
}

// FindingDiffItem represents a finding newly introduced, escalated, or resolved between scans.
type FindingDiffItem struct {
	IdentityID       string                `json:"identity_id"`
	IdentityARN      string                `json:"identity_arn"`
	IdentityName     string                `json:"identity_name"`
	IdentityType     model.IdentityType    `json:"identity_type"`
	AgentLikelihood  model.AgentLikelihood `json:"agent_likelihood"`
	RuleID           string                `json:"rule_id"`
	RuleName         string                `json:"rule_name"`
	Severity         model.Severity        `json:"severity"`
	PreviousSeverity model.Severity        `json:"previous_severity,omitempty"`
	Title            string                `json:"title"`
}

// Result contains the complete structured comparison between a base and head ScanRun.
type Result struct {
	Base              ScanRef           `json:"base"`
	Head              ScanRef           `json:"head"`
	Summary           DiffSummary       `json:"summary"`
	AddedIdentities   []model.Identity  `json:"added_identities,omitempty"`
	RemovedIdentities []model.Identity  `json:"removed_identities,omitempty"`
	ScoreChanges      []ScoreDelta      `json:"score_changes,omitempty"`
	NewFindings       []FindingDiffItem `json:"new_findings,omitempty"`
	ResolvedFindings  []FindingDiffItem `json:"resolved_findings,omitempty"`
}

// Compare computes identity, risk-score, and finding deltas between base and head scans.
func Compare(base, head *model.ScanRun) *Result {
	res := &Result{}
	if base != nil {
		res.Base = ScanRef{ID: base.ID, AccountID: base.AccountID, Region: base.Region, StartedAt: base.StartedAt}
	}
	if head != nil {
		res.Head = ScanRef{ID: head.ID, AccountID: head.AccountID, Region: head.Region, StartedAt: head.StartedAt}
	}

	baseByID := make(map[string]model.Identity)
	if base != nil {
		for _, id := range base.Identities {
			baseByID[id.ID] = id
		}
	}
	headByID := make(map[string]model.Identity)
	if head != nil {
		for _, id := range head.Identities {
			headByID[id.ID] = id
		}
	}

	// Added identities & score/finding changes for surviving identities.
	for idKey, hIdent := range headByID {
		bIdent, existed := baseByID[idKey]
		if !existed {
			res.AddedIdentities = append(res.AddedIdentities, hIdent)
			for _, f := range hIdent.Findings {
				res.NewFindings = append(res.NewFindings, toFindingDiff(hIdent, f, ""))
			}
			continue
		}

		delta := round1(hIdent.RiskScore - bIdent.RiskScore)
		if delta != 0 {
			res.ScoreChanges = append(res.ScoreChanges, ScoreDelta{
				IdentityID:      hIdent.ID,
				IdentityARN:     hIdent.ARN,
				IdentityName:    hIdent.Name,
				IdentityType:    hIdent.Type,
				AgentLikelihood: hIdent.AgentLikelihood,
				BaseScore:       bIdent.RiskScore,
				HeadScore:       hIdent.RiskScore,
				Delta:           delta,
			})
			if delta > 0 {
				res.Summary.ScoreIncreased++
			} else {
				res.Summary.ScoreDecreased++
			}
		}

		baseFindings := indexFindingsByRule(bIdent.Findings)
		headFindings := indexFindingsByRule(hIdent.Findings)

		for ruleID, hf := range headFindings {
			bf, hadRule := baseFindings[ruleID]
			if !hadRule {
				res.NewFindings = append(res.NewFindings, toFindingDiff(hIdent, hf, ""))
			} else if model.SeverityRank(hf.Severity) > model.SeverityRank(bf.Severity) {
				res.NewFindings = append(res.NewFindings, toFindingDiff(hIdent, hf, bf.Severity))
			}
		}
		for ruleID, bf := range baseFindings {
			if _, stillPresent := headFindings[ruleID]; !stillPresent {
				res.ResolvedFindings = append(res.ResolvedFindings, toFindingDiff(bIdent, bf, ""))
			}
		}
	}

	// Removed identities & their resolved findings.
	for idKey, bIdent := range baseByID {
		if _, exists := headByID[idKey]; !exists {
			res.RemovedIdentities = append(res.RemovedIdentities, bIdent)
			for _, f := range bIdent.Findings {
				res.ResolvedFindings = append(res.ResolvedFindings, toFindingDiff(bIdent, f, ""))
			}
		}
	}

	sortIdentities(res.AddedIdentities)
	sortIdentities(res.RemovedIdentities)
	sort.Slice(res.ScoreChanges, func(i, j int) bool {
		if res.ScoreChanges[i].Delta != res.ScoreChanges[j].Delta {
			return res.ScoreChanges[i].Delta > res.ScoreChanges[j].Delta
		}
		return res.ScoreChanges[i].IdentityName < res.ScoreChanges[j].IdentityName
	})
	sortFindingDiffs(res.NewFindings)
	sortFindingDiffs(res.ResolvedFindings)

	res.Summary.AddedIdentities = len(res.AddedIdentities)
	res.Summary.RemovedIdentities = len(res.RemovedIdentities)
	res.Summary.NewFindings = len(res.NewFindings)
	res.Summary.ResolvedFindings = len(res.ResolvedFindings)

	return res
}

// ExceedsFailOnNew reports whether any newly introduced or escalated finding meets or exceeds failOn.
func ExceedsFailOnNew(res *Result, failOn string) (bool, int) {
	if res == nil {
		return false, 0
	}
	minRank := model.SeverityRank(model.Severity(strings.ToLower(strings.TrimSpace(failOn))))
	if minRank == 0 {
		return false, 0
	}
	count := 0
	for _, f := range res.NewFindings {
		if model.SeverityRank(f.Severity) >= minRank {
			count++
		}
	}
	return count > 0, count
}

// WriteJSON encodes Result as indented JSON.
func WriteJSON(w io.Writer, res *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// WriteTable writes a concise terminal diff summary.
func WriteTable(w io.Writer, res *Result) error {
	fmt.Fprintf(w, "nhilens diff summary\n")
	fmt.Fprintf(w, "  Base scan:  %s (account %s, %s)\n", res.Base.ID, res.Base.AccountID, res.Base.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "  Head scan:  %s (account %s, %s)\n", res.Head.ID, res.Head.AccountID, res.Head.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "  Identities: +%d added, -%d removed\n", res.Summary.AddedIdentities, res.Summary.RemovedIdentities)
	fmt.Fprintf(w, "  Risk scores: %d increased, %d decreased\n", res.Summary.ScoreIncreased, res.Summary.ScoreDecreased)
	fmt.Fprintf(w, "  Findings:   +%d new/escalated, -%d resolved\n\n", res.Summary.NewFindings, res.Summary.ResolvedFindings)

	if len(res.NewFindings) > 0 {
		fmt.Fprintln(w, "New / Escalated Findings:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRULE\tTYPE\tIDENTITY\tAGENT\tDETAIL")
		for _, f := range res.NewFindings {
			sevStr := string(f.Severity)
			if f.PreviousSeverity != "" {
				sevStr = fmt.Sprintf("%s->%s", f.PreviousSeverity, f.Severity)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", sevStr, f.RuleID, f.IdentityType, f.IdentityName, f.AgentLikelihood, f.Title)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}

	if len(res.ScoreChanges) > 0 {
		fmt.Fprintln(w, "Risk Score Changes:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "DELTA\tBASE\tHEAD\tTYPE\tIDENTITY\tAGENT")
		for _, sc := range res.ScoreChanges {
			fmt.Fprintf(tw, "%+.1f\t%.1f\t%.1f\t%s\t%s\t%s\n", sc.Delta, sc.BaseScore, sc.HeadScore, sc.IdentityType, sc.IdentityName, sc.AgentLikelihood)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}

	if len(res.ResolvedFindings) > 0 {
		fmt.Fprintln(w, "Resolved Findings:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRULE\tTYPE\tIDENTITY")
		for _, f := range res.ResolvedFindings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, f.IdentityType, f.IdentityName)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}

	if len(res.AddedIdentities) > 0 {
		fmt.Fprintln(w, "Added Identities:")
		for _, id := range res.AddedIdentities {
			fmt.Fprintf(w, "  + [%s] %s (score %.1f/10, agent=%s)\n", id.Type, id.Name, id.RiskScore, id.AgentLikelihood)
		}
		fmt.Fprintln(w)
	}

	if len(res.RemovedIdentities) > 0 {
		fmt.Fprintln(w, "Removed Identities:")
		for _, id := range res.RemovedIdentities {
			fmt.Fprintf(w, "  - [%s] %s (was score %.1f/10)\n", id.Type, id.Name, id.RiskScore)
		}
		fmt.Fprintln(w)
	}

	if res.Summary == (DiffSummary{}) {
		fmt.Fprintln(w, "No identity, score, or finding changes detected.")
	}
	return nil
}

// WriteMarkdown renders a PR-comment-ready Markdown diff report.
func WriteMarkdown(w io.Writer, res *Result) error {
	fmt.Fprintf(w, "## nhilens Scan Diff\n\n")
	fmt.Fprintf(w, "- **Base:** `%s` (account `%s`, %s)\n", res.Base.ID, res.Base.AccountID, res.Base.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "- **Head:** `%s` (account `%s`, %s)\n", res.Head.ID, res.Head.AccountID, res.Head.StartedAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "- **Summary:** `+%d` / `-%d` identities | `%d` score up / `%d` score down | `+%d` new findings / `-%d` resolved\n\n",
		res.Summary.AddedIdentities, res.Summary.RemovedIdentities,
		res.Summary.ScoreIncreased, res.Summary.ScoreDecreased,
		res.Summary.NewFindings, res.Summary.ResolvedFindings,
	)

	if len(res.NewFindings) > 0 {
		fmt.Fprintln(w, "### New / Escalated Findings")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Severity | Rule | Type | Identity | Agent | Detail |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for _, f := range res.NewFindings {
			sevStr := string(f.Severity)
			if f.PreviousSeverity != "" {
				sevStr = fmt.Sprintf("%s → %s", f.PreviousSeverity, f.Severity)
			}
			fmt.Fprintf(w, "| %s | `%s` | %s | `%s` | %s | %s |\n", sevStr, f.RuleID, f.IdentityType, f.IdentityName, f.AgentLikelihood, f.Title)
		}
		fmt.Fprintln(w)
	}

	if len(res.ScoreChanges) > 0 {
		fmt.Fprintln(w, "### Risk Score Changes")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Delta | Base | Head | Type | Identity | Agent |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for _, sc := range res.ScoreChanges {
			fmt.Fprintf(w, "| %+.1f | %.1f | %.1f | %s | `%s` | %s |\n", sc.Delta, sc.BaseScore, sc.HeadScore, sc.IdentityType, sc.IdentityName, sc.AgentLikelihood)
		}
		fmt.Fprintln(w)
	}

	if len(res.ResolvedFindings) > 0 {
		fmt.Fprintln(w, "### Resolved Findings")
		fmt.Fprintln(w)
		for _, f := range res.ResolvedFindings {
			fmt.Fprintf(w, "- `%s` (%s) on `%s` (%s)\n", f.RuleID, f.Severity, f.IdentityName, f.IdentityType)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func indexFindingsByRule(findings []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		if existing, ok := out[f.RuleID]; !ok || model.SeverityRank(f.Severity) > model.SeverityRank(existing.Severity) {
			out[f.RuleID] = f
		}
	}
	return out
}

func toFindingDiff(ident model.Identity, f model.Finding, prev model.Severity) FindingDiffItem {
	return FindingDiffItem{
		IdentityID:       ident.ID,
		IdentityARN:      ident.ARN,
		IdentityName:     ident.Name,
		IdentityType:     ident.Type,
		AgentLikelihood:  ident.AgentLikelihood,
		RuleID:           f.RuleID,
		RuleName:         f.RuleName,
		Severity:         f.Severity,
		PreviousSeverity: prev,
		Title:            f.Title,
	}
}

func sortIdentities(in []model.Identity) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].RiskScore != in[j].RiskScore {
			return in[i].RiskScore > in[j].RiskScore
		}
		return in[i].Name < in[j].Name
	})
}

func sortFindingDiffs(in []FindingDiffItem) {
	sort.Slice(in, func(i, j int) bool {
		ri, rj := model.SeverityRank(in[i].Severity), model.SeverityRank(in[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if in[i].RuleID != in[j].RuleID {
			return in[i].RuleID < in[j].RuleID
		}
		return in[i].IdentityName < in[j].IdentityName
	})
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
