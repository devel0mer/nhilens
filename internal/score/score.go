package score

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

const defaultSaturationScale = 6.5

// ScoreIdentity calculates an explainable 0–10 RiskScore for one identity using weights
// and curve parameters from cfg.Scoring, and populates ident.RawRiskPoints, ident.ScoreExplanation,
// and ident.ScoreContributions.
//
// In addition to individual finding severity weights, ScoreIdentity applies:
//   - compound_exposure_bonus when high/critical privilege (R1 or R6) combines with high/critical
//     external/loose assumability (R5)
//   - agent_likely_bonus when agent_likelihood == likely and at least one finding exists
//
// Raw weighted points map monotonically onto [0, max_score] via a smooth saturating curve:
//
//	risk_score = max_score * (1 - exp(-raw / saturation_scale))
func ScoreIdentity(ident *model.Identity, cfg *config.Config) {
	if ident == nil {
		return
	}
	if cfg == nil {
		cfg = config.Default()
	}

	ident.RawRiskPoints = 0
	ident.RiskScore = 0
	ident.ScoreExplanation = ""
	ident.ScoreContributions = nil

	if len(ident.Findings) == 0 {
		return
	}

	maxScore := cfg.Scoring.MaxScore
	if maxScore <= 0 {
		maxScore = 10.0
	}
	scale := cfg.Scoring.SaturationScale
	if scale <= 0 {
		scale = defaultSaturationScale
	}

	var (
		raw              float64
		contribs         = make([]model.ScoreContribution, 0, len(ident.Findings)+2)
		hasHighPrivilege bool
		hasLooseExternal bool
	)

	for _, f := range ident.Findings {
		w := weightForSeverity(cfg.Scoring.Weights, f.Severity)
		raw += w
		contribs = append(contribs, model.ScoreContribution{
			Source: fmt.Sprintf("%s %s (%s)", f.RuleID, f.RuleName, f.Severity),
			Points: round1(w),
		})

		if (f.RuleID == "R1" || f.RuleID == "R6") && model.SeverityRank(f.Severity) >= model.SeverityRank(model.SeverityHigh) {
			hasHighPrivilege = true
		}
		if f.RuleID == "R5" && model.SeverityRank(f.Severity) >= model.SeverityRank(model.SeverityHigh) {
			hasLooseExternal = true
		}
	}

	if hasHighPrivilege && hasLooseExternal && cfg.Scoring.CompoundExposureBonus > 0 {
		bonus := cfg.Scoring.CompoundExposureBonus
		raw += bonus
		contribs = append(contribs, model.ScoreContribution{
			Source: "compound blast radius (high privilege + loose external trust)",
			Points: round1(bonus),
		})
	}

	if ident.AgentLikelihood == model.LikelihoodLikely && cfg.Scoring.AgentLikelyBonus > 0 {
		bonus := cfg.Scoring.AgentLikelyBonus
		raw += bonus
		contribs = append(contribs, model.ScoreContribution{
			Source: "agent_likelihood=likely bonus",
			Points: round1(bonus),
		})
	}

	normalized := maxScore * (1.0 - math.Exp(-raw/scale))
	if normalized > maxScore {
		normalized = maxScore
	}
	if normalized < 0 {
		normalized = 0
	}

	ident.RawRiskPoints = round1(raw)
	ident.RiskScore = round1(normalized)
	ident.ScoreContributions = contribs
	ident.ScoreExplanation = buildScoreExplanation(ident.RiskScore, ident.RawRiskPoints, contribs)
}

func buildScoreExplanation(scoreVal, rawVal float64, contribs []model.ScoreContribution) string {
	parts := make([]string, 0, len(contribs))
	for _, c := range contribs {
		parts = append(parts, fmt.Sprintf("%s (+%.1f)", c.Source, c.Points))
	}
	return fmt.Sprintf("%.1f/10 (raw %.1f): %s", scoreVal, rawVal, strings.Join(parts, " + "))
}

// ScoreAll scores every identity and sorts the slice highest risk first.
func ScoreAll(identities []model.Identity, cfg *config.Config) {
	if cfg == nil {
		cfg = config.Default()
	}
	for i := range identities {
		ScoreIdentity(&identities[i], cfg)
	}

	sort.Slice(identities, func(i, j int) bool {
		if identities[i].RiskScore != identities[j].RiskScore {
			return identities[i].RiskScore > identities[j].RiskScore
		}
		if identities[i].RawRiskPoints != identities[j].RawRiskPoints {
			return identities[i].RawRiskPoints > identities[j].RawRiskPoints
		}
		if len(identities[i].Findings) != len(identities[j].Findings) {
			return len(identities[i].Findings) > len(identities[j].Findings)
		}
		if identities[i].Type != identities[j].Type {
			return identities[i].Type < identities[j].Type
		}
		if identities[i].Name != identities[j].Name {
			return identities[i].Name < identities[j].Name
		}
		return identities[i].ID < identities[j].ID
	})
}

// ExceedsFailOn reports whether any finding across identities meets or exceeds the failOn
// severity threshold, along with the count of matching findings.
func ExceedsFailOn(identities []model.Identity, failOn string) (bool, int) {
	threshold := model.Severity(strings.ToLower(strings.TrimSpace(failOn)))
	minRank := model.SeverityRank(threshold)
	if minRank == 0 {
		return false, 0
	}

	count := 0
	for _, ident := range identities {
		for _, f := range ident.Findings {
			if model.SeverityRank(f.Severity) >= minRank {
				count++
			}
		}
	}
	return count > 0, count
}

// SummarizeSeverities counts findings across all identities grouped by Severity.
func SummarizeSeverities(identities []model.Identity) map[model.Severity]int {
	counts := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     0,
		model.SeverityMedium:   0,
		model.SeverityLow:      0,
		model.SeverityInfo:     0,
	}
	for _, ident := range identities {
		for _, f := range ident.Findings {
			counts[f.Severity]++
		}
	}
	return counts
}

func weightForSeverity(weights map[string]float64, sev model.Severity) float64 {
	if weights != nil {
		if w, ok := weights[strings.ToLower(string(sev))]; ok {
			return w
		}
	}
	switch sev {
	case model.SeverityCritical:
		return 4.0
	case model.SeverityHigh:
		return 3.0
	case model.SeverityMedium:
		return 2.0
	case model.SeverityLow:
		return 1.0
	case model.SeverityInfo:
		return 0.5
	default:
		return 0.0
	}
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
