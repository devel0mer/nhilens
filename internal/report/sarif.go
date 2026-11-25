package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/version"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	repoInfoURI  = "https://github.com/devel0mer/nhilens"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifMessage           `json:"shortDescription"`
	FullDescription      sarifMessage           `json:"fullDescription"`
	Help                 sarifMessage           `json:"help"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
	Properties           map[string]any         `json:"properties,omitempty"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// WriteSARIF writes a valid OASIS SARIF 2.1.0 log compatible with GitHub Code Scanning.
// Both active findings and baseline-suppressed findings (marked with SARIF suppressions[])
// are emitted so CI code-scanning dashboards stay accurate and auditable.
func WriteSARIF(w io.Writer, run *model.ScanRun) error {
	if run == nil {
		return errors.New("scan run is nil")
	}

	data := Build(run, run.CompletedAt)

	rules := make([]sarifRule, 0, len(data.RuleGroups))
	for _, rg := range data.RuleGroups {
		rules = append(rules, sarifRule{
			ID:               rg.RuleID,
			Name:             rg.RuleName,
			ShortDescription: sarifMessage{Text: fmt.Sprintf("%s (%s)", rg.RuleID, rg.RuleName)},
			FullDescription:  sarifMessage{Text: rg.Explanation},
			Help:             sarifMessage{Text: rg.Remediation},
			DefaultConfiguration: sarifRuleConfiguration{
				Level: sarifLevel(rg.HighestSeverity),
			},
			Properties: map[string]any{
				"tags":              []string{"security", "aws", "iam", "non-human-identity", "ai-agent"},
				"security-severity": sarifSecuritySeverity(rg.HighestSeverity),
			},
		})
	}

	results := make([]sarifResult, 0)
	for _, ident := range run.Identities {
		for _, f := range ident.Findings {
			results = append(results, buildSARIFResult(run.AccountID, ident, f, nil))
		}
		for _, sf := range ident.SuppressedFindings {
			just := sf.Reason
			if sf.Expires != "" {
				just = fmt.Sprintf("%s (expires: %s)", sf.Reason, sf.Expires)
			}
			results = append(results, buildSARIFResult(run.AccountID, ident, sf.Finding, []sarifSuppression{
				{Kind: "inSource", Justification: just},
			}))
		}
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "nhilens",
						Version:        version.Version,
						InformationURI: repoInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildSARIFResult(accountID string, ident model.Identity, f model.Finding, supps []sarifSuppression) sarifResult {
	msg := fmt.Sprintf("[%s/%s] %s on %s %q (agent=%s, score=%.1f/10)",
		f.RuleID, f.Severity, f.Title, ident.Type, ident.Name, ident.AgentLikelihood, ident.RiskScore)
	if len(f.Evidence) > 0 {
		msg += " — Evidence: " + strings.Join(f.Evidence, "; ")
	}

	owner := "<none>"
	if ident.Owner != nil && strings.TrimSpace(*ident.Owner) != "" {
		owner = *ident.Owner
	}

	artifactURI := fmt.Sprintf("aws/iam/%s/%s/%s", sanitizeURI(accountID), ident.Type, sanitizeURI(ident.Name))

	return sarifResult{
		RuleID:  f.RuleID,
		Level:   sarifLevel(f.Severity),
		Message: sarifMessage{Text: msg},
		Locations: []sarifLocation{
			{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogicalLocation{
					{
						Name:               ident.Name,
						FullyQualifiedName: ident.ARN,
						Kind:               "aws-iam-" + string(ident.Type),
					},
				},
			},
		},
		PartialFingerprints: map[string]string{
			"nhilensIdentityRule/v1": sarifFingerprint(accountID, ident.ID, f.RuleID),
		},
		Suppressions: supps,
		Properties: map[string]any{
			"identity_id":      ident.ID,
			"identity_arn":     ident.ARN,
			"identity_type":    string(ident.Type),
			"owner":            owner,
			"agent_likelihood": string(ident.AgentLikelihood),
			"ai_services":      ident.AIServices,
			"risk_score":       ident.RiskScore,
			"raw_risk_points":  ident.RawRiskPoints,
			"evidence":         f.Evidence,
			"remediation":      f.Remediation,
		},
	}
}

func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "9.0"
	case model.SeverityHigh:
		return "7.5"
	case model.SeverityMedium:
		return "5.0"
	case model.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func sarifFingerprint(accountID, identityID, ruleID string) string {
	sum := sha256.Sum256([]byte(accountID + "|" + identityID + "|" + ruleID))
	return hex.EncodeToString(sum[:16])
}

func sanitizeURI(s string) string {
	replacer := strings.NewReplacer(" ", "_", "\\", "_", ":", "_", "?", "_", "#", "_")
	out := replacer.Replace(strings.TrimSpace(s))
	if out == "" {
		return "unknown"
	}
	return out
}
