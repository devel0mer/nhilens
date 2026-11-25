package rules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
	"github.com/devel0mer/nhilens/internal/rules"
)

type corpusFile struct {
	Description   string         `json:"description"`
	ReferenceTime string         `json:"reference_time"`
	PeerRoles     []corpusPeer   `json:"peer_roles"`
	Cases         []corpusSample `json:"cases"`
}

type corpusPeer struct {
	ARN          string   `json:"arn"`
	Name         string   `json:"name"`
	Account      string   `json:"account"`
	TrustPolicy  string   `json:"trust_policy"`
	InlinePolicy string   `json:"inline_policy"`
	ManagedARNs  []string `json:"managed_arns"`
}

type corpusSample struct {
	ID              string            `json:"id"`
	RuleFocus       string            `json:"rule_focus"`
	Type            string            `json:"type"`
	Name            string            `json:"name"`
	Owner           string            `json:"owner"`
	TrustPolicy     string            `json:"trust_policy"`
	InlinePolicy    string            `json:"inline_policy"`
	ManagedARNs     []string          `json:"managed_arns"`
	BoundaryDoc     string            `json:"boundary_doc"`
	SCPDoc          string            `json:"scp_doc"`
	HasConsoleLogin *bool             `json:"has_console_login"`
	ActiveKeys      []string          `json:"active_keys"`
	KeyAgeDays      int               `json:"key_age_days"`
	KeyStatus       string            `json:"key_status"`
	Expected        map[string]string `json:"expected"`
}

// TestLabeledValidationCorpus evaluates every anonymized expert-labeled IAM & trust policy case
// in testdata/validation_corpus.json and measures exact TP/FP/FN precision & recall per rule.
func TestLabeledValidationCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "validation_corpus.json"))
	if err != nil {
		t.Fatalf("read validation corpus: %v", err)
	}
	var corpus corpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse validation corpus: %v", err)
	}

	now, err := time.Parse(time.RFC3339, corpus.ReferenceTime)
	if err != nil {
		t.Fatalf("parse reference_time: %v", err)
	}

	// Build and parse peer roles in the simulated account (for R6 target-role correlation).
	peers := make([]*model.Identity, 0, len(corpus.PeerRoles))
	for _, pr := range corpus.PeerRoles {
		ident := &model.Identity{
			ID:             pr.ARN,
			ARN:            pr.ARN,
			Type:           model.TypeRole,
			Name:           pr.Name,
			Account:        pr.Account,
			TrustPolicyRaw: pr.TrustPolicy,
		}
		for _, mARN := range pr.ManagedARNs {
			ident.Policies = append(ident.Policies, model.PolicyAttachment{
				Name: mARN,
				ARN:  mARN,
				Kind: "managed",
			})
		}
		if pr.InlinePolicy != "" {
			ident.Policies = append(ident.Policies, model.PolicyAttachment{
				Name:        "inline",
				Kind:        "inline",
				RawDocument: pr.InlinePolicy,
			})
		}
		if warns := policy.ParseAndSummarize(ident); len(warns) > 0 {
			t.Fatalf("parse peer role %s: %v", pr.Name, warns)
		}
		peers = append(peers, ident)
	}

	type metrics struct {
		tp, fp, fn, tn int
	}
	byRule := make(map[string]*metrics)
	getM := func(ruleID string) *metrics {
		m, ok := byRule[ruleID]
		if !ok {
			m = &metrics{}
			byRule[ruleID] = m
		}
		return m
	}

	cfg := config.Default()
	allRules := rules.DefaultRules()

	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			ident := buildCorpusIdentity(tc, now)
			if warns := policy.ParseAndSummarize(&ident); len(warns) > 0 {
				t.Fatalf("parse corpus case %s: %v", tc.ID, warns)
			}

			var scps []policy.NamedPolicy
			if tc.SCPDoc != "" {
				parsedSCP, err := policy.ParseDocument(tc.SCPDoc)
				if err != nil {
					t.Fatalf("parse SCP for %s: %v", tc.ID, err)
				}
				scps = []policy.NamedPolicy{{Name: tc.ID + "-scp", Parsed: parsedSCP}}
			}

			roles := append([]*model.Identity{}, peers...)
			if ident.Type == model.TypeRole {
				roles = append(roles, &ident)
			}

			rctx := rules.Context{
				Config:      cfg,
				Now:         now,
				SCPPolicies: scps,
				Roles:       roles,
			}

			got := make(map[string]string)
			for _, rule := range allRules {
				if f := rule.Evaluate(&ident, rctx); f != nil {
					got[f.RuleID] = string(f.Severity)
				}
			}

			// Measure TP/FP/FN for every rule.
			for _, rule := range allRules {
				rid := rule.ID()
				wantSev, wantHit := tc.Expected[rid]
				gotSev, gotHit := got[rid]
				m := getM(rid)

				switch {
				case wantHit && gotHit:
					m.tp++
					if gotSev != wantSev {
						t.Errorf("case %s rule %s: severity = %q, want %q", tc.ID, rid, gotSev, wantSev)
					}
				case !wantHit && gotHit:
					m.fp++
					t.Errorf("FALSE POSITIVE on case %s: unexpected finding %s (%s)", tc.ID, rid, gotSev)
				case wantHit && !gotHit:
					m.fn++
					t.Errorf("FALSE NEGATIVE on case %s: missed expected finding %s (%s)", tc.ID, rid, wantSev)
				default:
					m.tn++
				}
			}
		})
	}

	ruleIDs := make([]string, 0, len(byRule))
	for rid := range byRule {
		ruleIDs = append(ruleIDs, rid)
	}
	sort.Strings(ruleIDs)

	var totalTP, totalFP, totalFN int
	for _, rid := range ruleIDs {
		m := byRule[rid]
		totalTP += m.tp
		totalFP += m.fp
		totalFN += m.fn
		if m.tp+m.fp+m.fn > 0 {
			prec := 1.0
			if m.tp+m.fp > 0 {
				prec = float64(m.tp) / float64(m.tp+m.fp)
			}
			rec := 1.0
			if m.tp+m.fn > 0 {
				rec = float64(m.tp) / float64(m.tp+m.fn)
			}
			t.Logf("Rule %s: TP=%d FP=%d FN=%d TN=%d (precision=%.2f recall=%.2f)", rid, m.tp, m.fp, m.fn, m.tn, prec, rec)
		}
	}
	t.Logf("Corpus total (%d labeled cases): TP=%d FP=%d FN=%d", len(corpus.Cases), totalTP, totalFP, totalFN)
}

func buildCorpusIdentity(tc corpusSample, now time.Time) model.Identity {
	account := "111122223333"
	var arn string
	switch model.IdentityType(tc.Type) {
	case model.TypeRole:
		arn = "arn:aws:iam::" + account + ":role/" + tc.Name
	case model.TypeUser:
		arn = "arn:aws:iam::" + account + ":user/" + tc.Name
	default:
		arn = "arn:aws:iam::" + account + ":user/parent-bot"
	}

	ident := model.Identity{
		ID:              arn,
		ARN:             arn,
		Type:            model.IdentityType(tc.Type),
		Name:            tc.Name,
		Account:         account,
		TrustPolicyRaw:  tc.TrustPolicy,
		HasConsoleLogin: tc.HasConsoleLogin,
	}
	if tc.Owner != "" {
		o := tc.Owner
		ident.Owner = &o
		ident.Tags = map[string]string{"owner": o}
	}
	if tc.BoundaryDoc != "" {
		ident.PermissionsBoundaryARN = "arn:aws:iam::" + account + ":policy/" + tc.ID + "-boundary"
		ident.PermissionsBoundaryDoc = tc.BoundaryDoc
	}
	for _, mARN := range tc.ManagedARNs {
		ident.Policies = append(ident.Policies, model.PolicyAttachment{
			Name: mARN,
			ARN:  mARN,
			Kind: "managed",
		})
	}
	if tc.InlinePolicy != "" {
		ident.Policies = append(ident.Policies, model.PolicyAttachment{
			Name:        "inline",
			Kind:        "inline",
			RawDocument: tc.InlinePolicy,
		})
	}
	if len(tc.ActiveKeys) > 0 {
		ident.AccessKeyIDs = tc.ActiveKeys
		ident.ActiveAccessKeyIDs = tc.ActiveKeys
	}
	if ident.Type == model.TypeKey {
		ident.ID = arn + "/access-key/" + tc.Name
		created := now.Add(-time.Duration(tc.KeyAgeDays) * 24 * time.Hour)
		ident.Created = &created
		ident.AccessKey = &model.AccessKeyInfo{
			AccessKeyID:    tc.Name,
			ParentUserName: "parent-bot",
			ParentUserARN:  arn,
			Status:         tc.KeyStatus,
		}
	}
	return ident
}
