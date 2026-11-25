package suppress

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
	"gopkg.in/yaml.v3"
)

// File represents a parsed .nhilens-ignore.yaml baseline/suppression file.
type File struct {
	Suppressions []Entry `yaml:"suppressions"`
}

// Entry suppresses matching findings for an identity and rule, with mandatory justification
// and an optional expiration timestamp.
type Entry struct {
	RuleID   string `yaml:"rule_id"`
	Identity string `yaml:"identity"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires,omitempty"`

	expiresAt *time.Time
}

// Load reads and validates a .nhilens-ignore.yaml file.
// When filePath is empty, returns nil, nil (no suppressions active).
func Load(filePath string) (*File, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read suppression file %q: %w", filePath, err)
	}

	var f File
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("parse suppression file %q: %w", filePath, err)
		}
	}

	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("invalid suppression file %q: %w", filePath, err)
	}
	return &f, nil
}

// Validate checks every suppression entry for required fields, valid glob syntax, and valid dates.
func (f *File) Validate() error {
	if f == nil {
		return nil
	}
	for i := range f.Suppressions {
		e := &f.Suppressions[i]
		e.RuleID = strings.ToUpper(strings.TrimSpace(e.RuleID))
		e.Identity = strings.TrimSpace(e.Identity)
		e.Reason = strings.TrimSpace(e.Reason)
		e.Expires = strings.TrimSpace(e.Expires)

		if e.RuleID == "" {
			return fmt.Errorf("suppressions[%d]: rule_id is required (e.g. R3 or *)", i)
		}
		if e.Identity == "" {
			return fmt.Errorf("suppressions[%d]: identity pattern (ARN, ID, or name glob) is required", i)
		}
		if e.Reason == "" {
			return fmt.Errorf("suppressions[%d]: reason is required for audit accountability", i)
		}
		if _, err := path.Match(e.Identity, "test"); err != nil {
			return fmt.Errorf("suppressions[%d]: invalid identity glob %q: %w", i, e.Identity, err)
		}
		if e.Expires != "" {
			ts, err := parseExpiry(e.Expires)
			if err != nil {
				return fmt.Errorf("suppressions[%d]: invalid expires %q (use YYYY-MM-DD or RFC3339): %w", i, e.Expires, err)
			}
			e.expiresAt = &ts
		}
	}
	return nil
}

// Apply moves findings matching active (non-expired) suppressions from ident.Findings into
// ident.SuppressedFindings, so they remain auditable without inflating risk scores or failing --fail-on.
// Expired suppressions do NOT suppress findings and emit explicit warnings on run.Warnings.
func Apply(run *model.ScanRun, f *File, now time.Time) (int, []string) {
	if run == nil || f == nil || len(f.Suppressions) == 0 {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var (
		suppressedTotal int
		expiredSeen     = make(map[string]struct{})
		expiredWarnings []string
	)

	for i := range run.Identities {
		ident := &run.Identities[i]
		if len(ident.Findings) == 0 {
			continue
		}

		kept := make([]model.Finding, 0, len(ident.Findings))
		for _, finding := range ident.Findings {
			var matchedActive *Entry
			for j := range f.Suppressions {
				entry := &f.Suppressions[j]
				if !entry.matches(ident, finding.RuleID) {
					continue
				}
				if entry.isExpired(now) {
					warn := fmt.Sprintf("suppression expired on %s for rule %s / identity %q (reason: %s) — finding remains active",
						entry.Expires, entry.RuleID, entry.Identity, entry.Reason)
					if _, dup := expiredSeen[warn]; !dup {
						expiredSeen[warn] = struct{}{}
						expiredWarnings = append(expiredWarnings, warn)
					}
					continue
				}
				matchedActive = entry
				break
			}

			if matchedActive != nil {
				suppressedTotal++
				ident.SuppressedFindings = append(ident.SuppressedFindings, model.SuppressedFinding{
					Finding: finding,
					Reason:  matchedActive.Reason,
					Expires: matchedActive.Expires,
				})
			} else {
				kept = append(kept, finding)
			}
		}

		ident.Findings = kept
	}

	sort.Strings(expiredWarnings)
	run.SuppressedFindingCount = suppressedTotal
	if len(expiredWarnings) > 0 {
		run.Warnings = append(run.Warnings, expiredWarnings...)
		sort.Strings(run.Warnings)
	}
	return suppressedTotal, expiredWarnings
}

func (e *Entry) matches(ident *model.Identity, ruleID string) bool {
	if e.RuleID != "*" && !strings.EqualFold(e.RuleID, strings.TrimSpace(ruleID)) {
		return false
	}
	for _, candidate := range []string{ident.ID, ident.ARN, ident.Name} {
		if candidate == "" {
			continue
		}
		if candidate == e.Identity {
			return true
		}
		if ok, err := path.Match(e.Identity, candidate); err == nil && ok {
			return true
		}
	}
	return false
}

func (e *Entry) isExpired(now time.Time) bool {
	if e.expiresAt == nil {
		return false
	}
	return now.UTC().After(*e.expiresAt)
}

func parseExpiry(raw string) (time.Time, error) {
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), nil
	}
	// Date-only YYYY-MM-DD expires at the end of that UTC day (23:59:59 UTC).
	if d, err := time.Parse("2006-01-02", raw); err == nil {
		return time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized date format")
}
