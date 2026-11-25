package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

const maxUnusedEvidenceItems = 10

// R2UnusedPermissions flags non-human roles and users with granted AWS services
// that have not been accessed within the configured stale window (default 90 days).
type R2UnusedPermissions struct{}

func (R2UnusedPermissions) ID() string                      { return "R2" }
func (R2UnusedPermissions) Name() string                    { return "unused-permissions" }
func (R2UnusedPermissions) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r R2UnusedPermissions) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil || !IsNonHuman(ident) {
		return nil
	}
	if ident.Type != model.TypeRole && ident.Type != model.TypeUser {
		return nil
	}
	// If Access Advisor data was skipped or unavailable, do not emit a false finding.
	if len(ident.ServicesLastAccessed) == 0 {
		return nil
	}

	staleDays := 90
	if rctx.Config != nil && rctx.Config.Rules.StaleDays > 0 {
		staleDays = rctx.Config.Rules.StaleDays
	}

	now := rctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-time.Duration(staleDays) * 24 * time.Hour)

	type unusedSvc struct {
		namespace string
		detail    string
	}

	var unused []unusedSvc
	for _, svc := range ident.ServicesLastAccessed {
		ns := svc.ServiceNamespace
		if ns == "" {
			ns = svc.ServiceName
		}
		if svc.LastAuthenticated == nil {
			unused = append(unused, unusedSvc{
				namespace: ns,
				detail:    fmt.Sprintf("%s (never accessed)", ns),
			})
			continue
		}
		if svc.LastAuthenticated.Before(cutoff) {
			daysAgo := int(now.Sub(*svc.LastAuthenticated).Hours() / 24)
			unused = append(unused, unusedSvc{
				namespace: ns,
				detail:    fmt.Sprintf("%s (last accessed %s, %dd ago)", ns, svc.LastAuthenticated.UTC().Format("2006-01-02"), daysAgo),
			})
		}
	}

	if len(unused) == 0 {
		return nil
	}

	sort.Slice(unused, func(i, j int) bool {
		return unused[i].namespace < unused[j].namespace
	})

	evidence := make([]string, 0, min(len(unused), maxUnusedEvidenceItems)+2)
	evidence = append(evidence, fmt.Sprintf("%d of %d granted service(s) unused within the %dd window", len(unused), len(ident.ServicesLastAccessed), staleDays))
	for i, u := range unused {
		if i >= maxUnusedEvidenceItems {
			evidence = append(evidence, fmt.Sprintf("... and %d more unused service(s)", len(unused)-maxUnusedEvidenceItems))
			break
		}
		evidence = append(evidence, u.detail)
	}

	if ident.Created != nil && ident.Created.After(cutoff) {
		ageDays := max(int(now.Sub(*ident.Created).Hours()/24), 0)
		evidence = append(evidence, fmt.Sprintf("note: identity was created %d day(s) ago (younger than the %dd stale window)", ageDays, staleDays))
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    r.DefaultSeverity(),
		Title:       fmt.Sprintf("%d granted AWS service(s) unused in the last %d days", len(unused), staleDays),
		Explanation: fmt.Sprintf("IAM Access Advisor reports %d granted AWS service(s) with no recorded authentication within the last %d days. Excess unused permissions expand blast radius if this non-human identity or AI agent is misused. (Note: Access Advisor covers the trailing 400 days and data may lag slightly.)", len(unused), staleDays),
		Remediation: "Trim attached and inline policies to remove unused AWS services and keep only the actions required by the workload.",
		Evidence:    evidence,
	}
}
