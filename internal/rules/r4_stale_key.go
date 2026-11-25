package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

// R4StaleOrSharedKey flags IAM user access keys that exceed the maximum age threshold
// or appear to be used from multiple distinct source IP addresses (best-effort from CloudTrail).
type R4StaleOrSharedKey struct{}

func (R4StaleOrSharedKey) ID() string                      { return "R4" }
func (R4StaleOrSharedKey) Name() string                    { return "stale-or-shared-key" }
func (R4StaleOrSharedKey) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r R4StaleOrSharedKey) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil || ident.Type != model.TypeKey {
		return nil
	}

	maxAgeDays := 90
	minSharedIPs := 2
	if rctx.Config != nil {
		if rctx.Config.Rules.KeyMaxAgeDays > 0 {
			maxAgeDays = rctx.Config.Rules.KeyMaxAgeDays
		} else if rctx.Config.Rules.StaleDays > 0 {
			maxAgeDays = rctx.Config.Rules.StaleDays
		}
		if rctx.Config.Rules.MinSharedKeyIPs >= 2 {
			minSharedIPs = rctx.Config.Rules.MinSharedKeyIPs
		}
	}

	now := rctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var (
		isStale  bool
		isShared bool
		evidence []string
	)

	status := "Unknown"
	parentUser := ""
	if ident.AccessKey != nil {
		if ident.AccessKey.Status != "" {
			status = ident.AccessKey.Status
		}
		parentUser = ident.AccessKey.ParentUserName
	}

	if ident.Created != nil {
		age := now.Sub(*ident.Created)
		threshold := time.Duration(maxAgeDays) * 24 * time.Hour
		if age > threshold {
			isStale = true
			ageDays := int(age.Hours() / 24)
			lastUsedDesc := "never used"
			if ident.LastUsed != nil {
				lastUsedDesc = fmt.Sprintf("last used %s", ident.LastUsed.UTC().Format("2006-01-02"))
			}
			evidence = append(evidence, fmt.Sprintf("access key %s (user %q, status=%s) is %d days old (threshold %dd; created %s; %s)",
				ident.Name, parentUser, status, ageDays, maxAgeDays, ident.Created.UTC().Format("2006-01-02"), lastUsedDesc))
		}
	}

	distinctIPs := extractDistinctIPs(ident.SourceIPs)
	if len(distinctIPs) >= minSharedIPs {
		isShared = true
		shown := distinctIPs
		suffix := ""
		if len(shown) > 10 {
			suffix = fmt.Sprintf(" (+%d more)", len(shown)-10)
			shown = shown[:10]
		}
		evidence = append(evidence, fmt.Sprintf("best-effort CloudTrail attribution observed %d distinct source IPs (threshold %d): %s%s (note: NAT gateways, corporate proxies, or ephemeral runners can also produce multiple IPs)",
			len(distinctIPs), minSharedIPs, strings.Join(shown, ", "), suffix))
	}

	if !isStale && !isShared {
		return nil
	}

	var title, explanation string
	switch {
	case isStale && isShared:
		title = "Long-lived IAM access key is stale and used from multiple source IPs (best-effort)"
		explanation = fmt.Sprintf("This IAM access key exceeds the %d-day age threshold and was observed from %d distinct source IP addresses in CloudTrail (best-effort). Long-lived static credentials shared across hosts or agents are hard to revoke and audit.", maxAgeDays, len(distinctIPs))
	case isStale:
		title = fmt.Sprintf("IAM access key exceeds %d-day age threshold", maxAgeDays)
		explanation = fmt.Sprintf("This static IAM access key is older than %d days. Long-lived access keys increase the exposure window if embedded in agent prompts, config files, or CI environments.", maxAgeDays)
	default:
		title = "IAM access key used from multiple distinct source IPs (best-effort)"
		explanation = fmt.Sprintf("Best-effort CloudTrail attribution observed this access key from %d distinct source IP addresses, suggesting the static credential may be shared across multiple machines, developers, or agents (note: dynamic egress IPs or NAT pools can also trigger this signal).", len(distinctIPs))
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    r.DefaultSeverity(),
		Title:       title,
		Explanation: explanation,
		Remediation: "Prefer short-lived STS credentials via IAM roles (OIDC, EC2/ECS/Lambda task roles) instead of static IAM access keys. If a key is still required, rotate it, issue one key per workload, and delete inactive or stale keys.",
		Evidence:    evidence,
	}
}

// extractDistinctIPs filters to valid IPv4/IPv6 addresses (excluding CloudTrail service hostnames
// such as "AWS Internal" or "s3.amazonaws.com") and returns a sorted deduplicated slice.
func extractDistinctIPs(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if addr, err := netip.ParseAddr(s); err == nil {
			seen[addr.Unmap().String()] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
