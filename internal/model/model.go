package model

import (
	"sort"
	"strings"
	"time"
)

// IdentityType distinguishes the three normalized non-human identity kinds.
type IdentityType string

const (
	TypeRole IdentityType = "role"
	TypeUser IdentityType = "user"
	TypeKey  IdentityType = "key"
)

// AgentLikelihood represents a heuristic estimate of whether an identity is an AI agent or automation.
type AgentLikelihood string

const (
	LikelihoodNone     AgentLikelihood = "none"
	LikelihoodPossible AgentLikelihood = "possible"
	LikelihoodLikely   AgentLikelihood = "likely"
)

// Severity represents finding severity levels.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityRank returns an ordinal value for comparing severities (higher is more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// CloudTrailStatus describes whether CloudTrail attribution data was collected.
const (
	CloudTrailStatusUnknown  = "unknown"
	CloudTrailStatusOK       = "ok"
	CloudTrailStatusPartial  = "partial"
	CloudTrailStatusDisabled = "disabled"
)

// CoverageStatus reports whether all expected enrichment checks succeeded for a scan or identity.
const (
	CoverageStatusComplete = "complete"
	CoverageStatusPartial  = "partial"
)

// RegionCloudTrailCoverage records per-region CloudTrail LookupEvents coverage and errors.
type RegionCloudTrailCoverage struct {
	Region         string `json:"region"`
	Status         string `json:"status"` // ok | partial | unknown | disabled
	EventsAnalyzed int    `json:"events_analyzed"`
	Truncated      bool   `json:"truncated,omitempty"`
	Error          string `json:"error,omitempty"`
}

// ScanCoverage summarizes data completeness, scope, skipped checks, and collection errors
// so partial scans are never mistaken for "zero findings".
type ScanCoverage struct {
	Status                       string                     `json:"status"` // complete | partial
	AccountID                    string                     `json:"account_id"`
	Region                       string                     `json:"region"`
	RegionsScanned               []string                   `json:"regions_scanned,omitempty"`
	SinceWindow                  string                     `json:"since_window"`
	CloudTrailStatus             string                     `json:"cloudtrail_status"`
	CloudTrailEventsAnalyzed     int                        `json:"cloudtrail_events_analyzed"`
	CloudTrailEventLimit         int                        `json:"cloudtrail_event_limit"`
	CloudTrailTruncated          bool                       `json:"cloudtrail_truncated,omitempty"`
	CloudTrailRegions            []RegionCloudTrailCoverage `json:"cloudtrail_regions,omitempty"`
	LoginProfileChecked          int                        `json:"login_profile_checked"`
	LoginProfileFailed           int                        `json:"login_profile_failed"`
	AccessKeyListFailed          int                        `json:"access_key_list_failed"`
	AccessKeyLastUsedFailed      int                        `json:"access_key_last_used_failed"`
	AccessAdvisorSkipped         bool                       `json:"access_advisor_skipped"`
	AccessAdvisorAttempted       int                        `json:"access_advisor_attempted"`
	AccessAdvisorSucceeded       int                        `json:"access_advisor_succeeded"`
	AccessAdvisorFailed          int                        `json:"access_advisor_failed"`
	AccessAdvisorSkippedSLR      int                        `json:"access_advisor_skipped_slr,omitempty"`
	AccessAdvisorSkippedNoPolicy int                        `json:"access_advisor_skipped_no_policy,omitempty"`
	ServiceLinkedRolesExcluded   int                        `json:"service_linked_roles_excluded"`
	PolicyParseErrors            int                        `json:"policy_parse_errors"`
	SCPPoliciesLoaded            int                        `json:"scp_policies_loaded"`
	PartialIdentities            int                        `json:"partial_identities"`
	SkippedChecks                []string                   `json:"skipped_checks,omitempty"`
	CollectionErrorCount         int                        `json:"collection_error_count"`
}

// ScanRun represents a single read-only audit run against an AWS account.
type ScanRun struct {
	ID                     string        `json:"id"`
	AccountID              string        `json:"account_id"`
	CallerARN              string        `json:"caller_arn"`
	Region                 string        `json:"region"`
	Regions                []string      `json:"regions,omitempty"`
	Profile                string        `json:"profile,omitempty"`
	StartedAt              time.Time     `json:"started_at"`
	CompletedAt            time.Time     `json:"completed_at"`
	SinceWindow            string        `json:"since_window"`
	CloudTrailStatus       string        `json:"cloudtrail_status"`
	CloudTrailEventCount   int           `json:"cloudtrail_event_count"`
	SuppressedFindingCount int           `json:"suppressed_finding_count,omitempty"`
	Coverage               *ScanCoverage `json:"coverage,omitempty"`
	Warnings               []string      `json:"warnings,omitempty"`
	Identities             []Identity    `json:"identities"`
}

// Identity is the normalized audit record for a single IAM role, IAM user, or access key.
type Identity struct {
	ID                       string                `json:"id"`
	ARN                      string                `json:"arn"`
	Type                     IdentityType          `json:"type"`
	Name                     string                `json:"name"`
	Path                     string                `json:"path,omitempty"`
	IsServiceLinkedRole      bool                  `json:"is_service_linked_role,omitempty"`
	PermissionsBoundaryARN   string                `json:"permissions_boundary_arn,omitempty"`
	PermissionsBoundaryDoc   string                `json:"permissions_boundary_doc,omitempty"`
	Account                  string                `json:"account"`
	Created                  *time.Time            `json:"created,omitempty"`
	LastUsed                 *time.Time            `json:"last_used,omitempty"`
	Tags                     map[string]string     `json:"tags,omitempty"`
	Owner                    *string               `json:"owner"`
	HasConsoleLogin          *bool                 `json:"has_console_login,omitempty"`
	Groups                   []string              `json:"groups,omitempty"`
	AccessKey                *AccessKeyInfo        `json:"access_key,omitempty"`
	AccessKeyIDs             []string              `json:"access_key_ids,omitempty"`
	ActiveAccessKeyIDs       []string              `json:"active_access_key_ids,omitempty"`
	TrustPolicyRaw           string                `json:"trust_policy_raw,omitempty"`
	TrustPrincipals          []TrustPrincipal      `json:"trust_principals,omitempty"`
	Policies                 []PolicyAttachment    `json:"policies,omitempty"`
	EffectiveActions         AllowedActionsSummary `json:"effective_actions"`
	ServicesLastAccessed     []ServiceLastAccessed `json:"services_last_accessed,omitempty"`
	ServiceLastAccessedError string                `json:"service_last_accessed_error,omitempty"`
	CoverageStatus           string                `json:"coverage_status,omitempty"` // complete | partial
	DataGaps                 []string              `json:"data_gaps,omitempty"`
	SourceIPs                []string              `json:"source_ips,omitempty"`
	CloudTrailStatus         string                `json:"cloudtrail_status"`
	CloudTrailEventCount     int                   `json:"cloudtrail_event_count,omitempty"`
	RecentEventNames         []string              `json:"recent_event_names,omitempty"`
	ObservedUserAgents       []string              `json:"observed_user_agents,omitempty"`
	Activity30d              *ActivitySummary      `json:"activity_30d,omitempty"`
	AgentLikelihood          AgentLikelihood       `json:"agent_likelihood"`
	AgentConfidence          int                   `json:"agent_confidence,omitempty"`
	WorkloadKind             string                `json:"workload_kind,omitempty"` // ai_agent | automation
	AgentProfile             string                `json:"agent_profile,omitempty"`
	AgentReasons             []string              `json:"agent_reasons,omitempty"`
	AIServices               []string              `json:"ai_services,omitempty"`
	Findings                 []Finding             `json:"findings,omitempty"`
	SuppressedFindings       []SuppressedFinding   `json:"suppressed_findings,omitempty"`
	RawRiskPoints            float64               `json:"raw_risk_points,omitempty"`
	RiskScore                float64               `json:"risk_score"`
	ScoreExplanation         string                `json:"score_explanation,omitempty"`
	ScoreContributions       []ScoreContribution   `json:"score_contributions,omitempty"`
}

// AccessKeyInfo holds access-key-specific metadata for TypeKey identities.
type AccessKeyInfo struct {
	AccessKeyID     string `json:"access_key_id"`
	ParentUserName  string `json:"parent_user_name"`
	ParentUserARN   string `json:"parent_user_arn"`
	Status          string `json:"status"`
	LastUsedService string `json:"last_used_service,omitempty"`
	LastUsedRegion  string `json:"last_used_region,omitempty"`
}

// TrustPrincipal describes a principal allowed to assume a role along with conditions.
type TrustPrincipal struct {
	Type       string                         `json:"type"`
	Value      string                         `json:"value"`
	Actions    []string                       `json:"actions,omitempty"`
	Conditions map[string]map[string][]string `json:"conditions,omitempty"`
}

// PolicyAttachment links a raw (and later parsed) IAM policy document to an identity.
type PolicyAttachment struct {
	Name        string        `json:"name"`
	ARN         string        `json:"arn,omitempty"`
	Kind        string        `json:"kind"` // managed | inline | group_managed | group_inline
	SourceGroup string        `json:"source_group,omitempty"`
	RawDocument string        `json:"raw_document,omitempty"`
	Parsed      *ParsedPolicy `json:"parsed,omitempty"`
}

// ParsedPolicy is the normalized representation of an IAM JSON policy document.
type ParsedPolicy struct {
	Version    string            `json:"version,omitempty"`
	Statements []PolicyStatement `json:"statements,omitempty"`
}

// PolicyStatement represents one IAM statement with normalized slice fields.
type PolicyStatement struct {
	SID          string                         `json:"sid,omitempty"`
	Effect       string                         `json:"effect"`
	Actions      []string                       `json:"actions,omitempty"`
	NotActions   []string                       `json:"not_actions,omitempty"`
	Resources    []string                       `json:"resources,omitempty"`
	NotResources []string                       `json:"not_resources,omitempty"`
	Conditions   map[string]map[string][]string `json:"conditions,omitempty"`
}

// AllowedActionsSummary summarizes actions granted by attached/inline/group identity policies.
// Note: this is an identity-policy upper bound only; it does not evaluate AWS Organizations SCPs,
// permissions boundaries (captured separately in PermissionsBoundaryARN), resource-based policies,
// or session policies.
type AllowedActionsSummary struct {
	HasAdminWildcard      bool     `json:"has_admin_wildcard"`
	WildcardServices      []string `json:"wildcard_services,omitempty"`
	Services              []string `json:"services,omitempty"`
	TotalStatements       int      `json:"total_statements"`
	AllowStatements       int      `json:"allow_statements"`
	DenyStatements        int      `json:"deny_statements"`
	ConditionedStatements int      `json:"conditioned_statements"`
}

// ServiceLastAccessed records AWS Access Advisor service usage for an IAM role or user.
type ServiceLastAccessed struct {
	ServiceName             string     `json:"service_name"`
	ServiceNamespace        string     `json:"service_namespace"`
	LastAuthenticated       *time.Time `json:"last_authenticated,omitempty"`
	LastAuthenticatedRegion string     `json:"last_authenticated_region,omitempty"`
	LastAuthenticatedEntity string     `json:"last_authenticated_entity,omitempty"`
}

// Finding represents a single triggered risk rule against an identity.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation"`
	Evidence    []string `json:"evidence,omitempty"`
}

// SuppressedFinding records a finding intentionally accepted via a .nhilens-ignore.yaml baseline entry.
type SuppressedFinding struct {
	Finding
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
}

// ActivitySummary summarizes an identity's observed CloudTrail management activity over a recent window.
type ActivitySummary struct {
	WindowDays  int             `json:"window_days"`
	TotalEvents int             `json:"total_events"`
	TopServices []ActivityCount `json:"top_services,omitempty"`
	TopAPIs     []ActivityCount `json:"top_apis,omitempty"`
}

// ActivityCount pairs a service or API name with its observed CloudTrail event count.
type ActivityCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// ScoreContribution explains how one finding or heuristic bonus contributed to RiskScore.
type ScoreContribution struct {
	Source string  `json:"source"`
	Points float64 `json:"points"`
}

// EffectiveRegions returns the deduplicated list of AWS regions covered by this scan.
func (r *ScanRun) EffectiveRegions() []string {
	if r == nil {
		return nil
	}
	if len(r.Regions) > 0 {
		return r.Regions
	}
	if r.Coverage != nil && len(r.Coverage.RegionsScanned) > 0 {
		return r.Coverage.RegionsScanned
	}
	if reg := strings.TrimSpace(r.Region); reg != "" {
		return []string{reg}
	}
	return nil
}

// AddDataGap records a unique, sorted data-collection gap on an identity and marks it partial.
func (id *Identity) AddDataGap(gap string) {
	if id == nil {
		return
	}
	g := strings.TrimSpace(gap)
	if g == "" {
		return
	}
	for _, existing := range id.DataGaps {
		if existing == g {
			id.CoverageStatus = CoverageStatusPartial
			return
		}
	}
	id.DataGaps = append(id.DataGaps, g)
	sort.Strings(id.DataGaps)
	id.CoverageStatus = CoverageStatusPartial
}
