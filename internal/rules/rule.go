package rules

import (
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// Context provides read-only configuration, optional SCP guardrails, same-account role index,
// and reference clock to risk rules.
type Context struct {
	Config      *config.Config
	Now         time.Time
	SCPPolicies []policy.NamedPolicy
	Roles       []*model.Identity
}

// Rule is the common interface implemented by every risk check.
// Adding a new rule requires adding one implementation file, registering it in DefaultRules, and adding unit tests.
type Rule interface {
	ID() string
	Name() string
	DefaultSeverity() model.Severity
	Evaluate(ident *model.Identity, rctx Context) *model.Finding
}

// DefaultRules returns the registered risk rules in canonical order (R1–R8).
func DefaultRules() []Rule {
	return []Rule{
		R1WildcardPermissions{},
		R2UnusedPermissions{},
		R3NoOwner{},
		R4StaleOrSharedKey{},
		R5LooseTrust{},
		R6PrivilegeEscalation{},
		R7SensitiveServiceWildcard{},
		R8KeyHygiene{},
	}
}

// EvaluateAll runs enabled rules across every identity and populates ident.Findings.
// AWS service-linked roles (/aws-service-role/) are skipped unless cfg.Rules.IncludeServiceLinkedRoles is true.
func EvaluateAll(identities []model.Identity, cfg *config.Config, now time.Time, rules ...Rule) {
	EvaluateAllWithContext(identities, Context{Config: cfg, Now: now}, rules...)
}

// EvaluateAllWithContext runs enabled rules using an explicit Context (supporting optional SCP policies).
func EvaluateAllWithContext(identities []model.Identity, rctx Context, rules ...Rule) {
	if rctx.Config == nil {
		rctx.Config = config.Default()
	}
	if rctx.Now.IsZero() {
		rctx.Now = time.Now().UTC()
	} else {
		rctx.Now = rctx.Now.UTC()
	}
	if len(rules) == 0 {
		rules = DefaultRules()
	}

	if len(rctx.Roles) == 0 {
		roles := make([]*model.Identity, 0)
		for i := range identities {
			if identities[i].Type == model.TypeRole {
				roles = append(roles, &identities[i])
			}
		}
		rctx.Roles = roles
	}

	activeRules := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if rctx.Config.IsRuleEnabled(r.ID()) {
			activeRules = append(activeRules, r)
		}
	}

	for i := range identities {
		ident := &identities[i]
		ident.Findings = nil

		if ident.IsServiceLinkedRole && !rctx.Config.Rules.IncludeServiceLinkedRoles {
			continue
		}

		for _, r := range activeRules {
			if finding := r.Evaluate(ident, rctx); finding != nil {
				ident.Findings = append(ident.Findings, *finding)
			}
		}
	}
}

// IsNonHuman reports whether an identity should be audited as a non-human / machine identity.
//   - IAM roles and access keys are always treated as non-human identities.
//   - IAM users are treated as non-human if they lack a console login profile, hold access keys,
//     have agent-detection signals, or if console-login status could not be determined.
//   - Console-only IAM users with no access keys and no agent signals are treated as human users.
func IsNonHuman(ident *model.Identity) bool {
	if ident == nil {
		return false
	}
	switch ident.Type {
	case model.TypeRole, model.TypeKey:
		return true
	case model.TypeUser:
		if ident.HasConsoleLogin == nil || !*ident.HasConsoleLogin {
			return true
		}
		if len(ident.AccessKeyIDs) > 0 {
			return true
		}
		if ident.AgentLikelihood != "" && ident.AgentLikelihood != model.LikelihoodNone {
			return true
		}
		return false
	default:
		return false
	}
}
