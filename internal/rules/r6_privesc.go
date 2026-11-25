package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// directIAMPrivescActions lists explicit IAM write actions that allow direct privilege escalation
// when granted broadly or against privileged/self targets (excluding full Action:"*" and iam:* owned by R1).
var directIAMPrivescActions = []string{
	"iam:createpolicyversion",
	"iam:setdefaultpolicyversion",
	"iam:attachrolepolicy",
	"iam:attachuserpolicy",
	"iam:attachgrouppolicy",
	"iam:putrolepolicy",
	"iam:putuserpolicy",
	"iam:putgrouppolicy",
	"iam:createaccesskey",
	"iam:createloginprofile",
	"iam:updateloginprofile",
	"iam:updateassumerolepolicy",
	"iam:addusertogroup",
}

// computeLaunchService maps AWS compute/AI launch actions to the service principal that receives
// a passed IAM role via iam:PassRole.
var computeLaunchService = map[string]string{
	"lambda:createfunction":             "lambda.amazonaws.com",
	"lambda:updatefunctionconfiguration": "lambda.amazonaws.com",
	"ec2:runinstances":                  "ec2.amazonaws.com",
	"ecs:registertaskdefinition":        "ecs-tasks.amazonaws.com",
	"ecs:runtask":                       "ecs-tasks.amazonaws.com",
	"bedrock:createagent":               "bedrock.amazonaws.com",
	"bedrock:updateagent":               "bedrock.amazonaws.com",
	"sagemaker:createnotebookinstance":  "sagemaker.amazonaws.com",
	"sagemaker:createtrainingjob":       "sagemaker.amazonaws.com",
	"codebuild:createproject":           "codebuild.amazonaws.com",
	"glue:createdevendpoint":            "glue.amazonaws.com",
	"states:createstatemachine":         "states.amazonaws.com",
}

// R6PrivilegeEscalation evaluates IAM privilege-escalation and lateral-movement paths with
// action-level Permissions Boundary / SCP intersection, resource ARN matching, Condition checks,
// and target-role permission & trust correlation (when target roles are present in the scanned account):
//   - Direct IAM policy/credential mutation on Resource:"*", wildcard role/user ARNs, self ARN,
//     or a privileged target role in the same account
//   - iam:PassRole evaluated with target resource ARNs, iam:PassedToService, effective compute/AI
//     launch actions, and target-role privilege profiles
//   - sts:AssumeRole evaluated with target resource ARNs, conditions, and target-role privilege
//     and trust compatibility (preventing false alarms for scoped low-privilege roles while
//     catching scoped escalation into privileged roles)
//
// Full wildcards (AdministratorAccess, Action:"*", iam:*) are handled by R1 to avoid duplicate scoring.
type R6PrivilegeEscalation struct{}

func (R6PrivilegeEscalation) ID() string                      { return "R6" }
func (R6PrivilegeEscalation) Name() string                    { return "privilege-escalation-path" }
func (R6PrivilegeEscalation) DefaultSeverity() model.Severity { return model.SeverityHigh }

type passRoleGrant struct {
	stmtTag         string
	stmt            model.PolicyStatement
	condKeys        []string
	passedToService []string
}

type assumeRoleGrant struct {
	stmtTag  string
	stmt     model.PolicyStatement
	condKeys []string
}

func (r R6PrivilegeEscalation) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil || !IsNonHuman(ident) {
		return nil
	}
	if ident.Type != model.TypeRole && ident.Type != model.TypeUser {
		return nil
	}

	var (
		evidence       []string
		highestSev     model.Severity
		passGrants     []passRoleGrant
		assumeGrants   []assumeRoleGrant
		launchServices = make(map[string][]string) // service principal -> sorted effective launch actions
		allLaunches    = make(map[string]struct{})
	)
	seen := make(map[string]struct{})
	addEvidence := func(sev model.Severity, msg string) {
		if model.SeverityRank(sev) > model.SeverityRank(highestSev) {
			highestSev = sev
		}
		if _, ok := seen[msg]; !ok {
			seen[msg] = struct{}{}
			evidence = append(evidence, msg)
		}
	}

	// Precompute effective compute/AI launch actions (respecting boundary, SCP, and explicit Deny).
	for launchAct, svcPrincipal := range computeLaunchService {
		dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, launchAct, "*")
		if dec.Allowed {
			allLaunches[launchAct] = struct{}{}
			launchServices[svcPrincipal] = append(launchServices[svcPrincipal], launchAct)
		}
	}
	for svc := range launchServices {
		sort.Strings(launchServices[svc])
	}

	// Pre-index privileged roles in the scanned account for target-role correlation.
	privTargetSummary := make(map[string]string, len(rctx.Roles))
	for _, target := range rctx.Roles {
		if target == nil || target.ARN == "" {
			continue
		}
		if isPriv, summary := evaluateRolePrivilegeProfile(target, rctx.SCPPolicies); isPriv {
			privTargetSummary[target.ARN] = summary
		}
	}

	for _, att := range ident.Policies {
		if policy.IsAdministratorAccessARN(att.ARN) {
			continue
		}
		parsed := parsePolicyLazy(att)
		if parsed == nil {
			continue
		}

		label := formatPolicyLabel(att)
		for _, stmt := range parsed.Statements {
			if stmt.Effect != "Allow" {
				continue
			}
			// Skip full wildcards already owned by R1 so AdministratorAccess / iam:* are not double-counted.
			if policy.ContainsWildcardAction(stmt.Actions) || matchesActionPattern(stmt.Actions, "iam:*") {
				continue
			}

			condKeys := collectConditionKeys(stmt.Conditions)
			stmtTag := formatStmtTag(label, stmt.SID)

			// 1. Direct IAM mutation / credential escalation actions (wildcard OR scoped to self / privileged targets).
			r.evaluateDirectIAMMutation(ident, rctx, stmt, stmtTag, condKeys, privTargetSummary, addEvidence)

			// 2. Collect iam:PassRole grants (both wildcard and concrete/scoped role ARN grants).
			if matchesActionPattern(stmt.Actions, "iam:passrole") {
				passGrants = append(passGrants, passRoleGrant{
					stmtTag:         stmtTag,
					stmt:            stmt,
					condKeys:        condKeys,
					passedToService: extractConditionValues(stmt.Conditions, "iam:passedtoservice"),
				})
			}

			// 3. Collect sts:AssumeRole grants (both wildcard and concrete/scoped role ARN grants).
			if matchesActionPattern(stmt.Actions, "sts:assumerole") {
				assumeGrants = append(assumeGrants, assumeRoleGrant{
					stmtTag:  stmtTag,
					stmt:     stmt,
					condKeys: condKeys,
				})
			}
		}
	}

	// Deep evaluation of iam:PassRole grants.
	r.evaluatePassRoleGrants(ident, rctx, passGrants, allLaunches, launchServices, privTargetSummary, addEvidence)

	// Deep evaluation of sts:AssumeRole grants.
	r.evaluateAssumeRoleGrants(ident, rctx, assumeGrants, privTargetSummary, addEvidence)

	if len(evidence) == 0 {
		return nil
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    highestSev,
		Title:       "Non-human identity has an effective IAM privilege-escalation or role-chaining path",
		Explanation: "After intersecting identity policies, explicit Denies, permissions boundaries, and provided SCPs, this non-human identity retains an actionable IAM escalation, PassRole, or privileged AssumeRole path that a compromised agent or prompt injection could abuse.",
		Remediation: "Remove unnecessary IAM mutation permissions from workload/agent identities; restrict iam:PassRole to exact low-privilege role ARNs plus iam:PassedToService; and scope sts:AssumeRole to explicit non-privileged target role ARNs. Run `nhilens explain R6` for examples.",
		Evidence:    evidence,
	}
}

func (r R6PrivilegeEscalation) evaluateDirectIAMMutation(
	ident *model.Identity,
	rctx Context,
	stmt model.PolicyStatement,
	stmtTag string,
	condKeys []string,
	privTargetSummary map[string]string,
	addEvidence func(model.Severity, string),
) {
	isBroad := isBroadIAMResource(stmt.Resources)

	// Identify concrete target ARNs if resource is scoped (self-escalation or privileged role target).
	var scopedTargets []string
	if !isBroad {
		if ident.ARN != "" && policy.StatementMatchesResource(stmt, ident.ARN) {
			scopedTargets = append(scopedTargets, ident.ARN+" (self)")
		}
		for _, target := range rctx.Roles {
			if target == nil || target.ARN == "" || target.ARN == ident.ARN {
				continue
			}
			if summary, isPriv := privTargetSummary[target.ARN]; isPriv && policy.StatementMatchesResource(stmt, target.ARN) {
				scopedTargets = append(scopedTargets, fmt.Sprintf("%s (%s)", target.Name, summary))
			}
		}
		sort.Strings(scopedTargets)
	}

	if !isBroad && len(scopedTargets) == 0 {
		return
	}

	probeResource := "*"
	if !isBroad {
		probeResource = ident.ARN
		if !policy.StatementMatchesResource(stmt, probeResource) {
			// Pick first matched concrete ARN for boundary/SCP intersection.
			for _, target := range rctx.Roles {
				if target != nil && target.ARN != "" && privTargetSummary[target.ARN] != "" && policy.StatementMatchesResource(stmt, target.ARN) {
					probeResource = target.ARN
					break
				}
			}
		}
	}

	var (
		uncondActions []string
		condActions   []string
		mergedConds   = make(map[string]struct{})
	)
	for _, k := range condKeys {
		mergedConds[k] = struct{}{}
	}

	for _, escAct := range directIAMPrivescActions {
		if !matchesActionPattern(stmt.Actions, escAct) {
			continue
		}
		dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, escAct, probeResource)
		if !dec.Allowed {
			continue
		}
		if len(condKeys) > 0 || dec.Conditioned {
			condActions = append(condActions, escAct)
			for _, k := range dec.ConditionKeys {
				mergedConds[k] = struct{}{}
			}
		} else {
			uncondActions = append(uncondActions, escAct)
		}
	}

	targetDesc := "Resource:*"
	if !isBroad {
		targetDesc = fmt.Sprintf("scoped target(s) [%s]", strings.Join(limitList(scopedTargets, 3), ", "))
	}

	if len(uncondActions) > 0 {
		addEvidence(model.SeverityCritical, fmt.Sprintf("%s allows effective unconditioned IAM privilege-escalation action(s) [%s] on %s", stmtTag, strings.Join(uncondActions, ", "), targetDesc))
	}
	if len(condActions) > 0 {
		addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows direct IAM escalation action(s) [%s] on %s (conditioned on %s; verify conditions prevent self-escalation)", stmtTag, strings.Join(condActions, ", "), targetDesc, strings.Join(sortedStringSet(mergedConds), ", ")))
	}
}

func (r R6PrivilegeEscalation) evaluatePassRoleGrants(
	ident *model.Identity,
	rctx Context,
	grants []passRoleGrant,
	allLaunches map[string]struct{},
	launchServices map[string][]string,
	privTargetSummary map[string]string,
	addEvidence func(model.Severity, string),
) {
	if len(grants) == 0 {
		return
	}

	for _, g := range grants {
		isBroad := isBroadRoleResource(g.stmt.Resources)

		// Match concrete roles in the scanned account against this PassRole statement.
		var (
			matchedPrivRoles []string
			matchedAnyRole   bool
			passablePrivWithLaunch []string
		)
		for _, target := range rctx.Roles {
			if target == nil || target.ARN == "" || target.ARN == ident.ARN {
				continue
			}
			if !policy.StatementMatchesResource(g.stmt, target.ARN) {
				continue
			}
			// Verify effective permission on this specific target role ARN (boundary + SCP + explicit Deny).
			dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, "iam:passrole", target.ARN)
			if !dec.Allowed {
				continue
			}
			matchedAnyRole = true

			summary, isPriv := privTargetSummary[target.ARN]
			if !isPriv {
				continue
			}

			// Check if iam:PassedToService restricts passing to a service that can actually assume this role.
			if len(g.passedToService) > 0 {
				compatibleSvc := compatiblePassedServices(target, g.passedToService)
				if len(compatibleSvc) == 0 {
					continue
				}
				for _, svc := range compatibleSvc {
					if acts := launchServices[svc]; len(acts) > 0 {
						passablePrivWithLaunch = append(passablePrivWithLaunch, fmt.Sprintf("%s (%s) via %s", target.Name, summary, strings.Join(acts, "/")))
					}
				}
			} else {
				for svc, acts := range launchServices {
					if len(acts) > 0 && roleCanBeAssumedByService(target, svc) {
						passablePrivWithLaunch = append(passablePrivWithLaunch, fmt.Sprintf("%s (%s) via %s", target.Name, summary, strings.Join(acts, "/")))
					}
				}
			}
			matchedPrivRoles = append(matchedPrivRoles, fmt.Sprintf("%s (%s)", target.Name, summary))
		}
		sort.Strings(matchedPrivRoles)
		sort.Strings(passablePrivWithLaunch)

		// Case A: Scoped PassRole (not wildcard) — only flag when it can pass a genuinely privileged role!
		if !isBroad {
			if len(passablePrivWithLaunch) > 0 {
				sev := model.SeverityCritical
				if hasNonPassedToServiceCondition(g.condKeys) {
					sev = model.SeverityHigh
				}
				addEvidence(sev, fmt.Sprintf("%s allows effective scoped iam:PassRole to privileged target role(s) paired with compute/AI launch: %s", g.stmtTag, strings.Join(limitList(passablePrivWithLaunch, 3), "; ")))
			} else if len(matchedPrivRoles) > 0 && len(g.passedToService) == 0 {
				addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows effective scoped iam:PassRole without iam:PassedToService to privileged target role(s): %s", g.stmtTag, strings.Join(limitList(matchedPrivRoles, 3), ", ")))
			} else if len(matchedPrivRoles) > 0 && len(allLaunches) > 0 {
				// Scoped to privileged role + PassedToService matches a launch service even if trust wasn't parsed.
				matchedLaunch := matchingLaunchesForServices(g.passedToService, launchServices)
				if len(matchedLaunch) > 0 {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows effective iam:PassRole to privileged role(s) [%s] with launch action(s) [%s]", g.stmtTag, strings.Join(limitList(matchedPrivRoles, 3), ", "), strings.Join(matchedLaunch, ", ")))
				}
			}
			// Scoped PassRole targeting only low-privilege roles (matchedAnyRole && len(matchedPrivRoles)==0) is intentionally NOT flagged.
			_ = matchedAnyRole
			continue
		}

		// Case B: Broad wildcard iam:PassRole (Resource:"*" or arn:aws:iam::*:role/*).
		dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, "iam:passrole", "*")
		if !dec.Allowed {
			// Effectively blocked by explicit Deny, attached Permissions Boundary, or SCP.
			continue
		}
		mergedConds := mergeConditionKeys(g.condKeys, dec.ConditionKeys)

		if len(g.passedToService) > 0 {
			// Even with iam:PassedToService, wildcard PassRole is dangerous if paired with a launch action
			// for that service AND a privileged target role exists in the account.
			if len(passablePrivWithLaunch) > 0 {
				addEvidence(model.SeverityCritical, fmt.Sprintf("%s allows wildcard iam:PassRole (PassedToService=%s) reaching privileged target role(s): %s", g.stmtTag, strings.Join(g.passedToService, ","), strings.Join(limitList(passablePrivWithLaunch, 3), "; ")))
			}
			continue
		}

		if len(allLaunches) > 0 {
			launches := sortedStringSet(allLaunches)
			sev := model.SeverityCritical
			if len(mergedConds) > 0 {
				sev = model.SeverityHigh
			}
			extra := ""
			if len(matchedPrivRoles) > 0 {
				extra = fmt.Sprintf("; reachable privileged target role(s): %s", strings.Join(limitList(matchedPrivRoles, 3), ", "))
			}
			addEvidence(sev, fmt.Sprintf("%s allows effective iam:PassRole on Resource:* without iam:PassedToService combined with compute/AI launch action(s) [%s] (PassRole privilege-escalation path%s)", g.stmtTag, strings.Join(launches, ", "), extra))
		} else if len(mergedConds) > 0 {
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows effective iam:PassRole on Resource:* without iam:PassedToService (other conditions: %s)", g.stmtTag, strings.Join(mergedConds, ", ")))
		} else {
			extra := ""
			if len(matchedPrivRoles) > 0 {
				extra = fmt.Sprintf("; privileged role(s) in account: %s", strings.Join(limitList(matchedPrivRoles, 3), ", "))
			}
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows unconditioned iam:PassRole on Resource:* (can pass privileged roles to AWS compute/AI services%s)", g.stmtTag, extra))
		}
	}
}

func (r R6PrivilegeEscalation) evaluateAssumeRoleGrants(
	ident *model.Identity,
	rctx Context,
	grants []assumeRoleGrant,
	privTargetSummary map[string]string,
	addEvidence func(model.Severity, string),
) {
	if len(grants) == 0 {
		return
	}

	for _, g := range grants {
		isBroad := isBroadRoleResource(g.stmt.Resources)

		var assumablePrivTargets []string
		for _, target := range rctx.Roles {
			if target == nil || target.ARN == "" || target.ARN == ident.ARN {
				continue
			}
			summary, isPriv := privTargetSummary[target.ARN]
			if !isPriv {
				continue
			}
			if !policy.StatementMatchesResource(g.stmt, target.ARN) {
				continue
			}
			dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, "sts:assumerole", target.ARN)
			if !dec.Allowed {
				continue
			}
			if roleTrustAllowsCaller(target, ident) {
				assumablePrivTargets = append(assumablePrivTargets, fmt.Sprintf("%s (%s)", target.Name, summary))
			}
		}
		sort.Strings(assumablePrivTargets)

		// Case A: Scoped sts:AssumeRole — escalate ONLY when a matched target role is actually privileged and assumable!
		if !isBroad {
			if len(assumablePrivTargets) > 0 {
				sev := model.SeverityCritical
				if len(g.condKeys) > 0 {
					sev = model.SeverityHigh
				}
				addEvidence(sev, fmt.Sprintf("%s allows effective scoped sts:AssumeRole into privileged assumable target role(s): %s", g.stmtTag, strings.Join(limitList(assumablePrivTargets, 3), ", ")))
			}
			continue
		}

		// Case B: Broad wildcard sts:AssumeRole (Resource:"*" or arn:aws:iam::*:role/*).
		dec := policy.EvaluateEffectiveAction(ident, rctx.SCPPolicies, "sts:assumerole", "*")
		if !dec.Allowed {
			continue
		}
		mergedConds := mergeConditionKeys(g.condKeys, dec.ConditionKeys)

		if len(assumablePrivTargets) > 0 {
			sev := model.SeverityCritical
			if len(mergedConds) > 0 {
				sev = model.SeverityHigh
			}
			addEvidence(sev, fmt.Sprintf("%s allows effective sts:AssumeRole on Resource:* with assumable privileged target role(s) in account: %s", g.stmtTag, strings.Join(limitList(assumablePrivTargets, 3), ", ")))
		} else if len(mergedConds) > 0 {
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows effective sts:AssumeRole on Resource:* (conditioned on %s; verify target roles are restricted)", g.stmtTag, strings.Join(mergedConds, ", ")))
		} else {
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows unconditioned sts:AssumeRole on Resource:* (unbounded lateral movement / role chaining)", g.stmtTag))
		}
	}
}

func evaluateRolePrivilegeProfile(role *model.Identity, scps []policy.NamedPolicy) (bool, string) {
	if role == nil {
		return false, ""
	}
	// 1. Effective admin wildcard?
	adminDec := policy.EvaluateEffectiveAnyAction(role, scps, []string{"iam:attachrolepolicy", "iam:putrolepolicy", "iam:createpolicyversion", "iam:updateassumerolepolicy"}, "*")
	if adminDec.Allowed {
		if role.EffectiveActions.HasAdminWildcard {
			return true, "admin wildcard"
		}
		for _, att := range role.Policies {
			if policy.IsAdministratorAccessARN(att.ARN) {
				return true, "AdministratorAccess"
			}
		}
		return true, "IAM privilege-escalation permissions"
	}
	// 2. Broad sensitive secrets/KMS/AI control plane?
	sensDec := policy.EvaluateEffectiveAnyAction(role, scps, []string{"kms:decrypt", "secretsmanager:getsecretvalue", "bedrock:createagent", "sagemaker:createnotebookinstance"}, "*")
	if sensDec.Allowed {
		return true, "broad secrets/KMS/AI permissions"
	}
	return false, ""
}

func roleCanBeAssumedByService(role *model.Identity, servicePrincipal string) bool {
	if role == nil {
		return false
	}
	// If trust principals were not populated (e.g. partial fixture), treat conservatively as possible.
	if len(role.TrustPrincipals) == 0 && strings.TrimSpace(role.TrustPolicyRaw) == "" {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(servicePrincipal))
	for _, tp := range role.TrustPrincipals {
		if tp.Type == "wildcard" {
			return true
		}
		if tp.Type == "service" && strings.EqualFold(strings.TrimSpace(tp.Value), want) {
			return true
		}
	}
	return false
}

func roleTrustAllowsCaller(target, caller *model.Identity) bool {
	if target == nil || caller == nil {
		return false
	}
	// If target has no trust policy data, do not falsely claim it's assumable when checking scoped AssumeRole
	// unless trust explicitly allows account/caller/wildcard.
	for _, tp := range target.TrustPrincipals {
		val := strings.TrimSpace(tp.Value)
		switch tp.Type {
		case "wildcard":
			return true
		case "account":
			if val == "*" || val == caller.ARN {
				return true
			}
			if caller.Account != "" {
				if val == caller.Account || val == fmt.Sprintf("arn:aws:iam::%s:root", caller.Account) ||
					val == fmt.Sprintf("arn:aws-us-gov:iam::%s:root", caller.Account) ||
					val == fmt.Sprintf("arn:aws-cn:iam::%s:root", caller.Account) {
					return true
				}
			}
		}
	}
	return false
}

func compatiblePassedServices(target *model.Identity, passedTo []string) []string {
	var out []string
	for _, svc := range passedTo {
		ls := strings.ToLower(strings.TrimSpace(svc))
		if ls == "" {
			continue
		}
		if ls == "*" || roleCanBeAssumedByService(target, ls) {
			out = append(out, ls)
		}
	}
	return out
}

func matchingLaunchesForServices(passedTo []string, launchServices map[string][]string) []string {
	seen := make(map[string]struct{})
	for _, svc := range passedTo {
		ls := strings.ToLower(strings.TrimSpace(svc))
		if ls == "*" {
			for _, acts := range launchServices {
				for _, a := range acts {
					seen[a] = struct{}{}
				}
			}
			continue
		}
		for _, a := range launchServices[ls] {
			seen[a] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

func isBroadIAMResource(resources []string) bool {
	for _, r := range resources {
		tr := strings.TrimSpace(r)
		if tr == "*" || strings.HasSuffix(tr, ":role/*") || strings.HasSuffix(tr, ":user/*") || strings.HasSuffix(tr, ":policy/*") {
			return true
		}
	}
	return false
}

func isBroadRoleResource(resources []string) bool {
	for _, r := range resources {
		tr := strings.TrimSpace(r)
		if tr == "*" || strings.HasSuffix(tr, ":role/*") {
			return true
		}
	}
	return false
}

func extractConditionValues(conditions map[string]map[string][]string, targetKey string) []string {
	want := strings.ToLower(strings.TrimSpace(targetKey))
	seen := make(map[string]struct{})
	for op, inner := range conditions {
		lowerOp := strings.ToLower(op)
		if strings.Contains(lowerOp, "not") || lowerOp == "null" {
			continue
		}
		for k, vals := range inner {
			if strings.ToLower(strings.TrimSpace(k)) != want {
				continue
			}
			for _, v := range vals {
				if tv := strings.TrimSpace(v); tv != "" {
					seen[strings.ToLower(tv)] = struct{}{}
				}
			}
		}
	}
	return sortedStringSet(seen)
}

func hasNonPassedToServiceCondition(condKeys []string) bool {
	for _, k := range condKeys {
		if !strings.EqualFold(strings.TrimSpace(k), "iam:passedtoservice") {
			return true
		}
	}
	return false
}

func mergeConditionKeys(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, k := range a {
		if k != "" {
			seen[k] = struct{}{}
		}
	}
	for _, k := range b {
		if k != "" {
			seen[k] = struct{}{}
		}
	}
	return sortedStringSet(seen)
}

func limitList(in []string, maxN int) []string {
	if len(in) <= maxN {
		return in
	}
	out := make([]string, 0, maxN+1)
	out = append(out, in[:maxN]...)
	out = append(out, fmt.Sprintf("+%d more", len(in)-maxN))
	return out
}
