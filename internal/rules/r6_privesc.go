package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// directIAMPrivescActions lists explicit IAM write actions that allow direct privilege escalation
// when granted broadly (excluding full Action:"*" and iam:* which are reported by R1).
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

// computeLaunchActions are AWS service creation/invocation actions that combine with iam:PassRole
// on Resource:"*" to form a classic PassRole privilege-escalation path.
var computeLaunchActions = []string{
	"lambda:createfunction",
	"lambda:updatefunctionconfiguration",
	"ec2:runinstances",
	"ecs:registertaskdefinition",
	"ecs:runtask",
	"bedrock:createagent",
	"bedrock:updateagent",
	"sagemaker:createnotebookinstance",
	"sagemaker:createtrainingjob",
	"codebuild:createproject",
	"glue:createdevendpoint",
	"states:createstatemachine",
}

// R6PrivilegeEscalation flags explicit IAM privilege-escalation and lateral-movement permissions:
//   - Direct IAM self-escalation actions (iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreatePolicyVersion,
//     iam:CreateAccessKey, iam:UpdateAssumeRolePolicy, etc.) on Resource:"*" (critical unconditioned / high conditioned)
//   - iam:PassRole on Resource:"*" without iam:PassedToService (high alone; critical if combined with compute/AI launch actions)
//   - sts:AssumeRole on Resource:"*" (high: unbounded role chaining)
//
// Full wildcards (AdministratorAccess, Action:"*", iam:*) are handled by R1 to avoid duplicate scoring.
type R6PrivilegeEscalation struct{}

func (R6PrivilegeEscalation) ID() string                      { return "R6" }
func (R6PrivilegeEscalation) Name() string                    { return "privilege-escalation-path" }
func (R6PrivilegeEscalation) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r R6PrivilegeEscalation) Evaluate(ident *model.Identity, _ Context) *model.Finding {
	if ident == nil || !IsNonHuman(ident) {
		return nil
	}
	if ident.Type != model.TypeRole && ident.Type != model.TypeUser {
		return nil
	}

	var (
		evidence       []string
		highestSev     model.Severity
		hasWildPass    bool
		passRoleTag    string
		passRoleConds  []string
		launchMatched  = make(map[string]struct{})
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

			// Track compute/AI launch capabilities across all policies for PassRole+Compute correlation.
			for _, launchAct := range computeLaunchActions {
				if matchesActionPattern(stmt.Actions, launchAct) {
					launchMatched[launchAct] = struct{}{}
				}
			}

			if !policy.ContainsWildcardResource(stmt.Resources) {
				continue
			}

			condKeys := collectConditionKeys(stmt.Conditions)
			conditioned := len(condKeys) > 0
			stmtTag := formatStmtTag(label, stmt.SID)

			// 1. Direct IAM write / policy-mutation escalation actions.
			var matchedDirect []string
			for _, escAct := range directIAMPrivescActions {
				if matchesActionPattern(stmt.Actions, escAct) {
					matchedDirect = append(matchedDirect, escAct)
				}
			}
			if len(matchedDirect) > 0 {
				if conditioned {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows direct IAM escalation action(s) [%s] on Resource:* (conditioned on %s; verify conditions prevent self-escalation)", stmtTag, strings.Join(matchedDirect, ", "), strings.Join(condKeys, ", ")))
				} else {
					addEvidence(model.SeverityCritical, fmt.Sprintf("%s allows unconditioned IAM privilege-escalation action(s) [%s] on Resource:*", stmtTag, strings.Join(matchedDirect, ", ")))
				}
			}

			// 2. iam:PassRole on Resource:"*" without iam:PassedToService.
			if matchesActionPattern(stmt.Actions, "iam:passrole") && !hasConditionKey(stmt.Conditions, "iam:passedtoservice") {
				hasWildPass = true
				passRoleTag = stmtTag
				passRoleConds = condKeys
			}

			// 3. sts:AssumeRole on Resource:"*" (unbounded lateral movement / role chaining).
			if matchesActionPattern(stmt.Actions, "sts:assumerole") {
				if conditioned {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows sts:AssumeRole on Resource:* (conditioned on %s; verify target roles are restricted)", stmtTag, strings.Join(condKeys, ", ")))
				} else {
					addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows unconditioned sts:AssumeRole on Resource:* (unbounded lateral movement / role chaining)", stmtTag))
				}
			}
		}
	}

	if hasWildPass {
		if len(launchMatched) > 0 {
			launches := make([]string, 0, len(launchMatched))
			for a := range launchMatched {
				launches = append(launches, a)
			}
			sort.Strings(launches)
			sev := model.SeverityCritical
			if len(passRoleConds) > 0 {
				sev = model.SeverityHigh
			}
			addEvidence(sev, fmt.Sprintf("%s allows iam:PassRole on Resource:* without iam:PassedToService combined with compute/AI launch action(s) [%s] (PassRole privilege-escalation path)", passRoleTag, strings.Join(launches, ", ")))
		} else if len(passRoleConds) > 0 {
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows iam:PassRole on Resource:* without iam:PassedToService (other conditions: %s)", passRoleTag, strings.Join(passRoleConds, ", ")))
		} else {
			addEvidence(model.SeverityHigh, fmt.Sprintf("%s allows unconditioned iam:PassRole on Resource:* (can pass privileged roles to AWS compute/AI services)", passRoleTag))
		}
	}

	if len(evidence) == 0 {
		return nil
	}

	if ident.PermissionsBoundaryARN != "" {
		evidence = append(evidence, fmt.Sprintf("note: permissions boundary %s is attached and may restrict effective escalation", ident.PermissionsBoundaryARN))
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    highestSev,
		Title:       "Non-human identity has an IAM privilege-escalation or role-chaining path",
		Explanation: "This non-human identity holds explicit IAM policy-mutation, credential-creation, unbounded iam:PassRole, or wildcard sts:AssumeRole permissions on Resource \"*\". A compromised agent or prompt injection can abuse these actions to escalate privileges or pivot into higher-privileged roles.",
		Remediation: "Remove unnecessary IAM mutation permissions from workload/agent identities; restrict iam:PassRole to exact role ARNs plus iam:PassedToService; and scope sts:AssumeRole to explicit target role ARNs. Run `nhilens explain R6` for examples.",
		Evidence:    evidence,
	}
}
