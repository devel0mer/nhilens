package detect

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

const (
	// WorkloadAIAgent indicates at least one AI/LLM-specific signal was observed.
	WorkloadAIAgent = "ai_agent"
	// WorkloadAutomation indicates non-human/CI/service automation signals without AI-specific evidence.
	WorkloadAutomation = "automation"

	// maxAutomationOnlyConfidence caps agent_confidence when ONLY generic automation signals match
	// (no AI-specific tags, AI name tokens, AI service trusts/usage, or AI framework userAgents).
	// This prevents ordinary CI/CD users or roles from false-positiving as "likely" AI agents.
	maxAutomationOnlyConfidence = 45
)

// ClassifyAll evaluates heuristic AI-agent/automation signals across a slice of normalized identities.
// Passing the full slice allows TypeKey identities to incorporate their parent user's console-login status.
func ClassifyAll(identities []model.Identity, cfg *config.Config) {
	if cfg == nil {
		cfg = config.Default()
	}

	usersByARN := make(map[string]*model.Identity)
	for i := range identities {
		if identities[i].Type == model.TypeUser {
			usersByARN[identities[i].ARN] = &identities[i]
		}
	}

	for i := range identities {
		var parentUser *model.Identity
		if identities[i].Type == model.TypeKey && identities[i].AccessKey != nil {
			parentUser = usersByARN[identities[i].AccessKey.ParentUserARN]
		}
		Classify(&identities[i], parentUser, cfg)
	}
}

// Classify computes a weighted 0–100 heuristic AgentConfidence score, classifies WorkloadKind
// ("ai_agent" vs "automation"), derives AgentLikelihood (none=0, possible=1..49, likely=50..100),
// identifies optional high-signal AgentProfiles, populates AIServices, and lists AgentReasons.
//
// Important false-positive guardrail:
//   - General automation signals alone (e.g., programmatic IAM user with access keys + "ci-bot"
//     name, or GitHub Actions OIDC + "deploy" name) set WorkloadKind="automation" and cap
//     AgentConfidence at 45% (AgentLikelihood="possible") rather than falsely claiming "likely" AI agent.
//   - Reaching AgentLikelihood="likely" (>= 50%) requires at least one AI-specific signal
//     (AI tag, AI name token, Bedrock/SageMaker trust, AI/LLM service permission/usage, or
//     AI framework CloudTrail userAgent).
func Classify(ident *model.Identity, parentUser *model.Identity, cfg *config.Config) {
	if ident == nil {
		return
	}
	if cfg == nil {
		cfg = config.Default()
	}

	var (
		reasons    []string
		confidence int

		hasAISignal     bool
		hasAutoSignal   bool
		hasTag          bool
		hasName         bool
		hasBedrockTrust bool
		hasLambdaTrust  bool
		hasOIDCTrust    bool
		hasProgUser     bool
		hasMCPOrFWTrace bool
	)

	aiTokenPatterns := cfg.CompiledAINameTokens()

	// 1. Configured tag key / tag value signals (+35 AI-specific, +20 generic automation).
	tagReasons, tagIsAI := matchTagSignals(ident.Tags, cfg.AgentDetection.AgentTagKeys, cfg.AgentDetection.AgentTagValues, aiTokenPatterns)
	if len(tagReasons) > 0 {
		hasTag = true
		if tagIsAI {
			hasAISignal = true
			confidence += 35
		} else {
			hasAutoSignal = true
			confidence += 20
		}
		reasons = append(reasons, tagReasons...)
		for _, r := range tagReasons {
			lr := strings.ToLower(r)
			if strings.Contains(lr, "mcp") || strings.Contains(lr, "langchain") || strings.Contains(lr, "claude") {
				hasMCPOrFWTrace = true
			}
		}
	}

	// 2. Configured AI name tokens (+25, AI-specific) and general automation name regexes (+20).
	// AI name tokens are evaluated independently so tokens like openai, rag, gemini, or custom
	// entries (e.g. support-assistant) work without duplicating them into role_name_patterns.
	// Known infrastructure/CI/observability prefixes in ai_name_exclusions (e.g. jenkins-agent,
	// datadog-agent, ssm-agent) suppress generic "agent"/"agents" AI attribution and downgrade
	// them to general automation (+20, subject to the 45% automation cap).
	nameToCheck := ident.Name
	if ident.Type == model.TypeKey && ident.AccessKey != nil && ident.AccessKey.ParentUserName != "" {
		nameToCheck = ident.AccessKey.ParentUserName
	}
	matchedExclusion := ""
	for _, ex := range cfg.CompiledAINameExclusions() {
		if ex.Re.MatchString(nameToCheck) {
			matchedExclusion = ex.Token
			break
		}
	}
	excludedGenericAgent := false
	seenAITokens := make(map[string]struct{})
	var matchedAITokens []string
	for _, ntp := range aiTokenPatterns {
		if ntp.Re.MatchString(nameToCheck) {
			if _, dup := seenAITokens[ntp.Token]; dup {
				continue
			}
			seenAITokens[ntp.Token] = struct{}{}
			if matchedExclusion != "" && (ntp.Token == "agent" || ntp.Token == "agents") {
				excludedGenericAgent = true
				continue
			}
			if !hasName {
				hasName = true
				hasAISignal = true
				confidence += 25
			}
			matchedAITokens = append(matchedAITokens, fmt.Sprintf("%q", ntp.Token))
		}
	}
	if len(matchedAITokens) == 1 {
		reasons = append(reasons, fmt.Sprintf("name %q contains configured AI name token %s", nameToCheck, matchedAITokens[0]))
	} else if len(matchedAITokens) > 1 {
		reasons = append(reasons, fmt.Sprintf("name %q contains configured AI name tokens %s (counted once)", nameToCheck, strings.Join(matchedAITokens, ", ")))
	}
	if !hasName && excludedGenericAgent {
		hasName = true
		hasAutoSignal = true
		confidence += 20
		reasons = append(reasons, fmt.Sprintf("name %q matched infrastructure exclusion %q (treated as automation, not AI agent)", nameToCheck, matchedExclusion))
	}
	var matchedRolePatterns []string
	for _, re := range cfg.CompiledRolePatterns() {
		if re.MatchString(nameToCheck) {
			if !hasName {
				hasName = true
				hasAutoSignal = true
				confidence += 20
			}
			matchedRolePatterns = append(matchedRolePatterns, fmt.Sprintf("%q", re.String()))
		}
	}
	if len(matchedRolePatterns) == 1 {
		reasons = append(reasons, fmt.Sprintf("name %q matches configured pattern %s", nameToCheck, matchedRolePatterns[0]))
	} else if len(matchedRolePatterns) > 1 {
		reasons = append(reasons, fmt.Sprintf("name %q matches configured patterns %s (counted once)", nameToCheck, strings.Join(matchedRolePatterns, ", ")))
	}
	lowerName := strings.ToLower(nameToCheck)
	if strings.Contains(lowerName, "mcp") || strings.Contains(lowerName, "langchain") || strings.Contains(lowerName, "claude") {
		hasMCPOrFWTrace = true
	}

	// 3. Trust relationship signals (automation service principals and OIDC provider hints).
	autoPrincipals := toLowerSet(cfg.AgentDetection.AutomationServicePrincipals)
	oidcHints := make([]string, 0, len(cfg.AgentDetection.OIDCProviderHints))
	for _, h := range cfg.AgentDetection.OIDCProviderHints {
		if lh := strings.ToLower(strings.TrimSpace(h)); lh != "" {
			oidcHints = append(oidcHints, lh)
		}
	}

	seenTrustReasons := make(map[string]struct{})
	serviceTrustPoints := 0
	oidcTrustPoints := 0
	for _, tp := range ident.TrustPrincipals {
		lowerVal := strings.ToLower(strings.TrimSpace(tp.Value))
		switch tp.Type {
		case "service":
			if _, ok := autoPrincipals[lowerVal]; ok {
				msg := fmt.Sprintf("trust policy allows automation service principal %s", tp.Value)
				if _, dup := seenTrustReasons[msg]; !dup {
					seenTrustReasons[msg] = struct{}{}
					reasons = append(reasons, msg)
				}
				pts := 25
				if lowerVal == "bedrock.amazonaws.com" || lowerVal == "sagemaker.amazonaws.com" {
					pts = 35
					hasAISignal = true
					if lowerVal == "bedrock.amazonaws.com" {
						hasBedrockTrust = true
					}
				} else {
					hasAutoSignal = true
				}
				if lowerVal == "lambda.amazonaws.com" {
					hasLambdaTrust = true
				}
				if pts > serviceTrustPoints {
					serviceTrustPoints = pts
				}
			}
		case "oidc", "federated":
			for _, hint := range oidcHints {
				if strings.Contains(lowerVal, hint) {
					msg := fmt.Sprintf("trust policy federates with OIDC/workload provider matching %q (%s)", hint, tp.Value)
					if _, dup := seenTrustReasons[msg]; !dup {
						seenTrustReasons[msg] = struct{}{}
						reasons = append(reasons, msg)
					}
					hasOIDCTrust = true
					hasAutoSignal = true
					oidcTrustPoints = 25
					break
				}
			}
		}
	}
	confidence += serviceTrustPoints + oidcTrustPoints

	// 4. Programmatic IAM user heuristic: access key(s) present and no console login profile.
	// Treated as a general automation/non-human signal (not an AI-specific signal by itself).
	if ident.Type == model.TypeUser {
		if ident.HasConsoleLogin != nil && !*ident.HasConsoleLogin && len(ident.AccessKeyIDs) > 0 {
			hasProgUser = true
			hasAutoSignal = true
			confidence += 25
			reasons = append(reasons, fmt.Sprintf("IAM user has %d access key(s) and no console login profile (automation signal)", len(ident.AccessKeyIDs)))
		}
	} else if ident.Type == model.TypeKey && parentUser != nil {
		if parentUser.HasConsoleLogin != nil && !*parentUser.HasConsoleLogin {
			hasProgUser = true
			hasAutoSignal = true
			confidence += 25
			reasons = append(reasons, fmt.Sprintf("access key belongs to programmatic IAM user %q with no console login profile (automation signal)", parentUser.Name))
		}
	}

	// 5. AWS AI/LLM service capability & runtime activity signals (policies, Access Advisor, CloudTrail).
	aiServices, aiPoints, aiReasons := matchAIServiceSignals(ident, cfg.AgentDetection.AIServiceNamespaces)
	ident.AIServices = aiServices
	if aiPoints > 0 {
		hasAISignal = true
		confidence += aiPoints
		reasons = append(reasons, aiReasons...)
	}

	// 6. CloudTrail userAgent traces (AI frameworks vs generic AWS SDKs).
	uaPoints, uaHasFramework, uaReasons := matchUserAgentSignals(
		ident.ObservedUserAgents,
		cfg.AgentDetection.AIFrameworkUserAgents,
		cfg.AgentDetection.SDKUserAgents,
	)
	if uaPoints > 0 {
		confidence += uaPoints
		reasons = append(reasons, uaReasons...)
		if uaHasFramework {
			hasAISignal = true
			hasMCPOrFWTrace = true
		} else {
			hasAutoSignal = true
		}
	}

	// 7. High-signal profile correlation.
	profile := detectAgentProfile(hasBedrockTrust, hasLambdaTrust, hasOIDCTrust, hasProgUser, hasMCPOrFWTrace, hasTag || hasName, aiServices, ident.RecentEventNames)
	ident.AgentProfile = profile
	if profile != "" && confidence > 0 {
		if hasAISignal {
			confidence += 10
		}
		reasons = append(reasons, fmt.Sprintf("matched profile %q", profile))
	}

	// Distinguish AI-agent workloads from general CI/service automation so ordinary CI/CD users
	// or roles without any AI-specific evidence do not false-positive as "likely" AI agents.
	switch {
	case hasAISignal:
		ident.WorkloadKind = WorkloadAIAgent
	case hasAutoSignal:
		ident.WorkloadKind = WorkloadAutomation
		if confidence > maxAutomationOnlyConfidence {
			confidence = maxAutomationOnlyConfidence
		}
	default:
		ident.WorkloadKind = ""
	}

	if confidence > 100 {
		confidence = 100
	}

	ident.AgentConfidence = confidence
	ident.AgentReasons = reasons
	switch {
	case confidence == 0:
		ident.AgentLikelihood = model.LikelihoodNone
	case confidence < 50:
		ident.AgentLikelihood = model.LikelihoodPossible
	default:
		ident.AgentLikelihood = model.LikelihoodLikely
	}
}

func detectAgentProfile(
	hasBedrockTrust, hasLambdaTrust, hasOIDCTrust, hasProgUser, hasMCPOrFWTrace, hasTagOrName bool,
	aiServices []string,
	recentEvents []string,
) string {
	hasBedrockSvc := false
	for _, s := range aiServices {
		if strings.HasPrefix(s, "bedrock") {
			hasBedrockSvc = true
			break
		}
	}
	invokesBedrock := false
	for _, ev := range recentEvents {
		lev := strings.ToLower(ev)
		if strings.HasPrefix(lev, "bedrock") && (strings.Contains(lev, "invoke") || strings.Contains(lev, "converse")) {
			invokesBedrock = true
			break
		}
	}

	switch {
	case hasBedrockTrust && (hasBedrockSvc || hasTagOrName):
		return "bedrock-agent"
	case hasLambdaTrust && (hasBedrockSvc || invokesBedrock):
		return "lambda-ai-invoker"
	case hasMCPOrFWTrace && (len(aiServices) > 0 || hasTagOrName || hasProgUser || hasLambdaTrust || hasBedrockTrust):
		return "mcp-or-framework-agent"
	case hasOIDCTrust && hasTagOrName:
		return "ci-oidc-automation"
	case hasProgUser && (len(aiServices) > 0 || hasTagOrName):
		return "programmatic-key-bot"
	default:
		return ""
	}
}

func matchAIServiceSignals(ident *model.Identity, configured []string) ([]string, int, []string) {
	if len(configured) == 0 {
		return nil, 0, nil
	}
	aiSet := toLowerSet(configured)

	granted := make(map[string]struct{})
	observed := make(map[string]struct{})
	allAI := make(map[string]struct{})

	for _, svc := range ident.EffectiveActions.Services {
		ls := strings.ToLower(strings.TrimSpace(svc))
		if _, ok := aiSet[ls]; ok {
			granted[ls] = struct{}{}
			allAI[ls] = struct{}{}
		}
	}

	for _, sla := range ident.ServicesLastAccessed {
		if sla.LastAuthenticated == nil {
			continue
		}
		ns := strings.ToLower(strings.TrimSpace(sla.ServiceNamespace))
		if _, ok := aiSet[ns]; ok {
			observed[ns] = struct{}{}
			allAI[ns] = struct{}{}
		}
	}

	for _, evName := range ident.RecentEventNames {
		prefix, _, hasColon := strings.Cut(strings.ToLower(strings.TrimSpace(evName)), ":")
		if !hasColon {
			continue
		}
		if _, ok := aiSet[prefix]; ok {
			observed[prefix] = struct{}{}
			allAI[prefix] = struct{}{}
		}
	}

	var (
		reasons []string
		points  int
	)
	if len(granted) > 0 {
		reasons = append(reasons, fmt.Sprintf("policies explicitly grant AI/LLM service permission(s): %s", strings.Join(sortedSet(granted), ", ")))
	}
	if len(observed) > 0 {
		reasons = append(reasons, fmt.Sprintf("observed runtime activity in AI/LLM service(s): %s", strings.Join(sortedSet(observed), ", ")))
	}
	switch {
	case len(granted) > 0 && len(observed) > 0:
		points = 45
	case len(observed) > 0:
		points = 35
	case len(granted) > 0:
		points = 30
	}
	return sortedSet(allAI), points, reasons
}

func matchUserAgentSignals(observed, frameworkHints, sdkHints []string) (int, bool, []string) {
	if len(observed) == 0 {
		return 0, false, nil
	}

	fwHits := make(map[string]struct{})
	sdkHits := make(map[string]struct{})

	for _, ua := range observed {
		lua := strings.ToLower(ua)
		for _, hint := range frameworkHints {
			lh := strings.ToLower(strings.TrimSpace(hint))
			if lh != "" && strings.Contains(lua, lh) {
				fwHits[lh] = struct{}{}
			}
		}
		for _, hint := range sdkHints {
			lh := strings.ToLower(strings.TrimSpace(hint))
			if lh != "" && strings.Contains(lua, lh) {
				sdkHits[lh] = struct{}{}
			}
		}
	}

	var reasons []string
	if len(fwHits) > 0 {
		reasons = append(reasons, fmt.Sprintf("CloudTrail userAgent matches AI framework trace(s): %s", strings.Join(sortedSet(fwHits), ", ")))
		return 40, true, reasons
	}
	if len(sdkHits) > 0 {
		reasons = append(reasons, fmt.Sprintf("CloudTrail userAgent matches programmatic AWS SDK trace(s): %s", strings.Join(sortedSet(sdkHits), ", ")))
		return 15, false, reasons
	}
	return 0, false, nil
}

func matchTagSignals(tags map[string]string, agentKeys, agentValues []string, aiTokenPatterns []config.NamedTokenPattern) ([]string, bool) {
	if len(tags) == 0 {
		return nil, false
	}

	keySet := toLowerSet(agentKeys)
	valSet := toLowerSet(agentValues)

	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var (
		reasons []string
		isAI    bool
	)
	for _, k := range keys {
		v := strings.TrimSpace(tags[k])
		lk := strings.ToLower(strings.TrimSpace(k))
		lv := strings.ToLower(v)

		if _, ok := keySet[lk]; ok {
			if isExplicitlyFalsy(lv) {
				continue
			}
			reasons = append(reasons, fmt.Sprintf("tag %s=%q matches configured agent tag key", k, v))
			if lk != "automation" && lk != "workload-type" {
				isAI = true
			} else if isAITokenInString(lv, aiTokenPatterns) {
				isAI = true
			}
			continue
		}

		for _, tok := range tokenize(lv) {
			if _, ok := valSet[tok]; ok {
				reasons = append(reasons, fmt.Sprintf("tag %s=%q contains configured agent token %q", k, v, tok))
				if tok != "automation" && tok != "bot" {
					isAI = true
				}
				break
			}
		}
	}

	return reasons, isAI
}

func isAITokenInString(lowerVal string, aiTokenPatterns []config.NamedTokenPattern) bool {
	for _, ntp := range aiTokenPatterns {
		if ntp.Re.MatchString(lowerVal) {
			return true
		}
	}
	for _, tok := range tokenize(lowerVal) {
		if tok == "autonomous" {
			return true
		}
	}
	return false
}

func isExplicitlyFalsy(lowerVal string) bool {
	switch lowerVal {
	case "", "false", "0", "no", "none", "off":
		return true
	default:
		return false
	}
}

func tokenize(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func toLowerSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		if s := strings.ToLower(strings.TrimSpace(item)); s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

func sortedSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
