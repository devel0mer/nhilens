package detect

import (
	"reflect"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func boolPtr(v bool) *bool          { return &v }
func timePtr(t time.Time) *time.Time { return &t }

func TestClassifyHeuristicsTable(t *testing.T) {
	cfg := config.Default()

	tests := []struct {
		name           string
		ident          model.Identity
		wantLikelihood model.AgentLikelihood
		minReasons     int
	}{
		{
			name: "human console user with unrelated tags => none",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "jane-doe",
				HasConsoleLogin: boolPtr(true),
				Tags:            map[string]string{"owner": "jane", "team": "maintainer", "contact": "email"},
			},
			wantLikelihood: model.LikelihoodNone,
			minReasons:     0,
		},
		{
			name: "explicitly falsy agent tag does not trigger => none",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "billing-readonly",
				Tags: map[string]string{"agent": "false", "ai": "no"},
			},
			wantLikelihood: model.LikelihoodNone,
			minReasons:     0,
		},
		{
			name: "substring traps special/social/decide/reboot/email/storage do not match ci/cd/bot/ai/rag => none",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "special-social-decide-reboot-email-storage",
			},
			wantLikelihood: model.LikelihoodNone,
			minReasons:     0,
		},
		{
			name: "openai-proxy matches default ai_name_tokens independently of role_name_patterns => possible ai_agent",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "openai-proxy",
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     1,
		},
		{
			name: "openai-proxy with lambda trust => likely ai_agent (25+25=50%)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "openai-proxy",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "lambda.amazonaws.com"},
				},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "rag-pipeline with lambda trust => likely ai_agent (not capped)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "rag-pipeline",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "lambda.amazonaws.com"},
				},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "gemini-bot programmatic user => likely ai_agent (ai token + programmatic key + profile)",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "gemini-bot",
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA9999999999999999"},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "delimiter-bounded ci token matches => possible",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "ci-runner",
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     1,
		},
		{
			name: "single automation trust signal => possible",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "invoice-processor",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "lambda.amazonaws.com"},
				},
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     1,
		},
		{
			name: "bedrock trust + agent role name => likely",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "bedrock-support-agent",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "bedrock.amazonaws.com"},
				},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "github actions OIDC + deploy role name (automation only, zero AI signals) => possible (capped 45%)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "gh-deploy-role",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "oidc", Value: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     2,
		},
		{
			name: "ordinary CI user with access key + ci-bot name (no AI signals) stays possible automation, NOT likely AI agent",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "ci-bot",
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA1234567890123456"},
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     2,
		},
		{
			name: "programmatic IAM user with key, no console login, and agent tag value => likely",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "svc-runner",
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA1234567890123456"},
				Tags:            map[string]string{"purpose": "mcp-runner"},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "programmatic IAM user with key and no other signals => possible",
			ident: model.Identity{
				Type:            model.TypeUser,
				Name:            "legacy-sync",
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA1234567890123456"},
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     1,
		},
		{
			name: "explicit bedrock policy permission + CloudTrail InvokeModel on generic role name => possible (ai_service)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "customer-helper-role",
				EffectiveActions: model.AllowedActionsSummary{
					Services: []string{"bedrock", "s3"},
				},
				RecentEventNames: []string{"bedrock:InvokeModel"},
			},
			wantLikelihood: model.LikelihoodPossible,
			minReasons:     2,
		},
		{
			name: "lambda trust + observed Access Advisor sagemaker activity => likely (service_trust + ai_service)",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "invoice-worker",
				TrustPrincipals: []model.TrustPrincipal{
					{Type: "service", Value: "lambda.amazonaws.com"},
				},
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "sagemaker", LastAuthenticated: timePtr(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))},
				},
			},
			wantLikelihood: model.LikelihoodLikely,
			minReasons:     2,
		},
		{
			name: "unaccessed bedrock in Access Advisor + admin wildcard alone does not falsely trigger ai_service => none",
			ident: model.Identity{
				Type: model.TypeRole,
				Name: "breakglass-admin",
				EffectiveActions: model.AllowedActionsSummary{
					HasAdminWildcard: true,
				},
				ServicesLastAccessed: []model.ServiceLastAccessed{
					{ServiceNamespace: "bedrock", LastAuthenticated: nil},
				},
			},
			wantLikelihood: model.LikelihoodNone,
			minReasons:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.ident
			Classify(&id, nil, cfg)
			if id.AgentLikelihood != tc.wantLikelihood {
				t.Errorf("AgentLikelihood = %q, want %q (reasons: %v)", id.AgentLikelihood, tc.wantLikelihood, id.AgentReasons)
			}
			if len(id.AgentReasons) < tc.minReasons {
				t.Errorf("expected at least %d reasons, got %v", tc.minReasons, id.AgentReasons)
			}
		})
	}

	// Verify AIServices, AgentConfidence, userAgent traces, and high-signal AI profiles.
	lambdaAI := model.Identity{
		Type: model.TypeRole,
		Name: "doc-summarizer",
		TrustPrincipals: []model.TrustPrincipal{
			{Type: "service", Value: "lambda.amazonaws.com"},
		},
		EffectiveActions: model.AllowedActionsSummary{
			Services: []string{"bedrock-runtime", "s3"},
		},
		RecentEventNames:   []string{"bedrock-runtime:InvokeModel"},
		ObservedUserAgents: []string{"langchain-aws/0.2 Boto3/1.35"},
	}
	Classify(&lambdaAI, nil, cfg)
	if !reflect.DeepEqual(lambdaAI.AIServices, []string{"bedrock-runtime"}) {
		t.Errorf("AIServices = %v, want [bedrock-runtime]", lambdaAI.AIServices)
	}
	if lambdaAI.AgentLikelihood != model.LikelihoodLikely || lambdaAI.AgentConfidence < 80 {
		t.Errorf("expected high confidence likely agent, got %q (%d%%) reasons=%v", lambdaAI.AgentLikelihood, lambdaAI.AgentConfidence, lambdaAI.AgentReasons)
	}
	if lambdaAI.AgentProfile != "lambda-ai-invoker" {
		t.Errorf("AgentProfile = %q, want lambda-ai-invoker", lambdaAI.AgentProfile)
	}

	// Generic Boto3 userAgent alone gives gentle confidence (15% => possible, not likely).
	botoOnly := model.Identity{
		Type:               model.TypeRole,
		Name:               "nightly-backup",
		ObservedUserAgents: []string{"Boto3/1.35.0 Python/3.12"},
	}
	Classify(&botoOnly, nil, cfg)
	if botoOnly.AgentLikelihood != model.LikelihoodPossible || botoOnly.AgentConfidence != 15 {
		t.Errorf("generic Boto3 userAgent alone = (%q, %d%%), want (possible, 15%%)", botoOnly.AgentLikelihood, botoOnly.AgentConfidence)
	}
}

func TestClassifyAllPropagatesProgrammaticSignalToKeysAndRespectsCustomConfig(t *testing.T) {
	cfg := config.Default()
	cfg.AgentDetection.AgentTagKeys = []string{"custom-ai-flag"}
	cfg.AgentDetection.RoleNamePatterns = []string{`^zorro-`}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	userARN := "arn:aws:iam::123456789012:user/zorro-worker"
	identities := []model.Identity{
		{
			ID:              userARN,
			ARN:             userARN,
			Type:            model.TypeUser,
			Name:            "zorro-worker",
			HasConsoleLogin: boolPtr(false),
			AccessKeyIDs:    []string{"AKIAZZZZ111111111111"},
		},
		{
			ID:   userARN + "/access-key/AKIAZZZZ111111111111",
			ARN:  userARN,
			Type: model.TypeKey,
			Name: "AKIAZZZZ111111111111",
			AccessKey: &model.AccessKeyInfo{
				AccessKeyID:    "AKIAZZZZ111111111111",
				ParentUserName: "zorro-worker",
				ParentUserARN:  userARN,
			},
		},
		{
			ID:   "arn:aws:iam::123456789012:role/plain-role",
			ARN:  "arn:aws:iam::123456789012:role/plain-role",
			Type: model.TypeRole,
			Name: "plain-role",
			Tags: map[string]string{"custom-ai-flag": "yes"},
		},
	}

	ClassifyAll(identities, cfg)

	if identities[0].AgentLikelihood != model.LikelihoodPossible || identities[0].WorkloadKind != WorkloadAutomation {
		t.Errorf("expected custom non-AI automation user possible/automation, got %q/%q (%d%% %v)", identities[0].AgentLikelihood, identities[0].WorkloadKind, identities[0].AgentConfidence, identities[0].AgentReasons)
	}
	if identities[1].AgentLikelihood != model.LikelihoodPossible || identities[1].WorkloadKind != WorkloadAutomation {
		t.Errorf("expected key possible/automation via parent programmatic user, got %q/%q (%v)", identities[1].AgentLikelihood, identities[1].WorkloadKind, identities[1].AgentReasons)
	}
	if identities[2].AgentLikelihood != model.LikelihoodPossible || identities[2].WorkloadKind != WorkloadAIAgent {
		t.Errorf("expected custom AI tag key role possible/ai_agent, got %q/%q (%v)", identities[2].AgentLikelihood, identities[2].WorkloadKind, identities[2].AgentReasons)
	}
}

func TestCustomAINameTokensAndExactSignalWeights(t *testing.T) {
	cfg := config.Default()
	cfg.AgentDetection.AINameTokens = append(cfg.AgentDetection.AINameTokens, "assistant")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	// Custom AI name token "assistant" lifts support-assistant out of the automation cap.
	supportAssistant := model.Identity{
		Type: model.TypeRole,
		Name: "support-assistant",
		TrustPrincipals: []model.TrustPrincipal{
			{Type: "service", Value: "lambda.amazonaws.com"},
		},
	}
	Classify(&supportAssistant, nil, cfg)
	if supportAssistant.WorkloadKind != WorkloadAIAgent || supportAssistant.AgentLikelihood != model.LikelihoodLikely || supportAssistant.AgentConfidence != 50 {
		t.Errorf("support-assistant = (%q, %q, %d%%), want (ai_agent, likely, 50%%); reasons=%v",
			supportAssistant.WorkloadKind, supportAssistant.AgentLikelihood, supportAssistant.AgentConfidence, supportAssistant.AgentReasons)
	}

	// Verify exact documented weights for generic automation tag (+20), AI tag (+35),
	// automation name (+20), AI name (+25), and programmatic user (+25).
	autoTag := model.Identity{Type: model.TypeRole, Name: "nightly-job", Tags: map[string]string{"automation": "true"}}
	Classify(&autoTag, nil, cfg)
	if autoTag.WorkloadKind != WorkloadAutomation || autoTag.AgentConfidence != 20 {
		t.Errorf("automation=true tag = (%q, %d%%), want (automation, 20%%)", autoTag.WorkloadKind, autoTag.AgentConfidence)
	}

	aiTag := model.Identity{Type: model.TypeRole, Name: "nightly-job", Tags: map[string]string{"workload-type": "support-assistant"}}
	Classify(&aiTag, nil, cfg)
	if aiTag.WorkloadKind != WorkloadAIAgent || aiTag.AgentConfidence != 35 {
		t.Errorf("workload-type=support-assistant tag = (%q, %d%%), want (ai_agent, 35%%)", aiTag.WorkloadKind, aiTag.AgentConfidence)
	}

	autoName := model.Identity{Type: model.TypeRole, Name: "batch-worker"}
	Classify(&autoName, nil, cfg)
	if autoName.WorkloadKind != WorkloadAutomation || autoName.AgentConfidence != 20 {
		t.Errorf("batch-worker = (%q, %d%%), want (automation, 20%%)", autoName.WorkloadKind, autoName.AgentConfidence)
	}

	aiName := model.Identity{Type: model.TypeRole, Name: "openai-proxy"}
	Classify(&aiName, nil, cfg)
	if aiName.WorkloadKind != WorkloadAIAgent || aiName.AgentConfidence != 25 {
		t.Errorf("openai-proxy = (%q, %d%%), want (ai_agent, 25%%)", aiName.WorkloadKind, aiName.AgentConfidence)
	}

	progUser := model.Identity{
		Type:            model.TypeUser,
		Name:            "legacy-sync",
		HasConsoleLogin: boolPtr(false),
		AccessKeyIDs:    []string{"AKIA1111222233334444"},
	}
	Classify(&progUser, nil, cfg)
	if progUser.WorkloadKind != WorkloadAutomation || progUser.AgentConfidence != 25 {
		t.Errorf("programmatic user alone = (%q, %d%%), want (automation, 25%%)", progUser.WorkloadKind, progUser.AgentConfidence)
	}
}

func TestInfrastructureAgentExclusionsPreventFalsePositives(t *testing.T) {
	cfg := config.Default()

	// Programmatic IAM users for well-known CI/monitoring/infra agents must NOT false-positive as likely AI agents.
	for _, name := range []string{"jenkins-agent", "datadog-agent", "buildkite-agent", "ssm-agent", "codedeploy-agent", "cloudwatch-agent", "teamcity-agent"} {
		t.Run(name, func(t *testing.T) {
			id := model.Identity{
				Type:            model.TypeUser,
				Name:            name,
				HasConsoleLogin: boolPtr(false),
				AccessKeyIDs:    []string{"AKIA1234567890123456"},
			}
			Classify(&id, nil, cfg)
			if id.WorkloadKind != WorkloadAutomation || id.AgentLikelihood != model.LikelihoodPossible || id.AgentConfidence != 45 {
				t.Errorf("%s = (%q, %q, %d%%), want (automation, possible, 45%%); reasons=%v",
					name, id.WorkloadKind, id.AgentLikelihood, id.AgentConfidence, id.AgentReasons)
			}
		})
	}

	// Unambiguous AI tokens still classify as ai_agent even alongside an infrastructure prefix.
	jenkinsBedrock := model.Identity{
		Type: model.TypeRole,
		Name: "jenkins-bedrock-agent",
		TrustPrincipals: []model.TrustPrincipal{
			{Type: "service", Value: "lambda.amazonaws.com"},
		},
	}
	Classify(&jenkinsBedrock, nil, cfg)
	if jenkinsBedrock.WorkloadKind != WorkloadAIAgent || jenkinsBedrock.AgentLikelihood != model.LikelihoodLikely || jenkinsBedrock.AgentConfidence != 50 {
		t.Errorf("jenkins-bedrock-agent = (%q, %q, %d%%), want (ai_agent, likely, 50%%); reasons=%v",
			jenkinsBedrock.WorkloadKind, jenkinsBedrock.AgentLikelihood, jenkinsBedrock.AgentConfidence, jenkinsBedrock.AgentReasons)
	}

	// Custom org exclusion via agent_detection.ai_name_exclusions.
	customCfg := config.Default()
	customCfg.AgentDetection.AINameExclusions = append(customCfg.AgentDetection.AINameExclusions, "acme-backup")
	if err := customCfg.Validate(); err != nil {
		t.Fatalf("customCfg.Validate: %v", err)
	}
	backupAgent := model.Identity{
		Type:            model.TypeUser,
		Name:            "acme-backup-agent",
		HasConsoleLogin: boolPtr(false),
		AccessKeyIDs:    []string{"AKIA1234567890123456"},
	}
	Classify(&backupAgent, nil, customCfg)
	if backupAgent.WorkloadKind != WorkloadAutomation || backupAgent.AgentLikelihood != model.LikelihoodPossible || backupAgent.AgentConfidence != 45 {
		t.Errorf("acme-backup-agent = (%q, %q, %d%%), want (automation, possible, 45%%); reasons=%v",
			backupAgent.WorkloadKind, backupAgent.AgentLikelihood, backupAgent.AgentConfidence, backupAgent.AgentReasons)
	}
}
