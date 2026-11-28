package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// NamedTokenPattern pairs a configured literal token with its compiled delimiter-bounded regex.
type NamedTokenPattern struct {
	Token string
	Re    *regexp.Regexp
}

// Config holds optional user configuration loaded from nhilens.yaml.
type Config struct {
	AWS            AWSConfig            `yaml:"aws"`
	AgentDetection AgentDetectionConfig `yaml:"agent_detection"`
	Rules          RulesConfig          `yaml:"rules"`
	Scoring        ScoringConfig        `yaml:"scoring"`
	Output         OutputConfig         `yaml:"output"`

	compiledRolePatterns     []*regexp.Regexp
	compiledAINameTokens     []NamedTokenPattern
	compiledAINameExclusions []NamedTokenPattern
}

// AWSConfig configures default AWS SDK behavior.
type AWSConfig struct {
	Region         string   `yaml:"region"`
	Regions        []string `yaml:"regions"`
	MaxConcurrency int      `yaml:"max_concurrency"`
}

// AgentDetectionConfig configures heuristic signals used to estimate AI agent likelihood.
type AgentDetectionConfig struct {
	AgentTagKeys                []string `yaml:"agent_tag_keys"`
	AgentTagValues              []string `yaml:"agent_tag_values"`
	OwnerTagKeys                []string `yaml:"owner_tag_keys"`
	AINameTokens                []string `yaml:"ai_name_tokens"`
	AINameExclusions            []string `yaml:"ai_name_exclusions"`
	RoleNamePatterns            []string `yaml:"role_name_patterns"`
	AutomationServicePrincipals []string `yaml:"automation_service_principals"`
	OIDCProviderHints           []string `yaml:"oidc_provider_hints"`
	AIServiceNamespaces         []string `yaml:"ai_service_namespaces"`
	AIFrameworkUserAgents       []string `yaml:"ai_framework_user_agents"`
	SDKUserAgents               []string `yaml:"sdk_user_agents"`
}

// RulesConfig configures rule enablement and thresholds.
type RulesConfig struct {
	StaleDays                       int             `yaml:"stale_days"`
	KeyMaxAgeDays                   int             `yaml:"key_max_age_days"`
	MinSharedKeyIPs                 int             `yaml:"min_shared_key_ips"`
	IncludeServiceLinkedRoles       bool            `yaml:"include_service_linked_roles"`
	ConfusedDeputyServicePrincipals []string        `yaml:"confused_deputy_service_principals"`
	Enabled                         map[string]bool `yaml:"enabled"`
}

// ScoringConfig holds all scoring weights and curve parameters in one location.
type ScoringConfig struct {
	Weights               map[string]float64 `yaml:"weights"`
	AgentLikelyBonus      float64            `yaml:"agent_likely_bonus"`
	CompoundExposureBonus float64            `yaml:"compound_exposure_bonus"`
	MaxScore              float64            `yaml:"max_score"`
	SaturationScale       float64            `yaml:"saturation_scale"`
}

// OutputConfig configures default file output paths.
type OutputConfig struct {
	Dir        string `yaml:"dir"`
	DBFile     string `yaml:"db_file"`
	ReportFile string `yaml:"report_file"`
}

// Default returns a Config populated with sensible MVP defaults.
func Default() *Config {
	cfg := &Config{
		AWS: AWSConfig{
			Region:         "us-east-1",
			MaxConcurrency: 5,
		},
		AgentDetection: AgentDetectionConfig{
			AgentTagKeys: []string{
				"agent",
				"ai",
				"ai-agent",
				"workload-type",
				"automation",
			},
			AgentTagValues: []string{
				"agent",
				"ai",
				"llm",
				"mcp",
				"autonomous",
				"bot",
				"automation",
			},
			OwnerTagKeys: []string{
				"owner",
				"sponsor",
				"team",
				"maintainer",
				"created-by",
			},
			AINameTokens: []string{
				"agent",
				"agents",
				"ai",
				"llm",
				"bedrock",
				"mcp",
				"copilot",
				"rag",
				"claude",
				"gpt",
				"gemini",
				"openai",
				"anthropic",
				"langchain",
				"strands",
				"crewai",
				"autogen",
			},
			AINameExclusions: []string{
				"jenkins",
				"buildkite",
				"teamcity",
				"datadog",
				"ssm",
				"codedeploy",
				"cloudwatch",
				"splunk",
				"newrelic",
				"dynatrace",
				"grafana",
				"otel",
				"prometheus",
				"zabbix",
				"fluentd",
				"fluentbit",
				"filebeat",
				"vault",
				"consul",
				"puppet",
				"chef",
				"wazuh",
				"crowdstrike",
			},
			RoleNamePatterns: []string{
				`(?i)(^|[-_/.:])(bots?|auto|automation|pipeline|deploy|ci|cd|worker|runner)([-_/.:]|$)`,
			},
			AutomationServicePrincipals: []string{
				"lambda.amazonaws.com",
				"ecs-tasks.amazonaws.com",
				"bedrock.amazonaws.com",
				"codebuild.amazonaws.com",
				"codepipeline.amazonaws.com",
				"states.amazonaws.com",
				"sagemaker.amazonaws.com",
				"scheduler.amazonaws.com",
				"events.amazonaws.com",
			},
			OIDCProviderHints: []string{
				"token.actions.githubusercontent.com",
				"gitlab.com",
				"oidc.eks.",
				"accounts.google.com",
			},
			AIServiceNamespaces: []string{
				"bedrock",
				"bedrock-runtime",
				"bedrock-agent",
				"bedrock-agent-runtime",
				"bedrock-agentcore",
				"sagemaker",
				"sagemaker-runtime",
				"q",
				"qbusiness",
			},
			AIFrameworkUserAgents: []string{
				"langchain",
				"langgraph",
				"strands",
				"crewai",
				"autogen",
				"llamaindex",
				"mcp",
				"bedrock-agent",
				"claude",
				"anthropic",
				"openai",
			},
			SDKUserAgents: []string{
				"boto3",
				"botocore",
				"aws-sdk-",
			},
		},
		Rules: RulesConfig{
			StaleDays:       90,
			KeyMaxAgeDays:   90,
			MinSharedKeyIPs: 2,
			ConfusedDeputyServicePrincipals: []string{
				"bedrock.amazonaws.com",
				"sagemaker.amazonaws.com",
				"scheduler.amazonaws.com",
				"events.amazonaws.com",
				"codebuild.amazonaws.com",
				"codepipeline.amazonaws.com",
				"states.amazonaws.com",
				"cloudtrail.amazonaws.com",
				"delivery.logs.amazonaws.com",
				"backup.amazonaws.com",
			},
			Enabled: map[string]bool{
				"R1": true,
				"R2": true,
				"R3": true,
				"R4": true,
				"R5": true,
				"R6": true,
				"R7": true,
				"R8": true,
			},
		},
		Scoring: ScoringConfig{
			Weights: map[string]float64{
				"critical": 4.0,
				"high":     3.0,
				"medium":   2.0,
				"low":      1.0,
				"info":     0.5,
			},
			AgentLikelyBonus:      1.5,
			CompoundExposureBonus: 2.0,
			MaxScore:              10.0,
			SaturationScale:       6.5,
		},
		Output: OutputConfig{
			Dir:        "./nhilens-out",
			DBFile:     "nhilens.db",
			ReportFile: "report.html",
		},
	}
	// Default patterns are static and guaranteed valid.
	_ = cfg.Validate()
	return cfg
}

// Load reads a YAML configuration file and overlays it onto Default().
// When path is empty, Default() is returned directly.
func Load(path string) (*Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	if len(bytes.TrimSpace(raw)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}

	if cfg.Rules.KeyMaxAgeDays == 0 {
		cfg.Rules.KeyMaxAgeDays = cfg.Rules.StaleDays
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

// Validate checks configuration invariants and compiles agent role-name regexes.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.AWS.MaxConcurrency < 0 || c.AWS.MaxConcurrency > 32 {
		return fmt.Errorf("aws.max_concurrency must be between 1 and 32, got %d", c.AWS.MaxConcurrency)
	}
	if c.AWS.MaxConcurrency == 0 {
		c.AWS.MaxConcurrency = 5
	}
	if len(c.AWS.Regions) > 0 {
		seen := make(map[string]struct{}, len(c.AWS.Regions))
		cleaned := make([]string, 0, len(c.AWS.Regions))
		for _, r := range c.AWS.Regions {
			trimmed := strings.ToLower(strings.TrimSpace(r))
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			cleaned = append(cleaned, trimmed)
		}
		c.AWS.Regions = cleaned
	}
	if c.Rules.StaleDays <= 0 {
		return fmt.Errorf("rules.stale_days must be > 0, got %d", c.Rules.StaleDays)
	}
	if c.Rules.KeyMaxAgeDays <= 0 {
		return fmt.Errorf("rules.key_max_age_days must be > 0, got %d", c.Rules.KeyMaxAgeDays)
	}
	if c.Rules.MinSharedKeyIPs < 2 {
		return fmt.Errorf("rules.min_shared_key_ips must be >= 2, got %d", c.Rules.MinSharedKeyIPs)
	}
	if c.Scoring.MaxScore <= 0 {
		return fmt.Errorf("scoring.max_score must be > 0, got %v", c.Scoring.MaxScore)
	}
	if c.Scoring.SaturationScale <= 0 {
		return fmt.Errorf("scoring.saturation_scale must be > 0, got %v", c.Scoring.SaturationScale)
	}
	if c.Scoring.AgentLikelyBonus < 0 {
		return fmt.Errorf("scoring.agent_likely_bonus must be >= 0, got %v", c.Scoring.AgentLikelyBonus)
	}
	if c.Scoring.CompoundExposureBonus < 0 {
		return fmt.Errorf("scoring.compound_exposure_bonus must be >= 0, got %v", c.Scoring.CompoundExposureBonus)
	}
	for sev, w := range c.Scoring.Weights {
		if w < 0 {
			return fmt.Errorf("scoring.weights.%s must be >= 0, got %v", sev, w)
		}
	}

	compiled := make([]*regexp.Regexp, 0, len(c.AgentDetection.RoleNamePatterns))
	for _, pattern := range c.AgentDetection.RoleNamePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid agent_detection.role_name_patterns entry %q: %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	c.compiledRolePatterns = compiled

	aiTokens, err := compileTokenPatterns("agent_detection.ai_name_tokens", c.AgentDetection.AINameTokens)
	if err != nil {
		return err
	}
	c.compiledAINameTokens = aiTokens

	aiExclusions, err := compileTokenPatterns("agent_detection.ai_name_exclusions", c.AgentDetection.AINameExclusions)
	if err != nil {
		return err
	}
	c.compiledAINameExclusions = aiExclusions
	return nil
}

func compileTokenPatterns(field string, rawTokens []string) ([]NamedTokenPattern, error) {
	out := make([]NamedTokenPattern, 0, len(rawTokens))
	for _, rawTok := range rawTokens {
		tok := strings.ToLower(strings.TrimSpace(rawTok))
		if tok == "" {
			continue
		}
		expr := `(?i)(^|[-_/.:])` + regexp.QuoteMeta(tok) + `([-_/.:]|$)`
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s entry %q: %w", field, rawTok, err)
		}
		out = append(out, NamedTokenPattern{Token: tok, Re: re})
	}
	return out, nil
}

// CompiledRolePatterns returns the pre-compiled regexes for general automation role/user name heuristics.
func (c *Config) CompiledRolePatterns() []*regexp.Regexp {
	return c.compiledRolePatterns
}

// CompiledAINameTokens returns delimiter-bounded matchers for configured AI-specific name tokens.
func (c *Config) CompiledAINameTokens() []NamedTokenPattern {
	return c.compiledAINameTokens
}

// CompiledAINameExclusions returns delimiter-bounded matchers for infrastructure/CI agent prefixes
// that suppress generic "agent"/"agents" AI-name matches.
func (c *Config) CompiledAINameExclusions() []NamedTokenPattern {
	return c.compiledAINameExclusions
}

// IsRuleEnabled reports whether a rule ID (e.g. "R1") is enabled.
// Rules omitted from the Enabled map default to enabled.
func (c *Config) IsRuleEnabled(ruleID string) bool {
	if c == nil || c.Rules.Enabled == nil {
		return true
	}
	enabled, ok := c.Rules.Enabled[strings.ToUpper(strings.TrimSpace(ruleID))]
	if !ok {
		return true
	}
	return enabled
}
