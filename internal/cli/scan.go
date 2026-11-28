package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/detect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
	"github.com/devel0mer/nhilens/internal/report"
	"github.com/devel0mer/nhilens/internal/rules"
	"github.com/devel0mer/nhilens/internal/score"
	"github.com/devel0mer/nhilens/internal/store"
	"github.com/devel0mer/nhilens/internal/suppress"
	"github.com/spf13/cobra"
)

// ScanDeps injects external AWS clients and clock hooks so nhilens scan can be tested end-to-end without AWS calls.
type ScanDeps struct {
	NewClients          func(ctx context.Context, profile, region string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error)
	NewCloudTrailClient func(ctx context.Context, profile, region string) (collect.CloudTrailClient, error)
	Now                 func() time.Time
	CollectorHooks      func(opts *collect.Options)
	CloudTrailHooks     func(opts *collect.CloudTrailOptions)
}

func defaultScanDeps() ScanDeps {
	return ScanDeps{
		NewClients:          collect.NewAWSClients,
		NewCloudTrailClient: collect.NewCloudTrailClientForRegion,
		Now:                 time.Now,
	}
}

// ScanOptions captures validated inputs for the scan subcommand.
type ScanOptions struct {
	Profile                   string
	Region                    string
	Regions                   []string
	Since                     time.Duration
	SinceRaw                  string
	MaxEvents                 int
	SkipServiceLastAccessed   bool
	IncludeServiceLinkedRoles bool
	IgnoreFile                string
	SCPFile                   string
	Config                    *config.Config
	OutDir                    string
	DBPath                    string
	Format                    string
	FailOn                    string
}

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

func newScanCmd(deps ScanDeps) *cobra.Command {
	var (
		profile                   string
		region                    string
		regions                   []string
		sinceStr                  string
		maxEvents                 int
		skipServiceLastAccessed   bool
		includeServiceLinkedRoles bool
		ignoreFile                string
		scpFile                   string
		configPath                string
		outDir                    string
		format                    string
		failOn                    string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan an AWS account (read-only) and persist findings to SQLite",
		Long: `Collect IAM inventory, access key metadata, service last-accessed data,
and CloudTrail management events from an AWS account using strictly read-only
APIs, score non-human identities, persist results to SQLite, and print a ranked
summary.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := buildScanOptionsWithRegions(
				profile, region, cmd.Flags().Changed("region"),
				regions,
				sinceStr, maxEvents,
				skipServiceLastAccessed,
				includeServiceLinkedRoles,
				cmd.Flags().Changed("include-service-linked-roles"),
				ignoreFile,
				scpFile,
				configPath, outDir, format, failOn,
			)
			if err != nil {
				return err
			}
			return runScan(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS shared configuration/credentials profile name")
	cmd.Flags().StringVar(&region, "region", "", "Primary AWS region override (defaults to config or AWS SDK chain)")
	cmd.Flags().StringSliceVar(&regions, "regions", nil, "Comma-separated AWS regions for multi-region CloudTrail lookup, or 'all' for the 17 default-enabled AWS regions")
	cmd.Flags().StringVar(&sinceStr, "since", "90d", "CloudTrail lookback window (e.g. 90d, 7d, 24h)")
	cmd.Flags().IntVar(&maxEvents, "max-events", 5000, "Maximum number of CloudTrail events to fetch per region (0 disables CloudTrail lookup)")
	cmd.Flags().BoolVar(&skipServiceLastAccessed, "skip-service-last-accessed", false, "Skip IAM Access Advisor service last-accessed jobs (faster on large accounts; skips R2)")
	cmd.Flags().BoolVar(&includeServiceLinkedRoles, "include-service-linked-roles", false, "Evaluate risk rules against AWS service-linked roles (/aws-service-role/)")
	cmd.Flags().StringVar(&ignoreFile, "ignore", "", "Path to optional .nhilens-ignore.yaml baseline/suppression file")
	cmd.Flags().StringVar(&scpFile, "scp-file", "", "Path to optional AWS Organizations SCP JSON file for effective-permission guardrail intersection")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to optional nhilens.yaml configuration file")
	cmd.Flags().StringVar(&outDir, "out", "", "Output directory for SQLite database and scan artifacts")
	cmd.Flags().StringVar(&format, "format", "table", "Console output format: table, json, sarif, markdown, or csv")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit non-zero if any finding meets or exceeds severity (low|medium|high|critical)")

	return cmd
}

func runScan(ctx context.Context, stdout io.Writer, opts *ScanOptions, deps ScanDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.NewClients == nil {
		deps.NewClients = collect.NewAWSClients
	}
	nowFn := deps.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	// Load and validate suppression and optional SCP files before hitting AWS so typos fail fast.
	suppFile, err := suppress.Load(opts.IgnoreFile)
	if err != nil {
		return err
	}
	scpPolicies, err := policy.LoadSCPFile(opts.SCPFile)
	if err != nil {
		return err
	}

	stsClient, iamClient, ctClient, err := deps.NewClients(ctx, opts.Profile, opts.Region)
	if err != nil {
		return err
	}

	cOpts := collect.Options{
		OwnerTagKeys:              opts.Config.AgentDetection.OwnerTagKeys,
		MaxConcurrency:            opts.Config.AWS.MaxConcurrency,
		SkipServiceLastAccessed:   opts.SkipServiceLastAccessed,
		IncludeServiceLinkedRoles: opts.IncludeServiceLinkedRoles,
		Now:                       nowFn,
	}
	if deps.CollectorHooks != nil {
		deps.CollectorHooks(&cOpts)
	}

	collector := collect.NewIAMCollector(stsClient, iamClient, cOpts)
	run, err := collector.Collect(ctx, opts.Profile, opts.Region, opts.SinceRaw)
	if err != nil {
		return err
	}

	// Enrich with best-effort CloudTrail management events across all configured regions
	// before rule evaluation (powers R4 cross-region shared-key detection and AI userAgent traces).
	ctOpts := collect.CloudTrailOptions{
		Since:          opts.Since,
		MaxEvents:      opts.MaxEvents,
		MaxConcurrency: opts.Config.AWS.MaxConcurrency,
		Now:            nowFn,
	}
	if deps.CloudTrailHooks != nil {
		deps.CloudTrailHooks(&ctOpts)
	}

	targetRegions := opts.Regions
	if len(targetRegions) == 0 {
		targetRegions = []string{opts.Region}
	}
	ctFactory := deps.NewCloudTrailClient
	if ctFactory == nil {
		ctFactory = collect.NewCloudTrailClientForRegion
	}
	regionClients := make([]collect.RegionCloudTrailClient, 0, len(targetRegions))
	for _, r := range targetRegions {
		if r == opts.Region || len(targetRegions) == 1 {
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: ctClient})
			continue
		}
		if opts.MaxEvents == 0 {
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: nil})
			continue
		}
		regionalCT, ctErr := ctFactory(ctx, opts.Profile, r)
		if ctErr != nil {
			run.Warnings = append(run.Warnings, fmt.Sprintf("[%s] failed to initialize CloudTrail client: %v", r, ctErr))
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: nil})
			continue
		}
		regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: regionalCT})
	}
	collect.EnrichRegions(ctx, regionClients, ctOpts, run)

	// Parse attached/inline/group policies and trust documents.
	parseWarnings := policy.ParseAll(run.Identities)
	if len(parseWarnings) > 0 {
		run.Warnings = append(run.Warnings, parseWarnings...)
		sort.Strings(run.Warnings)
	}

	nowUTC := nowFn().UTC()

	// Run heuristic agent classification, enabled risk rules (with boundary & optional SCP intersection),
	// optional baseline suppressions, and scoring.
	detect.ClassifyAll(run.Identities, opts.Config)
	rules.EvaluateAllWithContext(run.Identities, rules.Context{
		Config:      opts.Config,
		Now:         nowUTC,
		SCPPolicies: scpPolicies,
	})
	if suppFile != nil {
		suppress.Apply(run, suppFile, nowUTC)
	}
	score.ScoreAll(run.Identities, opts.Config)
	finalizeScanCoverage(run, opts, len(scpPolicies), len(parseWarnings))

	// Persist normalized results to SQLite before printing output or evaluating --fail-on.
	st, err := store.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open store %q: %w", opts.DBPath, err)
	}
	defer func() { _ = st.Close() }()

	if err := st.SaveScan(ctx, run); err != nil {
		return fmt.Errorf("save scan to %q: %w", opts.DBPath, err)
	}

	switch opts.Format {
	case "json":
		if err := WriteScanJSON(stdout, run); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}
	case "sarif":
		if err := report.WriteSARIF(stdout, run); err != nil {
			return fmt.Errorf("write SARIF output: %w", err)
		}
	case "markdown":
		if err := report.WriteMarkdown(stdout, run); err != nil {
			return fmt.Errorf("write Markdown output: %w", err)
		}
	case "csv":
		if err := report.WriteCSV(stdout, run); err != nil {
			return fmt.Errorf("write CSV output: %w", err)
		}
	default:
		if err := WriteScanTable(stdout, run, opts.DBPath); err != nil {
			return fmt.Errorf("write table output: %w", err)
		}
	}

	if exceeded, count := score.ExceedsFailOn(run.Identities, opts.FailOn); exceeded {
		return &ExitError{
			Code: 2,
			Err:  fmt.Errorf("%d finding(s) meet or exceed --fail-on=%s", count, opts.FailOn),
		}
	}

	return nil
}

func finalizeScanCoverage(run *model.ScanRun, opts *ScanOptions, scpCount, parseErrCount int) {
	if run == nil {
		return
	}
	if run.Coverage == nil {
		run.Coverage = &model.ScanCoverage{}
	}
	cov := run.Coverage
	cov.AccountID = run.AccountID
	cov.Region = run.Region
	if len(run.Regions) > 0 {
		cov.RegionsScanned = run.Regions
	} else if len(cov.RegionsScanned) == 0 && strings.TrimSpace(run.Region) != "" {
		cov.RegionsScanned = []string{run.Region}
	}
	cov.SinceWindow = run.SinceWindow
	cov.CloudTrailStatus = run.CloudTrailStatus
	cov.CloudTrailEventsAnalyzed = run.CloudTrailEventCount
	if opts != nil {
		cov.CloudTrailEventLimit = opts.MaxEvents
		cov.AccessAdvisorSkipped = opts.SkipServiceLastAccessed
	}
	cov.PolicyParseErrors = parseErrCount
	cov.SCPPoliciesLoaded = scpCount

	var skipped []string
	if opts != nil {
		if opts.SkipServiceLastAccessed {
			skipped = append(skipped, "Access Advisor / R2 (--skip-service-last-accessed)")
		}
		if opts.MaxEvents == 0 {
			skipped = append(skipped, "CloudTrail attribution (--max-events=0)")
		}
		if opts.Config != nil {
			for _, meta := range rules.Catalog() {
				if !opts.Config.IsRuleEnabled(meta.ID) {
					skipped = append(skipped, fmt.Sprintf("%s (%s) disabled in config", meta.ID, meta.Name))
				}
			}
		}
	}

	slrExcluded := 0
	partialCount := 0
	for i := range run.Identities {
		id := &run.Identities[i]
		if id.IsServiceLinkedRole && (opts == nil || !opts.IncludeServiceLinkedRoles) {
			slrExcluded++
		}
		if len(id.DataGaps) > 0 {
			id.CoverageStatus = model.CoverageStatusPartial
			partialCount++
		} else {
			id.CoverageStatus = model.CoverageStatusComplete
		}
	}
	if slrExcluded > 0 {
		skipped = append(skipped, fmt.Sprintf("%d AWS service-linked role(s) excluded by default", slrExcluded))
	}
	cov.ServiceLinkedRolesExcluded = slrExcluded
	cov.PartialIdentities = partialCount
	cov.SkippedChecks = skipped
	ctRegionErrors := 0
	for _, rc := range cov.CloudTrailRegions {
		if rc.Error != "" {
			ctRegionErrors++
		}
	}
	cov.CollectionErrorCount = cov.LoginProfileFailed +
		cov.AccessKeyListFailed +
		cov.AccessKeyLastUsedFailed +
		cov.AccessAdvisorFailed +
		cov.PolicyParseErrors +
		ctRegionErrors

	isPartial := cov.CollectionErrorCount > 0 ||
		cov.PartialIdentities > 0 ||
		cov.AccessAdvisorSkipped ||
		cov.CloudTrailTruncated ||
		cov.CloudTrailStatus == model.CloudTrailStatusPartial ||
		cov.CloudTrailStatus == model.CloudTrailStatusUnknown ||
		cov.CloudTrailStatus == model.CloudTrailStatusDisabled
	if isPartial {
		cov.Status = model.CoverageStatusPartial
	} else {
		cov.Status = model.CoverageStatusComplete
	}
}

func buildScanOptions(
	profile, region, sinceStr string,
	maxEvents int,
	skipServiceLastAccessed bool,
	includeServiceLinkedRoles bool,
	includeSLRFlagSet bool,
	ignoreFile string,
	scpFile string,
	configPath, outDir, format, failOn string,
) (*ScanOptions, error) {
	return buildScanOptionsWithRegions(
		profile, region, strings.TrimSpace(region) != "",
		nil,
		sinceStr, maxEvents,
		skipServiceLastAccessed,
		includeServiceLinkedRoles,
		includeSLRFlagSet,
		ignoreFile, scpFile, configPath, outDir, format, failOn,
	)
}

func buildScanOptionsWithRegions(
	profile, region string,
	regionFlagSet bool,
	regionsFlag []string,
	sinceStr string,
	maxEvents int,
	skipServiceLastAccessed bool,
	includeServiceLinkedRoles bool,
	includeSLRFlagSet bool,
	ignoreFile string,
	scpFile string,
	configPath, outDir, format, failOn string,
) (*ScanOptions, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	if includeSLRFlagSet {
		cfg.Rules.IncludeServiceLinkedRoles = includeServiceLinkedRoles
	}

	since, err := ParseDuration(sinceStr)
	if err != nil {
		return nil, fmt.Errorf("invalid --since: %w", err)
	}
	if maxEvents < 0 {
		return nil, fmt.Errorf("invalid --max-events: must be >= 0, got %d", maxEvents)
	}

	normFormat := strings.ToLower(strings.TrimSpace(format))
	switch normFormat {
	case "table", "json", "sarif", "markdown", "md", "csv":
		if normFormat == "md" {
			normFormat = "markdown"
		}
	default:
		return nil, fmt.Errorf("invalid --format %q (expected table, json, sarif, markdown, or csv)", format)
	}

	normFailOn, err := ParseSeverity(failOn)
	if err != nil {
		return nil, fmt.Errorf("invalid --fail-on: %w", err)
	}

	resolvedRegion, resolvedRegions, err := resolveRegions(region, regionFlagSet, regionsFlag, cfg)
	if err != nil {
		return nil, err
	}

	resolvedOutDir := strings.TrimSpace(outDir)
	if resolvedOutDir == "" {
		resolvedOutDir = cfg.Output.Dir
	}

	return &ScanOptions{
		Profile:                   strings.TrimSpace(profile),
		Region:                    resolvedRegion,
		Regions:                   resolvedRegions,
		Since:                     since,
		SinceRaw:                  strings.TrimSpace(sinceStr),
		MaxEvents:                 maxEvents,
		SkipServiceLastAccessed:   skipServiceLastAccessed,
		IncludeServiceLinkedRoles: cfg.Rules.IncludeServiceLinkedRoles,
		IgnoreFile:                strings.TrimSpace(ignoreFile),
		SCPFile:                   strings.TrimSpace(scpFile),
		Config:                    cfg,
		OutDir:                    resolvedOutDir,
		DBPath:                    filepath.Join(resolvedOutDir, cfg.Output.DBFile),
		Format:                    normFormat,
		FailOn:                    normFailOn,
	}, nil
}

func resolveRegions(regionFlag string, regionFlagSet bool, regionsFlag []string, cfg *config.Config) (string, []string, error) {
	rawRegion := strings.ToLower(strings.TrimSpace(regionFlag))
	if rawRegion != "" && !awsRegionPattern.MatchString(rawRegion) {
		return "", nil, fmt.Errorf("invalid --region %q (expected AWS region like us-east-1)", regionFlag)
	}

	// 1. Explicit --regions flag takes precedence for multi-region CloudTrail lookup.
	if len(regionsFlag) > 0 {
		expanded, err := expandAndValidateRegions(regionsFlag)
		if err != nil {
			return "", nil, err
		}
		if regionFlagSet && rawRegion != "" {
			if !containsString(expanded, rawRegion) {
				expanded = append([]string{rawRegion}, expanded...)
			}
			return rawRegion, expanded, nil
		}
		return expanded[0], expanded, nil
	}

	// 2. Explicit --region flag targets a single region (overrides aws.regions in config).
	if regionFlagSet && rawRegion != "" {
		return rawRegion, []string{rawRegion}, nil
	}

	// 3. Fallback to aws.regions in nhilens.yaml if configured.
	if cfg != nil && len(cfg.AWS.Regions) > 0 {
		expanded, err := expandAndValidateRegions(cfg.AWS.Regions)
		if err != nil {
			return "", nil, fmt.Errorf("invalid aws.regions in config: %w", err)
		}
		return expanded[0], expanded, nil
	}

	// 4. Default to aws.region from config (or us-east-1).
	primary := rawRegion
	if primary == "" && cfg != nil {
		primary = strings.ToLower(strings.TrimSpace(cfg.AWS.Region))
	}
	if primary == "" {
		primary = "us-east-1"
	}
	return primary, []string{primary}, nil
}

func expandAndValidateRegions(raw []string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	add := func(r string) {
		if _, ok := seen[r]; ok {
			return
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}

	for _, entry := range raw {
		for _, part := range strings.Split(entry, ",") {
			tok := strings.ToLower(strings.TrimSpace(part))
			if tok == "" {
				continue
			}
			if tok == "all" {
				for _, defReg := range collect.DefaultEnabledAWSRegions {
					add(defReg)
				}
				continue
			}
			if !awsRegionPattern.MatchString(tok) {
				return nil, fmt.Errorf("invalid region %q in --regions (expected AWS region like us-east-1 or 'all')", part)
			}
			add(tok)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid --regions: must specify at least one AWS region or 'all'")
	}
	return out, nil
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}
