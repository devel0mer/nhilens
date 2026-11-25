package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/detect"
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
	NewClients      func(ctx context.Context, profile, region string) (collect.STSClient, collect.IAMClient, collect.CloudTrailClient, error)
	Now             func() time.Time
	CollectorHooks  func(opts *collect.Options)
	CloudTrailHooks func(opts *collect.CloudTrailOptions)
}

func defaultScanDeps() ScanDeps {
	return ScanDeps{
		NewClients: collect.NewAWSClients,
		Now:        time.Now,
	}
}

// ScanOptions captures validated inputs for the scan subcommand.
type ScanOptions struct {
	Profile                   string
	Region                    string
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

func newScanCmd(deps ScanDeps) *cobra.Command {
	var (
		profile                   string
		region                    string
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
			opts, err := buildScanOptions(
				profile, region, sinceStr, maxEvents,
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
	cmd.Flags().StringVar(&region, "region", "", "AWS region override (defaults to config or AWS SDK chain)")
	cmd.Flags().StringVar(&sinceStr, "since", "90d", "CloudTrail lookback window (e.g. 90d, 7d, 24h)")
	cmd.Flags().IntVar(&maxEvents, "max-events", 5000, "Maximum number of CloudTrail events to fetch (0 disables CloudTrail lookup)")
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
		OwnerTagKeys:            opts.Config.AgentDetection.OwnerTagKeys,
		SkipServiceLastAccessed: opts.SkipServiceLastAccessed,
		Now:                     nowFn,
	}
	if deps.CollectorHooks != nil {
		deps.CollectorHooks(&cOpts)
	}

	collector := collect.NewIAMCollector(stsClient, iamClient, cOpts)
	run, err := collector.Collect(ctx, opts.Profile, opts.Region, opts.SinceRaw)
	if err != nil {
		return err
	}

	// Enrich with best-effort CloudTrail management events before rule evaluation (powers R4 shared-key detection).
	ctOpts := collect.CloudTrailOptions{
		Since:     opts.Since,
		MaxEvents: opts.MaxEvents,
		Now:       nowFn,
	}
	if deps.CloudTrailHooks != nil {
		deps.CloudTrailHooks(&ctOpts)
	}
	collect.NewCloudTrailCollector(ctClient, ctOpts).Enrich(ctx, run)

	// Parse attached/inline/group policies and trust documents.
	if parseWarnings := policy.ParseAll(run.Identities); len(parseWarnings) > 0 {
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

	// Persist normalized results to SQLite before printing output or evaluating --fail-on.
	st, err := store.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open store %q: %w", opts.DBPath, err)
	}
	defer st.Close()

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

	resolvedRegion := strings.TrimSpace(region)
	if resolvedRegion == "" {
		resolvedRegion = cfg.AWS.Region
	}

	resolvedOutDir := strings.TrimSpace(outDir)
	if resolvedOutDir == "" {
		resolvedOutDir = cfg.Output.Dir
	}

	return &ScanOptions{
		Profile:                   strings.TrimSpace(profile),
		Region:                    resolvedRegion,
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
