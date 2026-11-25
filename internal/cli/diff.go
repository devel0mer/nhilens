package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/devel0mer/nhilens/internal/diff"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/store"
	"github.com/spf13/cobra"
)

// DiffOptions captures validated inputs for the diff subcommand.
type DiffOptions struct {
	BaseDB    string
	HeadDB    string
	BaseScan  string
	HeadScan  string
	Format    string
	FailOnNew string
}

func newDiffCmd() *cobra.Command {
	var (
		baseDB    string
		headDB    string
		baseScan  string
		headScan  string
		format    string
		failOnNew string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scans to track new/removed identities, score changes, and finding regressions",
		Long: `Compare a baseline scan against a newer head scan from two SQLite databases
(--base old.db --head new.db) or two runs inside the same database (--base nhilens.db --head nhilens.db).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := buildDiffOptions(baseDB, headDB, baseScan, headScan, format, failOnNew)
			if err != nil {
				return err
			}
			return runDiff(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&baseDB, "base", "", "Path to baseline SQLite database (required)")
	cmd.Flags().StringVar(&headDB, "head", "", "Path to head SQLite database (defaults to --base when comparing two scans in one DB)")
	cmd.Flags().StringVar(&baseScan, "base-scan", "", "Optional specific scan ID inside --base")
	cmd.Flags().StringVar(&headScan, "head-scan", "", "Optional specific scan ID inside --head")
	cmd.Flags().StringVar(&format, "format", "table", "Diff output format: table, json, or markdown")
	cmd.Flags().StringVar(&failOnNew, "fail-on-new", "", "Exit non-zero (code 2) if any new or escalated finding meets/exceeds severity (low|medium|high|critical)")

	return cmd
}

func buildDiffOptions(baseDB, headDB, baseScan, headScan, format, failOnNew string) (*DiffOptions, error) {
	b := strings.TrimSpace(baseDB)
	h := strings.TrimSpace(headDB)
	if b == "" {
		return nil, fmt.Errorf("--base SQLite database path is required")
	}
	if h == "" {
		h = b
	}

	normFormat := strings.ToLower(strings.TrimSpace(format))
	switch normFormat {
	case "table", "json", "markdown", "md":
		if normFormat == "md" {
			normFormat = "markdown"
		}
	default:
		return nil, fmt.Errorf("invalid --format %q (expected table, json, or markdown)", format)
	}

	normFailOn, err := ParseSeverity(failOnNew)
	if err != nil {
		return nil, fmt.Errorf("invalid --fail-on-new: %w", err)
	}

	return &DiffOptions{
		BaseDB:    b,
		HeadDB:    h,
		BaseScan:  strings.TrimSpace(baseScan),
		HeadScan:  strings.TrimSpace(headScan),
		Format:    normFormat,
		FailOnNew: normFailOn,
	}, nil
}

func runDiff(ctx context.Context, stdout io.Writer, opts *DiffOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var (
		baseRun *model.ScanRun
		headRun *model.ScanRun
		err     error
	)

	if opts.BaseDB == opts.HeadDB && opts.BaseScan == "" && opts.HeadScan == "" {
		// Convenience mode: compare previous scan vs latest scan in a single DB.
		if _, statErr := os.Stat(opts.BaseDB); statErr != nil {
			return fmt.Errorf("database %q not accessible: %w", opts.BaseDB, statErr)
		}
		st, openErr := store.Open(opts.BaseDB)
		if openErr != nil {
			return fmt.Errorf("open database %q: %w", opts.BaseDB, openErr)
		}
		defer st.Close()

		scans, listErr := st.ListScans(ctx)
		if listErr != nil {
			return fmt.Errorf("list scans in %q: %w", opts.BaseDB, listErr)
		}
		if len(scans) < 2 {
			return fmt.Errorf("database %q has %d scan(s); need at least 2 scans (or pass distinct --base and --head DBs)", opts.BaseDB, len(scans))
		}
		// ListScans orders newest first: scans[0] = head, scans[1] = base.
		headRun, err = st.LoadScan(ctx, scans[0].ID)
		if err != nil {
			return fmt.Errorf("load head scan %q: %w", scans[0].ID, err)
		}
		baseRun, err = st.LoadScan(ctx, scans[1].ID)
		if err != nil {
			return fmt.Errorf("load base scan %q: %w", scans[1].ID, err)
		}
	} else {
		baseRun, err = loadScanFromDB(ctx, opts.BaseDB, opts.BaseScan)
		if err != nil {
			return fmt.Errorf("load base scan: %w", err)
		}
		headRun, err = loadScanFromDB(ctx, opts.HeadDB, opts.HeadScan)
		if err != nil {
			return fmt.Errorf("load head scan: %w", err)
		}
	}

	res := diff.Compare(baseRun, headRun)

	switch opts.Format {
	case "json":
		if err := diff.WriteJSON(stdout, res); err != nil {
			return fmt.Errorf("write diff JSON: %w", err)
		}
	case "markdown":
		if err := diff.WriteMarkdown(stdout, res); err != nil {
			return fmt.Errorf("write diff markdown: %w", err)
		}
	default:
		if err := diff.WriteTable(stdout, res); err != nil {
			return fmt.Errorf("write diff table: %w", err)
		}
	}

	if exceeded, count := diff.ExceedsFailOnNew(res, opts.FailOnNew); exceeded {
		return &ExitError{
			Code: 2,
			Err:  fmt.Errorf("%d new or escalated finding(s) meet or exceed --fail-on-new=%s", count, opts.FailOnNew),
		}
	}
	return nil
}

func loadScanFromDB(ctx context.Context, dbPath, scanID string) (*model.ScanRun, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("database %q not accessible: %w", dbPath, err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", dbPath, err)
	}
	defer st.Close()

	if scanID != "" {
		return st.LoadScan(ctx, scanID)
	}
	return st.LoadLatestScan(ctx)
}
