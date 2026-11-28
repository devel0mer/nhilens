package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/devel0mer/nhilens/internal/demo"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/report"
	"github.com/devel0mer/nhilens/internal/store"
	"github.com/spf13/cobra"
)

// DemoOptions captures validated inputs for the offline demo subcommand.
type DemoOptions struct {
	OutDir  string
	DBPath  string
	HTMLOut string
	Format  string
	NoWrite bool
	Org     bool
}

func newDemoCmd() *cobra.Command {
	var (
		outDir  string
		format  string
		noWrite bool
		org     bool
	)

	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run a 60-second offline demo on a synthetic AWS account or org (no AWS credentials needed)",
		Long: `Run the full nhilens classification, risk rule evaluation (R1–R8), scoring,
SQLite persistence, and offline HTML report pipeline on a realistic synthetic
sandbox account (111122223333) — or a 3-account, 2-region synthetic AWS
Organization with --org — with zero AWS API calls and zero credentials.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := buildDemoOptions(outDir, format, noWrite, org)
			if err != nil {
				return err
			}
			return runDemo(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "./nhilens-demo", "Output directory for the synthetic SQLite database and HTML report")
	cmd.Flags().StringVar(&format, "format", "table", "Console output format: table, json, sarif, markdown, or csv")
	cmd.Flags().BoolVar(&noWrite, "no-write", false, "Print console output only without writing nhilens.db or report.html")
	cmd.Flags().BoolVar(&org, "org", false, "Simulate a 3-account, 2-region AWS Organizations rollup demo")

	return cmd
}

func buildDemoOptions(outDir, format string, noWrite, org bool) (*DemoOptions, error) {
	normFormat := strings.ToLower(strings.TrimSpace(format))
	switch normFormat {
	case "table", "json", "sarif", "markdown", "md", "csv":
		if normFormat == "md" {
			normFormat = "markdown"
		}
	default:
		return nil, fmt.Errorf("invalid --format %q (expected table, json, sarif, markdown, or csv)", format)
	}

	resolvedOut := strings.TrimSpace(outDir)
	if resolvedOut == "" {
		resolvedOut = "./nhilens-demo"
	}

	return &DemoOptions{
		OutDir:  resolvedOut,
		DBPath:  filepath.Join(resolvedOut, "nhilens.db"),
		HTMLOut: filepath.Join(resolvedOut, "report.html"),
		Format:  normFormat,
		NoWrite: noWrite,
		Org:     org,
	}, nil
}

func runDemo(ctx context.Context, stdout io.Writer, opts *DemoOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var run *model.ScanRun
	if opts.Org {
		run = demo.BuildSyntheticOrgRun()
	} else {
		run = demo.BuildSyntheticRun()
	}
	dbPath := ""
	htmlPath := ""

	if !opts.NoWrite {
		st, err := store.Open(opts.DBPath)
		if err != nil {
			return fmt.Errorf("open demo store %q: %w", opts.DBPath, err)
		}
		saveErr := st.SaveScan(ctx, run)
		closeErr := st.Close()
		if saveErr != nil {
			return fmt.Errorf("save demo scan to %q: %w", opts.DBPath, saveErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close demo store %q: %w", opts.DBPath, closeErr)
		}
		dbPath = opts.DBPath

		f, err := os.OpenFile(opts.HTMLOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("create demo HTML report %q: %w", opts.HTMLOut, err)
		}
		writeErr := report.WriteHTML(f, run)
		fCloseErr := f.Close()
		if writeErr != nil {
			return fmt.Errorf("write demo HTML report: %w", writeErr)
		}
		if fCloseErr != nil {
			return fmt.Errorf("close demo HTML report %q: %w", opts.HTMLOut, fCloseErr)
		}
		htmlPath = opts.HTMLOut
	}

	switch opts.Format {
	case "json":
		return WriteScanJSON(stdout, run)
	case "sarif":
		return report.WriteSARIF(stdout, run)
	case "markdown":
		return report.WriteMarkdown(stdout, run)
	case "csv":
		return report.WriteCSV(stdout, run)
	default:
		if err := WriteScanTable(stdout, run, dbPath); err != nil {
			return fmt.Errorf("write demo table output: %w", err)
		}
		if htmlPath != "" {
			_, _ = fmt.Fprintf(stdout, "\nOffline demo complete (synthetic account %s — zero AWS API calls):\n", run.AccountID)
			_, _ = fmt.Fprintf(stdout, "  HTML report: %s (open in any browser, 100%% offline)\n", htmlPath)
			_, _ = fmt.Fprintf(stdout, "  Next steps:  nhilens explain R6  |  nhilens scan --profile <profile> --region us-east-1\n")
		}
		return nil
	}
}
