package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/report"
	"github.com/devel0mer/nhilens/internal/store"
	"github.com/spf13/cobra"
)

// ReportOptions captures validated inputs for the report subcommand.
type ReportOptions struct {
	InDB   string
	Out    string
	Format string
}

func newReportCmd() *cobra.Command {
	var (
		inDB   string
		out    string
		format string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a static HTML, JSON, SARIF, Markdown, or CSV report from a scan SQLite database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := buildReportOptions(inDB, out, format)
			if err != nil {
				return err
			}
			return runReport(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&inDB, "in", "", "Path to input SQLite database produced by 'nhilens scan'")
	cmd.Flags().StringVar(&out, "out", "", "Path to output report file (default ./nhilens-out/report.<ext>)")
	cmd.Flags().StringVar(&format, "format", "html", "Report output format: html, json, sarif, markdown, or csv")

	return cmd
}

func runReport(ctx context.Context, stdout io.Writer, opts *ReportOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if _, err := os.Stat(opts.InDB); err != nil {
		return fmt.Errorf("input database %q not accessible: %w", opts.InDB, err)
	}

	st, err := store.Open(opts.InDB)
	if err != nil {
		return fmt.Errorf("open database %q: %w", opts.InDB, err)
	}
	defer st.Close()

	run, err := st.LoadLatestScan(ctx)
	if err != nil {
		return fmt.Errorf("load latest scan from %q: %w", opts.InDB, err)
	}

	outDir := filepath.Dir(opts.Out)
	if outDir != "" && outDir != "." {
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			return fmt.Errorf("create output directory %q: %w", outDir, err)
		}
	}

	f, err := os.OpenFile(opts.Out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create report file %q: %w", opts.Out, err)
	}

	var writeErr error
	switch opts.Format {
	case "json":
		writeErr = report.WriteJSON(f, run)
	case "sarif":
		writeErr = report.WriteSARIF(f, run)
	case "markdown":
		writeErr = report.WriteMarkdown(f, run)
	case "csv":
		writeErr = report.WriteCSV(f, run)
	default:
		writeErr = report.WriteHTML(f, run)
	}
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("write %s report: %w", opts.Format, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close report file %q: %w", opts.Out, closeErr)
	}

	fmt.Fprintf(stdout, "Wrote %s report for scan %s (account %s) to %s\n", opts.Format, run.ID, run.AccountID, opts.Out)
	return nil
}

func buildReportOptions(inDB, out, format string) (*ReportOptions, error) {
	defaults := config.Default()

	normFormat := strings.ToLower(strings.TrimSpace(format))
	switch normFormat {
	case "html", "json", "sarif", "markdown", "md", "csv":
		if normFormat == "md" {
			normFormat = "markdown"
		}
	default:
		return nil, fmt.Errorf("invalid --format %q (expected html, json, sarif, markdown, or csv)", format)
	}

	resolvedIn := strings.TrimSpace(inDB)
	if resolvedIn == "" {
		resolvedIn = filepath.Join(defaults.Output.Dir, defaults.Output.DBFile)
	}

	resolvedOut := strings.TrimSpace(out)
	if resolvedOut == "" {
		switch normFormat {
		case "json":
			resolvedOut = filepath.Join(defaults.Output.Dir, "report.json")
		case "sarif":
			resolvedOut = filepath.Join(defaults.Output.Dir, "report.sarif")
		case "markdown":
			resolvedOut = filepath.Join(defaults.Output.Dir, "report.md")
		case "csv":
			resolvedOut = filepath.Join(defaults.Output.Dir, "report.csv")
		default:
			resolvedOut = filepath.Join(defaults.Output.Dir, defaults.Output.ReportFile)
		}
	}

	return &ReportOptions{
		InDB:   resolvedIn,
		Out:    resolvedOut,
		Format: normFormat,
	}, nil
}
