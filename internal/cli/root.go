package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCmd builds the top-level nhilens Cobra command using default AWS SDK clients.
// Running nhilens with no arguments prints help only and never triggers an AWS scan.
func NewRootCmd() *cobra.Command {
	return NewRootCmdWithDeps(defaultScanDeps())
}

// NewRootCmdWithDeps builds the top-level nhilens Cobra command with injectable dependencies for testing.
func NewRootCmdWithDeps(deps ScanDeps) *cobra.Command {
	root := &cobra.Command{
		Use:   "nhilens",
		Short: "Read-only AWS non-human identity auditor for AI agents",
		Long: `nhilens scans an AWS account using strictly read-only APIs to inventory
non-human identities (IAM roles, users, and access keys), highlight heuristic
signals of AI agents or automation, surface ownership gaps, and score risk.

Running nhilens with no arguments prints help only and never performs a scan.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.AddCommand(
		newScanCmd(deps),
		newReportCmd(),
		newDiffCmd(),
		newExplainCmd(),
		newVersionCmd(),
	)

	return root
}

// Execute runs the CLI with default dependencies and returns the exit code to pass to os.Exit.
func Execute(args []string, stdout, stderr io.Writer) int {
	return ExecuteWithDeps(args, stdout, stderr, defaultScanDeps())
}

// ExecuteWithDeps runs the CLI with injected dependencies and returns the process exit code.
func ExecuteWithDeps(args []string, stdout, stderr io.Writer, deps ScanDeps) int {
	cmd := NewRootCmdWithDeps(deps)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.Execute(); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Err != nil {
				fmt.Fprintf(stderr, "error: %v\n", exitErr.Err)
			}
			return exitErr.Code
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// Main is the process entrypoint invoked by cmd/nhilens.
func Main() {
	os.Exit(Execute(os.Args[1:], os.Stdout, os.Stderr))
}
