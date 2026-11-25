package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/devel0mer/nhilens/internal/rules"
	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain [RULE_ID_OR_NAME]",
		Short: "Explain a risk rule with guardrails, config knobs, and read-only remediation templates",
		Long: `Display detailed documentation, false-positive guardrails, configuration options,
and copy-pasteable AWS CLI / Terraform remediation examples for a risk rule.
Run 'nhilens explain' with no arguments to list all built-in rules (R1–R8).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "RULE\tNAME\tDEFAULT SEVERITY\tSUMMARY")
				fmt.Fprintln(tw, "----\t----\t----------------\t-------")
				for _, m := range rules.Catalog() {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Name, m.DefaultSeverity, m.Summary)
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				fmt.Fprintln(out, "\nRun `nhilens explain <RULE_ID>` (e.g., `nhilens explain R5`) for remediation templates.")
				return nil
			}

			meta, ok := rules.LookupMetadata(args[0])
			if !ok {
				ids := make([]string, 0, len(rules.Catalog()))
				for _, m := range rules.Catalog() {
					ids = append(ids, m.ID)
				}
				return fmt.Errorf("unknown rule %q (valid rules: %s)", args[0], strings.Join(ids, ", "))
			}

			fmt.Fprintf(out, "%s — %s (default severity: %s)\n", meta.ID, meta.Name, meta.DefaultSeverity)
			fmt.Fprintf(out, "%s\n\n", strings.Repeat("=", len(meta.ID)+len(meta.Name)+30))
			fmt.Fprintf(out, "What it checks:\n  %s\n\n", meta.Description)
			fmt.Fprintf(out, "Guardrails:\n  %s\n\n", meta.Guardrails)
			fmt.Fprintf(out, "Config knobs (nhilens.yaml):\n  %s\n\n", strings.Join(meta.ConfigKnobs, ", "))
			fmt.Fprintf(out, "Remediation:\n  %s\n\n", meta.Remediation)
			fmt.Fprintf(out, "AWS CLI snippet (review before running — nhilens is strictly read-only):\n")
			for _, line := range strings.Split(meta.ExampleCLI, "\n") {
				fmt.Fprintf(out, "  %s\n", line)
			}
			fmt.Fprintf(out, "\nTerraform snippet:\n")
			for _, line := range strings.Split(meta.ExampleTerraform, "\n") {
				fmt.Fprintf(out, "  %s\n", line)
			}
			return nil
		},
	}
}
