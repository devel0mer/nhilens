package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxTerraformFixtureGuardrailsAndCIExclusion(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "sandbox-fixture")

	for _, name := range []string{"versions.tf", "variables.tf", "main.tf", "outputs.tf", "README.md"} {
		if _, err := os.Stat(filepath.Join(fixtureDir, name)); err != nil {
			t.Fatalf("expected sandbox fixture file %s: %v", name, err)
		}
	}

	varsRaw, err := os.ReadFile(filepath.Join(fixtureDir, "variables.tf"))
	if err != nil {
		t.Fatal(err)
	}
	varsStr := string(varsRaw)
	if !strings.Contains(varsStr, `variable "confirm_sandbox_account"`) || !strings.Contains(varsStr, "default     = false") {
		t.Errorf("variables.tf must require confirm_sandbox_account defaulting to false")
	}

	outputsRaw, err := os.ReadFile(filepath.Join(fixtureDir, "outputs.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(outputsRaw), ".r4_ci_bot_key.secret") && strings.Contains(string(outputsRaw), "value       = aws_iam_access_key.r4_ci_bot_key.secret") {
		t.Errorf("outputs.tf must never output secret access keys")
	}

	mainRaw, err := os.ReadFile(filepath.Join(fixtureDir, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	mainStr := string(mainRaw)
	for _, wantResource := range []string{
		"r1_wildcard_agent",
		"r2_unused_agent",
		"r3_no_owner",
		"r4_ci_bot",
		"r5_loose_trust",
	} {
		if !strings.Contains(mainStr, wantResource) {
			t.Errorf("main.tf missing expected fixture resource %q", wantResource)
		}
	}

	// Ensure CI workflow never executes Terraform automatically.
	ciRaw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(ciRaw)), "terraform") {
		t.Errorf(".github/workflows/ci.yml must never run Terraform fixtures automatically")
	}
}
