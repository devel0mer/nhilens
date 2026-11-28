package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootNoArgsPrintsHelpOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Usage:", "scan", "report", "version", "never performs a scan"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected help output to contain %q, got:\n%s", want, out)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("expected empty stderr, got %q", stderr.String())
	}
}

func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "nhilens ") {
		t.Errorf("unexpected version output: %q", stdout.String())
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "90d", want: 90 * 24 * time.Hour},
		{in: "7d", want: 7 * 24 * time.Hour},
		{in: "24h", want: 24 * time.Hour},
		{in: "30m", want: 30 * time.Minute},
		{in: "0d", wantErr: true},
		{in: "-5d", wantErr: true},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
	}

	for _, tc := range tests {
		got, err := ParseDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseDuration(%q) expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDuration(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"low", "low"},
		{"MEDIUM", "medium"},
		{"High", "high"},
		{"critical", "critical"},
	}
	for _, tc := range valid {
		got, err := ParseSeverity(tc.in)
		if err != nil {
			t.Errorf("ParseSeverity(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := ParseSeverity("blocker"); err == nil {
		t.Errorf("expected error for invalid severity")
	}
}

func TestScanAndReportOptionValidation(t *testing.T) {
	opts, err := buildScanOptions("sandbox", "eu-central-1", "30d", 1000, true, true, true, ".nhilens-ignore.yaml", "scp.json", "", "/tmp/out", "sarif", "high")
	if err != nil {
		t.Fatalf("buildScanOptions valid case failed: %v", err)
	}
	if opts.Region != "eu-central-1" || opts.Format != "sarif" || opts.FailOn != "high" || opts.IgnoreFile != ".nhilens-ignore.yaml" || opts.SCPFile != "scp.json" {
		t.Errorf("unexpected scan options: %+v", opts)
	}
	if !opts.SkipServiceLastAccessed || !opts.IncludeServiceLinkedRoles {
		t.Errorf("expected skip-service-last-accessed and include-service-linked-roles true, got %+v", opts)
	}
	if opts.Since != 30*24*time.Hour {
		t.Errorf("expected 30d, got %v", opts.Since)
	}

	if _, err := buildScanOptions("", "", "90d", 100, false, false, false, "", "", "", "", "xml", ""); err == nil {
		t.Errorf("expected error for invalid scan --format")
	}
	if _, err := buildScanOptions("", "", "90d", -1, false, false, false, "", "", "", "", "table", ""); err == nil {
		t.Errorf("expected error for negative --max-events")
	}
	if _, err := buildScanOptions("", "", "bad", 100, false, false, false, "", "", "", "", "table", ""); err == nil {
		t.Errorf("expected error for invalid --since")
	}
	if _, err := buildScanOptions("", "", "90d", 100, false, false, false, "", "", "", "", "table", "urgent"); err == nil {
		t.Errorf("expected error for invalid --fail-on")
	}

	repOpts, err := buildReportOptions("", "", "sarif")
	if err != nil {
		t.Fatalf("buildReportOptions sarif case failed: %v", err)
	}
	if !strings.HasSuffix(repOpts.Out, "report.sarif") {
		t.Errorf("expected default sarif output path, got %q", repOpts.Out)
	}
	if _, err := buildReportOptions("", "", "pdf"); err == nil {
		t.Errorf("expected error for invalid report --format")
	}
}

func TestScanRegionsFlagParsingAndValidation(t *testing.T) {
	// 1. Comma-separated deduplicated regions.
	opts, err := buildScanOptionsWithRegions("", "", false, []string{"us-east-1,eu-west-1", "us-east-1"}, "90d", 100, false, false, false, "", "", "", "", "table", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Region != "us-east-1" || len(opts.Regions) != 2 || opts.Regions[0] != "us-east-1" || opts.Regions[1] != "eu-west-1" {
		t.Errorf("unexpected resolved regions: primary=%q all=%v", opts.Region, opts.Regions)
	}

	// 2. --regions all expands to the 17 default-enabled AWS regions.
	optsAll, err := buildScanOptionsWithRegions("", "", false, []string{"all"}, "90d", 100, false, false, false, "", "", "", "", "table", "")
	if err != nil {
		t.Fatalf("unexpected error for --regions all: %v", err)
	}
	if len(optsAll.Regions) != 17 || optsAll.Region != "us-east-1" {
		t.Errorf("expected 17 default regions starting with us-east-1, got primary=%q len=%d", optsAll.Region, len(optsAll.Regions))
	}

	// 3. Explicit --region combined with --regions prepends --region as primary.
	optsCombo, err := buildScanOptionsWithRegions("", "ap-northeast-1", true, []string{"us-east-1,eu-west-1"}, "90d", 100, false, false, false, "", "", "", "", "table", "")
	if err != nil {
		t.Fatalf("unexpected error for combo flags: %v", err)
	}
	if optsCombo.Region != "ap-northeast-1" || len(optsCombo.Regions) != 3 || optsCombo.Regions[0] != "ap-northeast-1" {
		t.Errorf("unexpected combo regions: primary=%q all=%v", optsCombo.Region, optsCombo.Regions)
	}

	// 4. Invalid region fails fast.
	if _, err := buildScanOptionsWithRegions("", "", false, []string{"not-a-region"}, "90d", 100, false, false, false, "", "", "", "", "table", ""); err == nil {
		t.Errorf("expected error for invalid --regions entry")
	}
	if _, err := buildScanOptionsWithRegions("", "bad region", true, nil, "90d", 100, false, false, false, "", "", "", "", "table", ""); err == nil {
		t.Errorf("expected error for invalid --region")
	}

	// 5. aws.regions from nhilens.yaml is picked up when CLI flags are omitted, and overridden by --region.
	cfgPath := filepath.Join(t.TempDir(), "nhilens.yaml")
	if err := os.WriteFile(cfgPath, []byte("aws:\n  regions:\n    - eu-central-1\n    - us-west-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	optsCfg, err := buildScanOptionsWithRegions("", "", false, nil, "90d", 100, false, false, false, "", "", cfgPath, "", "table", "")
	if err != nil {
		t.Fatalf("config aws.regions failed: %v", err)
	}
	if optsCfg.Region != "eu-central-1" || len(optsCfg.Regions) != 2 || optsCfg.Regions[1] != "us-west-2" {
		t.Errorf("expected config aws.regions, got primary=%q all=%v", optsCfg.Region, optsCfg.Regions)
	}
	optsOverride, err := buildScanOptionsWithRegions("", "us-east-1", true, nil, "90d", 100, false, false, false, "", "", cfgPath, "", "table", "")
	if err != nil {
		t.Fatalf("explicit --region override failed: %v", err)
	}
	if optsOverride.Region != "us-east-1" || len(optsOverride.Regions) != 1 {
		t.Errorf("expected explicit --region to override config aws.regions, got primary=%q all=%v", optsOverride.Region, optsOverride.Regions)
	}
}

func TestIAMPolicyDocIsStrictlyReadOnly(t *testing.T) {
	policyPath := filepath.Join("..", "..", "docs", "iam-policy.json")
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read %s: %v", policyPath, err)
	}

	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid      string   `json:"Sid"`
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource string   `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse iam-policy.json: %v", err)
	}
	if doc.Version != "2012-10-17" {
		t.Errorf("expected Version 2012-10-17, got %q", doc.Version)
	}
	if len(doc.Statement) == 0 {
		t.Fatalf("iam-policy.json has no statements")
	}

	// Explicit allowlist of strictly read-only AWS actions required by nhilens.
	allowedReadOnly := map[string]bool{
		"sts:GetCallerIdentity":                  true,
		"iam:GetAccountAuthorizationDetails":     true,
		"iam:GetLoginProfile":                    true,
		"iam:ListAccessKeys":                     true,
		"iam:GetAccessKeyLastUsed":               true,
		"iam:GenerateServiceLastAccessedDetails": true,
		"iam:GetServiceLastAccessedDetails":      true,
		"cloudtrail:LookupEvents":                true,
	}

	seen := map[string]bool{}
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			t.Errorf("unexpected Effect %q", stmt.Effect)
		}
		for _, act := range stmt.Action {
			if strings.Contains(act, "*") {
				t.Errorf("wildcard action %q is forbidden in minimal policy", act)
			}
			if !allowedReadOnly[act] {
				t.Errorf("action %q is not in the strictly read-only allowlist", act)
			}
			seen[act] = true
		}
	}

	for act := range allowedReadOnly {
		if !seen[act] {
			t.Errorf("expected read-only action %q to be listed in docs/iam-policy.json", act)
		}
	}
}
