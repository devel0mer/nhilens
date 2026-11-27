package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/model"
)

func TestDemoCommandOfflineArtifactsAndFormats(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "demo-out")
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"demo", "--out", outDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("nhilens demo failed (code=%d): %s", code, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"111122223333",
		"bedrock-support-agent",
		"mcp-ops-agent",
		"gh-wildcard-deploy",
		"region us-east-1 only",
		"Scope note: CloudTrail signals",
		"Offline demo complete",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected demo output to contain %q, got:\n%s", want, out)
		}
	}

	dbPath := filepath.Join(outDir, "nhilens.db")
	htmlPath := filepath.Join(outDir, "report.html")
	for _, p := range []string{dbPath, htmlPath} {
		st, err := os.Stat(p)
		if err != nil || st.Size() == 0 {
			t.Fatalf("expected non-empty demo artifact %s (err=%v)", p, err)
		}
	}

	// Verify generated demo DB works directly with `nhilens report`.
	sarifPath := filepath.Join(outDir, "demo.sarif")
	var repOut, repErr bytes.Buffer
	if rc := Execute([]string{"report", "--in", dbPath, "--out", sarifPath, "--format", "sarif"}, &repOut, &repErr); rc != 0 {
		t.Fatalf("report from demo DB failed (code=%d): %s", rc, repErr.String())
	}

	// Verify --no-write skips writing artifacts and --format json emits valid ScanRun.
	noWriteDir := filepath.Join(t.TempDir(), "should-not-exist")
	var jsonOut, jsonErr bytes.Buffer
	if rc := Execute([]string{"demo", "--out", noWriteDir, "--no-write", "--format", "json"}, &jsonOut, &jsonErr); rc != 0 {
		t.Fatalf("demo --no-write --format json failed (code=%d): %s", rc, jsonErr.String())
	}
	if _, err := os.Stat(noWriteDir); !os.IsNotExist(err) {
		t.Errorf("expected --no-write not to create %s", noWriteDir)
	}
	var decoded model.ScanRun
	if err := json.Unmarshal(jsonOut.Bytes(), &decoded); err != nil {
		t.Fatalf("demo --format json produced invalid JSON: %v", err)
	}
	if decoded.AccountID != "111122223333" || len(decoded.Identities) == 0 {
		t.Errorf("unexpected demo ScanRun: account=%q identities=%d", decoded.AccountID, len(decoded.Identities))
	}

	// Verify invalid format fails cleanly.
	var badOut, badErr bytes.Buffer
	if rc := Execute([]string{"demo", "--no-write", "--format", "xml"}, &badOut, &badErr); rc == 0 {
		t.Errorf("expected non-zero exit code for invalid demo --format")
	}
}
