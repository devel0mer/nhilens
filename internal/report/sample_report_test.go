package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devel0mer/nhilens/internal/demo"
	"github.com/devel0mer/nhilens/internal/report"
)

// TestSampleReportHTML verifies docs/sample-report.html is present and CDN-free.
// Set NHILENS_UPDATE_SAMPLE=1 to regenerate docs/sample-report.html from synthetic data.
func TestSampleReportHTML(t *testing.T) {
	samplePath := filepath.Join("..", "..", "docs", "sample-report.html")

	if os.Getenv("NHILENS_UPDATE_SAMPLE") == "1" {
		run := demo.BuildSyntheticRun()
		var buf bytes.Buffer
		if err := report.WriteHTML(&buf, run); err != nil {
			t.Fatalf("WriteHTML synthetic sample: %v", err)
		}
		if err := os.WriteFile(samplePath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", samplePath, err)
		}
	}

	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read %s: %v (run with NHILENS_UPDATE_SAMPLE=1 to generate)", samplePath, err)
	}
	html := string(raw)
	if !strings.Contains(html, "111122223333") {
		t.Errorf("expected synthetic account 111122223333 in sample report")
	}
	if !strings.Contains(html, "Single-region CloudTrail scope:") {
		t.Errorf("expected prominent single-region CloudTrail scope banner in sample report")
	}
	if strings.Contains(html, "<script src=") || strings.Contains(html, "cdn.jsdelivr.net") {
		t.Errorf("sample report must not reference external CDNs")
	}
}
