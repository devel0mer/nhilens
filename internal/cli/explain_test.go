package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplainCommand(t *testing.T) {
	// 1. No args lists all 8 rules.
	var listOut, listErr bytes.Buffer
	if code := Execute([]string{"explain"}, &listOut, &listErr); code != 0 {
		t.Fatalf("explain list failed (code=%d): %s", code, listErr.String())
	}
	for _, id := range []string{"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"} {
		if !strings.Contains(listOut.String(), id) {
			t.Errorf("expected explain list to contain %s", id)
		}
	}

	// 2. Lookup by rule ID (case-insensitive) shows remediation & Terraform snippets.
	var r5Out, r5Err bytes.Buffer
	if code := Execute([]string{"explain", "r5"}, &r5Out, &r5Err); code != 0 {
		t.Fatalf("explain r5 failed (code=%d): %s", code, r5Err.String())
	}
	for _, want := range []string{"R5 — loose-trust", "AWS CLI snippet", "Terraform snippet", "strictly read-only"} {
		if !strings.Contains(r5Out.String(), want) {
			t.Errorf("explain r5 missing %q", want)
		}
	}

	// 3. Lookup by rule name also works.
	var r6Out, r6Err bytes.Buffer
	if code := Execute([]string{"explain", "privilege-escalation-path"}, &r6Out, &r6Err); code != 0 {
		t.Fatalf("explain by name failed (code=%d): %s", code, r6Err.String())
	}
	if !strings.Contains(r6Out.String(), "R6 — privilege-escalation-path") {
		t.Errorf("unexpected explain by name output:\n%s", r6Out.String())
	}

	// 4. Unknown rule ID returns exit code 1.
	var badOut, badErr bytes.Buffer
	if code := Execute([]string{"explain", "R99"}, &badOut, &badErr); code == 0 {
		t.Errorf("expected non-zero exit code for unknown rule R99")
	}
}
