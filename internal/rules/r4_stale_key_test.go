package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR4StaleOrSharedKeyTable(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	freshCreated := now.Add(-30 * 24 * time.Hour)
	staleCreated := now.Add(-150 * 24 * time.Hour)
	lastUsed := now.Add(-1 * 24 * time.Hour)

	r := R4StaleOrSharedKey{}
	rctx := Context{Config: config.Default(), Now: now}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantEvidenceSub string
	}{
		{
			name: "key older than 90 days triggers R4",
			ident: model.Identity{
				Type:     model.TypeKey,
				Name:     "AKIAOLD1111111111111",
				Created:  &staleCreated,
				LastUsed: &lastUsed,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIAOLD1111111111111",
					ParentUserName: "ci-bot",
					Status:         "Active",
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "150 days old",
		},
		{
			name: "fresh key used from multiple distinct source IPs triggers best-effort shared R4",
			ident: model.Identity{
				Type:      model.TypeKey,
				Name:      "AKIASHARED2222222222",
				Created:   &freshCreated,
				SourceIPs: []string{"198.51.100.10", "203.0.113.42", "198.51.100.10"},
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIASHARED2222222222",
					ParentUserName: "agent-bot",
					Status:         "Active",
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "best-effort",
		},
		{
			name: "stale AND shared key reports both evidence items",
			ident: model.Identity{
				Type:      model.TypeKey,
				Name:      "AKIABOTH333333333333",
				Created:   &staleCreated,
				SourceIPs: []string{"198.51.100.10", "2001:db8::1"},
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIABOTH333333333333",
					ParentUserName: "shared-agent",
					Status:         "Active",
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "2 distinct source IPs",
		},
		{
			name: "fresh key with single IP plus AWS Internal hostname does not trigger R4",
			ident: model.Identity{
				Type:      model.TypeKey,
				Name:      "AKIAFRESH44444444444",
				Created:   &freshCreated,
				SourceIPs: []string{"198.51.100.10", "AWS Internal", "s3.amazonaws.com"},
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIAFRESH44444444444",
					ParentUserName: "clean-bot",
					Status:         "Active",
				},
			},
			wantTriggered: false,
		},
		{
			name: "non-key identity is ignored by R4",
			ident: model.Identity{
				Type:    model.TypeRole,
				Name:    "old-role",
				Created: &staleCreated,
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R4 finding, got nil")
				}
				if f.RuleID != "R4" || f.Severity != model.SeverityHigh {
					t.Errorf("unexpected rule metadata: %+v", f)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R4 finding, got %+v", f)
			}
		})
	}
}
