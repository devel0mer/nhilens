package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/devel0mer/nhilens/internal/config"
	"github.com/devel0mer/nhilens/internal/model"
)

func TestR8KeyHygieneTable(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	oldCreated := now.Add(-30 * 24 * time.Hour)
	recentCreated := now.Add(-2 * 24 * time.Hour)
	usedRecently := now.Add(-1 * 24 * time.Hour)

	r := R8KeyHygiene{}
	rctx := Context{Config: config.Default(), Now: now}

	tests := []struct {
		name            string
		ident           model.Identity
		wantTriggered   bool
		wantEvidenceSub string
	}{
		{
			name: "user with two active access keys triggers R8",
			ident: model.Identity{
				Type:               model.TypeUser,
				Name:               "ci-bot",
				ActiveAccessKeyIDs: []string{"AKIA111", "AKIA222"},
			},
			wantTriggered:   true,
			wantEvidenceSub: "2 Active access keys",
		},
		{
			name: "user with only one active access key does not trigger R8",
			ident: model.Identity{
				Type:               model.TypeUser,
				Name:               "clean-bot",
				AccessKeyIDs:       []string{"AKIA111", "AKIA222"},
				ActiveAccessKeyIDs: []string{"AKIA111"},
			},
			wantTriggered: false,
		},
		{
			name: "active access key older than 7 days never used triggers R8",
			ident: model.Identity{
				Type:     model.TypeKey,
				Name:     "AKIAUNUSED1111111111",
				Created:  &oldCreated,
				LastUsed: nil,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIAUNUSED1111111111",
					ParentUserName: "ci-bot",
					Status:         "Active",
				},
			},
			wantTriggered:   true,
			wantEvidenceSub: "never been used",
		},
		{
			name: "brand new unused active key within 7-day grace window does not trigger R8",
			ident: model.Identity{
				Type:     model.TypeKey,
				Name:     "AKIANEW1111111111111",
				Created:  &recentCreated,
				LastUsed: nil,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIANEW1111111111111",
					ParentUserName: "ci-bot",
					Status:         "Active",
				},
			},
			wantTriggered: false,
		},
		{
			name: "inactive unused key does not trigger R8",
			ident: model.Identity{
				Type:     model.TypeKey,
				Name:     "AKIAINACTIVE11111111",
				Created:  &oldCreated,
				LastUsed: nil,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIAINACTIVE11111111",
					ParentUserName: "ci-bot",
					Status:         "Inactive",
				},
			},
			wantTriggered: false,
		},
		{
			name: "active key with recorded usage does not trigger R8",
			ident: model.Identity{
				Type:     model.TypeKey,
				Name:     "AKIAUSED111111111111",
				Created:  &oldCreated,
				LastUsed: &usedRecently,
				AccessKey: &model.AccessKeyInfo{
					AccessKeyID:    "AKIAUSED111111111111",
					ParentUserName: "ci-bot",
					Status:         "Active",
				},
			},
			wantTriggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := r.Evaluate(&tc.ident, rctx)
			if tc.wantTriggered {
				if f == nil {
					t.Fatalf("expected R8 finding, got nil")
				}
				if f.RuleID != "R8" || f.Severity != model.SeverityMedium {
					t.Errorf("got (%s, %s), want (R8, medium)", f.RuleID, f.Severity)
				}
				if tc.wantEvidenceSub != "" && !strings.Contains(strings.Join(f.Evidence, " | "), tc.wantEvidenceSub) {
					t.Errorf("expected evidence containing %q, got %v", tc.wantEvidenceSub, f.Evidence)
				}
			} else if f != nil {
				t.Fatalf("expected no R8 finding, got %+v", f)
			}
		})
	}
}
