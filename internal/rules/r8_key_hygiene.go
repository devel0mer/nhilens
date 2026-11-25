package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/devel0mer/nhilens/internal/model"
)

const unusedActiveKeyGraceDays = 7

// R8KeyHygiene flags static IAM access-key hygiene risks not covered by R4:
//   - An IAM user holding two or more Active access keys simultaneously
//   - An Active access key older than 7 days that has never been used
type R8KeyHygiene struct{}

func (R8KeyHygiene) ID() string                      { return "R8" }
func (R8KeyHygiene) Name() string                    { return "key-hygiene" }
func (R8KeyHygiene) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r R8KeyHygiene) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil {
		return nil
	}

	now := rctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	switch ident.Type {
	case model.TypeUser:
		if len(ident.ActiveAccessKeyIDs) < 2 {
			return nil
		}
		return &model.Finding{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.DefaultSeverity(),
			Title:       fmt.Sprintf("IAM user has %d active access keys simultaneously", len(ident.ActiveAccessKeyIDs)),
			Explanation: "Holding two active static access keys on the same IAM user outside brief rotation windows doubles credential exposure and obscures which workload or agent owns each key.",
			Remediation: fmt.Sprintf("Audit which key is active, deactivate/delete the redundant key (`aws iam update-access-key --user-name %s --access-key-id <OLD_KEY> --status Inactive` followed by `delete-access-key`), or migrate workloads to short-lived IAM roles. Run `nhilens explain R8` for details.", ident.Name),
			Evidence: []string{
				fmt.Sprintf("user %q has %d Active access keys: %s", ident.Name, len(ident.ActiveAccessKeyIDs), strings.Join(ident.ActiveAccessKeyIDs, ", ")),
			},
		}

	case model.TypeKey:
		if ident.AccessKey == nil || !strings.EqualFold(ident.AccessKey.Status, "Active") {
			return nil
		}
		if ident.LastUsed != nil || ident.Created == nil {
			return nil
		}
		age := now.Sub(*ident.Created)
		if age < unusedActiveKeyGraceDays*24*time.Hour {
			return nil
		}
		ageDays := int(age.Hours() / 24)
		return &model.Finding{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.DefaultSeverity(),
			Title:       "Active IAM access key has never been used",
			Explanation: fmt.Sprintf("This Active IAM access key was created %d days ago (%s) and has no recorded AWS API usage. Unused active keys are unnecessary long-lived credentials waiting to be leaked.", ageDays, ident.Created.UTC().Format("2006-01-02")),
			Remediation: fmt.Sprintf("Deactivate and delete the unused key (`aws iam delete-access-key --user-name %s --access-key-id %s`). Run `nhilens explain R8` for details.", ident.AccessKey.ParentUserName, ident.Name),
			Evidence: []string{
				fmt.Sprintf("access key %s (user %q, status=Active) created %s (%dd ago) has never been used", ident.Name, ident.AccessKey.ParentUserName, ident.Created.UTC().Format("2006-01-02"), ageDays),
			},
		}

	default:
		return nil
	}
}
