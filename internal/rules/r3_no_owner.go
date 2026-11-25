package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
)

// R3NoOwner flags taggable non-human identities (roles and non-human users) without an owner/sponsor tag.
type R3NoOwner struct{}

func (R3NoOwner) ID() string                      { return "R3" }
func (R3NoOwner) Name() string                    { return "no-owner" }
func (R3NoOwner) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r R3NoOwner) Evaluate(ident *model.Identity, rctx Context) *model.Finding {
	if ident == nil || !IsNonHuman(ident) {
		return nil
	}
	// AWS IAM access keys cannot carry tags independently of their parent IAM user;
	// ownership is audited on the role or parent IAM user.
	if ident.Type != model.TypeRole && ident.Type != model.TypeUser {
		return nil
	}

	if ident.Owner != nil && strings.TrimSpace(*ident.Owner) != "" {
		return nil
	}

	var ownerKeys []string
	if rctx.Config != nil {
		ownerKeys = rctx.Config.AgentDetection.OwnerTagKeys
	}
	if len(ownerKeys) == 0 {
		ownerKeys = []string{"owner", "sponsor"}
	}

	evidence := []string{
		fmt.Sprintf("none of the configured owner tag keys matched: %s", strings.Join(ownerKeys, ", ")),
	}
	if len(ident.Tags) == 0 {
		evidence = append(evidence, "identity has no IAM tags attached")
	} else {
		existing := make([]string, 0, len(ident.Tags))
		for k := range ident.Tags {
			existing = append(existing, k)
		}
		sort.Strings(existing)
		evidence = append(evidence, fmt.Sprintf("existing tag keys: %s", strings.Join(existing, ", ")))
	}

	remediation := fmt.Sprintf("Tag this IAM role with an accountable owner or team (e.g., aws iam tag-role --role-name %s --tags Key=%s,Value=<team-or-email>).", ident.Name, ownerKeys[0])
	if ident.Type == model.TypeUser {
		remediation = fmt.Sprintf("Tag this IAM user with an accountable owner or team (e.g., aws iam tag-user --user-name %s --tags Key=%s,Value=<team-or-email>).", ident.Name, ownerKeys[0])
	}

	return &model.Finding{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    r.DefaultSeverity(),
		Title:       "Non-human identity has no owner tag",
		Explanation: "No configured owner or sponsor tag was found on this non-human identity, making incident response, periodic access reviews, and AI agent lifecycle governance difficult.",
		Remediation: remediation,
		Evidence:    evidence,
	}
}
