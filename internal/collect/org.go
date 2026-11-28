package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

const maxOrgParentDepth = 16

// OrgAccount represents one active AWS Organizations member or management account.
type OrgAccount struct {
	ID     string
	Name   string
	Email  string
	Status string
}

// OrgDiscoveryOptions configures read-only AWS Organizations account discovery.
type OrgDiscoveryOptions struct {
	IncludeAccounts []string
	ExcludeAccounts []string
	Retry           RetryPolicy
}

// OrgDiscoveryResult holds discovered Organization metadata and filtered active accounts.
type OrgDiscoveryResult struct {
	OrganizationID  string
	MasterAccountID string
	Accounts        []OrgAccount
	Warnings        []string
}

// DiscoverOrgAccounts lists ACTIVE AWS Organizations accounts using strictly read-only APIs,
// applying optional include/exclude account filters.
func DiscoverOrgAccounts(ctx context.Context, client OrganizationsClient, opts OrgDiscoveryOptions) (*OrgDiscoveryResult, error) {
	if client == nil {
		return nil, errors.New("organizations client is nil")
	}
	retry := opts.Retry.normalize()

	res := &OrgDiscoveryResult{}

	// Best-effort DescribeOrganization to capture Org ID & management account ID (SCP exemption).
	if descOut, err := DoWithRetry(ctx, retry, func(ctx context.Context) (*organizations.DescribeOrganizationOutput, error) {
		return client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	}); err == nil && descOut != nil && descOut.Organization != nil {
		res.OrganizationID = aws.ToString(descOut.Organization.Id)
		res.MasterAccountID = aws.ToString(descOut.Organization.MasterAccountId)
	} else if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("organizations DescribeOrganization unavailable (continuing with ListAccounts): %v", err))
	}

	includeSet := toAccountSet(opts.IncludeAccounts)
	excludeSet := toAccountSet(opts.ExcludeAccounts)

	var (
		nextToken    *string
		skippedCount int
	)
	for {
		out, err := DoWithRetry(ctx, retry, func(ctx context.Context) (*organizations.ListAccountsOutput, error) {
			return client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: nextToken})
		})
		if err != nil {
			return nil, fmt.Errorf("organizations ListAccounts: %w", err)
		}

		for _, acct := range out.Accounts {
			id := strings.TrimSpace(aws.ToString(acct.Id))
			if id == "" {
				continue
			}
			if acct.Status != orgtypes.AccountStatusActive {
				skippedCount++
				continue
			}
			if len(includeSet) > 0 {
				if _, ok := includeSet[id]; !ok {
					continue
				}
			}
			if _, excluded := excludeSet[id]; excluded {
				continue
			}
			res.Accounts = append(res.Accounts, OrgAccount{
				ID:     id,
				Name:   strings.TrimSpace(aws.ToString(acct.Name)),
				Email:  strings.TrimSpace(aws.ToString(acct.Email)),
				Status: string(acct.Status),
			})
		}

		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	if skippedCount > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d non-ACTIVE AWS Organizations account(s)", skippedCount))
	}

	sort.Slice(res.Accounts, func(i, j int) bool {
		return res.Accounts[i].ID < res.Accounts[j].ID
	})
	return res, nil
}

// SCPResolver resolves effective AWS Organizations Service Control Policies per account
// by walking the account -> OU -> Root hierarchy with thread-safe in-memory caching.
//
// Per AWS Organizations evaluation semantics:
//   - The management (master) account is exempt from SCPs.
//   - Policies attached at the same hierarchy target (Account, OU, or Root) are unioned
//     (Allow is OR'd within a level, explicit Deny blocks).
//   - Hierarchy levels from Root down to Account are intersected (AND'd across levels).
type SCPResolver struct {
	client          OrganizationsClient
	masterAccountID string
	retry           RetryPolicy

	mu            sync.Mutex
	parentsCache  map[string][]string
	targetPols    map[string][]orgPolicyRef
	policyDocByID map[string]*model.ParsedPolicy
}

type orgPolicyRef struct {
	ID   string
	Name string
}

// NewSCPResolver constructs a cached, thread-safe Organizations SCP resolver.
func NewSCPResolver(client OrganizationsClient, masterAccountID string, retry RetryPolicy) *SCPResolver {
	return &SCPResolver{
		client:          client,
		masterAccountID: strings.TrimSpace(masterAccountID),
		retry:           retry.normalize(),
		parentsCache:    make(map[string][]string),
		targetPols:      make(map[string][]orgPolicyRef),
		policyDocByID:   make(map[string]*model.ParsedPolicy),
	}
}

// ResolveForAccount returns the effective per-level merged SCP guardrails for accountID,
// along with the number of unique SCP documents evaluated and any non-fatal warnings.
func (r *SCPResolver) ResolveForAccount(ctx context.Context, accountID string) ([]policy.NamedPolicy, int, []string) {
	if r == nil || r.client == nil {
		return nil, 0, nil
	}
	acct := strings.TrimSpace(accountID)
	if acct == "" {
		return nil, 0, nil
	}
	// AWS Organizations SCPs never restrict the management account.
	if r.masterAccountID != "" && acct == r.masterAccountID {
		return nil, 0, nil
	}

	// Walk hierarchy: account -> parent OU(s) -> ... -> Root.
	chain := []string{acct}
	visited := map[string]struct{}{acct: {}}
	curr := acct
	var warnings []string

	for depth := 0; depth < maxOrgParentDepth; depth++ {
		parents, err := r.listParents(ctx, curr)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("[account %s] SCP discovery ListParents(%s) failed: %v", acct, curr, err))
			break
		}
		if len(parents) == 0 {
			break
		}
		next := parents[0]
		if _, seen := visited[next]; seen {
			break
		}
		visited[next] = struct{}{}
		chain = append(chain, next)
		if strings.HasPrefix(next, "r-") {
			break
		}
		curr = next
	}

	// Reverse chain so evaluation order is Root -> OUs -> Account.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	uniqueSCPIDs := make(map[string]struct{})
	effectiveLevels := make([]policy.NamedPolicy, 0, len(chain))

	for _, targetID := range chain {
		refs, err := r.listSCPsForTarget(ctx, targetID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("[account %s] SCP discovery ListPoliciesForTarget(%s) failed: %v", acct, targetID, err))
			continue
		}
		if len(refs) == 0 {
			continue
		}

		merged := &model.ParsedPolicy{Version: "2012-10-17"}
		names := make([]string, 0, len(refs))
		for _, ref := range refs {
			doc, err := r.describeSCP(ctx, ref.ID)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("[account %s] SCP DescribePolicy(%s/%s) failed: %v", acct, ref.ID, ref.Name, err))
				continue
			}
			uniqueSCPIDs[ref.ID] = struct{}{}
			names = append(names, ref.Name)
			merged.Statements = append(merged.Statements, doc.Statements...)
		}
		if len(merged.Statements) > 0 {
			sort.Strings(names)
			effectiveLevels = append(effectiveLevels, policy.NamedPolicy{
				Name:   fmt.Sprintf("%s[%s]", targetID, strings.Join(names, "+")),
				Parsed: merged,
			})
		}
	}

	return effectiveLevels, len(uniqueSCPIDs), warnings
}

func (r *SCPResolver) listParents(ctx context.Context, childID string) ([]string, error) {
	r.mu.Lock()
	if cached, ok := r.parentsCache[childID]; ok {
		r.mu.Unlock()
		return cached, nil
	}
	r.mu.Unlock()

	var (
		nextToken *string
		parents   []string
	)
	for {
		out, err := DoWithRetry(ctx, r.retry, func(ctx context.Context) (*organizations.ListParentsOutput, error) {
			return r.client.ListParents(ctx, &organizations.ListParentsInput{
				ChildId:   aws.String(childID),
				NextToken: nextToken,
			})
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.Parents {
			if id := strings.TrimSpace(aws.ToString(p.Id)); id != "" {
				parents = append(parents, id)
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	r.mu.Lock()
	r.parentsCache[childID] = parents
	r.mu.Unlock()
	return parents, nil
}

func (r *SCPResolver) listSCPsForTarget(ctx context.Context, targetID string) ([]orgPolicyRef, error) {
	r.mu.Lock()
	if cached, ok := r.targetPols[targetID]; ok {
		r.mu.Unlock()
		return cached, nil
	}
	r.mu.Unlock()

	var (
		nextToken *string
		refs      []orgPolicyRef
	)
	for {
		out, err := DoWithRetry(ctx, r.retry, func(ctx context.Context) (*organizations.ListPoliciesForTargetOutput, error) {
			return r.client.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
				TargetId:  aws.String(targetID),
				Filter:    orgtypes.PolicyTypeServiceControlPolicy,
				NextToken: nextToken,
			})
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.Policies {
			id := strings.TrimSpace(aws.ToString(p.Id))
			if id == "" {
				continue
			}
			name := strings.TrimSpace(aws.ToString(p.Name))
			if name == "" {
				name = id
			}
			refs = append(refs, orgPolicyRef{ID: id, Name: name})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		nextToken = out.NextToken
	}

	r.mu.Lock()
	r.targetPols[targetID] = refs
	r.mu.Unlock()
	return refs, nil
}

func (r *SCPResolver) describeSCP(ctx context.Context, policyID string) (*model.ParsedPolicy, error) {
	r.mu.Lock()
	if cached, ok := r.policyDocByID[policyID]; ok {
		r.mu.Unlock()
		return cached, nil
	}
	r.mu.Unlock()

	out, err := DoWithRetry(ctx, r.retry, func(ctx context.Context) (*organizations.DescribePolicyOutput, error) {
		return r.client.DescribePolicy(ctx, &organizations.DescribePolicyInput{
			PolicyId: aws.String(policyID),
		})
	})
	if err != nil {
		return nil, err
	}
	if out == nil || out.Policy == nil || strings.TrimSpace(aws.ToString(out.Policy.Content)) == "" {
		return nil, fmt.Errorf("empty policy content for %s", policyID)
	}
	parsed, err := policy.ParseDocument(aws.ToString(out.Policy.Content))
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.policyDocByID[policyID] = parsed
	r.mu.Unlock()
	return parsed, nil
}

func toAccountSet(list []string) map[string]struct{} {
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(list))
	for _, a := range list {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out
}
