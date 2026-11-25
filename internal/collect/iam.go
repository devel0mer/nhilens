package collect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/devel0mer/nhilens/internal/model"
)

// Options configures IAM inventory collection behavior.
type Options struct {
	OwnerTagKeys            []string
	MaxConcurrency          int
	Retry                   RetryPolicy
	PollInitialInterval     time.Duration
	PollMaxInterval         time.Duration
	LastAccessedTimeout     time.Duration
	SkipServiceLastAccessed bool
	Sleep                   func(ctx context.Context, d time.Duration) error
	Now                     func() time.Time
}

func (o Options) normalize() Options {
	out := o
	if out.MaxConcurrency <= 0 {
		out.MaxConcurrency = 5
	}
	out.Retry = out.Retry.normalize()
	if out.PollInitialInterval <= 0 {
		out.PollInitialInterval = 500 * time.Millisecond
	}
	if out.PollMaxInterval <= 0 {
		out.PollMaxInterval = 3 * time.Second
	}
	if out.LastAccessedTimeout <= 0 {
		out.LastAccessedTimeout = 30 * time.Second
	}
	if out.Sleep == nil {
		out.Sleep = out.Retry.Sleep
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	return out
}

// IAMCollector collects read-only IAM roles, users, access keys, policies, and service last-accessed data.
type IAMCollector struct {
	sts  STSClient
	iam  IAMClient
	opts Options
}

// NewIAMCollector creates a collector using injected STS and IAM interfaces.
func NewIAMCollector(stsClient STSClient, iamClient IAMClient, opts Options) *IAMCollector {
	return &IAMCollector{
		sts:  stsClient,
		iam:  iamClient,
		opts: opts.normalize(),
	}
}

// Collect gathers a normalized inventory snapshot for the AWS account accessible via the configured clients.
func (c *IAMCollector) Collect(ctx context.Context, profile, region, sinceWindow string) (*model.ScanRun, error) {
	startedAt := c.opts.Now().UTC()

	caller, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
		return c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	})
	if err != nil {
		return nil, fmt.Errorf("sts GetCallerIdentity: %w", err)
	}

	accountID := aws.ToString(caller.Account)
	callerARN := aws.ToString(caller.Arn)

	authSnapshot, err := c.fetchAccountAuthorizationDetails(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam GetAccountAuthorizationDetails: %w", err)
	}

	managedPolicyDocs := indexManagedPolicyDocuments(authSnapshot.policies)
	groupsByName := make(map[string]iamtypes.GroupDetail, len(authSnapshot.groups))
	for _, g := range authSnapshot.groups {
		groupsByName[aws.ToString(g.GroupName)] = g
	}

	identities := make([]model.Identity, 0, len(authSnapshot.roles)+len(authSnapshot.users))
	roleIndices := make([]int, 0, len(authSnapshot.roles))
	userIndices := make([]int, 0, len(authSnapshot.users))

	for _, r := range authSnapshot.roles {
		ident := normalizeRole(r, accountID, managedPolicyDocs, c.opts.OwnerTagKeys)
		roleIndices = append(roleIndices, len(identities))
		identities = append(identities, ident)
	}

	for _, u := range authSnapshot.users {
		ident := normalizeUser(u, accountID, managedPolicyDocs, groupsByName, c.opts.OwnerTagKeys)
		userIndices = append(userIndices, len(identities))
		identities = append(identities, ident)
	}

	var (
		mu       sync.Mutex
		keyIdents []model.Identity
		warnings []string
	)

	addWarning := func(msg string) {
		mu.Lock()
		warnings = append(warnings, msg)
		mu.Unlock()
	}

	// Enrich users (login profile + access keys + service last accessed) and roles (service last accessed)
	// using a bounded worker pool to respect AWS IAM rate limits.
	type task struct {
		idx    int
		isUser bool
	}

	tasks := make([]task, 0, len(roleIndices)+len(userIndices))
	for _, idx := range roleIndices {
		tasks = append(tasks, task{idx: idx, isUser: false})
	}
	for _, idx := range userIndices {
		tasks = append(tasks, task{idx: idx, isUser: true})
	}

	sem := make(chan struct{}, c.opts.MaxConcurrency)
	var wg sync.WaitGroup

	for _, t := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			ident := &identities[t.idx]

			if t.isUser {
				hasLogin, loginErr := c.checkLoginProfile(ctx, ident.Name)
				if loginErr != nil {
					addWarning(fmt.Sprintf("user %s: GetLoginProfile failed: %v", ident.Name, loginErr))
				} else {
					ident.HasConsoleLogin = &hasLogin
				}

				keys, keyIDs, activeKeyIDs, latestKeyUse, keyWarnings := c.collectUserAccessKeys(ctx, ident)
				for _, w := range keyWarnings {
					addWarning(w)
				}
				ident.AccessKeyIDs = keyIDs
				ident.ActiveAccessKeyIDs = activeKeyIDs
				if latestKeyUse != nil && (ident.LastUsed == nil || latestKeyUse.After(*ident.LastUsed)) {
					ts := latestKeyUse.UTC()
					ident.LastUsed = &ts
				}
				if len(keys) > 0 {
					mu.Lock()
					keyIdents = append(keyIdents, keys...)
					mu.Unlock()
				}
			}

			if !c.opts.SkipServiceLastAccessed {
				services, slaErr := c.collectServiceLastAccessed(ctx, ident.ARN)
				if slaErr != nil {
					ident.ServiceLastAccessedError = slaErr.Error()
					addWarning(fmt.Sprintf("%s %s: service last-accessed incomplete: %v", ident.Type, ident.Name, slaErr))
				} else {
					ident.ServicesLastAccessed = services
				}
			}
		}(t)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	identities = append(identities, keyIdents...)
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Type != identities[j].Type {
			return identities[i].Type < identities[j].Type
		}
		if identities[i].Name != identities[j].Name {
			return identities[i].Name < identities[j].Name
		}
		return identities[i].ID < identities[j].ID
	})
	sort.Strings(warnings)

	completedAt := c.opts.Now().UTC()
	return &model.ScanRun{
		ID:               newScanID(accountID, startedAt),
		AccountID:        accountID,
		CallerARN:        callerARN,
		Region:           region,
		Profile:          profile,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		SinceWindow:      sinceWindow,
		CloudTrailStatus: model.CloudTrailStatusUnknown,
		Warnings:         warnings,
		Identities:       identities,
	}, nil
}

type authDetailsSnapshot struct {
	users    []iamtypes.UserDetail
	groups   []iamtypes.GroupDetail
	roles    []iamtypes.RoleDetail
	policies []iamtypes.ManagedPolicyDetail
}

func (c *IAMCollector) fetchAccountAuthorizationDetails(ctx context.Context) (*authDetailsSnapshot, error) {
	snap := &authDetailsSnapshot{}
	var marker *string

	for {
		out, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GetAccountAuthorizationDetailsOutput, error) {
			return c.iam.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
				Marker: marker,
			})
		})
		if err != nil {
			return nil, err
		}

		snap.users = append(snap.users, out.UserDetailList...)
		snap.groups = append(snap.groups, out.GroupDetailList...)
		snap.roles = append(snap.roles, out.RoleDetailList...)
		snap.policies = append(snap.policies, out.Policies...)

		if !out.IsTruncated || out.Marker == nil || aws.ToString(out.Marker) == "" {
			break
		}
		marker = out.Marker
	}

	return snap, nil
}

func (c *IAMCollector) checkLoginProfile(ctx context.Context, userName string) (bool, error) {
	_, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GetLoginProfileOutput, error) {
		return c.iam.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
			UserName: aws.String(userName),
		})
	})
	if err == nil {
		return true, nil
	}
	if IsNoSuchEntityError(err) {
		return false, nil
	}
	return false, err
}

func (c *IAMCollector) collectUserAccessKeys(ctx context.Context, user *model.Identity) ([]model.Identity, []string, []string, *time.Time, []string) {
	var (
		keyMeta  []iamtypes.AccessKeyMetadata
		warnings []string
		marker   *string
	)

	for {
		out, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.ListAccessKeysOutput, error) {
			return c.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: aws.String(user.Name),
				Marker:   marker,
			})
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("user %s: ListAccessKeys failed: %v", user.Name, err))
			return nil, nil, nil, nil, warnings
		}

		keyMeta = append(keyMeta, out.AccessKeyMetadata...)
		if !out.IsTruncated || out.Marker == nil || aws.ToString(out.Marker) == "" {
			break
		}
		marker = out.Marker
	}

	keys := make([]model.Identity, 0, len(keyMeta))
	keyIDs := make([]string, 0, len(keyMeta))
	activeKeyIDs := make([]string, 0, len(keyMeta))
	var latestUse *time.Time

	for _, km := range keyMeta {
		keyID := aws.ToString(km.AccessKeyId)
		if keyID == "" {
			continue
		}
		keyIDs = append(keyIDs, keyID)
		if km.Status == iamtypes.StatusTypeActive {
			activeKeyIDs = append(activeKeyIDs, keyID)
		}

		var (
			lastUsedDate    *time.Time
			lastUsedService string
			lastUsedRegion  string
		)

		lastOut, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GetAccessKeyLastUsedOutput, error) {
			return c.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: aws.String(keyID),
			})
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("key %s (user %s): GetAccessKeyLastUsed failed: %v", keyID, user.Name, err))
		} else if lastOut.AccessKeyLastUsed != nil {
			if lastOut.AccessKeyLastUsed.LastUsedDate != nil {
				ts := lastOut.AccessKeyLastUsed.LastUsedDate.UTC()
				lastUsedDate = &ts
				if latestUse == nil || ts.After(*latestUse) {
					tCopy := ts
					latestUse = &tCopy
				}
			}
			lastUsedService = aws.ToString(lastOut.AccessKeyLastUsed.ServiceName)
			lastUsedRegion = aws.ToString(lastOut.AccessKeyLastUsed.Region)
		}

		var created *time.Time
		if km.CreateDate != nil {
			ts := km.CreateDate.UTC()
			created = &ts
		}

		var ownerCopy *string
		if user.Owner != nil {
			v := *user.Owner
			ownerCopy = &v
		}

		keys = append(keys, model.Identity{
			ID:       user.ARN + "/access-key/" + keyID,
			ARN:      user.ARN,
			Type:     model.TypeKey,
			Name:     keyID,
			Account:  user.Account,
			Created:  created,
			LastUsed: lastUsedDate,
			Tags:     cloneStringMap(user.Tags),
			Owner:    ownerCopy,
			AccessKey: &model.AccessKeyInfo{
				AccessKeyID:     keyID,
				ParentUserName:  user.Name,
				ParentUserARN:   user.ARN,
				Status:          string(km.Status),
				LastUsedService: lastUsedService,
				LastUsedRegion:  lastUsedRegion,
			},
			CloudTrailStatus: model.CloudTrailStatusUnknown,
			AgentLikelihood:  model.LikelihoodNone,
		})
	}

	sort.Strings(keyIDs)
	sort.Strings(activeKeyIDs)
	return keys, keyIDs, activeKeyIDs, latestUse, warnings
}

func (c *IAMCollector) collectServiceLastAccessed(ctx context.Context, arn string) ([]model.ServiceLastAccessed, error) {
	genOut, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
		return c.iam.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
			Arn: aws.String(arn),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("GenerateServiceLastAccessedDetails: %w", err)
	}

	jobID := aws.ToString(genOut.JobId)
	if jobID == "" {
		return nil, fmt.Errorf("GenerateServiceLastAccessedDetails returned empty JobId")
	}

	deadline := c.opts.Now().Add(c.opts.LastAccessedTimeout)
	pollInterval := c.opts.PollInitialInterval

	var firstCompleted *iam.GetServiceLastAccessedDetailsOutput
	for {
		out, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GetServiceLastAccessedDetailsOutput, error) {
			return c.iam.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
				JobId: aws.String(jobID),
			})
		})
		if err != nil {
			return nil, fmt.Errorf("GetServiceLastAccessedDetails: %w", err)
		}

		switch out.JobStatus {
		case iamtypes.JobStatusTypeCompleted:
			firstCompleted = out
		case iamtypes.JobStatusTypeFailed:
			msg := "unknown failure"
			if out.Error != nil && out.Error.Message != nil {
				msg = *out.Error.Message
			}
			return nil, fmt.Errorf("service last-accessed job %s failed: %s", jobID, msg)
		case iamtypes.JobStatusTypeInProgress:
			if c.opts.Now().After(deadline) {
				return nil, fmt.Errorf("service last-accessed job %s timed out after %s", jobID, c.opts.LastAccessedTimeout)
			}
			if err := c.opts.Sleep(ctx, pollInterval); err != nil {
				return nil, err
			}
			pollInterval *= 2
			if pollInterval > c.opts.PollMaxInterval {
				pollInterval = c.opts.PollMaxInterval
			}
			continue
		default:
			return nil, fmt.Errorf("unexpected service last-accessed job status %q", out.JobStatus)
		}
		break
	}

	results := make([]model.ServiceLastAccessed, 0, len(firstCompleted.ServicesLastAccessed))
	appendServices := func(in []iamtypes.ServiceLastAccessed) {
		for _, svc := range in {
			var lastAuth *time.Time
			if svc.LastAuthenticated != nil {
				ts := svc.LastAuthenticated.UTC()
				lastAuth = &ts
			}
			results = append(results, model.ServiceLastAccessed{
				ServiceName:             aws.ToString(svc.ServiceName),
				ServiceNamespace:        aws.ToString(svc.ServiceNamespace),
				LastAuthenticated:       lastAuth,
				LastAuthenticatedRegion: aws.ToString(svc.LastAuthenticatedRegion),
				LastAuthenticatedEntity: aws.ToString(svc.LastAuthenticatedEntity),
			})
		}
	}

	appendServices(firstCompleted.ServicesLastAccessed)
	marker := firstCompleted.Marker
	isTruncated := firstCompleted.IsTruncated

	for isTruncated && marker != nil && aws.ToString(marker) != "" {
		out, err := DoWithRetry(ctx, c.opts.Retry, func(ctx context.Context) (*iam.GetServiceLastAccessedDetailsOutput, error) {
			return c.iam.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
				JobId:  aws.String(jobID),
				Marker: marker,
			})
		})
		if err != nil {
			return nil, fmt.Errorf("GetServiceLastAccessedDetails page: %w", err)
		}
		appendServices(out.ServicesLastAccessed)
		isTruncated = out.IsTruncated
		marker = out.Marker
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ServiceNamespace < results[j].ServiceNamespace
	})
	return results, nil
}

func normalizeRole(r iamtypes.RoleDetail, accountID string, managedDocs map[string]string, ownerTagKeys []string) model.Identity {
	arn := aws.ToString(r.Arn)
	tags := tagsToMap(r.Tags)
	policies := make([]model.PolicyAttachment, 0, len(r.AttachedManagedPolicies)+len(r.RolePolicyList))

	for _, ap := range r.AttachedManagedPolicies {
		pARN := aws.ToString(ap.PolicyArn)
		policies = append(policies, model.PolicyAttachment{
			Name:        aws.ToString(ap.PolicyName),
			ARN:         pARN,
			Kind:        "managed",
			RawDocument: managedDocs[pARN],
		})
	}
	for _, ip := range r.RolePolicyList {
		policies = append(policies, model.PolicyAttachment{
			Name:        aws.ToString(ip.PolicyName),
			Kind:        "inline",
			RawDocument: decodePolicyDocument(aws.ToString(ip.PolicyDocument)),
		})
	}

	var created *time.Time
	if r.CreateDate != nil {
		ts := r.CreateDate.UTC()
		created = &ts
	}
	var lastUsed *time.Time
	if r.RoleLastUsed != nil && r.RoleLastUsed.LastUsedDate != nil {
		ts := r.RoleLastUsed.LastUsedDate.UTC()
		lastUsed = &ts
	}

	var permBoundaryARN, permBoundaryDoc string
	if r.PermissionsBoundary != nil {
		permBoundaryARN = aws.ToString(r.PermissionsBoundary.PermissionsBoundaryArn)
		permBoundaryDoc = managedDocs[permBoundaryARN]
	}
	path := aws.ToString(r.Path)

	return model.Identity{
		ID:                     arn,
		ARN:                    arn,
		Type:                   model.TypeRole,
		Name:                   aws.ToString(r.RoleName),
		Path:                   path,
		IsServiceLinkedRole:    strings.HasPrefix(path, "/aws-service-role/"),
		PermissionsBoundaryARN: permBoundaryARN,
		PermissionsBoundaryDoc: permBoundaryDoc,
		Account:                accountID,
		Created:          created,
		LastUsed:         lastUsed,
		Tags:             tags,
		Owner:            extractOwner(tags, ownerTagKeys),
		TrustPolicyRaw:   decodePolicyDocument(aws.ToString(r.AssumeRolePolicyDocument)),
		Policies:         policies,
		CloudTrailStatus: model.CloudTrailStatusUnknown,
		AgentLikelihood:  model.LikelihoodNone,
	}
}

func normalizeUser(
	u iamtypes.UserDetail,
	accountID string,
	managedDocs map[string]string,
	groupsByName map[string]iamtypes.GroupDetail,
	ownerTagKeys []string,
) model.Identity {
	arn := aws.ToString(u.Arn)
	tags := tagsToMap(u.Tags)
	policies := make([]model.PolicyAttachment, 0, len(u.AttachedManagedPolicies)+len(u.UserPolicyList))

	for _, ap := range u.AttachedManagedPolicies {
		pARN := aws.ToString(ap.PolicyArn)
		policies = append(policies, model.PolicyAttachment{
			Name:        aws.ToString(ap.PolicyName),
			ARN:         pARN,
			Kind:        "managed",
			RawDocument: managedDocs[pARN],
		})
	}
	for _, ip := range u.UserPolicyList {
		policies = append(policies, model.PolicyAttachment{
			Name:        aws.ToString(ip.PolicyName),
			Kind:        "inline",
			RawDocument: decodePolicyDocument(aws.ToString(ip.PolicyDocument)),
		})
	}

	groups := make([]string, 0, len(u.GroupList))
	for _, groupName := range u.GroupList {
		groups = append(groups, groupName)
		if g, ok := groupsByName[groupName]; ok {
			for _, ap := range g.AttachedManagedPolicies {
				pARN := aws.ToString(ap.PolicyArn)
				policies = append(policies, model.PolicyAttachment{
					Name:        aws.ToString(ap.PolicyName),
					ARN:         pARN,
					Kind:        "group_managed",
					SourceGroup: groupName,
					RawDocument: managedDocs[pARN],
				})
			}
			for _, ip := range g.GroupPolicyList {
				policies = append(policies, model.PolicyAttachment{
					Name:        aws.ToString(ip.PolicyName),
					Kind:        "group_inline",
					SourceGroup: groupName,
					RawDocument: decodePolicyDocument(aws.ToString(ip.PolicyDocument)),
				})
			}
		}
	}
	sort.Strings(groups)

	var created *time.Time
	if u.CreateDate != nil {
		ts := u.CreateDate.UTC()
		created = &ts
	}

	var permBoundaryARN, permBoundaryDoc string
	if u.PermissionsBoundary != nil {
		permBoundaryARN = aws.ToString(u.PermissionsBoundary.PermissionsBoundaryArn)
		permBoundaryDoc = managedDocs[permBoundaryARN]
	}

	return model.Identity{
		ID:                     arn,
		ARN:                    arn,
		Type:                   model.TypeUser,
		Name:                   aws.ToString(u.UserName),
		Path:                   aws.ToString(u.Path),
		PermissionsBoundaryARN: permBoundaryARN,
		PermissionsBoundaryDoc: permBoundaryDoc,
		Account:                accountID,
		Created:          created,
		Tags:             tags,
		Owner:            extractOwner(tags, ownerTagKeys),
		Groups:           groups,
		Policies:         policies,
		CloudTrailStatus: model.CloudTrailStatusUnknown,
		AgentLikelihood:  model.LikelihoodNone,
	}
}

func indexManagedPolicyDocuments(policies []iamtypes.ManagedPolicyDetail) map[string]string {
	docs := make(map[string]string, len(policies))
	for _, p := range policies {
		arn := aws.ToString(p.Arn)
		if arn == "" {
			continue
		}
		defaultVer := aws.ToString(p.DefaultVersionId)
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion || (defaultVer != "" && aws.ToString(v.VersionId) == defaultVer) {
				docs[arn] = decodePolicyDocument(aws.ToString(v.Document))
				break
			}
		}
	}
	return docs
}

// decodePolicyDocument safely URL-decodes IAM policy JSON strings.
// AWS IAM returns policy documents percent-encoded; already-decoded JSON passes through unchanged.
func decodePolicyDocument(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		return trimmed
	}
	decoded, err := url.QueryUnescape(trimmed)
	if err != nil {
		return trimmed
	}
	return strings.TrimSpace(decoded)
}

func tagsToMap(tags []iamtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		k := aws.ToString(t.Key)
		if k != "" {
			out[k] = aws.ToString(t.Value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractOwner(tags map[string]string, ownerKeys []string) *string {
	if len(tags) == 0 || len(ownerKeys) == 0 {
		return nil
	}
	lowerTags := make(map[string]string, len(tags))
	for k, v := range tags {
		lowerTags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	for _, candidate := range ownerKeys {
		if val, ok := lowerTags[strings.ToLower(strings.TrimSpace(candidate))]; ok && val != "" {
			v := val
			return &v
		}
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newScanID(accountID string, started time.Time) string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf("scan-%s-%s-%s", accountID, started.UTC().Format("20060102T150405Z"), hex.EncodeToString(buf[:]))
}
