package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/devel0mer/nhilens/internal/collect"
	"github.com/devel0mer/nhilens/internal/detect"
	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
	"github.com/devel0mer/nhilens/internal/rules"
	"github.com/devel0mer/nhilens/internal/score"
	"github.com/devel0mer/nhilens/internal/suppress"
)

type accountWorkerResult struct {
	summary       model.AccountScanSummary
	run           *model.ScanRun
	scpCount      int
	parseErrCount int
	warnings      []string
}

func runMultiAccountScan(
	ctx context.Context,
	opts *ScanOptions,
	deps ScanDeps,
	suppFile *suppress.File,
	fileSCPs []policy.NamedPolicy,
	nowFn func() time.Time,
) (*model.ScanRun, error) {
	startedAt := nowFn().UTC()

	baseSTS, baseIAM, baseCT, err := deps.NewClients(ctx, opts.Profile, opts.Region)
	if err != nil {
		return nil, err
	}

	callerOut, err := collect.DoWithRetry(ctx, collect.DefaultRetryPolicy(), func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
		return baseSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	})
	if err != nil {
		return nil, fmt.Errorf("sts GetCallerIdentity: %w", err)
	}
	callerAccountID := strings.TrimSpace(aws.ToString(callerOut.Account))
	callerARN := strings.TrimSpace(aws.ToString(callerOut.Arn))
	partition := collect.PartitionFromARN(callerARN)

	var (
		orgID       string
		targets     []collect.OrgAccount
		orgWarnings []string
		scpResolver *collect.SCPResolver
	)

	if opts.Org {
		orgFactory := deps.NewOrganizationsClient
		if orgFactory == nil {
			orgFactory = collect.NewOrganizationsClient
		}
		orgClient, orgErr := orgFactory(ctx, opts.Profile, opts.Region)
		if orgErr != nil {
			return nil, orgErr
		}

		discOpts := collect.OrgDiscoveryOptions{
			IncludeAccounts: opts.Accounts,
			ExcludeAccounts: opts.ExcludeAccounts,
			Retry:           collect.DefaultRetryPolicy(),
		}
		if deps.CollectorHooks != nil {
			var hookProbe collect.Options
			deps.CollectorHooks(&hookProbe)
			if hookProbe.Sleep != nil {
				discOpts.Retry.Sleep = hookProbe.Sleep
			}
		}

		disc, discErr := collect.DiscoverOrgAccounts(ctx, orgClient, discOpts)
		if discErr != nil {
			return nil, discErr
		}
		orgID = disc.OrganizationID
		targets = disc.Accounts
		orgWarnings = append(orgWarnings, disc.Warnings...)

		if !opts.SkipOrgSCPs {
			scpResolver = collect.NewSCPResolver(orgClient, disc.MasterAccountID, discOpts.Retry)
		}
	} else {
		excludeSet := make(map[string]struct{}, len(opts.ExcludeAccounts))
		for _, ex := range opts.ExcludeAccounts {
			excludeSet[ex] = struct{}{}
		}
		for _, acctID := range opts.Accounts {
			if _, skip := excludeSet[acctID]; skip {
				continue
			}
			targets = append(targets, collect.OrgAccount{ID: acctID, Status: "ACTIVE"})
		}
		sort.Slice(targets, func(i, j int) bool {
			return targets[i].ID < targets[j].ID
		})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no active target AWS accounts matched the specified filters")
	}

	// Verify --assume-role-name is supplied whenever scanning any account other than the caller's own account.
	for _, acct := range targets {
		if acct.ID != callerAccountID && strings.TrimSpace(opts.AssumeRoleName) == "" {
			return nil, fmt.Errorf("--assume-role-name is required to scan member account %s (e.g. --assume-role-name nhilens-readonly)", acct.ID)
		}
	}

	baseCTFactory := deps.NewCloudTrailClient
	if baseCTFactory == nil {
		baseCTFactory = collect.NewCloudTrailClientForRegion
	}
	assumeFn := deps.AssumeAccount
	if assumeFn == nil {
		assumeFn = collect.AssumeAccountClients
	}

	workers := opts.AccountConcurrency
	if workers <= 0 {
		workers = 4
	}
	workers = min(workers, len(targets))

	results := make([]accountWorkerResult, len(targets))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, acct := range targets {
		wg.Add(1)
		go func(idx int, acct collect.OrgAccount) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = accountWorkerResult{
					summary: model.AccountScanSummary{
						AccountID:   acct.ID,
						AccountName: acct.Name,
						Status:      "failed",
						Error:       ctx.Err().Error(),
					},
					warnings: []string{fmt.Sprintf("[account %s] scan canceled: %v", acct.ID, ctx.Err())},
				}
				return
			}
			defer func() { <-sem }()

			results[idx] = scanOneTargetAccount(
				ctx, acct, callerAccountID, partition,
				opts, deps, suppFile, fileSCPs, scpResolver,
				baseSTS, baseIAM, baseCT, baseCTFactory, assumeFn, nowFn,
			)
		}(i, acct)
	}
	wg.Wait()

	return mergeMultiAccountResults(orgID, callerARN, opts, startedAt, nowFn().UTC(), orgWarnings, results), nil
}

func scanOneTargetAccount(
	ctx context.Context,
	acct collect.OrgAccount,
	callerAccountID string,
	partition string,
	opts *ScanOptions,
	deps ScanDeps,
	suppFile *suppress.File,
	fileSCPs []policy.NamedPolicy,
	scpResolver *collect.SCPResolver,
	baseSTS collect.STSClient,
	baseIAM collect.IAMClient,
	baseCT collect.CloudTrailClient,
	baseCTFactory func(ctx context.Context, profile, region string) (collect.CloudTrailClient, error),
	assumeFn func(ctx context.Context, profile, primaryRegion, targetAccountID string, aOpts collect.AssumeRoleOptions) (*collect.AccountClients, error),
	nowFn func() time.Time,
) accountWorkerResult {
	var (
		stsClient collect.STSClient
		iamClient collect.IAMClient
		ctClient  collect.CloudTrailClient
		ctFactory func(ctx context.Context, region string) (collect.CloudTrailClient, error)
	)

	if acct.ID == callerAccountID {
		stsClient = baseSTS
		iamClient = baseIAM
		ctClient = baseCT
		ctFactory = func(ctx context.Context, region string) (collect.CloudTrailClient, error) {
			return baseCTFactory(ctx, opts.Profile, region)
		}
	} else {
		assumed, err := assumeFn(ctx, opts.Profile, opts.Region, acct.ID, collect.AssumeRoleOptions{
			RoleName:   opts.AssumeRoleName,
			ExternalID: opts.ExternalID,
			Partition:  partition,
		})
		if err != nil {
			return accountWorkerResult{
				summary: model.AccountScanSummary{
					AccountID:   acct.ID,
					AccountName: acct.Name,
					Status:      "failed",
					Error:       err.Error(),
				},
				warnings: []string{fmt.Sprintf("[account %s] assume role failed: %v", acct.ID, err)},
			}
		}
		stsClient = assumed.STS
		iamClient = assumed.IAM
		ctClient = assumed.PrimaryCloudTrail
		ctFactory = assumed.CloudTrailForRegion
	}

	// Combine optional --scp-file policies with automatic Organizations SCPs for this account.
	accountSCPs := make([]policy.NamedPolicy, 0, len(fileSCPs))
	accountSCPs = append(accountSCPs, fileSCPs...)
	scpCount := len(fileSCPs)
	var extraWarnings []string

	if scpResolver != nil {
		orgSCPs, uniqueOrgSCPs, scpWarnings := scpResolver.ResolveForAccount(ctx, acct.ID)
		accountSCPs = append(accountSCPs, orgSCPs...)
		scpCount += uniqueOrgSCPs
		extraWarnings = append(extraWarnings, scpWarnings...)
	}

	run, parseErrCount, err := executeAccountPipeline(
		ctx, opts, deps, suppFile, accountSCPs, scpCount,
		stsClient, iamClient, ctClient, ctFactory, nowFn,
	)
	if err != nil {
		return accountWorkerResult{
			summary: model.AccountScanSummary{
				AccountID:   acct.ID,
				AccountName: acct.Name,
				Status:      "failed",
				SCPCount:    scpCount,
				Error:       err.Error(),
			},
			warnings: append(extraWarnings, fmt.Sprintf("[account %s] scan failed: %v", acct.ID, err)),
		}
	}

	// Stamp friendly Organizations account name onto every identity.
	if acct.Name != "" {
		for i := range run.Identities {
			run.Identities[i].AccountName = acct.Name
		}
	}

	// Prefix per-account warnings with account context so rollup logs stay actionable.
	prefixedWarnings := make([]string, 0, len(extraWarnings)+len(run.Warnings))
	prefixedWarnings = append(prefixedWarnings, extraWarnings...)
	for _, w := range run.Warnings {
		if strings.HasPrefix(w, "[account ") {
			prefixedWarnings = append(prefixedWarnings, w)
		} else {
			prefixedWarnings = append(prefixedWarnings, fmt.Sprintf("[account %s] %s", acct.ID, w))
		}
	}

	sevCounts := score.SummarizeSeverities(run.Identities)
	totalFindings := sevCounts[model.SeverityCritical] +
		sevCounts[model.SeverityHigh] +
		sevCounts[model.SeverityMedium] +
		sevCounts[model.SeverityLow] +
		sevCounts[model.SeverityInfo]
	likelyCount := 0
	for _, id := range run.Identities {
		if id.AgentLikelihood == model.LikelihoodLikely {
			likelyCount++
		}
	}

	acctStatus := "ok"
	if run.Coverage != nil && run.Coverage.Status == model.CoverageStatusPartial {
		acctStatus = "partial"
	}

	return accountWorkerResult{
		summary: model.AccountScanSummary{
			AccountID:     acct.ID,
			AccountName:   acct.Name,
			Status:        acctStatus,
			Identities:    len(run.Identities),
			AgentLikely:   likelyCount,
			FindingsTotal: totalFindings,
			CriticalCount: sevCounts[model.SeverityCritical],
			HighCount:     sevCounts[model.SeverityHigh],
			SCPCount:      scpCount,
		},
		run:           run,
		scpCount:      scpCount,
		parseErrCount: parseErrCount,
		warnings:      prefixedWarnings,
	}
}

func executeAccountPipeline(
	ctx context.Context,
	opts *ScanOptions,
	deps ScanDeps,
	suppFile *suppress.File,
	scpPolicies []policy.NamedPolicy,
	scpCount int,
	stsClient collect.STSClient,
	iamClient collect.IAMClient,
	ctClient collect.CloudTrailClient,
	ctFactory func(ctx context.Context, region string) (collect.CloudTrailClient, error),
	nowFn func() time.Time,
) (*model.ScanRun, int, error) {
	cOpts := collect.Options{
		OwnerTagKeys:              opts.Config.AgentDetection.OwnerTagKeys,
		MaxConcurrency:            opts.Config.AWS.MaxConcurrency,
		SkipServiceLastAccessed:   opts.SkipServiceLastAccessed,
		IncludeServiceLinkedRoles: opts.IncludeServiceLinkedRoles,
		Now:                       nowFn,
	}
	if deps.CollectorHooks != nil {
		deps.CollectorHooks(&cOpts)
	}

	collector := collect.NewIAMCollector(stsClient, iamClient, cOpts)
	run, err := collector.Collect(ctx, opts.Profile, opts.Region, opts.SinceRaw)
	if err != nil {
		return nil, 0, err
	}

	ctOpts := collect.CloudTrailOptions{
		Since:          opts.Since,
		MaxEvents:      opts.MaxEvents,
		MaxConcurrency: opts.Config.AWS.MaxConcurrency,
		Now:            nowFn,
	}
	if deps.CloudTrailHooks != nil {
		deps.CloudTrailHooks(&ctOpts)
	}

	targetRegions := opts.Regions
	if len(targetRegions) == 0 {
		targetRegions = []string{opts.Region}
	}
	regionClients := make([]collect.RegionCloudTrailClient, 0, len(targetRegions))
	for _, r := range targetRegions {
		if r == opts.Region || len(targetRegions) == 1 {
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: ctClient})
			continue
		}
		if opts.MaxEvents == 0 {
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: nil})
			continue
		}
		if ctFactory == nil {
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: nil})
			continue
		}
		regionalCT, ctErr := ctFactory(ctx, r)
		if ctErr != nil {
			run.Warnings = append(run.Warnings, fmt.Sprintf("[%s] failed to initialize CloudTrail client: %v", r, ctErr))
			regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: nil})
			continue
		}
		regionClients = append(regionClients, collect.RegionCloudTrailClient{Region: r, Client: regionalCT})
	}
	collect.EnrichRegions(ctx, regionClients, ctOpts, run)

	parseWarnings := policy.ParseAll(run.Identities)
	if len(parseWarnings) > 0 {
		run.Warnings = append(run.Warnings, parseWarnings...)
		sort.Strings(run.Warnings)
	}

	nowUTC := nowFn().UTC()

	detect.ClassifyAll(run.Identities, opts.Config)
	rules.EvaluateAllWithContext(run.Identities, rules.Context{
		Config:      opts.Config,
		Now:         nowUTC,
		SCPPolicies: scpPolicies,
	})
	if suppFile != nil {
		suppress.Apply(run, suppFile, nowUTC)
	}
	score.ScoreAll(run.Identities, opts.Config)
	finalizeScanCoverage(run, opts, scpCount, len(parseWarnings))

	return run, len(parseWarnings), nil
}

func mergeMultiAccountResults(
	orgID string,
	callerARN string,
	opts *ScanOptions,
	startedAt time.Time,
	completedAt time.Time,
	orgWarnings []string,
	results []accountWorkerResult,
) *model.ScanRun {
	accountLabel := fmt.Sprintf("multi-account(%d)", len(results))
	idPrefix := "multi"
	if orgID != "" {
		accountLabel = "org:" + orgID
		idPrefix = orgID
	}

	targetRegions := opts.Regions
	if len(targetRegions) == 0 {
		targetRegions = []string{opts.Region}
	}

	rollup := &model.ScanRun{
		ID:             buildMultiAccountScanID(idPrefix, startedAt),
		AccountID:      accountLabel,
		OrganizationID: orgID,
		CallerARN:      callerARN,
		Region:         opts.Region,
		Regions:        append([]string(nil), targetRegions...),
		Profile:        opts.Profile,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		SinceWindow:    opts.SinceRaw,
		Warnings:       append([]string(nil), orgWarnings...),
	}

	cov := &model.ScanCoverage{
		AccountID:            accountLabel,
		OrganizationID:       orgID,
		Region:               opts.Region,
		RegionsScanned:       append([]string(nil), targetRegions...),
		SinceWindow:          opts.SinceRaw,
		CloudTrailEventLimit: opts.MaxEvents,
		AccessAdvisorSkipped: opts.SkipServiceLastAccessed,
	}

	regionOrder := append([]string(nil), targetRegions...)
	regionAgg := make(map[string]*model.RegionCloudTrailCoverage, len(regionOrder))
	regionOK := make(map[string]int, len(regionOrder))
	regionTotal := make(map[string]int, len(regionOrder))
	for _, r := range regionOrder {
		regionAgg[r] = &model.RegionCloudTrailCoverage{Region: r, Status: model.CloudTrailStatusUnknown}
	}

	var (
		ctOKAccounts      int
		ctUnknownAccounts int
		ctDisabledCount   int
		succeededAccounts int
		skippedSet        = make(map[string]struct{})
	)

	for _, res := range results {
		rollup.Accounts = append(rollup.Accounts, res.summary)
		rollup.Warnings = append(rollup.Warnings, res.warnings...)

		if res.summary.Status == "failed" || res.run == nil {
			cov.AccountsFailed++
			cov.CollectionErrorCount++
			continue
		}

		succeededAccounts++
		cov.AccountsScanned++
		rollup.Identities = append(rollup.Identities, res.run.Identities...)
		rollup.CloudTrailEventCount += res.run.CloudTrailEventCount
		rollup.SuppressedFindingCount += res.run.SuppressedFindingCount

		switch res.run.CloudTrailStatus {
		case model.CloudTrailStatusOK:
			ctOKAccounts++
		case model.CloudTrailStatusUnknown:
			ctUnknownAccounts++
		case model.CloudTrailStatusDisabled:
			ctDisabledCount++
		}

		if ac := res.run.Coverage; ac != nil {
			cov.CloudTrailEventsAnalyzed += ac.CloudTrailEventsAnalyzed
			if ac.CloudTrailTruncated {
				cov.CloudTrailTruncated = true
			}
			cov.LoginProfileChecked += ac.LoginProfileChecked
			cov.LoginProfileFailed += ac.LoginProfileFailed
			cov.AccessKeyListFailed += ac.AccessKeyListFailed
			cov.AccessKeyLastUsedFailed += ac.AccessKeyLastUsedFailed
			cov.AccessAdvisorAttempted += ac.AccessAdvisorAttempted
			cov.AccessAdvisorSucceeded += ac.AccessAdvisorSucceeded
			cov.AccessAdvisorFailed += ac.AccessAdvisorFailed
			cov.AccessAdvisorSkippedSLR += ac.AccessAdvisorSkippedSLR
			cov.AccessAdvisorSkippedNoPolicy += ac.AccessAdvisorSkippedNoPolicy
			cov.ServiceLinkedRolesExcluded += ac.ServiceLinkedRolesExcluded
			cov.PolicyParseErrors += ac.PolicyParseErrors
			cov.SCPPoliciesLoaded += ac.SCPPoliciesLoaded
			cov.PartialIdentities += ac.PartialIdentities
			cov.CollectionErrorCount += ac.CollectionErrorCount
			for _, sk := range ac.SkippedChecks {
				if !strings.Contains(sk, "service-linked role") {
					skippedSet[sk] = struct{}{}
				}
			}
			for _, rc := range ac.CloudTrailRegions {
				agg, ok := regionAgg[rc.Region]
				if !ok {
					agg = &model.RegionCloudTrailCoverage{Region: rc.Region, Status: model.CloudTrailStatusUnknown}
					regionAgg[rc.Region] = agg
					regionOrder = append(regionOrder, rc.Region)
				}
				regionTotal[rc.Region]++
				agg.EventsAnalyzed += rc.EventsAnalyzed
				if rc.Truncated {
					agg.Truncated = true
				}
				if rc.Error != "" && agg.Error == "" {
					agg.Error = rc.Error
				}
				if rc.Status == model.CloudTrailStatusOK {
					regionOK[rc.Region]++
				}
			}
		}
	}

	// Finalize aggregate CloudTrail status across accounts.
	switch {
	case opts.MaxEvents == 0 || (succeededAccounts > 0 && ctDisabledCount == succeededAccounts):
		rollup.CloudTrailStatus = model.CloudTrailStatusDisabled
	case succeededAccounts == 0 || ctUnknownAccounts == succeededAccounts:
		rollup.CloudTrailStatus = model.CloudTrailStatusUnknown
	case ctOKAccounts == succeededAccounts && cov.AccountsFailed == 0:
		rollup.CloudTrailStatus = model.CloudTrailStatusOK
	default:
		rollup.CloudTrailStatus = model.CloudTrailStatusPartial
	}
	cov.CloudTrailStatus = rollup.CloudTrailStatus

	for _, r := range regionOrder {
		agg := regionAgg[r]
		tot := regionTotal[r]
		switch {
		case opts.MaxEvents == 0:
			agg.Status = model.CloudTrailStatusDisabled
		case tot == 0:
			agg.Status = model.CloudTrailStatusUnknown
		case regionOK[r] == tot && agg.Error == "" && !agg.Truncated:
			agg.Status = model.CloudTrailStatusOK
		case agg.EventsAnalyzed == 0 && agg.Error != "":
			agg.Status = model.CloudTrailStatusUnknown
		default:
			agg.Status = model.CloudTrailStatusPartial
		}
		cov.CloudTrailRegions = append(cov.CloudTrailRegions, *agg)
	}

	cov.AccountSummaries = append([]model.AccountScanSummary(nil), rollup.Accounts...)
	if cov.ServiceLinkedRolesExcluded > 0 {
		skippedSet[fmt.Sprintf("%d AWS service-linked role(s) excluded by default", cov.ServiceLinkedRolesExcluded)] = struct{}{}
	}
	if len(skippedSet) > 0 {
		skipped := make([]string, 0, len(skippedSet))
		for s := range skippedSet {
			skipped = append(skipped, s)
		}
		sort.Strings(skipped)
		cov.SkippedChecks = skipped
	}

	isPartial := cov.AccountsFailed > 0 ||
		cov.CollectionErrorCount > 0 ||
		cov.PartialIdentities > 0 ||
		cov.AccessAdvisorSkipped ||
		cov.CloudTrailTruncated ||
		cov.CloudTrailStatus == model.CloudTrailStatusPartial ||
		cov.CloudTrailStatus == model.CloudTrailStatusUnknown ||
		cov.CloudTrailStatus == model.CloudTrailStatusDisabled
	if isPartial {
		cov.Status = model.CoverageStatusPartial
	} else {
		cov.Status = model.CoverageStatusComplete
	}
	rollup.Coverage = cov

	// Deterministically rank all identities across accounts (highest risk first).
	sort.Slice(rollup.Identities, func(i, j int) bool {
		if rollup.Identities[i].RiskScore != rollup.Identities[j].RiskScore {
			return rollup.Identities[i].RiskScore > rollup.Identities[j].RiskScore
		}
		if len(rollup.Identities[i].Findings) != len(rollup.Identities[j].Findings) {
			return len(rollup.Identities[i].Findings) > len(rollup.Identities[j].Findings)
		}
		if rollup.Identities[i].Account != rollup.Identities[j].Account {
			return rollup.Identities[i].Account < rollup.Identities[j].Account
		}
		if rollup.Identities[i].Type != rollup.Identities[j].Type {
			return rollup.Identities[i].Type < rollup.Identities[j].Type
		}
		if rollup.Identities[i].Name != rollup.Identities[j].Name {
			return rollup.Identities[i].Name < rollup.Identities[j].Name
		}
		return rollup.Identities[i].ID < rollup.Identities[j].ID
	})

	sort.Strings(rollup.Warnings)
	return rollup
}

func buildMultiAccountScanID(prefix string, ts time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("scan-%s-%s-%s", prefix, ts.UTC().Format("20060102T150405Z"), hex.EncodeToString(b[:]))
}

func parseAndValidateAccountIDs(flagName string, raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		for _, part := range strings.Split(entry, ",") {
			acct := strings.TrimSpace(part)
			if acct == "" {
				continue
			}
			if !collect.IsValidAccountID(acct) {
				return nil, fmt.Errorf("invalid %s entry %q (expected 12-digit AWS account ID)", flagName, part)
			}
			if _, dup := seen[acct]; dup {
				continue
			}
			seen[acct] = struct{}{}
			out = append(out, acct)
		}
	}
	return out, nil
}
