package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/devel0mer/nhilens/internal/model"
)

const (
	// maxCloudTrailHistoryWindow reflects AWS CloudTrail Event History's 90-day retention limit.
	maxCloudTrailHistoryWindow = 90 * 24 * time.Hour
	// activitySummaryWindowDays defines the rolling window for per-identity 30-day activity summaries.
	activitySummaryWindowDays = 30
	// maxCloudTrailPageSize is the AWS LookupEvents MaxResults ceiling (1..50).
	maxCloudTrailPageSize = 50
	// maxRecentEventNamesPerIdentity caps stored action summaries per identity.
	maxRecentEventNamesPerIdentity = 10
	// maxObservedUserAgents caps stored distinct userAgent strings per identity.
	maxObservedUserAgents = 10
	// maxUserAgentLen bounds long raw CloudTrail userAgent headers.
	maxUserAgentLen = 120
	// maxActivityTopItems caps top services and top APIs stored in Activity30d.
	maxActivityTopItems = 5
	// defaultCloudTrailConcurrency bounds simultaneous regional LookupEvents workers.
	defaultCloudTrailConcurrency = 5
)

// CloudTrailOptions configures read-only CloudTrail LookupEvents attribution.
type CloudTrailOptions struct {
	Since              time.Duration
	MaxEvents          int // Per-region event cap (0 disables CloudTrail lookup).
	MaxConcurrency     int
	Retry              RetryPolicy
	MinRequestInterval time.Duration
	Sleep              func(ctx context.Context, d time.Duration) error
	Now                func() time.Time
}

func (o CloudTrailOptions) normalize() CloudTrailOptions {
	out := o
	if out.Since <= 0 {
		out.Since = maxCloudTrailHistoryWindow
	}
	if out.MaxConcurrency <= 0 {
		out.MaxConcurrency = defaultCloudTrailConcurrency
	}
	out.Retry = out.Retry.normalize()
	// CloudTrail LookupEvents is rate-limited to 2 requests/second per account per region.
	if out.MinRequestInterval == 0 {
		out.MinRequestInterval = 550 * time.Millisecond
	}
	if out.MinRequestInterval < 0 {
		out.MinRequestInterval = 0
	}
	if out.Sleep == nil {
		out.Sleep = out.Retry.Sleep
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	return out
}

// RegionCloudTrailClient pairs an AWS region identifier with its regional CloudTrail client.
type RegionCloudTrailClient struct {
	Region string
	Client CloudTrailClient
}

// CloudTrailCollector enriches normalized identities with best-effort CloudTrail management event attribution.
type CloudTrailCollector struct {
	client CloudTrailClient
	opts   CloudTrailOptions
}

// NewCloudTrailCollector constructs a single-region CloudTrail attribution collector.
func NewCloudTrailCollector(client CloudTrailClient, opts CloudTrailOptions) *CloudTrailCollector {
	return &CloudTrailCollector{
		client: client,
		opts:   opts.normalize(),
	}
}

type ctEventPayload struct {
	EventSource     string `json:"eventSource"`
	EventName       string `json:"eventName"`
	SourceIPAddress string `json:"sourceIPAddress"`
	UserAgent       string `json:"userAgent"`
	UserIdentity    struct {
		Type           string `json:"type"`
		ARN            string `json:"arn"`
		AccessKeyID    string `json:"accessKeyId"`
		UserName       string `json:"userName"`
		SessionContext *struct {
			SessionIssuer *struct {
				Type     string `json:"type"`
				ARN      string `json:"arn"`
				UserName string `json:"userName"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

type identityTrailAcc struct {
	ips         map[string]struct{}
	actions     map[string]int
	userAgents  map[string]int
	count       int
	lastTime    *time.Time
	count30d    int
	services30d map[string]int
	apis30d     map[string]int
}

type regionFetchResult struct {
	coverage model.RegionCloudTrailCoverage
	events   []cttypes.Event
	warnings []string
}

// Enrich queries CloudTrail management events for the scan's primary region and attributes valid
// source IPs, userAgent traces, 30-day top service/API summaries, recent actions, and fresher
// last-used timestamps to matching identities.
//
// Errors (such as AccessDeniedException) degrade gracefully to CloudTrailStatusUnknown with a
// non-fatal warning so IAM auditing still completes cleanly.
func (c *CloudTrailCollector) Enrich(ctx context.Context, run *model.ScanRun) {
	if run == nil {
		return
	}
	EnrichRegions(ctx, []RegionCloudTrailClient{{Region: run.Region, Client: c.client}}, c.opts, run)
}

// EnrichRegions queries CloudTrail management events concurrently across one or more AWS regions
// (each pacing its own per-region 2 req/s AWS rate limit independently) and merges source IPs,
// userAgent traces, 30-day activity, recent actions, and last-used timestamps onto each identity.
// Events are deduplicated by EventId when present so cross-region/global events are never double-counted.
func EnrichRegions(ctx context.Context, clients []RegionCloudTrailClient, opts CloudTrailOptions, run *model.ScanRun) {
	if run == nil {
		return
	}
	normOpts := opts.normalize()

	if len(clients) == 0 {
		clients = []RegionCloudTrailClient{{Region: run.Region, Client: nil}}
	}

	regionsScanned := make([]string, 0, len(clients))
	for _, rc := range clients {
		reg := strings.TrimSpace(rc.Region)
		if reg != "" {
			regionsScanned = append(regionsScanned, reg)
		}
	}

	if run.Coverage == nil {
		run.Coverage = &model.ScanCoverage{
			AccountID:   run.AccountID,
			Region:      run.Region,
			SinceWindow: run.SinceWindow,
		}
	}
	run.Coverage.CloudTrailEventLimit = normOpts.MaxEvents
	if len(regionsScanned) > 0 {
		run.Regions = regionsScanned
		run.Coverage.RegionsScanned = regionsScanned
		if strings.TrimSpace(run.Region) == "" {
			run.Region = regionsScanned[0]
			run.Coverage.Region = regionsScanned[0]
		}
	}

	if normOpts.MaxEvents == 0 {
		setCloudTrailStatus(run, model.CloudTrailStatusDisabled)
		run.Coverage.CloudTrailStatus = model.CloudTrailStatusDisabled
		regionCovs := make([]model.RegionCloudTrailCoverage, 0, len(clients))
		for _, rc := range clients {
			regionCovs = append(regionCovs, model.RegionCloudTrailCoverage{
				Region: rc.Region,
				Status: model.CloudTrailStatusDisabled,
			})
		}
		run.Coverage.CloudTrailRegions = regionCovs
		return
	}

	now := normOpts.Now().UTC()
	since := normOpts.Since
	if since > maxCloudTrailHistoryWindow {
		since = maxCloudTrailHistoryWindow
		run.Warnings = append(run.Warnings, "CloudTrail Event History retains up to 90 days; clamped --since window to 90d")
	}
	startTime := now.Add(-since)
	cutoff30d := now.Add(-time.Duration(activitySummaryWindowDays) * 24 * time.Hour)

	multiRegion := len(clients) > 1
	results := make([]regionFetchResult, len(clients))

	workers := min(normOpts.MaxConcurrency, len(clients))
	if workers <= 1 {
		for i, rc := range clients {
			results[i] = fetchRegionEvents(ctx, rc, normOpts, startTime, now, multiRegion)
		}
	} else {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i, rc := range clients {
			wg.Add(1)
			go func(idx int, rc RegionCloudTrailClient) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					results[idx] = regionFetchResult{
						coverage: model.RegionCloudTrailCoverage{
							Region: rc.Region,
							Status: model.CloudTrailStatusUnknown,
							Error:  ctx.Err().Error(),
						},
						warnings: []string{formatRegionWarning(rc.Region, multiRegion, fmt.Sprintf("CloudTrail lookup interrupted: %v", ctx.Err()))},
					}
					return
				}
				defer func() { <-sem }()
				results[idx] = fetchRegionEvents(ctx, rc, normOpts, startTime, now, multiRegion)
			}(i, rc)
		}
		wg.Wait()
	}

	roleByARN := make(map[string]int)
	roleByName := make(map[string]int)
	userByARN := make(map[string]int)
	keyByID := make(map[string]int)

	for i := range run.Identities {
		id := &run.Identities[i]
		switch id.Type {
		case model.TypeRole:
			roleByARN[id.ARN] = i
			roleByName[id.Name] = i
		case model.TypeUser:
			userByARN[id.ARN] = i
		case model.TypeKey:
			if id.AccessKey != nil && id.AccessKey.AccessKeyID != "" {
				keyByID[id.AccessKey.AccessKeyID] = i
			} else if id.Name != "" {
				keyByID[id.Name] = i
			}
		}
	}

	acc := make(map[int]*identityTrailAcc)
	getAcc := func(idx int) *identityTrailAcc {
		a, ok := acc[idx]
		if !ok {
			a = &identityTrailAcc{
				ips:         make(map[string]struct{}),
				actions:     make(map[string]int),
				userAgents:  make(map[string]int),
				services30d: make(map[string]int),
				apis30d:     make(map[string]int),
			}
			acc[idx] = a
		}
		return a
	}

	var (
		totalFetched int
		okCount      int
		unknownCount int
		anyTruncated bool
		seenEventIDs = make(map[string]struct{})
		regionCovs   = make([]model.RegionCloudTrailCoverage, 0, len(results))
	)

	for _, res := range results {
		regionCovs = append(regionCovs, res.coverage)
		run.Warnings = append(run.Warnings, res.warnings...)
		if res.coverage.Truncated {
			anyTruncated = true
		}
		switch res.coverage.Status {
		case model.CloudTrailStatusOK:
			okCount++
		case model.CloudTrailStatusUnknown:
			unknownCount++
		}

		for _, ev := range res.events {
			if evID := strings.TrimSpace(aws.ToString(ev.EventId)); evID != "" {
				if _, dup := seenEventIDs[evID]; dup {
					continue
				}
				seenEventIDs[evID] = struct{}{}
			}
			totalFetched++
			attributeEvent(ev, cutoff30d, roleByARN, roleByName, userByARN, keyByID, getAcc)
		}
	}

	status := model.CloudTrailStatusPartial
	switch {
	case len(results) == 0 || unknownCount == len(results):
		status = model.CloudTrailStatusUnknown
	case okCount == len(results):
		status = model.CloudTrailStatusOK
	}

	run.CloudTrailEventCount = totalFetched
	setCloudTrailStatus(run, status)
	run.Coverage.CloudTrailStatus = status
	run.Coverage.CloudTrailEventsAnalyzed = totalFetched
	run.Coverage.CloudTrailTruncated = anyTruncated
	run.Coverage.CloudTrailRegions = regionCovs

	if status == model.CloudTrailStatusPartial || status == model.CloudTrailStatusUnknown {
		gap := "cloudtrail_" + status
		for i := range run.Identities {
			if !run.Identities[i].IsServiceLinkedRole {
				run.Identities[i].AddDataGap(gap)
			}
		}
	}

	for idx, a := range acc {
		ident := &run.Identities[idx]
		ident.CloudTrailEventCount = a.count

		if len(a.ips) > 0 {
			ips := make([]string, 0, len(a.ips))
			for ip := range a.ips {
				ips = append(ips, ip)
			}
			sort.Strings(ips)
			ident.SourceIPs = ips
		}

		if len(a.actions) > 0 {
			ident.RecentEventNames = topKeys(a.actions, maxRecentEventNamesPerIdentity)
		}

		if len(a.userAgents) > 0 {
			ident.ObservedUserAgents = topKeys(a.userAgents, maxObservedUserAgents)
		}

		if a.count30d > 0 {
			ident.Activity30d = &model.ActivitySummary{
				WindowDays:  activitySummaryWindowDays,
				TotalEvents: a.count30d,
				TopServices: topCounts(a.services30d, maxActivityTopItems),
				TopAPIs:     topCounts(a.apis30d, maxActivityTopItems),
			}
		}

		if a.lastTime != nil && (ident.LastUsed == nil || a.lastTime.After(*ident.LastUsed)) {
			ts := a.lastTime.UTC()
			ident.LastUsed = &ts
		}
	}

	sort.Strings(run.Warnings)
}

func fetchRegionEvents(
	ctx context.Context,
	rc RegionCloudTrailClient,
	opts CloudTrailOptions,
	startTime, endTime time.Time,
	multiRegion bool,
) regionFetchResult {
	if rc.Client == nil {
		return regionFetchResult{
			coverage: model.RegionCloudTrailCoverage{
				Region: rc.Region,
				Status: model.CloudTrailStatusUnknown,
				Error:  "cloudtrail client unavailable",
			},
		}
	}

	var (
		nextToken *string
		events    []cttypes.Event
		warnings  []string
		status    = model.CloudTrailStatusOK
		truncated bool
		errMsg    string
		pageNum   int
	)

	for len(events) < opts.MaxEvents {
		if ctx.Err() != nil {
			status = partialOrUnknown(len(events))
			errMsg = ctx.Err().Error()
			warnings = append(warnings, formatRegionWarning(rc.Region, multiRegion, fmt.Sprintf("CloudTrail lookup interrupted: %v", ctx.Err())))
			break
		}

		if pageNum > 0 && opts.MinRequestInterval > 0 {
			if err := opts.Sleep(ctx, opts.MinRequestInterval); err != nil {
				status = partialOrUnknown(len(events))
				errMsg = err.Error()
				warnings = append(warnings, formatRegionWarning(rc.Region, multiRegion, fmt.Sprintf("CloudTrail lookup interrupted during rate-limit pacing: %v", err)))
				break
			}
		}
		pageNum++

		remaining := opts.MaxEvents - len(events)
		pageSize := int32(min(remaining, maxCloudTrailPageSize))

		out, err := DoWithRetry(ctx, opts.Retry, func(ctx context.Context) (*cloudtrail.LookupEventsOutput, error) {
			return rc.Client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				StartTime:  &startTime,
				EndTime:    &endTime,
				MaxResults: aws.Int32(pageSize),
				NextToken:  nextToken,
			})
		})
		if err != nil {
			status = partialOrUnknown(len(events))
			errMsg = err.Error()
			warnings = append(warnings, formatRegionWarning(rc.Region, multiRegion, fmt.Sprintf("CloudTrail LookupEvents failed (status=%s): %v", status, err)))
			break
		}

		for _, ev := range out.Events {
			if len(events) >= opts.MaxEvents {
				break
			}
			events = append(events, ev)
		}

		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		if len(events) >= opts.MaxEvents {
			status = model.CloudTrailStatusPartial
			truncated = true
			warnings = append(warnings, formatRegionWarning(rc.Region, multiRegion, fmt.Sprintf("CloudTrail lookup reached --max-events=%d cap; attribution may be incomplete", opts.MaxEvents)))
			break
		}
		nextToken = out.NextToken
	}

	return regionFetchResult{
		coverage: model.RegionCloudTrailCoverage{
			Region:         rc.Region,
			Status:         status,
			EventsAnalyzed: len(events),
			Truncated:      truncated,
			Error:          errMsg,
		},
		events:   events,
		warnings: warnings,
	}
}

func formatRegionWarning(region string, multiRegion bool, msg string) string {
	if multiRegion && strings.TrimSpace(region) != "" {
		return fmt.Sprintf("[%s] %s", region, msg)
	}
	return msg
}

func attributeEvent(
	ev cttypes.Event,
	cutoff30d time.Time,
	roleByARN, roleByName, userByARN, keyByID map[string]int,
	getAcc func(int) *identityTrailAcc,
) {
	var payload ctEventPayload
	if raw := aws.ToString(ev.CloudTrailEvent); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}

	accessKeyID := strings.TrimSpace(payload.UserIdentity.AccessKeyID)
	if accessKeyID == "" {
		accessKeyID = strings.TrimSpace(aws.ToString(ev.AccessKeyId))
	}

	matched := make(map[int]struct{}, 2)

	if accessKeyID != "" {
		if idx, ok := keyByID[accessKeyID]; ok {
			matched[idx] = struct{}{}
		}
	}

	userARN := strings.TrimSpace(payload.UserIdentity.ARN)
	if userARN != "" {
		if idx, ok := userByARN[userARN]; ok {
			matched[idx] = struct{}{}
		}
	}

	if payload.UserIdentity.SessionContext != nil && payload.UserIdentity.SessionContext.SessionIssuer != nil {
		issuerARN := strings.TrimSpace(payload.UserIdentity.SessionContext.SessionIssuer.ARN)
		if idx, ok := roleByARN[issuerARN]; ok {
			matched[idx] = struct{}{}
		}
	}
	if roleName := extractAssumedRoleName(userARN); roleName != "" {
		if idx, ok := roleByName[roleName]; ok {
			matched[idx] = struct{}{}
		}
	}

	if len(matched) == 0 {
		return
	}

	var validIP string
	if ipRaw := strings.TrimSpace(payload.SourceIPAddress); ipRaw != "" {
		if addr, err := netip.ParseAddr(ipRaw); err == nil {
			validIP = addr.Unmap().String()
		}
	}

	rawSrc := firstNonEmpty(payload.EventSource, aws.ToString(ev.EventSource))
	rawName := firstNonEmpty(payload.EventName, aws.ToString(ev.EventName))
	svcPrefix := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawSrc)), ".amazonaws.com")
	actionLabel := formatCloudTrailAction(rawSrc, rawName)
	ua := normalizeUserAgent(payload.UserAgent)
	in30d := ev.EventTime != nil && !ev.EventTime.UTC().Before(cutoff30d)

	for idx := range matched {
		a := getAcc(idx)
		a.count++
		if validIP != "" {
			a.ips[validIP] = struct{}{}
		}
		if actionLabel != "" {
			a.actions[actionLabel]++
		}
		if ua != "" {
			a.userAgents[ua]++
		}
		if in30d {
			a.count30d++
			if svcPrefix != "" {
				a.services30d[svcPrefix]++
			}
			if actionLabel != "" {
				a.apis30d[actionLabel]++
			}
		}
		if ev.EventTime != nil {
			ts := ev.EventTime.UTC()
			if a.lastTime == nil || ts.After(*a.lastTime) {
				tCopy := ts
				a.lastTime = &tCopy
			}
		}
	}
}

func normalizeUserAgent(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if len(s) > maxUserAgentLen {
		s = s[:maxUserAgentLen]
	}
	return s
}

func extractAssumedRoleName(arn string) string {
	const marker = ":assumed-role/"
	idx := strings.Index(arn, marker)
	if idx < 0 {
		return ""
	}
	rest := arn[idx+len(marker):]
	name, _, _ := strings.Cut(rest, "/")
	return strings.TrimSpace(name)
}

func formatCloudTrailAction(eventSource, eventName string) string {
	name := strings.TrimSpace(eventName)
	if name == "" {
		return ""
	}
	src := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(eventSource)), ".amazonaws.com")
	if src == "" {
		return name
	}
	return src + ":" + name
}

func topKeys(counts map[string]int, limit int) []string {
	tc := topCounts(counts, limit)
	out := make([]string, len(tc))
	for i, item := range tc {
		out[i] = item.Name
	}
	return out
}

func topCounts(counts map[string]int, limit int) []model.ActivityCount {
	list := make([]model.ActivityCount, 0, len(counts))
	for name, cnt := range counts {
		list = append(list, model.ActivityCount{Name: name, Count: cnt})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Name < list[j].Name
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}

func setCloudTrailStatus(run *model.ScanRun, status string) {
	run.CloudTrailStatus = status
	for i := range run.Identities {
		run.Identities[i].CloudTrailStatus = status
	}
}

func partialOrUnknown(fetched int) string {
	if fetched > 0 {
		return model.CloudTrailStatusPartial
	}
	return model.CloudTrailStatusUnknown
}

func firstNonEmpty(a, b string) string {
	if s := strings.TrimSpace(a); s != "" {
		return s
	}
	return strings.TrimSpace(b)
}
