package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	communityFeedSource       = "vedetta-community"
	communityFeedPath         = "/api/v1/feed/community"
	communityFeedSchema       = 1
	communityFeedMaxItems     = 5000
	communityFeedMaxBodyBytes = 8 << 20 // 8 MiB, including fields Core does not consume.
	communityFeedTimeout      = 30 * time.Second
	communityFeedMaxTTLHours  = 30 * 24
	communityFeedMaxReasons   = 64
	communityFeedMaxReasonLen = 128
	communityFeedClockSkew    = 15 * time.Minute
)

// communityFeedResponse mirrors schema v1 of the public threat-network feed.
// Unknown JSON fields are intentionally ignored: additive fields are permitted
// within v1 by the feed contract.
type communityFeedResponse struct {
	SchemaVersion int                 `json:"schema_version"`
	Feed          string              `json:"feed"`
	GeneratedAt   string              `json:"generated_at"`
	TTLSeconds    int                 `json:"ttl_seconds"`
	Advisory      bool                `json:"advisory"`
	TotalItems    int                 `json:"total_items"`
	ReturnedItems int                 `json:"returned_items"`
	NextCursor    string              `json:"next_cursor,omitempty"`
	Items         []communityFeedItem `json:"items"`
}

type communityFeedItem struct {
	FeedID            string   `json:"feed_id"`
	Kind              string   `json:"kind"`
	Indicator         string   `json:"indicator"`
	IndicatorType     string   `json:"indicator_type"`
	Confidence        float64  `json:"confidence"`
	Severity          string   `json:"severity"`
	Advisory          bool     `json:"advisory"`
	RecommendedAction string   `json:"recommended_action"`
	SourcesRequired   int      `json:"sources_required"`
	SourcesObserved   int      `json:"sources_observed"`
	Reasons           []string `json:"reasons"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	PublishedAt       string   `json:"published_at"`
	UpdatedAt         string   `json:"updated_at"`
	ExpiresAt         string   `json:"expires_at"`
}

// ImportCommunityFeed downloads one complete, bounded public community-feed
// snapshot and imports the indicator types Core can match locally. The request
// carries no credentials. Its returned count is the number of domain values
// written to the local threat-intelligence database; behavior-only items and
// already-expired items are valid feed entries but are not imported.
//
// The helper is intentionally independent of FeedScheduler so the scheduler can
// call it with its existing DB and HTTP client while retaining ownership of
// scheduling and health state.
func ImportCommunityFeed(db *ThreatIntelDB, client *http.Client, baseURL string) (int, error) {
	return importCommunityFeedAt(db, client, baseURL, time.Now().UTC())
}

// LookupAll returns every source that currently carries value, ordered by raw
// confidence (descending) and then source (ascending). Community intelligence
// is advisory-only, so callers that fuse evidence must be able to distinguish a
// community match from an independently curated feed instead of letting the
// highest-confidence row hide all other provenance behind Lookup's LIMIT 1.
func (t *ThreatIntelDB) LookupAll(value string) []LookupResult {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || !t.mayContain(value) {
		return nil
	}

	rows, err := t.db.Query(`
		SELECT indicator, type, source, confidence, tags, first_seen, last_seen, ttl_hours
		FROM threat_indicators
		WHERE indicator = ?
		ORDER BY confidence DESC, source ASC
	`, value)
	if err != nil {
		return nil
	}
	defer rows.Close()

	results := make([]LookupResult, 0, 2)
	for rows.Next() {
		var ind Indicator
		var tagsJSON, firstSeen, lastSeen string
		if err := rows.Scan(&ind.Value, &ind.Type, &ind.Source, &ind.Confidence,
			&tagsJSON, &firstSeen, &lastSeen, &ind.TTLHours); err != nil {
			continue
		}
		ind.FirstSeen, _ = parseTimestamp(firstSeen)
		ind.LastSeen, _ = parseTimestamp(lastSeen)
		_ = json.Unmarshal([]byte(tagsJSON), &ind.Tags)
		if ind.Tags == nil {
			ind.Tags = []string{}
		}

		stale := time.Since(ind.LastSeen) > time.Duration(ind.TTLHours)*time.Hour
		adjusted := ind.Confidence
		if stale {
			adjusted *= 0.5
		}
		results = append(results, LookupResult{
			Found:      true,
			Indicator:  &ind,
			IsStale:    stale,
			Confidence: adjusted,
		})
	}
	return results
}

func importCommunityFeedAt(db *ThreatIntelDB, client *http.Client, baseURL string, now time.Time) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("community feed: nil threat database")
	}
	if client == nil {
		return 0, fmt.Errorf("community feed: nil HTTP client")
	}

	feedURL, err := buildCommunityFeedURL(baseURL)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), communityFeedTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return 0, fmt.Errorf("community feed: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	initialURL, _ := url.Parse(feedURL) // already validated by buildCommunityFeedURL
	safeClient := *client
	safeClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("community feed: too many redirects")
		}
		if !strings.EqualFold(next.URL.Scheme, initialURL.Scheme) || !strings.EqualFold(next.URL.Host, initialURL.Host) {
			return fmt.Errorf("community feed: cross-origin or scheme-changing redirect refused")
		}
		return nil
	}
	resp, err := safeClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("community feed: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("community feed: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > communityFeedMaxBodyBytes {
		return 0, fmt.Errorf("community feed: response exceeds %d-byte limit", communityFeedMaxBodyBytes)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, communityFeedMaxBodyBytes+1))
	if err != nil {
		return 0, fmt.Errorf("community feed: read response: %w", err)
	}
	if len(body) > communityFeedMaxBodyBytes {
		return 0, fmt.Errorf("community feed: response exceeds %d-byte limit", communityFeedMaxBodyBytes)
	}

	var payload communityFeedResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&payload); err != nil {
		return 0, fmt.Errorf("community feed: decode schema v1: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return 0, fmt.Errorf("community feed: decode schema v1: %w", err)
	}

	indicators, err := validateCommunityFeed(payload, now)
	if err != nil {
		return 0, err
	}
	imported, err := db.ReplaceSource(communityFeedSource, indicators)
	if err != nil {
		return 0, fmt.Errorf("community feed: import: %w", err)
	}
	return imported, nil
}

func buildCommunityFeedURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("community feed: invalid base URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("community feed: base URL must be absolute HTTP(S)")
	}
	if u.User != nil {
		return "", fmt.Errorf("community feed: base URL must not contain credentials")
	}
	u.Path = strings.TrimRight(u.Path, "/") + communityFeedPath
	u.RawPath = ""
	u.RawQuery = url.Values{"limit": {"5000"}}.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	err := dec.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values in response")
	}
	return err
}

func validateCommunityFeed(payload communityFeedResponse, now time.Time) ([]Indicator, error) {
	if payload.SchemaVersion != communityFeedSchema {
		return nil, fmt.Errorf("community feed: unsupported schema_version %d", payload.SchemaVersion)
	}
	if payload.Feed != "community" {
		return nil, fmt.Errorf("community feed: unexpected feed %q", payload.Feed)
	}
	if !payload.Advisory {
		return nil, fmt.Errorf("community feed: schema v1 envelope is not advisory-only")
	}
	if payload.TTLSeconds < 1 || payload.TTLSeconds > 24*60*60 {
		return nil, fmt.Errorf("community feed: ttl_seconds out of bounds")
	}
	generatedAt, err := time.Parse(time.RFC3339, payload.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("community feed: invalid generated_at: %w", err)
	}
	if generatedAt.After(now.Add(communityFeedClockSkew)) {
		return nil, fmt.Errorf("community feed: generated_at is too far in the future")
	}
	if payload.TotalItems < 0 || payload.ReturnedItems < 0 || payload.ReturnedItems != len(payload.Items) || payload.TotalItems < payload.ReturnedItems {
		return nil, fmt.Errorf("community feed: inconsistent item counts")
	}
	if payload.Items == nil {
		return nil, fmt.Errorf("community feed: items must be an array")
	}
	if len(payload.Items) > communityFeedMaxItems || payload.TotalItems > communityFeedMaxItems {
		return nil, fmt.Errorf("community feed: item count exceeds %d", communityFeedMaxItems)
	}
	if payload.TotalItems != payload.ReturnedItems || payload.NextCursor != "" {
		return nil, fmt.Errorf("community feed: incomplete snapshot despite maximum page limit")
	}

	indicators := make([]Indicator, 0, len(payload.Items))
	seenItems := make(map[string]struct{}, len(payload.Items))
	indicatorIndex := make(map[string]int, len(payload.Items))
	for i, item := range payload.Items {
		indicator, importable, err := validateCommunityFeedItem(item, now)
		if err != nil {
			return nil, fmt.Errorf("community feed: item %d: %w", i, err)
		}
		normalizedValue := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item.Indicator), "."))
		itemKey := item.Kind + "\x00" + normalizedValue
		if _, exists := seenItems[itemKey]; exists {
			return nil, fmt.Errorf("community feed: item %d: duplicate kind and indicator", i)
		}
		seenItems[itemKey] = struct{}{}
		if importable {
			if existing, ok := indicatorIndex[indicator.Value]; ok {
				indicators[existing] = mergeCommunityIndicators(indicators[existing], indicator)
			} else {
				indicatorIndex[indicator.Value] = len(indicators)
				indicators = append(indicators, indicator)
			}
		}
	}
	return indicators, nil
}

func validateCommunityFeedItem(item communityFeedItem, now time.Time) (Indicator, bool, error) {
	if strings.TrimSpace(item.FeedID) == "" || len(item.FeedID) > 128 {
		return Indicator{}, false, fmt.Errorf("invalid feed_id")
	}
	if !item.Advisory || item.RecommendedAction != "advise" {
		return Indicator{}, false, fmt.Errorf("schema v1 item is not advisory-only")
	}
	if math.IsNaN(item.Confidence) || math.IsInf(item.Confidence, 0) || item.Confidence < 0 || item.Confidence > 1 {
		return Indicator{}, false, fmt.Errorf("confidence out of bounds")
	}
	switch item.Severity {
	case "low", "medium", "high":
	default:
		return Indicator{}, false, fmt.Errorf("invalid severity %q", item.Severity)
	}
	// The v1 community trust model never promotes a single-reporter signal.
	// Accept threshold changes within v1, but retain that minimum invariant.
	if item.SourcesRequired < 2 || item.SourcesObserved < item.SourcesRequired || item.SourcesObserved > 1_000_000 {
		return Indicator{}, false, fmt.Errorf("invalid source counts")
	}
	if item.Reasons == nil || len(item.Reasons) > communityFeedMaxReasons {
		return Indicator{}, false, fmt.Errorf("invalid reasons")
	}
	for _, reason := range item.Reasons {
		if strings.TrimSpace(reason) == "" || len(reason) > communityFeedMaxReasonLen {
			return Indicator{}, false, fmt.Errorf("invalid reason")
		}
	}

	firstSeen, err := parseCommunityTimestamp("first_seen", item.FirstSeen)
	if err != nil {
		return Indicator{}, false, err
	}
	lastSeen, err := parseCommunityTimestamp("last_seen", item.LastSeen)
	if err != nil {
		return Indicator{}, false, err
	}
	publishedAt, err := parseCommunityTimestamp("published_at", item.PublishedAt)
	if err != nil {
		return Indicator{}, false, err
	}
	updatedAt, err := parseCommunityTimestamp("updated_at", item.UpdatedAt)
	if err != nil {
		return Indicator{}, false, err
	}
	expiresAt, err := parseCommunityTimestamp("expires_at", item.ExpiresAt)
	if err != nil {
		return Indicator{}, false, err
	}
	if firstSeen.After(lastSeen) || publishedAt.After(updatedAt) || !expiresAt.After(lastSeen) {
		return Indicator{}, false, fmt.Errorf("inconsistent lifecycle timestamps")
	}
	latestAllowed := now.Add(communityFeedClockSkew)
	if firstSeen.After(latestAllowed) || lastSeen.After(latestAllowed) || publishedAt.After(latestAllowed) || updatedAt.After(latestAllowed) {
		return Indicator{}, false, fmt.Errorf("lifecycle timestamp is too far in the future")
	}

	indicatorValue := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item.Indicator), "."))
	importable := false
	scopeTag := ""
	switch {
	case item.Kind == "domain_indicator" && item.IndicatorType == "domain":
		importable = true
		scopeTag = "indicator_scope:exact"
	case item.Kind == "etld1_indicator" && item.IndicatorType == "etld_plus_one":
		importable = true
		scopeTag = "indicator_scope:etld_plus_one"
	case item.Kind == "behavior_cluster" && item.IndicatorType == "behavior":
		// Core currently has no typed behavior-cluster observable. Validate the
		// item as part of the v1 response but deliberately do not import it.
		return Indicator{}, false, nil
	default:
		return Indicator{}, false, fmt.Errorf("invalid kind/indicator_type pair %q/%q", item.Kind, item.IndicatorType)
	}
	if importable && !validCommunityDomain(indicatorValue) {
		return Indicator{}, false, fmt.Errorf("invalid domain indicator")
	}
	if !expiresAt.After(now) {
		return Indicator{}, false, nil
	}

	// threat_indicators currently constrains Type to "domain" rather than the
	// feed's more-specific "etld_plus_one". Both are DNS names observable by
	// Core, so store the value as a domain while preserving the feed's exact
	// consensus reasons in Tags. A future schema widening can retain the subtype.
	ttlHours := int(math.Ceil(expiresAt.Sub(lastSeen).Hours()))
	if ttlHours < 1 {
		ttlHours = 1
	}
	if ttlHours > communityFeedMaxTTLHours {
		ttlHours = communityFeedMaxTTLHours
	}
	return Indicator{
		Value:      indicatorValue,
		Type:       "domain",
		Source:     communityFeedSource,
		Confidence: item.Confidence,
		// Preserve the feed subtype inside the existing domain-only SQLite
		// contract so Core can apply an eTLD+1 match to observed subdomains without
		// accidentally treating ordinary exact-domain feeds as subtree rules.
		Tags:      append([]string{scopeTag}, item.Reasons...),
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
		TTLHours:  ttlHours,
	}, true, nil
}

func mergeCommunityIndicators(a, b Indicator) Indicator {
	if b.Confidence > a.Confidence {
		a.Confidence = b.Confidence
	}
	if b.FirstSeen.Before(a.FirstSeen) {
		a.FirstSeen = b.FirstSeen
	}
	aExpires := a.LastSeen.Add(time.Duration(a.TTLHours) * time.Hour)
	bExpires := b.LastSeen.Add(time.Duration(b.TTLHours) * time.Hour)
	if b.LastSeen.After(a.LastSeen) {
		a.LastSeen = b.LastSeen
	}
	if bExpires.After(aExpires) {
		aExpires = bExpires
	}
	a.TTLHours = int(math.Ceil(aExpires.Sub(a.LastSeen).Hours()))
	if a.TTLHours < 1 {
		a.TTLHours = 1
	}
	if a.TTLHours > communityFeedMaxTTLHours {
		a.TTLHours = communityFeedMaxTTLHours
	}

	seenReasons := make(map[string]struct{}, len(a.Tags)+len(b.Tags))
	mergedReasons := make([]string, 0, len(a.Tags)+len(b.Tags))
	for _, reasons := range [][]string{a.Tags, b.Tags} {
		for _, reason := range reasons {
			if _, exists := seenReasons[reason]; exists {
				continue
			}
			seenReasons[reason] = struct{}{}
			mergedReasons = append(mergedReasons, reason)
		}
	}
	a.Tags = mergedReasons
	return a
}

func parseCommunityTimestamp(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed.UTC(), nil
}

func validCommunityDomain(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
