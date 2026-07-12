package threatintel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestImportCommunityFeedImportsObservableDomains(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	payload := validCommunityPayload(now,
		communityItem(now, "domain-1", "domain_indicator", "domain", "c2.badzone.example", 0.96),
		communityItem(now, "etld-1", "etld1_indicator", "etld_plus_one", "rotator.example", 0.83),
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != communityFeedPath || r.URL.Query().Get("limit") != "5000" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("public feed request carried Authorization: %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		writeCommunityJSON(t, w, payload)
	}))
	defer server.Close()

	db := testThreatDB(t)
	imported, err := importCommunityFeedAt(db, server.Client(), server.URL, now)
	if err != nil {
		t.Fatalf("ImportCommunityFeed: %v", err)
	}
	if imported != 2 {
		t.Fatalf("imported = %d, want 2", imported)
	}

	for value, wantConfidence := range map[string]float64{
		"c2.badzone.example": 0.96,
		"rotator.example":    0.83,
	} {
		got := db.Lookup(value)
		if !got.Found || got.Indicator.Source != communityFeedSource || got.Indicator.Type != "domain" {
			t.Fatalf("lookup %q = %+v", value, got)
		}
		if got.Indicator.Confidence != wantConfidence {
			t.Fatalf("lookup %q confidence = %v, want %v", value, got.Indicator.Confidence, wantConfidence)
		}
		wantScope := "indicator_scope:exact"
		if value == "rotator.example" {
			wantScope = "indicator_scope:etld_plus_one"
		}
		if strings.Join(got.Indicator.Tags, ",") != wantScope+",known_bad,cross_reporter_match" {
			t.Fatalf("lookup %q reasons not retained: %v", value, got.Indicator.Tags)
		}
	}
}

func TestImportCommunityFeedSkipsBehaviorCoreCannotObserve(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	payload := validCommunityPayload(now,
		communityItem(now, "behavior-1", "behavior_cluster", "behavior", "dns_beaconing_candidate", 0.81),
		communityItem(now, "domain-1", "domain_indicator", "domain", "c2.badzone.example", 0.91),
	)
	server := communityServer(t, payload)
	defer server.Close()

	db := testThreatDB(t)
	imported, err := importCommunityFeedAt(db, server.Client(), server.URL, now)
	if err != nil {
		t.Fatal(err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}
	if db.Lookup("dns_beaconing_candidate").Found {
		t.Fatal("behavior-only item must not be imported")
	}
	if !db.Lookup("c2.badzone.example").Found {
		t.Fatal("observable domain was not imported")
	}
}

func TestLookupAllRetainsEverySourceAndAdjustsStaleness(t *testing.T) {
	db := testThreatDB(t)
	now := time.Now().UTC()
	_, err := db.BulkImport([]Indicator{
		{Value: "c2.badzone.example", Type: "domain", Source: communityFeedSource, Confidence: 0.95, Tags: []string{"cross_reporter_match"}, LastSeen: now, TTLHours: 168},
		{Value: "c2.badzone.example", Type: "domain", Source: "urlhaus", Confidence: 0.85, Tags: []string{"malware_distribution"}, LastSeen: now, TTLHours: 168},
		{Value: "c2.badzone.example", Type: "domain", Source: "older-feed", Confidence: 0.70, LastSeen: now.Add(-48 * time.Hour), TTLHours: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	results := db.LookupAll("C2.BADZONE.EXAMPLE")
	if len(results) != 3 {
		t.Fatalf("LookupAll returned %d sources: %+v", len(results), results)
	}
	if results[0].Indicator.Source != communityFeedSource || results[0].Confidence != 0.95 {
		t.Fatalf("first result = %+v", results[0])
	}
	if results[1].Indicator.Source != "urlhaus" || results[1].Confidence != 0.85 {
		t.Fatalf("second result = %+v", results[1])
	}
	if results[2].Indicator.Source != "older-feed" || !results[2].IsStale || results[2].Confidence != 0.35 {
		t.Fatalf("stale result = %+v", results[2])
	}
}

func TestImportCommunityFeedCoalescesSameValueAcrossKinds(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	exact := communityItem(now, "domain-1", "domain_indicator", "domain", "badzone.example", 0.91)
	exact.Reasons = []string{"known_bad", "cross_reporter_match"}
	registered := communityItem(now, "etld-1", "etld1_indicator", "etld_plus_one", "badzone.example", 0.83)
	registered.Reasons = []string{"dga_candidate", "cross_reporter_match"}
	payload := validCommunityPayload(now, exact, registered)
	server := communityServer(t, payload)
	defer server.Close()

	db := testThreatDB(t)
	imported, err := importCommunityFeedAt(db, server.Client(), server.URL, now)
	if err != nil {
		t.Fatal(err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want one storage key", imported)
	}
	got := db.Lookup("badzone.example")
	if !got.Found || got.Indicator.Confidence != 0.91 || strings.Join(got.Indicator.Tags, ",") != "indicator_scope:exact,known_bad,cross_reporter_match,indicator_scope:etld_plus_one,dga_candidate" {
		t.Fatalf("coalesced indicator = %+v", got)
	}
}

func TestImportCommunityFeedRejectsMalformedResponsesAtomically(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*communityFeedResponse)
	}{
		{name: "schema", mutate: func(p *communityFeedResponse) { p.SchemaVersion = 2 }},
		{name: "feed name", mutate: func(p *communityFeedResponse) { p.Feed = "different" }},
		{name: "count mismatch", mutate: func(p *communityFeedResponse) { p.ReturnedItems++ }},
		{name: "confidence", mutate: func(p *communityFeedResponse) { p.Items[0].Confidence = 1.01 }},
		{name: "kind type mismatch", mutate: func(p *communityFeedResponse) { p.Items[0].IndicatorType = "behavior" }},
		{name: "invalid domain", mutate: func(p *communityFeedResponse) { p.Items[0].Indicator = "https://badzone.example/path" }},
		{name: "bad expiration", mutate: func(p *communityFeedResponse) { p.Items[0].ExpiresAt = p.Items[0].LastSeen }},
		{name: "future observation", mutate: func(p *communityFeedResponse) {
			p.Items[0].LastSeen = now.Add(time.Hour).Format(time.RFC3339)
			p.Items[0].ExpiresAt = now.Add(8 * 24 * time.Hour).Format(time.RFC3339)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := validCommunityPayload(now,
				communityItem(now, "domain-1", "domain_indicator", "domain", "c2.badzone.example", 0.9),
			)
			tt.mutate(&payload)
			server := communityServer(t, payload)
			defer server.Close()
			db := testThreatDB(t)
			if imported, err := importCommunityFeedAt(db, server.Client(), server.URL, now); err == nil {
				t.Fatalf("imported %d items from malformed response", imported)
			}
			if db.Lookup("c2.badzone.example").Found {
				t.Fatal("malformed response was partially imported")
			}
		})
	}
}

func TestImportCommunityFeedRejectsMalformedJSONAndTrailingValue(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":`,
		`{"schema_version":1} {"second":true}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		db := testThreatDB(t)
		_, err := ImportCommunityFeed(db, server.Client(), server.URL)
		server.Close()
		if err == nil {
			t.Fatalf("accepted malformed body %q", body)
		}
	}
}

func TestImportCommunityFeedRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(communityFeedMaxBodyBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := ImportCommunityFeed(testThreatDB(t), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestImportCommunityFeedRejectsChunkedOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"padding":"`))
		if flusher != nil {
			flusher.Flush() // force chunked encoding, so Content-Length is unknown
		}
		_, _ = w.Write([]byte(strings.Repeat("x", communityFeedMaxBodyBytes+1)))
	}))
	defer server.Close()

	if _, err := ImportCommunityFeed(testThreatDB(t), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("chunked oversized response error = %v", err)
	}
}

func TestImportCommunityFeedRejectsNonAdvisorySemantics(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*communityFeedResponse)
	}{
		{name: "envelope", mutate: func(p *communityFeedResponse) { p.Advisory = false }},
		{name: "item", mutate: func(p *communityFeedResponse) { p.Items[0].Advisory = false }},
		{name: "action", mutate: func(p *communityFeedResponse) { p.Items[0].RecommendedAction = "block" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := validCommunityPayload(now,
				communityItem(now, "domain-1", "domain_indicator", "domain", "c2.badzone.example", 0.9),
			)
			tt.mutate(&payload)
			server := communityServer(t, payload)
			defer server.Close()
			if _, err := importCommunityFeedAt(testThreatDB(t), server.Client(), server.URL, now); err == nil || !strings.Contains(err.Error(), "advisory") && !strings.Contains(err.Error(), "action") {
				t.Fatalf("non-advisory response error = %v", err)
			}
		})
	}
}

func TestImportCommunityFeedRefusesCrossOriginRedirect(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+communityFeedPath, http.StatusFound)
	}))
	defer source.Close()

	if _, err := ImportCommunityFeed(testThreatDB(t), source.Client(), source.URL); err == nil {
		t.Fatal("cross-origin redirect unexpectedly succeeded")
	}
	if redirected {
		t.Fatal("community client followed redirect to a different origin")
	}
}

func TestImportCommunityFeedExpirationConfidenceAndTTLCap(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	expired := communityItem(now, "expired", "domain_indicator", "domain", "expired.badzone.example", 0.99)
	expired.FirstSeen = now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	expired.LastSeen = now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	expired.ExpiresAt = now.Add(-24 * time.Hour).Format(time.RFC3339)

	current := communityItem(now, "current", "domain_indicator", "domain", "current.badzone.example", 0.73)
	current.LastSeen = now.Add(-24 * time.Hour).Format(time.RFC3339)
	current.ExpiresAt = now.Add(6 * 24 * time.Hour).Format(time.RFC3339) // seven days from last_seen

	longLived := communityItem(now, "bounded", "domain_indicator", "domain", "bounded.badzone.example", 0.65)
	longLived.ExpiresAt = now.Add(365 * 24 * time.Hour).Format(time.RFC3339)

	payload := validCommunityPayload(now, expired, current, longLived)
	server := communityServer(t, payload)
	defer server.Close()
	db := testThreatDB(t)
	imported, err := importCommunityFeedAt(db, server.Client(), server.URL, now)
	if err != nil {
		t.Fatal(err)
	}
	if imported != 2 {
		t.Fatalf("imported = %d, want 2", imported)
	}
	if db.Lookup("expired.badzone.example").Found {
		t.Fatal("expired item was imported")
	}
	got := db.Lookup("current.badzone.example")
	if !got.Found || got.Indicator.Confidence != 0.73 || got.Indicator.TTLHours != 7*24 {
		t.Fatalf("current item = %+v", got)
	}
	bounded := db.Lookup("bounded.badzone.example")
	if !bounded.Found || bounded.Indicator.TTLHours != communityFeedMaxTTLHours {
		t.Fatalf("bounded item = %+v", bounded)
	}
}

func validCommunityPayload(now time.Time, items ...communityFeedItem) communityFeedResponse {
	if items == nil {
		items = make([]communityFeedItem, 0)
	}
	return communityFeedResponse{
		SchemaVersion: communityFeedSchema,
		Feed:          "community",
		GeneratedAt:   now.Format(time.RFC3339),
		TTLSeconds:    900,
		Advisory:      true,
		TotalItems:    len(items),
		ReturnedItems: len(items),
		Items:         items,
	}
}

func communityItem(now time.Time, id, kind, indicatorType, indicator string, confidence float64) communityFeedItem {
	return communityFeedItem{
		FeedID:            id,
		Kind:              kind,
		Indicator:         indicator,
		IndicatorType:     indicatorType,
		Confidence:        confidence,
		Severity:          "high",
		Advisory:          true,
		RecommendedAction: "advise",
		SourcesRequired:   2,
		SourcesObserved:   3,
		Reasons:           []string{"known_bad", "cross_reporter_match"},
		FirstSeen:         now.Add(-48 * time.Hour).Format(time.RFC3339),
		LastSeen:          now.Format(time.RFC3339),
		PublishedAt:       now.Add(-24 * time.Hour).Format(time.RFC3339),
		UpdatedAt:         now.Format(time.RFC3339),
		ExpiresAt:         now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}
}

func communityServer(t *testing.T, payload communityFeedResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeCommunityJSON(t, w, payload)
	}))
}

func writeCommunityJSON(t *testing.T, w http.ResponseWriter, payload communityFeedResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
