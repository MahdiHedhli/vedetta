package feed

import (
	"fmt"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func newBuilder(t *testing.T, now time.Time) (*Builder, *store.DB) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Builder{DB: db, Now: func() time.Time { return now }}, db
}

// seedItems inserts n live feed items with staggered updated_at for stable order.
func seedItems(t *testing.T, db *store.DB, n int, now time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		upd := now.Add(time.Duration(i) * time.Minute).UTC().Format(time.RFC3339)
		exp := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
		if err := db.UpsertFeedItem(store.FeedItem{
			FeedID:          fmt.Sprintf("feed-%02d", i),
			Kind:            "domain_indicator",
			Indicator:       fmt.Sprintf("item%02d.badzone.example", i),
			IndicatorType:   "domain",
			Confidence:      0.90,
			Severity:        "high",
			SourcesRequired: 2,
			SourcesObserved: 3,
			Reasons:         `["known_bad","cross_reporter_match"]`,
			FirstSeen:       now.Add(-time.Hour).UTC().Format(time.RFC3339),
			LastSeen:        upd,
			PublishedAt:     upd,
			UpdatedAt:       upd,
			ExpiresAt:       exp,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdvisoryInvariantOnEveryItem(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 5, now)
	resp, _, err := b.Build(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Advisory {
		t.Fatal("response advisory must be true")
	}
	for _, it := range resp.Items {
		if !it.Advisory {
			t.Fatalf("item %s advisory must be true", it.FeedID)
		}
		if it.RecommendedAction != "advise" {
			t.Fatalf("item %s recommended_action must be 'advise', got %q", it.FeedID, it.RecommendedAction)
		}
	}
}

func TestCursorPaginationStable(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 12, now)

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		resp, _, err := b.Build(Query{Limit: 5, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, it := range resp.Items {
			if seen[it.FeedID] {
				t.Fatalf("duplicate item across pages: %s", it.FeedID)
			}
			seen[it.FeedID] = true
		}
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 12 {
		t.Fatalf("expected 12 unique items across pages, got %d", len(seen))
	}
	if pages != 3 {
		t.Fatalf("expected 3 pages at limit=5 over 12 items, got %d", pages)
	}
}

// seedItemsVaryingConfidence inserts n live feed items with distinct confidences
// so ordering by confidence DESC is observable. Confidence i/(n) keeps values in
// (0,1); feed_id encodes the index for a deterministic tiebreak.
func seedItemsVaryingConfidence(t *testing.T, db *store.DB, n int, now time.Time) {
	t.Helper()
	exp := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	upd := now.UTC().Format(time.RFC3339)
	for i := 0; i < n; i++ {
		conf := float64(i+1) / float64(n+1) // in (0,1), strictly increasing with i
		if err := db.UpsertFeedItem(store.FeedItem{
			FeedID:          fmt.Sprintf("feed-%06d", i),
			Kind:            "domain_indicator",
			Indicator:       fmt.Sprintf("item%06d.badzone.example", i),
			IndicatorType:   "domain",
			Confidence:      conf,
			Severity:        "high",
			SourcesRequired: 2,
			SourcesObserved: 3,
			Reasons:         `["known_bad","cross_reporter_match"]`,
			FirstSeen:       now.Add(-time.Hour).UTC().Format(time.RFC3339),
			LastSeen:        upd,
			PublishedAt:     upd,
			UpdatedAt:       upd,
			ExpiresAt:       exp,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFeedCapEnforcedByConfidence is the finding #3 regression: the published
// feed is capped at store.FeedItemCap (5000) items ordered by confidence DESC.
// With >5000 promotable indicators, at most 5000 are served, highest-confidence
// first, and the served set is exactly the top-5000 by confidence — the
// lowest-confidence overflow is withheld even when paging to exhaustion.
func TestFeedCapEnforcedByConfidence(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)

	const n = store.FeedItemCap + 250 // 5250 promotable indicators
	seedItemsVaryingConfidence(t, db, n, now)

	// A single large request must serve at most the cap, highest-confidence first.
	resp, _, err := b.Build(Query{Limit: MaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ReturnedItems > store.FeedItemCap {
		t.Fatalf("served feed must be capped at %d, got %d", store.FeedItemCap, resp.ReturnedItems)
	}
	if resp.TotalItems > store.FeedItemCap {
		t.Fatalf("total_items must not advertise more than the cap, got %d", resp.TotalItems)
	}
	for i := 1; i < len(resp.Items); i++ {
		if resp.Items[i-1].Confidence < resp.Items[i].Confidence {
			t.Fatalf("items must be highest-confidence-first: pos %d conf %v < pos %d conf %v",
				i-1, resp.Items[i-1].Confidence, i, resp.Items[i].Confidence)
		}
	}
	// The very highest-confidence indicator (index n-1) must be present; the
	// lowest (index 0) must be withheld beyond the cap.
	topID := fmt.Sprintf("feed-%06d", n-1)
	bottomID := fmt.Sprintf("feed-%06d", 0)

	// Page through the whole feed and collect served ids; the total served across
	// all pages must still be <= cap, and the top item present, bottom absent.
	served := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, _, err := b.Build(Query{Limit: 1000, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, it := range page.Items {
			served[it.FeedID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate under the cap")
		}
	}
	if len(served) > store.FeedItemCap {
		t.Fatalf("paging must never serve more than the cap, served %d", len(served))
	}
	if len(served) != store.FeedItemCap {
		t.Fatalf("expected exactly %d served (top-by-confidence), got %d", store.FeedItemCap, len(served))
	}
	if !served[topID] {
		t.Fatalf("highest-confidence indicator %s must be served", topID)
	}
	if served[bottomID] {
		t.Fatalf("lowest-confidence overflow %s must be withheld beyond the cap", bottomID)
	}
}

func TestETagUnchangedFeed(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 3, now)
	_, etag1, err := b.Build(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	_, etag2, _ := b.Build(Query{Limit: 100})
	if etag1 != etag2 {
		t.Fatalf("ETag must be stable for unchanged feed: %s vs %s", etag1, etag2)
	}
	// Add an item → ETag changes.
	seedItems(t, db, 4, now)
	_, etag3, _ := b.Build(Query{Limit: 100})
	if etag3 == etag1 {
		t.Fatal("ETag must change when feed changes")
	}
}

func TestMinConfidenceFilter(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 3, now) // all confidence 0.90
	// Lower one item to 0.5.
	db.Exec(`UPDATE feed_items SET confidence = 0.5 WHERE feed_id = 'feed-00'`)
	resp, _, err := b.Build(Query{Limit: 100, MinConfidence: 0.8})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ReturnedItems != 2 {
		t.Fatalf("expected 2 items >= 0.8, got %d", resp.ReturnedItems)
	}
}

func TestExpiredAndRevokedExcluded(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 2, now)
	// Expire feed-00 and revoke feed-01.
	db.Exec(`UPDATE feed_items SET expires_at = ? WHERE feed_id='feed-00'`,
		now.Add(-time.Hour).UTC().Format(time.RFC3339))
	db.RevokeFeedItem("feed-01", now.UTC().Format(time.RFC3339))
	resp, _, err := b.Build(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ReturnedItems != 0 {
		t.Fatalf("expired and revoked items must be excluded, got %d", resp.ReturnedItems)
	}
}

func TestInvalidCursorRejected(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	b, _ := newBuilder(t, now)
	_, _, err := b.Build(Query{Limit: 10, Cursor: "!!!not-base64!!!"})
	qe, ok := err.(*QueryError)
	if !ok || qe.Code != "INVALID_CURSOR" {
		t.Fatalf("expected INVALID_CURSOR, got %T (%v)", err, err)
	}
}

func TestParseQueryValidation(t *testing.T) {
	if _, err := ParseQuery("", "0", "", ""); err == nil {
		t.Fatal("limit 0 must be rejected")
	}
	if _, err := ParseQuery("", "6000", "", ""); err == nil {
		t.Fatal("limit >5000 must be rejected")
	}
	if _, err := ParseQuery("", "", "1.5", ""); err == nil {
		t.Fatal("min_confidence >1 must be rejected")
	}
	if _, err := ParseQuery("", "", "", "bogus"); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
	q, err := ParseQuery("", "50", "0.5", "domain_indicator")
	if err != nil {
		t.Fatal(err)
	}
	if q.Limit != 50 || q.MinConfidence != 0.5 || q.Kind != "domain_indicator" {
		t.Fatalf("unexpected parsed query: %+v", q)
	}
}
