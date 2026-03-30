package store

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestInsertEvents_Basic(t *testing.T) {
	db := testDB(t)

	events := []models.Event{
		{
			EventID:        "evt-001",
			Timestamp:      time.Now().UTC(),
			EventType:      "dns_query",
			SourceHash:     "sha256:abc123",
			Domain:         "example.com",
			QueryType:      "A",
			ResolvedIP:     "93.184.216.34",
			Blocked:        false,
			AnomalyScore:   0.1,
			Tags:           []string{"test"},
			NetworkSegment: "default",
		},
		{
			EventID:        "evt-002",
			Timestamp:      time.Now().UTC(),
			EventType:      "dns_query",
			SourceHash:     "sha256:abc123",
			Domain:         "suspicious.xyz",
			QueryType:      "A",
			Blocked:        true,
			AnomalyScore:   0.85,
			Tags:           []string{"dga_candidate", "known_bad"},
			NetworkSegment: "iot",
		},
	}

	inserted, err := db.InsertEvents(events)
	if err != nil {
		t.Fatalf("InsertEvents failed: %v", err)
	}
	if inserted != 2 {
		t.Errorf("expected 2 inserted, got %d", inserted)
	}

	// Verify count
	count, err := db.CountEvents()
	if err != nil {
		t.Fatalf("CountEvents failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestInsertEvents_Empty(t *testing.T) {
	db := testDB(t)

	inserted, err := db.InsertEvents(nil)
	if err != nil {
		t.Fatalf("InsertEvents(nil) failed: %v", err)
	}
	if inserted != 0 {
		t.Errorf("expected 0 inserted for nil, got %d", inserted)
	}
}

func TestInsertEvents_DuplicateIgnored(t *testing.T) {
	db := testDB(t)

	evt := models.Event{
		EventID:    "dup-001",
		Timestamp:  time.Now().UTC(),
		EventType:  "dns_query",
		SourceHash: "hash",
	}

	// Insert once
	inserted, _ := db.InsertEvents([]models.Event{evt})
	if inserted != 1 {
		t.Errorf("first insert: expected 1, got %d", inserted)
	}

	// Insert same event again — should be ignored (INSERT OR IGNORE)
	inserted, _ = db.InsertEvents([]models.Event{evt})
	if inserted != 0 {
		t.Errorf("duplicate insert: expected 0, got %d", inserted)
	}

	count, _ := db.CountEvents()
	if count != 1 {
		t.Errorf("expected 1 total after duplicate, got %d", count)
	}
}

func TestQueryEvents_NoFilters(t *testing.T) {
	db := testDB(t)
	seedEvents(t, db, 5)

	result, err := db.QueryEvents(EventQueryParams{})
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if len(result.Events) != 5 {
		t.Errorf("expected 5 events, got %d", len(result.Events))
	}
	if result.Page != 1 {
		t.Errorf("expected page 1, got %d", result.Page)
	}
}

func TestQueryEvents_Pagination(t *testing.T) {
	db := testDB(t)
	seedEvents(t, db, 10)

	result, err := db.QueryEvents(EventQueryParams{Page: 1, Limit: 3})
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if result.Total != 10 {
		t.Errorf("expected total 10, got %d", result.Total)
	}
	if len(result.Events) != 3 {
		t.Errorf("expected 3 events on page 1, got %d", len(result.Events))
	}

	result2, _ := db.QueryEvents(EventQueryParams{Page: 4, Limit: 3})
	if len(result2.Events) != 1 {
		t.Errorf("expected 1 event on page 4, got %d", len(result2.Events))
	}
}

func TestQueryEvents_FilterByType(t *testing.T) {
	db := testDB(t)

	events := []models.Event{
		{EventID: "a1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h"},
		{EventID: "a2", Timestamp: time.Now().UTC(), EventType: "firewall_log", SourceHash: "h"},
		{EventID: "a3", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h"},
	}
	db.InsertEvents(events)

	result, _ := db.QueryEvents(EventQueryParams{Type: "dns_query"})
	if result.Total != 2 {
		t.Errorf("expected 2 dns_query events, got %d", result.Total)
	}

	result, _ = db.QueryEvents(EventQueryParams{Type: "firewall_log"})
	if result.Total != 1 {
		t.Errorf("expected 1 firewall_log event, got %d", result.Total)
	}
}

func TestQueryEvents_FilterByTimeRange(t *testing.T) {
	db := testDB(t)

	now := time.Now().UTC()
	events := []models.Event{
		{EventID: "t1", Timestamp: now.Add(-48 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "t2", Timestamp: now.Add(-1 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "t3", Timestamp: now, EventType: "dns_query", SourceHash: "h"},
	}
	db.InsertEvents(events)

	from := now.Add(-2 * time.Hour)
	result, _ := db.QueryEvents(EventQueryParams{From: &from})
	if result.Total != 2 {
		t.Errorf("expected 2 recent events, got %d", result.Total)
	}
}

func TestQueryEvents_FilterByMinScore(t *testing.T) {
	db := testDB(t)

	events := []models.Event{
		{EventID: "s1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", AnomalyScore: 0.1},
		{EventID: "s2", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", AnomalyScore: 0.5},
		{EventID: "s3", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", AnomalyScore: 0.9},
	}
	db.InsertEvents(events)

	minScore := 0.5
	result, _ := db.QueryEvents(EventQueryParams{MinScore: &minScore})
	if result.Total != 2 {
		t.Errorf("expected 2 events with score >= 0.5, got %d", result.Total)
	}
}

func TestQueryEvents_FilterByTags(t *testing.T) {
	db := testDB(t)

	events := []models.Event{
		{EventID: "tg1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Tags: []string{"dga_candidate", "known_bad"}},
		{EventID: "tg2", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Tags: []string{"known_bad"}},
		{EventID: "tg3", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Tags: []string{"beaconing"}},
	}
	db.InsertEvents(events)

	result, _ := db.QueryEvents(EventQueryParams{Tags: []string{"known_bad"}})
	if result.Total != 2 {
		t.Errorf("expected 2 events with known_bad tag, got %d", result.Total)
	}

	result, _ = db.QueryEvents(EventQueryParams{Tags: []string{"dga_candidate", "known_bad"}})
	if result.Total != 1 {
		t.Errorf("expected 1 event with both tags, got %d", result.Total)
	}
}

func TestQueryEvents_SortOrder(t *testing.T) {
	db := testDB(t)

	now := time.Now().UTC()
	events := []models.Event{
		{EventID: "o1", Timestamp: now.Add(-2 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "o2", Timestamp: now.Add(-1 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "o3", Timestamp: now, EventType: "dns_query", SourceHash: "h"},
	}
	db.InsertEvents(events)

	// Default: desc
	result, _ := db.QueryEvents(EventQueryParams{Sort: "timestamp", Order: "desc"})
	if len(result.Events) == 3 && result.Events[0].EventID != "o3" {
		t.Errorf("expected newest first (o3), got %s", result.Events[0].EventID)
	}

	// Ascending
	result, _ = db.QueryEvents(EventQueryParams{Sort: "timestamp", Order: "asc"})
	if len(result.Events) == 3 && result.Events[0].EventID != "o1" {
		t.Errorf("expected oldest first (o1), got %s", result.Events[0].EventID)
	}
}

func TestQueryEvents_LimitCap(t *testing.T) {
	db := testDB(t)

	// Request limit > 500 should be capped
	result, _ := db.QueryEvents(EventQueryParams{Limit: 999})
	if result.Limit != 500 {
		t.Errorf("expected limit capped to 500, got %d", result.Limit)
	}
}

func TestDeleteEventsOlderThan(t *testing.T) {
	db := testDB(t)

	now := time.Now().UTC()
	events := []models.Event{
		{EventID: "old1", Timestamp: now.Add(-100 * 24 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "old2", Timestamp: now.Add(-95 * 24 * time.Hour), EventType: "dns_query", SourceHash: "h"},
		{EventID: "new1", Timestamp: now.Add(-1 * time.Hour), EventType: "dns_query", SourceHash: "h"},
	}
	db.InsertEvents(events)

	cutoff := now.Add(-90 * 24 * time.Hour)
	deleted, err := db.DeleteEventsOlderThan(cutoff)
	if err != nil {
		t.Fatalf("DeleteEventsOlderThan failed: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}

	count, _ := db.CountEvents()
	if count != 1 {
		t.Errorf("expected 1 remaining, got %d", count)
	}
}

func TestGetRetentionDays(t *testing.T) {
	db := testDB(t)

	days, err := db.GetRetentionDays()
	if err != nil {
		t.Fatalf("GetRetentionDays failed: %v", err)
	}
	if days != 90 {
		t.Errorf("expected default 90 days, got %d", days)
	}

	// Update retention
	db.Exec("UPDATE retention_config SET value = '30' WHERE key = 'retention_days'")
	days, _ = db.GetRetentionDays()
	if days != 30 {
		t.Errorf("expected 30 days after update, got %d", days)
	}
}

func TestNullableString(t *testing.T) {
	if nullableString("") != nil {
		t.Error("expected nil for empty string")
	}
	if nullableString("hello") != "hello" {
		t.Error("expected 'hello' for non-empty string")
	}
}

// seedEvents inserts n generic events into the database.
func seedEvents(t *testing.T, db *DB, n int) {
	t.Helper()
	events := make([]models.Event, n)
	for i := range events {
		events[i] = models.Event{
			EventID:        "seed-" + time.Now().Format("150405.000000000") + "-" + string(rune('a'+i)),
			Timestamp:      time.Now().UTC().Add(-time.Duration(i) * time.Minute),
			EventType:      "dns_query",
			SourceHash:     "seed-hash",
			Domain:         "example.com",
			AnomalyScore:   float64(i) * 0.1,
			Tags:           []string{},
			NetworkSegment: "default",
		}
	}
	inserted, err := db.InsertEvents(events)
	if err != nil {
		t.Fatalf("seedEvents failed: %v", err)
	}
	if inserted != n {
		t.Fatalf("seedEvents: expected %d inserted, got %d", n, inserted)
	}
}
