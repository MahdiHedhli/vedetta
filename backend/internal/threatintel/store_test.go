package threatintel

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// testThreatDB creates an in-memory SQLite DB with the threat_indicators table.
func testThreatDB(t *testing.T) *ThreatIntelDB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create the threat_indicators table (mirrors 003_threat_indicators.sql)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS threat_indicators (
			indicator TEXT NOT NULL,
			type      TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash')),
			source    TEXT NOT NULL,
			confidence REAL NOT NULL DEFAULT 0.5,
			tags      TEXT DEFAULT '[]',
			first_seen TEXT NOT NULL,
			last_seen  TEXT NOT NULL,
			ttl_hours  INTEGER NOT NULL DEFAULT 168,
			PRIMARY KEY (indicator, source)
		);
		CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator);
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	tid, err := NewThreatIntelDB(db)
	if err != nil {
		t.Fatalf("NewThreatIntelDB: %v", err)
	}
	return tid
}

func TestBulkImport_AndLookup(t *testing.T) {
	tid := testThreatDB(t)

	indicators := []Indicator{
		{
			Value:      "evil.com",
			Type:       "domain",
			Source:     "urlhaus",
			Confidence: 0.85,
			Tags:       []string{"malware_distribution"},
			TTLHours:   168,
		},
		{
			Value:      "198.51.100.42",
			Type:       "ipv4",
			Source:     "feodotracker",
			Confidence: 0.95,
			Tags:       []string{"c2", "emotet"},
			TTLHours:   72,
		},
	}

	imported, err := tid.BulkImport(indicators)
	if err != nil {
		t.Fatalf("BulkImport: %v", err)
	}
	if imported != 2 {
		t.Errorf("expected 2 imported, got %d", imported)
	}

	// Lookup domain
	result := tid.Lookup("evil.com")
	if !result.Found {
		t.Fatal("expected evil.com to be found")
	}
	if result.Indicator.Source != "urlhaus" {
		t.Errorf("expected source urlhaus, got %s", result.Indicator.Source)
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %.2f", result.Confidence)
	}

	// Lookup IP
	result = tid.Lookup("198.51.100.42")
	if !result.Found {
		t.Fatal("expected IP to be found")
	}
	if len(result.Indicator.Tags) < 2 {
		t.Errorf("expected at least 2 tags, got %v", result.Indicator.Tags)
	}

	// Lookup non-existent
	result = tid.Lookup("safe.com")
	if result.Found {
		t.Error("safe.com should not be found")
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	tid := testThreatDB(t)

	tid.BulkImport([]Indicator{
		{Value: "EVIL.COM", Type: "domain", Source: "test", Confidence: 0.9, TTLHours: 168},
	})

	// Should find regardless of case
	result := tid.Lookup("evil.com")
	if !result.Found {
		t.Error("expected case-insensitive lookup to find EVIL.COM")
	}

	result = tid.Lookup("Evil.Com")
	if !result.Found {
		t.Error("expected case-insensitive lookup to find Evil.Com")
	}
}

func TestLookup_StaleIndicator(t *testing.T) {
	tid := testThreatDB(t)

	// Insert an indicator with 1-hour TTL and old last_seen
	indicators := []Indicator{
		{
			Value:      "stale.com",
			Type:       "domain",
			Source:     "test",
			Confidence: 0.9,
			FirstSeen:  time.Now().Add(-48 * time.Hour),
			LastSeen:   time.Now().Add(-48 * time.Hour),
			TTLHours:   1, // 1 hour TTL, but last seen 48h ago
		},
	}
	tid.BulkImport(indicators)

	result := tid.Lookup("stale.com")
	if !result.Found {
		t.Fatal("stale indicator should still be found")
	}
	if !result.IsStale {
		t.Error("expected indicator to be marked as stale")
	}
	if result.Confidence >= 0.9 {
		t.Errorf("stale confidence should be reduced, got %.2f", result.Confidence)
	}
}

func TestBulkImport_EmptySlice(t *testing.T) {
	tid := testThreatDB(t)

	imported, err := tid.BulkImport(nil)
	if err != nil {
		t.Fatalf("BulkImport(nil): %v", err)
	}
	if imported != 0 {
		t.Errorf("expected 0, got %d", imported)
	}
}

func TestBulkImport_Upsert(t *testing.T) {
	tid := testThreatDB(t)

	// Import once
	tid.BulkImport([]Indicator{
		{Value: "evil.com", Type: "domain", Source: "urlhaus", Confidence: 0.7, TTLHours: 168},
	})

	// Import again with higher confidence — should update
	tid.BulkImport([]Indicator{
		{Value: "evil.com", Type: "domain", Source: "urlhaus", Confidence: 0.95, TTLHours: 168},
	})

	result := tid.Lookup("evil.com")
	if result.Confidence != 0.95 {
		t.Errorf("expected updated confidence 0.95, got %.2f", result.Confidence)
	}
}

func TestStats(t *testing.T) {
	tid := testThreatDB(t)

	tid.BulkImport([]Indicator{
		{Value: "a.com", Type: "domain", Source: "urlhaus", Confidence: 0.8, TTLHours: 168},
		{Value: "b.com", Type: "domain", Source: "urlhaus", Confidence: 0.8, TTLHours: 168},
		{Value: "1.2.3.4", Type: "ipv4", Source: "feodotracker", Confidence: 0.9, TTLHours: 72},
	})

	stats, err := tid.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["urlhaus"] != 2 {
		t.Errorf("expected 2 urlhaus indicators, got %d", stats["urlhaus"])
	}
	if stats["feodotracker"] != 1 {
		t.Errorf("expected 1 feodotracker indicator, got %d", stats["feodotracker"])
	}
}

func TestBloomFilter_Integration(t *testing.T) {
	tid := testThreatDB(t)

	tid.BulkImport([]Indicator{
		{Value: "evil.com", Type: "domain", Source: "test", Confidence: 0.9, TTLHours: 168},
	})

	// Bloom filter should reject non-existent domains without hitting SQLite
	result := tid.Lookup("definitely-safe-domain-12345.org")
	if result.Found {
		t.Error("bloom filter should have rejected this lookup")
	}

	// Bloom filter should pass evil.com through to SQLite
	result = tid.Lookup("evil.com")
	if !result.Found {
		t.Error("bloom filter should have allowed evil.com lookup")
	}
}
