package store

import (
	"database/sql"
	"strings"
	"testing"
)

func TestEnsureOpenEventQueryTypePreservesExistingForeignKeys(t *testing.T) {
	raw, err := sql.Open("sqlite3", t.TempDir()+"/events-rebuild.db?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	db := &DB{DB: raw}
	if _, err := db.Exec(`CREATE TABLE devices (device_id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	restricted := strings.Replace(eventsOpenQueryTypeCreateDDL, "query_type TEXT,",
		"query_type TEXT CHECK (query_type IN ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV', 'PTR', NULL)),", 1)
	if _, err := db.Exec(restricted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE event_child (
		child_id TEXT PRIMARY KEY,
		event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(event_id, timestamp, event_type, source_hash, query_type)
		VALUES ('existing-event', '2026-07-12T12:00:00Z', 'dns_query', 'local-hash', 'A')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO event_child(child_id, event_id) VALUES ('child', 'existing-event')`); err != nil {
		t.Fatal(err)
	}

	if err := db.ensureOpenEventQueryType(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(event_id, timestamp, event_type, source_hash, query_type)
		VALUES ('soa-event', '2026-07-12T12:00:01Z', 'dns_query', 'local-hash', 'SOA')`); err != nil {
		t.Fatalf("relaxed query type still rejected: %v", err)
	}
	var eventID string
	if err := db.QueryRow(`SELECT event_id FROM event_child WHERE child_id='child'`).Scan(&eventID); err != nil || eventID != "existing-event" {
		t.Fatalf("child relationship lost: event=%q err=%v", eventID, err)
	}
	var childSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='event_child'`).Scan(&childSQL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(childSQL, "events_old_query_type") {
		t.Fatalf("child FK retargeted to temporary table: %s", childSQL)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("events rebuild left a foreign-key violation")
	}
}
