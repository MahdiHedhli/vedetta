package store

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestInsertEvents_ClampsFutureTimestamp is the GHSA-9m7g regression at the single
// persistence choke point: a far-future event timestamp — regardless of which write
// path produced it — must be clamped to ~now on insert so it cannot strand the
// telemetry cursor. Handlers are not the only writers, so the clamp lives here.
func TestInsertEvents_ClampsFutureTimestamp(t *testing.T) {
	db := testDB(t)

	future := time.Now().UTC().Add(10 * 365 * 24 * time.Hour) // ~2036
	ok := time.Now().UTC().Add(-time.Minute)
	n, err := db.InsertEvents([]models.Event{
		{EventID: "evt-future", Timestamp: future, EventType: "dns_query", SourceHash: "sha256:x"},
		{EventID: "evt-ok", Timestamp: ok, EventType: "dns_query", SourceHash: "sha256:x"},
	})
	if err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 inserted, got %d", n)
	}

	var stored time.Time
	if err := db.QueryRow("SELECT timestamp FROM events WHERE event_id = 'evt-future'").Scan(&stored); err != nil {
		t.Fatalf("read back future event: %v", err)
	}
	if stored.After(time.Now().UTC().Add(maxEventFutureSkew + time.Minute)) {
		t.Fatalf("future timestamp was not clamped on insert: %s", stored)
	}

	// A normally-dated event must be untouched.
	var storedOK time.Time
	if err := db.QueryRow("SELECT timestamp FROM events WHERE event_id = 'evt-ok'").Scan(&storedOK); err != nil {
		t.Fatalf("read back ok event: %v", err)
	}
	if diff := storedOK.Sub(ok); diff > time.Second || diff < -time.Second {
		t.Fatalf("in-range timestamp was altered: got %s want ~%s", storedOK, ok)
	}
}

// TestScrubFutureEvents is the upgrade-repair regression: a poisoned far-future row
// written by a pre-clamp build must be clamped back to now on startup.
func TestScrubFutureEvents(t *testing.T) {
	db := testDB(t)

	// Write a poisoned row directly, bypassing InsertEvents' clamp, to simulate a
	// row that predates the persistence-level fix.
	future := time.Now().UTC().Add(10 * 365 * 24 * time.Hour)
	if _, err := db.Exec(
		"INSERT INTO events (event_id, timestamp, event_type, source_hash) VALUES (?, ?, 'dns_query', 'sha256:x')",
		"evt-poison", future,
	); err != nil {
		t.Fatalf("seed poisoned row: %v", err)
	}

	n, err := db.ScrubFutureEvents()
	if err != nil {
		t.Fatalf("ScrubFutureEvents: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row repaired, got %d", n)
	}

	var stored time.Time
	if err := db.QueryRow("SELECT timestamp FROM events WHERE event_id = 'evt-poison'").Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.After(time.Now().UTC().Add(maxEventFutureSkew + time.Minute)) {
		t.Fatalf("poisoned timestamp not clamped by scrub: %s", stored)
	}

	// Idempotent: a second run repairs nothing.
	if n2, err := db.ScrubFutureEvents(); err != nil || n2 != 0 {
		t.Fatalf("expected second scrub to be a no-op, got n=%d err=%v", n2, err)
	}
}
