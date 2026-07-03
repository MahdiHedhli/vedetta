package corereader

import (
	"testing"
	"time"
)

func TestCursorPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cur := Cursor{LastTimestamp: time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC), LastEventID: "abc"}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastTimestamp.Equal(cur.LastTimestamp) || got.LastEventID != "abc" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestCursorMissingIsZero(t *testing.T) {
	got, err := LoadCursor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastTimestamp.IsZero() {
		t.Errorf("missing cursor should be zero")
	}
}

func TestCursorAfterTieBreaker(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	cur := Cursor{LastTimestamp: base, LastEventID: "seen"}

	// Exact same event: already processed.
	if cur.After(Event{Timestamp: base, EventID: "seen"}) {
		t.Errorf("exact last event should not be After")
	}
	// Same instant, different ID: still new (bounded duplicate within a tick window).
	if !cur.After(Event{Timestamp: base, EventID: "other"}) {
		t.Errorf("same instant different id should be After")
	}
	// Earlier: not after.
	if cur.After(Event{Timestamp: base.Add(-time.Second), EventID: "old"}) {
		t.Errorf("earlier event should not be After")
	}
	// Later: after.
	if !cur.After(Event{Timestamp: base.Add(time.Second), EventID: "new"}) {
		t.Errorf("later event should be After")
	}
}

// Crash-resume: process page 1, persist cursor, resume — no events lost, and the
// last-seen event is not re-emitted.
func TestCursorCrashResume(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	events := []Event{
		mkEvent("e1", base),
		mkEvent("e2", base.Add(time.Second)),
		mkEvent("e3", base.Add(2*time.Second)),
	}
	// Simulate processing first two, then "crash".
	cur := Cursor{}
	for _, e := range events[:2] {
		if cur.After(e) {
			cur = cur.Advance(e)
		}
	}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}

	// Resume from persisted cursor.
	resumed, _ := LoadCursor(dir)
	var got []string
	for _, e := range events { // server re-serves all (inclusive from)
		if resumed.After(e) {
			got = append(got, e.EventID)
		}
	}
	if len(got) != 1 || got[0] != "e3" {
		t.Errorf("resume emitted %v, want only [e3]", got)
	}
}
