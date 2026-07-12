package corereader

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestCursorPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cur := Cursor{
		LastTimestamp: time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC),
		LastEventID:   "abc",
		SeenEventIDs:  []string{"def", "abc"},
	}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastTimestamp.Equal(cur.LastTimestamp) || got.LastEventID != "abc" ||
		!reflect.DeepEqual(got.SeenEventIDs, []string{"abc", "def"}) {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestCursorSaveCanonicalizesTimestampCohort(t *testing.T) {
	dir := t.TempDir()
	cur := Cursor{
		LastTimestamp: time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC),
		LastEventID:   " middle ",
		SeenEventIDs:  []string{"z-last", "a-first", "z-last", ""},
	}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a-first", "middle", "z-last"}
	if !reflect.DeepEqual(got.SeenEventIDs, want) {
		t.Fatalf("canonical cohort = %v, want %v", got.SeenEventIDs, want)
	}
	if got.LastEventID != "middle" {
		t.Fatalf("canonical last_event_id = %q, want middle", got.LastEventID)
	}
}

func TestCursorLegacyFileSeedsLastEventIDCohort(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"version":1,"last_timestamp":"2026-07-03T14:00:00Z","last_event_id":"legacy-seen"}`
	if err := os.WriteFile(filepath.Join(dir, cursorFile), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.SeenEventIDs, []string{"legacy-seen"}) {
		t.Fatalf("legacy cohort = %v, want [legacy-seen]", got.SeenEventIDs)
	}
	if got.After(Event{Timestamp: got.LastTimestamp, EventID: "legacy-seen"}) {
		t.Fatal("legacy last_event_id replayed after migration")
	}
	if !got.After(Event{Timestamp: got.LastTimestamp, EventID: "late-lower-id"}) {
		t.Fatal("legacy migration suppressed an unseen equal-time event")
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

// GHSA-9m7g: a persisted cursor dated implausibly in the future (beyond skew)
// would make After() reject every real event forever, stranding telemetry. Such
// a cursor must be reset to zero on load so telemetry re-reads from a sane point.
func TestCursorFutureDatedIsReset(t *testing.T) {
	dir := t.TempDir()

	// Cursor two hours ahead of the local clock (beyond the 1h skew tolerance).
	future := Cursor{LastTimestamp: nowUTC().Add(2 * time.Hour), LastEventID: "from-the-future"}
	if err := future.Save(dir); err != nil {
		t.Fatal(err)
	}

	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastTimestamp.IsZero() || got.LastEventID != "" || len(got.SeenEventIDs) != 0 {
		t.Errorf("future-dated cursor should reset to zero, got %+v", got)
	}
	// After reset it must be zero, so any real event is once again "after" it.
	if !got.After(Event{Timestamp: nowUTC(), EventID: "real"}) {
		t.Errorf("reset cursor must treat real events as After (not stranded)")
	}
}

// A cursor within the tolerated skew window (slightly ahead of the clock) is a
// legitimate value and must be preserved, not reset.
func TestCursorWithinSkewIsKept(t *testing.T) {
	dir := t.TempDir()
	ts := nowUTC().Add(5 * time.Minute) // inside the 1h skew tolerance
	cur := Cursor{LastTimestamp: ts, LastEventID: "recent"}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastEventID != "recent" || got.LastTimestamp.IsZero() {
		t.Errorf("cursor within skew must be preserved, got %+v", got)
	}
}

func TestCursorAfterTieBreaker(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	cur := Cursor{LastTimestamp: base, LastEventID: "seen", SeenEventIDs: []string{"other-seen", "seen"}}

	// Exact same event: already processed.
	if cur.After(Event{Timestamp: base, EventID: "seen"}) {
		t.Errorf("exact last event should not be After")
	}
	// Every persisted member of the equal-time cohort is already processed.
	if cur.After(Event{Timestamp: base, EventID: "other-seen"}) {
		t.Errorf("equal-time cohort member should not be After")
	}
	// A different ID at the same instant is a late new event regardless of its
	// lexical ordering relative to LastEventID.
	if !cur.After(Event{Timestamp: base, EventID: "aaa-late"}) {
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
			var err error
			cur, err = cur.Advance(e)
			if err != nil {
				t.Fatal(err)
			}
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

func TestCursorTimestampCohortCapFailsClosed(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	ids := make([]string, maxCursorTimestampCohort)
	for i := range ids {
		ids[i] = "id-" + strconv.Itoa(i)
	}
	cur := Cursor{LastTimestamp: base, LastEventID: ids[len(ids)-1], SeenEventIDs: ids}
	if _, err := cur.Advance(Event{Timestamp: base, EventID: "one-too-many"}); err == nil {
		t.Fatal("over-cap cohort advanced instead of failing closed")
	}

	overCap := append(append([]string(nil), ids...), "one-too-many")
	if err := (Cursor{LastTimestamp: base, SeenEventIDs: overCap}).Save(t.TempDir()); err == nil {
		t.Fatal("over-cap cohort was persisted")
	}
}
