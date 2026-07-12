package corereader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeCore serves synthetic event pages. Events use RFC 5737 / RFC 2606 values.
func fakeCore(t *testing.T, pages map[int][]Event, total int, requireAuth bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth && r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := 1
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		evs := pages[page]
		if evs == nil {
			evs = []Event{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"events": evs, "total": total, "page": page, "limit": 500,
		})
	}))
}

func mkEvent(id string, ts time.Time) Event {
	return Event{EventID: id, Timestamp: ts, EventType: "dns_query", Domain: "x.badzone.example"}
}

// mutablePagedCore models Core's real inclusive from filter and stable
// timestamp/event_id ordering. It honors page and limit so pagination tests
// catch offset changes rather than relying on pre-sliced fixture pages.
type mutablePagedCore struct {
	mu     sync.RWMutex
	events []Event
}

func (s *mutablePagedCore) set(events []Event) {
	s.mu.Lock()
	s.events = append([]Event(nil), events...)
	s.mu.Unlock()
}

func (s *mutablePagedCore) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	events := append([]Event(nil), s.events...)
	s.mu.RUnlock()

	from := time.Time{}
	if raw := r.URL.Query().Get("from"); raw != "" {
		from, _ = time.Parse(time.RFC3339Nano, raw)
	}
	filtered := events[:0]
	for _, event := range events {
		if from.IsZero() || !event.Timestamp.Before(from) {
			filtered = append(filtered, event)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Timestamp.Equal(filtered[j].Timestamp) {
			return filtered[i].EventID < filtered[j].EventID
		}
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 500
	}
	start := (page - 1) * limit
	end := start + limit
	if start > len(filtered) {
		start = len(filtered)
	}
	if end > len(filtered) {
		end = len(filtered)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events": filtered[start:end], "total": len(filtered), "page": page, "limit": limit,
	})
}

func TestFetchPageAuth(t *testing.T) {
	srv := fakeCore(t, map[int][]Event{}, 0, true)
	defer srv.Close()

	c := NewClient(srv.URL, "wrong-token")
	if _, err := c.FetchPage(context.Background(), time.Time{}, 1, 500); err == nil {
		t.Fatalf("expected auth error")
	}
	c.Token = "good-token"
	if _, err := c.FetchPage(context.Background(), time.Time{}, 1, 500); err != nil {
		t.Fatalf("good token should succeed: %v", err)
	}
}

func TestReadPaging(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	// 500 events on page 1 (full), 3 on page 2.
	p1 := make([]Event, 500)
	for i := range p1 {
		p1[i] = mkEvent(fmt.Sprintf("id-%03d", i), base.Add(time.Duration(i)*time.Second))
	}
	p2 := []Event{
		mkEvent("id-500", base.Add(500*time.Second)),
		mkEvent("id-501", base.Add(501*time.Second)),
		mkEvent("id-502", base.Add(502*time.Second)),
	}
	srv := fakeCore(t, map[int][]Event{1: p1, 2: p2}, 503, false)
	defer srv.Close()

	c := NewClient(srv.URL, "")
	res, err := c.Read(context.Background(), Cursor{}, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 503 {
		t.Errorf("read %d events, want 503", len(res.Events))
	}
	if res.NewCursor.LastEventID != "id-502" {
		t.Errorf("cursor at %q, want id-502", res.NewCursor.LastEventID)
	}
}

func TestReadEqualTimestampCohortDoesNotReplayAndAcceptsLateLowerID(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 123_000_000, time.UTC)
	source := &mutablePagedCore{}
	source.set([]Event{mkEvent("middle", base), mkEvent("z-last", base)})
	srv := httptest.NewServer(http.HandlerFunc(source.handler))
	defer srv.Close()
	c := NewClient(srv.URL, "")

	first, err := c.Read(context.Background(), Cursor{}, 5000)
	if err != nil || len(first.Events) != 2 {
		t.Fatalf("first read events=%d err=%v", len(first.Events), err)
	}
	dir := t.TempDir()
	if err := first.NewCursor.Save(dir); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}

	unchanged, err := c.Read(context.Background(), restarted, 5000)
	if err != nil || len(unchanged.Events) != 0 || unchanged.CursorAdvanced {
		t.Fatalf("unchanged read replayed events=%v advanced=%v err=%v", unchanged.Events, unchanged.CursorAdvanced, err)
	}

	// The new ID sorts before every previously seen ID. A lexicographic
	// high-water cursor would lose it; the exact cohort must emit it once.
	source.set([]Event{mkEvent("a-late", base), mkEvent("middle", base), mkEvent("z-last", base)})
	late, err := c.Read(context.Background(), restarted, 5000)
	if err != nil || len(late.Events) != 1 || late.Events[0].EventID != "a-late" {
		t.Fatalf("late read = %+v err=%v", late, err)
	}
	if err := late.NewCursor.Save(dir); err != nil {
		t.Fatal(err)
	}
	restarted, err = LoadCursor(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Read(context.Background(), restarted, 5000)
	if err != nil || len(again.Events) != 0 {
		t.Fatalf("late event replayed: events=%v err=%v", again.Events, err)
	}
}

func TestReadSameTimestampCohortAcrossPageAndTickBoundaries(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	const total = 1203
	events := make([]Event, total)
	for i := range events {
		events[i] = mkEvent(fmt.Sprintf("id-%04d", i), base)
	}
	source := &mutablePagedCore{}
	source.set(events)
	srv := httptest.NewServer(http.HandlerFunc(source.handler))
	defer srv.Close()
	c := NewClient(srv.URL, "")

	seen := map[string]bool{}
	cur := Cursor{}
	for tick := 0; tick < 3; tick++ {
		res, err := c.Read(context.Background(), cur, 700)
		if err != nil {
			t.Fatalf("tick %d: %v", tick+1, err)
		}
		for _, event := range res.Events {
			if seen[event.EventID] {
				t.Fatalf("tick %d replayed %s", tick+1, event.EventID)
			}
			seen[event.EventID] = true
		}
		cur = res.NewCursor
	}
	if len(seen) != total {
		t.Fatalf("read %d unique events, want %d", len(seen), total)
	}
	empty, err := c.Read(context.Background(), cur, 700)
	if err != nil || len(empty.Events) != 0 {
		t.Fatalf("drained cohort replayed %d events err=%v", len(empty.Events), err)
	}
}

func TestReadFullMalformedPageContinuesToNextPage(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	malformed := make([]Event, pageSize)
	for i := range malformed {
		malformed[i] = Event{Timestamp: base}
	}
	srv := fakeCore(t, map[int][]Event{
		1: malformed,
		2: {mkEvent("good-on-page-two", base.Add(time.Second))},
	}, pageSize+1, false)
	defer srv.Close()

	res, err := NewClient(srv.URL, "").Read(context.Background(), Cursor{}, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].EventID != "good-on-page-two" {
		t.Fatalf("page two was not reached: %+v", res.Events)
	}
	if res.SkippedMalformed != pageSize {
		t.Fatalf("skipped malformed=%d, want %d", res.SkippedMalformed, pageSize)
	}
}

func TestReadOverCapCohortReturnsNoPartialResult(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	ids := make([]string, maxCursorTimestampCohort-1)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%05d", i)
	}
	cur := Cursor{LastTimestamp: base, LastEventID: ids[len(ids)-1], SeenEventIDs: ids}
	source := &mutablePagedCore{}
	// The first new row fills the cohort and would be a partial result; the
	// second crosses the cap. Read must return neither of them to the exporter.
	source.set([]Event{mkEvent("new-fills-cap", base), mkEvent("new-over-cap", base)})
	srv := httptest.NewServer(http.HandlerFunc(source.handler))
	defer srv.Close()

	res, err := NewClient(srv.URL, "").Read(context.Background(), cur, 5000)
	if err == nil || res != nil {
		t.Fatalf("over-cap read returned partial result=%+v err=%v", res, err)
	}
}

func TestReadCap(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	p1 := make([]Event, 500)
	for i := range p1 {
		p1[i] = mkEvent(fmt.Sprintf("id-%03d", i), base.Add(time.Duration(i)*time.Second))
	}
	srv := fakeCore(t, map[int][]Event{1: p1}, 500, false)
	defer srv.Close()

	c := NewClient(srv.URL, "")
	res, err := c.Read(context.Background(), Cursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 100 {
		t.Errorf("read cap not honored: %d events", len(res.Events))
	}
}

func TestReadMalformedSkipped(t *testing.T) {
	// Serve a page with one good event and one malformed (missing id).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"events":[
			{"event_id":"good","timestamp":"2026-07-03T14:00:00Z","event_type":"dns_query","domain":"x.badzone.example"},
			{"event_id":"","timestamp":"2026-07-03T14:00:01Z"}
		],"total":2,"page":1,"limit":500}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	res, err := c.Read(context.Background(), Cursor{}, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Errorf("expected 1 good event, got %d", len(res.Events))
	}
	if res.SkippedMalformed != 1 {
		t.Errorf("expected 1 skipped malformed, got %d", res.SkippedMalformed)
	}
}

// Issue #37: EffectiveOptIn reads the `effective` field from Core's telemetry
// setting endpoint (using the read token), and returns an error on any
// transport/status/decode failure so the caller can fall back to env OptIn.
func TestEffectiveOptIn(t *testing.T) {
	t.Run("effective true", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/settings/telemetry" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer good-token" {
				t.Errorf("read token not sent: %q", r.Header.Get("Authorization"))
			}
			json.NewEncoder(w).Encode(map[string]any{"opt_in": true, "source": "setting", "effective": true})
		}))
		defer srv.Close()
		eff, err := NewClient(srv.URL, "good-token").EffectiveOptIn(context.Background())
		if err != nil || !eff {
			t.Fatalf("want effective=true err=nil, got %v %v", eff, err)
		}
	})
	t.Run("effective false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"opt_in": false, "source": "setting", "effective": false})
		}))
		defer srv.Close()
		eff, err := NewClient(srv.URL, "").EffectiveOptIn(context.Background())
		if err != nil || eff {
			t.Fatalf("want effective=false err=nil, got %v %v", eff, err)
		}
	})
	t.Run("unreachable errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		if _, err := NewClient(srv.URL, "").EffectiveOptIn(context.Background()); err == nil {
			t.Fatalf("expected error on non-200")
		}
	})
}

func TestReadUnreachableCursorUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	start := Cursor{LastTimestamp: time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC), LastEventID: "prev"}
	_, err := c.Read(context.Background(), start, 5000)
	if err == nil {
		t.Fatalf("expected error from failing Core")
	}
}
