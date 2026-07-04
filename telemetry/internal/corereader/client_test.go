package corereader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
