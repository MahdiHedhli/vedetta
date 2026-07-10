package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// GHSA-9m7g: Core must not persist a far-future event Timestamp. Telemetry uses the
// event Timestamp as its persistent cursor, so a single 2036-dated event would strand
// every normal event behind it forever. Both ingest paths must clamp to server-now.

// latestEventTimestamp reads back the single most recent stored event's timestamp.
func latestEventTimestamp(t *testing.T, db *store.DB) time.Time {
	t.Helper()
	res, err := db.QueryEvents(store.EventQueryParams{Page: 1, Limit: 1})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(res.Events) == 0 {
		t.Fatal("expected at least one stored event")
	}
	return res.Events[0].Timestamp
}

func TestHandleIngest_ClampsFutureTimestamp(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	future := time.Now().UTC().AddDate(10, 0, 0) // ~2036
	event := models.Event{
		EventID:    "future-001",
		Timestamp:  future,
		EventType:  "dns_query",
		SourceHash: "sha256:test",
		Domain:     "example.com",
		QueryType:  "A",
	}
	body, _ := json.Marshal(event)

	before := time.Now().UTC()
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	after := time.Now().UTC()

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	got := latestEventTimestamp(t, db)
	if got.After(after.Add(maxTimestampSkew)) {
		t.Fatalf("future timestamp was not clamped: stored %s, expected <= now (%s)", got, after)
	}
	// Clamped value should be approximately "now", not the far-future original.
	if got.Before(before.Add(-time.Minute)) {
		t.Fatalf("clamped timestamp %s is implausibly far in the past", got)
	}
}

func TestHandleIngest_KeepsRecentTimestamp(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// A legitimately-dated recent event (within skew) must be preserved exactly.
	recent := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	event := models.Event{
		EventID:    "recent-001",
		Timestamp:  recent,
		EventType:  "dns_query",
		SourceHash: "sha256:test",
		Domain:     "example.com",
		QueryType:  "A",
	}
	body, _ := json.Marshal(event)

	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	got := latestEventTimestamp(t, db).UTC().Truncate(time.Second)
	if !got.Equal(recent) {
		t.Fatalf("recent timestamp was altered: stored %s, expected %s", got, recent)
	}
}

func TestHandleSensorDNS_ClampsFutureTimestamp(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	authToken := registerTestSensor(t, router, "sensor-future")

	futureMillis := time.Now().UTC().AddDate(10, 0, 0).UnixMilli()
	body, _ := json.Marshal(map[string]any{
		"sensor_id": "sensor-future",
		"queries": []map[string]any{
			{
				"timestamp":  futureMillis,
				"domain":     "example.com",
				"query_type": "A",
				"client_ip":  "192.0.2.50",
				"source":     "test",
			},
		},
	})

	req := httptest.NewRequest("POST", "/api/v1/sensor/dns", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Sensor-ID", "sensor-future")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	after := time.Now().UTC()

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	got := latestEventTimestamp(t, db)
	if got.After(after.Add(maxTimestampSkew)) {
		t.Fatalf("sensor DNS future timestamp was not clamped: stored %s, expected <= now (%s)", got, after)
	}
}

func TestClampFutureTimestamp_Unit(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		ts   time.Time
		want time.Time
	}{
		{"zero stays zero", time.Time{}, time.Time{}},
		{"past preserved", now.Add(-72 * time.Hour), now.Add(-72 * time.Hour)},
		{"within skew preserved", now.Add(30 * time.Minute), now.Add(30 * time.Minute)},
		{"just over skew clamped", now.Add(maxTimestampSkew + time.Minute), now},
		{"far future clamped", now.AddDate(10, 0, 0), now},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clampFutureTimestamp(c.ts, now)
			if !got.Equal(c.want) {
				t.Fatalf("clampFutureTimestamp(%s) = %s, want %s", c.ts, got, c.want)
			}
		})
	}
}
