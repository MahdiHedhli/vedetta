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

// setupTestServer creates a Server backed by an in-memory SQLite DB.
func setupTestServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	srv := &Server{DB: db}
	return srv, db
}

// --- Ingest Endpoint Tests ---

func TestHandleIngest_SingleEvent(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	event := models.Event{
		EventID:    "test-001",
		Timestamp:  time.Now().UTC(),
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["accepted"] != float64(1) {
		t.Errorf("expected accepted=1, got %v", resp["accepted"])
	}
}

func TestHandleIngest_BatchEvents(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	events := []models.Event{
		{EventID: "b1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h"},
		{EventID: "b2", Timestamp: time.Now().UTC(), EventType: "firewall_log", SourceHash: "h"},
		{EventID: "b3", Timestamp: time.Now().UTC(), EventType: "anomaly", SourceHash: "h"},
	}
	body, _ := json.Marshal(events)

	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["accepted"] != float64(3) {
		t.Errorf("expected accepted=3, got %v", resp["accepted"])
	}
}

func TestHandleIngest_InvalidEventType(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	event := models.Event{
		EventID:    "bad-001",
		Timestamp:  time.Now().UTC(),
		EventType:  "invalid_type",
		SourceHash: "h",
	}
	body, _ := json.Marshal(event)

	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["rejected"] != float64(1) {
		t.Errorf("expected rejected=1 for invalid type, got %v", resp["rejected"])
	}
}

func TestHandleIngest_EmptyBody(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d", w.Code)
	}
}

func TestHandleIngest_AutoGeneratesFields(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// Event with no event_id or timestamp — should be auto-filled
	body := []byte(`{"event_type": "dns_query", "source_hash": "h", "domain": "auto.test"}`)
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the event was stored with auto-generated fields
	result, _ := db.QueryEvents(store.EventQueryParams{Domain: "auto.test"})
	if result.Total != 1 {
		t.Fatalf("expected 1 event, got %d", result.Total)
	}
	evt := result.Events[0]
	if evt.EventID == "" {
		t.Error("expected auto-generated event_id")
	}
	if evt.Timestamp.IsZero() {
		t.Error("expected auto-generated timestamp")
	}
}

// --- Events Query Endpoint Tests ---

func TestHandleEvents_Empty(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp store.EventQueryResult
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 0 {
		t.Errorf("expected 0 events, got %d", resp.Total)
	}
}

func TestHandleEvents_WithFilters(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// Seed some events
	events := []models.Event{
		{EventID: "q1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Domain: "good.com", AnomalyScore: 0.1},
		{EventID: "q2", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Domain: "bad.xyz", AnomalyScore: 0.9},
		{EventID: "q3", Timestamp: time.Now().UTC(), EventType: "firewall_log", SourceHash: "h", AnomalyScore: 0.5},
	}
	db.InsertEvents(events)

	// Filter by type
	req := httptest.NewRequest("GET", "/api/v1/events?type=dns_query", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp store.EventQueryResult
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("expected 2 dns_query events, got %d", resp.Total)
	}

	// Filter by min_score
	req = httptest.NewRequest("GET", "/api/v1/events?min_score=0.5", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("expected 2 events with score >= 0.5, got %d", resp.Total)
	}
}

func TestHandleEvents_CSVExport(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	db.InsertEvents([]models.Event{
		{EventID: "csv1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "h", Domain: "test.com"},
	})

	req := httptest.NewRequest("GET", "/api/v1/events?format=csv", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/csv" {
		t.Errorf("expected Content-Type text/csv, got %s", ct)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("event_id,timestamp")) {
		t.Error("CSV should contain header row")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("csv1")) {
		t.Error("CSV should contain event data")
	}
}

// --- Status Endpoint Tests ---

func TestHandleStatus(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["service"] != "vedetta-core" {
		t.Errorf("expected service=vedetta-core, got %v", resp["service"])
	}
	// event_count should be present
	if _, ok := resp["event_count"]; !ok {
		t.Error("expected event_count in status response")
	}
}
