package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
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

func registerTestSensor(t *testing.T, router http.Handler, sensorID string) string {
	t.Helper()

	body := map[string]any{
		"sensor_id": sensorID,
		"hostname":  "sensor-host",
		"os":        "linux",
		"arch":      "amd64",
		"cidr":      "192.168.1.0/24",
		"version":   "test",
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal register body: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register sensor: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if resp.AuthToken == "" {
		t.Fatal("expected bootstrap auth token in registration response")
	}

	return resp.AuthToken
}

func createTestToken(t *testing.T, db *store.DB, scope auth.TokenScope, sensorID string) string {
	t.Helper()

	rawToken, token, err := auth.GenerateToken(scope, sensorID, "test-token")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := db.CreateToken(token); err != nil {
		t.Fatalf("store token: %v", err)
	}

	return rawToken
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

func TestHandleSensorRegister_RequiresExistingTokenForReRegistration(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	authToken := registerTestSensor(t, router, "sensor-reregister")

	body := []byte(`{"sensor_id":"sensor-reregister","hostname":"sensor-host","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"test"}`)

	req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated re-registration, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.RemoteAddr = "192.0.2.10:12345"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated re-registration, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode re-registration response: %v", err)
	}
	if resp.AuthToken != "" {
		t.Fatal("expected re-registration to avoid issuing a second bootstrap token")
	}
}

func TestHandleSensorDevices_AuthenticatedDeviceReportSucceeds(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)
	authToken := registerTestSensor(t, router, "sensor-devices")

	body := []byte(`{
		"sensor_id":"sensor-devices",
		"cidr":"192.168.1.0/24",
		"hosts":[
			{
				"ip_address":"192.168.1.10",
				"mac_address":"aa:bb:cc:dd:ee:ff",
				"hostname":"printer",
				"status":"up"
			}
		]
	}`)

	req := httptest.NewRequest("POST", "/api/v1/sensor/devices", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Sensor-ID", "sensor-devices")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSensorDevices_RequiresAuthentication(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	body := []byte(`{
		"sensor_id":"sensor-devices",
		"cidr":"192.168.1.0/24",
		"hosts":[
			{
				"ip_address":"192.168.1.11",
				"mac_address":"aa:bb:cc:dd:ee:01",
				"hostname":"camera",
				"status":"up"
			}
		]
	}`)

	req := httptest.NewRequest("POST", "/api/v1/sensor/devices", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-ID", "sensor-devices")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSensorDevices_WrongScopeTokenRejected(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")

	body := []byte(`{
		"sensor_id":"sensor-devices",
		"cidr":"192.168.1.0/24",
		"hosts":[
			{
				"ip_address":"192.168.1.12",
				"mac_address":"aa:bb:cc:dd:ee:02",
				"hostname":"tv",
				"status":"up"
			}
		]
	}`)

	req := httptest.NewRequest("POST", "/api/v1/sensor/devices", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Sensor-ID", "sensor-devices")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
