package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// testSetupCode is the first-admin bootstrap setup code provisioned on the test
// server (GHSA-6cmx). Real deployments generate this at boot; tests use a fixed
// value so they can present it in the X-Vedetta-Setup-Code header.
const testSetupCode = "TEST-SETUP-CODE-0001"

// setupTestServer creates a Server backed by an in-memory SQLite DB, pre-loaded
// with the bootstrap setup code so first-admin creation can be exercised.
func setupTestServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	srv := &Server{DB: db, SetupCode: testSetupCode}
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
	// Bootstrap sensor enrollment now requires the one-time setup code (GHSA-6cmx).
	req.Header.Set("X-Vedetta-Setup-Code", testSetupCode)
	req.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register sensor: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AuthToken     string `json:"auth_token"`
		DeliveryEpoch string `json:"delivery_epoch"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if resp.AuthToken == "" {
		t.Fatal("expected bootstrap auth token in registration response")
	}
	if resp.DeliveryEpoch == "" {
		t.Fatal("expected Core-issued delivery epoch in registration response")
	}

	return resp.AuthToken
}

func createTestToken(t *testing.T, db *store.DB, scope auth.TokenScope, sensorID string) string {
	t.Helper()

	rawToken, token, err := auth.GenerateToken(scope, sensorID, "test-token")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if scope == auth.ScopeSensor {
		// Production sensor tokens must go through atomic enrollment. A few API
		// authorization tests deliberately need a synthetic sensor credential to
		// exercise a scope boundary without enrolling a device, so insert it only
		// in this test helper.
		var boundID any
		if sensorID != "" {
			boundID = sensorID
		}
		if _, err := db.Exec(`
			INSERT INTO api_tokens
				(token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked)
			VALUES (?, ?, ?, ?, ?, ?, ?, 0)
		`, token.TokenID, token.TokenHash, token.Scope, boundID, token.Label, token.CreatedAt, token.LastUsed); err != nil {
			t.Fatalf("store synthetic sensor token: %v", err)
		}
	} else if err := db.CreateToken(token); err != nil {
		t.Fatalf("store token: %v", err)
	}

	return rawToken
}

func TestSensorHeartbeatRefreshesLastSeenWithoutDrainingWork(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	authToken := registerTestSensor(t, router, "sensor-heartbeat")

	before := time.Now().UTC().Add(-10 * time.Minute)
	if _, err := db.Exec(`UPDATE sensors SET last_seen = ? WHERE sensor_id = ?`, before, "sensor-heartbeat"); err != nil {
		t.Fatalf("age sensor heartbeat: %v", err)
	}
	if srv.ScanQueue == nil {
		srv.ScanQueue = &ScanQueue{}
	}
	srv.ScanQueue.Enqueue("192.0.2.0/24", "default", false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Sensor-ID", "sensor-heartbeat")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: expected 204, got %d: %s", w.Code, w.Body.String())
	}

	sensors, err := db.ListSensors()
	if err != nil {
		t.Fatalf("list sensors: %v", err)
	}
	if len(sensors) != 1 || !sensors[0].LastSeen.After(before.Add(5*time.Minute)) {
		t.Fatalf("heartbeat did not refresh last_seen: %+v", sensors)
	}
	if got := srv.ScanQueue.Drain(); len(got) != 1 {
		t.Fatalf("heartbeat drained queued scan work: %+v", got)
	}
}

func TestSensorAuthCheckIsAuthenticatedAndDoesNotMutateSensor(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	authToken := registerTestSensor(t, router, "sensor-auth-check")
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")
	unboundSensorToken := createTestToken(t, db, auth.ScopeSensor, "")

	before := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	const tokenBefore = "2001-02-03T04:05:06Z"
	if _, err := db.Exec(`UPDATE sensors SET last_seen = ?, status = 'offline' WHERE sensor_id = ?`, before, "sensor-auth-check"); err != nil {
		t.Fatalf("age sensor before auth check: %v", err)
	}
	if _, err := db.Exec(`UPDATE api_tokens SET last_used = ? WHERE token_hash = ?`, tokenBefore, auth.HashToken(authToken)); err != nil {
		t.Fatalf("age token before auth check: %v", err)
	}
	if srv.ScanQueue == nil {
		srv.ScanQueue = &ScanQueue{}
	}
	srv.ScanQueue.Enqueue("192.0.2.0/24", "default", false)

	request := func(token, sensorID string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/auth-check", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if sensorID != "" {
			req.Header.Set("X-Sensor-ID", sensorID)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("auth check Cache-Control = %q, want no-store", got)
		}
		return w
	}

	missing := request("", "sensor-auth-check")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: expected 401, got %d: %s", missing.Code, missing.Body.String())
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"admin token":          request(adminToken, "sensor-auth-check"),
		"unbound sensor token": request(unboundSensorToken, "sensor-auth-check"),
		"mismatched sensor id": request(authToken, "different-sensor"),
		"missing sensor id":    request(authToken, ""),
	} {
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected generic 401, got %d: %s", name, w.Code, w.Body.String())
		}
		if w.Body.String() != missing.Body.String() {
			t.Fatalf("%s: credential failure differed from missing-token response: %q vs %q", name, w.Body.String(), missing.Body.String())
		}
	}
	if w := request(authToken, "sensor-auth-check"); w.Code != http.StatusNoContent {
		t.Fatalf("valid auth check: expected 204, got %d: %s", w.Code, w.Body.String())
	} else if w.Body.Len() != 0 {
		t.Fatalf("auth check leaked an unexpected response body: %q", w.Body.String())
	}

	var lastSeen time.Time
	var status string
	if err := db.QueryRow(`SELECT last_seen, status FROM sensors WHERE sensor_id = ?`, "sensor-auth-check").Scan(&lastSeen, &status); err != nil {
		t.Fatalf("read sensor after auth check: %v", err)
	}
	if !lastSeen.Equal(before) || status != "offline" {
		t.Fatalf("auth check mutated sensor state: last_seen=%s status=%q; want %s/offline", lastSeen, status, before)
	}
	var tokenLastUsed string
	if err := db.QueryRow(`SELECT last_used FROM api_tokens WHERE token_hash = ?`, auth.HashToken(authToken)).Scan(&tokenLastUsed); err != nil {
		t.Fatalf("read token after auth check: %v", err)
	}
	if tokenLastUsed != tokenBefore {
		t.Fatalf("auth check mutated token last_used: got %q, want %q", tokenLastUsed, tokenBefore)
	}
	if _, err := db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE token_hash = ?`, auth.HashToken(authToken)); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	if w := request(authToken, "sensor-auth-check"); w.Code != http.StatusUnauthorized || w.Body.String() != missing.Body.String() {
		t.Fatalf("revoked token: expected same generic 401, got %d: %s", w.Code, w.Body.String())
	}
	if err := db.QueryRow(`SELECT last_used FROM api_tokens WHERE token_hash = ?`, auth.HashToken(authToken)).Scan(&tokenLastUsed); err != nil {
		t.Fatalf("read revoked token after auth check: %v", err)
	}
	if tokenLastUsed != tokenBefore {
		t.Fatalf("revoked auth check mutated token last_used: got %q, want %q", tokenLastUsed, tokenBefore)
	}
	if got := srv.ScanQueue.Drain(); len(got) != 1 {
		t.Fatalf("auth check drained queued work: %+v", got)
	}
}

func TestSensorAuthCheckIsRateLimitedPerSourceIP(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	request := func(remoteAddr string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/auth-check", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer invalid-sensor-token")
		req.Header.Set("X-Sensor-ID", "sensor-auth-check-rate-limit")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	for i := 0; i < sensorAuthCheckRequestsPerMinute; i++ {
		if w := request("192.0.2.40:12345"); w.Code != http.StatusUnauthorized {
			t.Fatalf("request %d before limit: expected 401, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}
	limited := request("192.0.2.40:12345")
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("request above limit: expected 429, got %d: %s", limited.Code, limited.Body.String())
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited auth check omitted Retry-After")
	}
	if got := limited.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("rate-limited auth check Cache-Control = %q, want no-store", got)
	}
	if w := request("192.0.2.41:12345"); w.Code != http.StatusUnauthorized {
		t.Fatalf("independent source IP was rate limited: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSensorAuthCheckRejectsTombstonedIdentityWithoutMutation(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	initialToken := registerTestSensor(t, router, "sensor-auth-check-tombstone")
	if _, err := db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE token_hash = ?`, auth.HashToken(initialToken)); err != nil {
		t.Fatalf("revoke initial sensor token: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE sensors
		SET removed_at = ?, status = 'offline', removal_reason = 'test tombstone'
		WHERE sensor_id = ?
	`, time.Now().UTC(), "sensor-auth-check-tombstone"); err != nil {
		t.Fatalf("tombstone sensor: %v", err)
	}

	// Recreate the legacy/manual-token condition that the DB lifecycle guard must
	// defeat: an unrevoked, correctly bound credential exists for a tombstone.
	legacyToken := createTestToken(t, db, auth.ScopeSensor, "sensor-auth-check-tombstone")
	const tokenBefore = "2002-03-04T05:06:07Z"
	if _, err := db.Exec(`UPDATE api_tokens SET last_used = ? WHERE token_hash = ?`, tokenBefore, auth.HashToken(legacyToken)); err != nil {
		t.Fatalf("age legacy token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/auth-check", nil)
	req.Header.Set("Authorization", "Bearer "+legacyToken)
	req.Header.Set("X-Sensor-ID", "sensor-auth-check-tombstone")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("tombstoned auth check Cache-Control = %q, want no-store", got)
	}
	if w.Code != http.StatusUnauthorized || w.Body.String() != "{\"error\":\"invalid or revoked sensor token\"}\n" {
		t.Fatalf("tombstoned identity: expected generic 401, got %d: %s", w.Code, w.Body.String())
	}
	active, err := db.SensorActive("sensor-auth-check-tombstone")
	if err != nil {
		t.Fatalf("read tombstone state: %v", err)
	}
	if active {
		t.Fatal("auth check reactivated tombstoned sensor identity")
	}
	var tokenLastUsed string
	if err := db.QueryRow(`SELECT last_used FROM api_tokens WHERE token_hash = ?`, auth.HashToken(legacyToken)).Scan(&tokenLastUsed); err != nil {
		t.Fatalf("read legacy token after auth check: %v", err)
	}
	if tokenLastUsed != tokenBefore {
		t.Fatalf("tombstone auth check mutated token last_used: got %q, want %q", tokenLastUsed, tokenBefore)
	}
}

func TestSensorAuthCheckReturnsServiceUnavailableOnDatabaseFailure(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	if err := db.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/auth-check", nil)
	req.Header.Set("Authorization", "Bearer syntactically-valid-but-unavailable")
	req.Header.Set("X-Sensor-ID", "sensor-auth-check")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("failed auth check Cache-Control = %q, want no-store", got)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("database failure: expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestValidateReadOnlySensorRequestRejectsNilDatabaseWithoutPanic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/auth-check", nil)
	req.Header.Set("Authorization", "Bearer syntactically-valid-but-unavailable")
	req.Header.Set("X-Sensor-ID", "sensor-auth-check")

	err := (&Server{}).validateReadOnlySensorRequest(req)
	if err == nil || err.Error() != "database not available" {
		t.Fatalf("nil database error = %v, want database not available", err)
	}
	if errors.Is(err, errInvalidReadOnlySensorCredential) {
		t.Fatalf("nil database was collapsed into a credential failure: %v", err)
	}
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

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
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

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
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

func TestHandleIngest_WhollyMalformedBatchIsRejectedAndAccounted(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	payload := []byte(`[
		{"message":"missing normalized event fields"},
		[1773310272,{"raw_log":"pair missing event_type"}],
		"not-an-event"
	]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed-only ingest = %d, want 422: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["received"] != float64(3) || resp["accepted"] != float64(0) ||
		resp["rejected"] != float64(3) || resp["ignored"] != float64(0) {
		t.Fatalf("malformed-only accounting = %#v", resp)
	}

	health, err := db.ListCollectionSourceHealth(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(health) != 1 || health[0].SourceID != "collector" || health[0].Status != "error" || health[0].LastSuccess != nil {
		t.Fatalf("malformed-only collector health = %+v", health)
	}
}

func TestHandleIngest_MixedValidAndMalformedBatchIsPartialSuccess(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	payload := []byte(`[
		{"timestamp":"2025-07-12T10:11:12Z","event_type":"dns_query","source_ip":"192.0.2.20","domain":"mixed-valid.example","query_type":"A"},
		{"message":"missing normalized event fields"},
		{"timestamp":"2025-07-12T10:11:13Z","event_type":"unsupported_type"}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("mixed ingest = %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["received"] != float64(3) || resp["accepted"] != float64(1) ||
		resp["inserted"] != float64(1) || resp["rejected"] != float64(2) ||
		resp["ignored"] != float64(0) {
		t.Fatalf("mixed accounting = %#v", resp)
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "mixed-valid.example"})
	if err != nil || result.Total != 1 {
		t.Fatalf("valid mixed-batch sibling total=%d err=%v", result.Total, err)
	}
	health, err := db.ListCollectionSourceHealth(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(health) != 1 || health[0].Status != "healthy" || health[0].ItemCount != 1 || health[0].LastSuccess == nil {
		t.Fatalf("mixed collector health = %+v", health)
	}
}

func TestHandleIngest_MalformedBatchChangesHealthyCollectorToError(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	valid := []byte(`{"timestamp":"2025-07-12T10:11:12Z","event_type":"dns_query","source_ip":"192.0.2.21","domain":"health-seed.example","query_type":"A"}`)
	validReq := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(valid))
	validReq.Header.Set("Content-Type", "application/json")
	validW := httptest.NewRecorder()
	router.ServeHTTP(validW, validReq)
	if validW.Code != http.StatusAccepted {
		t.Fatalf("health seed = %d: %s", validW.Code, validW.Body.String())
	}

	malformedReq := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader([]byte(`[]`)))
	malformedReq.Header.Set("Content-Type", "application/json")
	malformedW := httptest.NewRecorder()
	router.ServeHTTP(malformedW, malformedReq)
	if malformedW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty collector batch = %d, want 422: %s", malformedW.Code, malformedW.Body.String())
	}

	health, err := db.ListCollectionSourceHealth(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(health) != 1 || health[0].Status != "error" || health[0].LastSuccess == nil || health[0].ItemCount != 1 {
		t.Fatalf("collector health after malformed batch = %+v", health)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/api/v1/health/detection", nil)
	healthW := httptest.NewRecorder()
	router.ServeHTTP(healthW, healthReq)
	if healthW.Code != http.StatusOK {
		t.Fatalf("detection health = %d: %s", healthW.Code, healthW.Body.String())
	}
	var detection struct {
		State   string `json:"state"`
		Sources []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"sources"`
	}
	if err := json.NewDecoder(healthW.Body).Decode(&detection); err != nil {
		t.Fatal(err)
	}
	if detection.State != "error" || len(detection.Sources) != 1 ||
		detection.Sources[0].ID != "collector" || detection.Sources[0].State != "error" {
		t.Fatalf("detection health did not surface collector error: %s", healthW.Body.String())
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

func TestHandleIngest_UpstreamIDAllowsReceiptTimestamp(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// An upstream ID provides the replay boundary when the collector cannot
	// provide event time. Core still namespaces the database key and records the
	// local receipt timestamp.
	body := []byte(`{"event_id":"upstream-auto","event_type":"dns_query","source_hash":"h","domain":"auto.test"}`)
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the event was stored with Core-owned fields.
	result, _ := db.QueryEvents(store.EventQueryParams{Domain: "auto.test"})
	if result.Total != 1 {
		t.Fatalf("expected 1 event, got %d", result.Total)
	}
	evt := result.Events[0]
	if evt.EventID == "" || evt.EventID == "upstream-auto" {
		t.Errorf("expected namespaced event_id, got %q", evt.EventID)
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

func TestHandleSensorRegister_RequiresAuthForReRegistration(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	originalToken := registerTestSensor(t, router, "sensor-reregister")

	body := []byte(`{"sensor_id":"sensor-reregister","hostname":"sensor-host","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"test"}`)
	callN := 0
	reReg := func(bearer string) *httptest.ResponseRecorder {
		callN++
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		// Distinct source IP per call so the per-IP registration rate limiter
		// (5/min) doesn't mask the behavior under test.
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:12345", 10+callN)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		tok, _ := m["auth_token"].(string)
		return tok
	}

	// 1. Unauthenticated re-registration of an already-enrolled sensor MUST be
	//    rejected. sensor_ids are guessable (hostname-os-arch), so the old
	//    "recovery mode" let an attacker revoke the real credential and be issued a
	//    replacement — a silent credential hijack (beta-gate B1a).
	if w := reReg(""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated re-registration, got %d: %s", w.Code, w.Body.String())
	}
	// The rejected attempt must NOT have revoked the legitimate token.
	if w := reReg(originalToken); w.Code != http.StatusOK {
		t.Fatalf("expected original sensor token still valid after rejected anon re-register, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Authenticated re-registration with the sensor's own token → 200 metadata
	//    refresh, and NO new token is issued (existing credential preserved).
	if got := tokenOf(reReg(originalToken)); got != "" {
		t.Fatal("expected sensor-token re-registration to reuse the existing token (no new one issued)")
	}

	// 3. Admin-initiated reset: an admin bearer forces revoke-old + issue-new.
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")
	newToken := tokenOf(reReg(adminToken))
	if newToken == "" {
		t.Fatal("expected admin-initiated reset to issue a fresh sensor token")
	}
	// The old sensor token is now revoked; the freshly issued one is valid.
	if w := reReg(originalToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected old sensor token revoked after admin reset, got %d", w.Code)
	}
	if w := reReg(newToken); w.Code != http.StatusOK {
		t.Fatalf("expected new sensor token valid after admin reset, got %d: %s", w.Code, w.Body.String())
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

func TestHandleIngest_FirewallFieldsRoundtrip_FaithfulCollectorShape(t *testing.T) {
	// Honest note: this test uses a synthetic payload with the listed firewall fields (action, protocol, etc.)
	// at top-level to verify the handler's preservation of top-level non-Event fields into metadata
	// (the drop-bug fix from the faithful shape test). It does NOT use the current collector's actual
	// output shape (which only has event_type/source_hash/raw_log at top-level per fluent-bit.conf
	// modify filter + rfc3164 parser; details stay inside raw_log CSV). See docs/connector-guide.md
	// for the documented limitation and that raw_log parsing belongs to the connector layer (Stage 5).
	// The test confirms that if/when top-level fields are emitted, they reach metadata for PIECE 3 filters.
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	token := createTestToken(t, db, auth.ScopeAdmin, "")

	// Faithful to collector config for firewall: top-level event_type, source_hash, raw_log (CSV with details inside),
	// plus parser fields. To directly test the top-level drop concern for the listed fields (action etc),
	// the payload includes them at top-level as the "if emitted top-level" case (actual collector leaves in raw_log CSV;
	// see STEP 1). After fix, top-level non-Event go to metadata for filter json_extract.
	payload := []byte(`{
		"timestamp": "2026-07-12T12:00:00Z",
		"event_type": "firewall_log",
		"source_hash": "pfsense-host",
		"raw_log": "5,16777216,,1000000103,igb1,match,block,in,4,0x10,,128,0,0,none,17,udp,328,198.51.100.1,198.51.100.2,67,68,308",
		"action": "block",
		"protocol": "udp",
		"src_ip": "198.51.100.1",
		"dst_ip": "198.51.100.2",
		"src_port": 67,
		"dst_port": 68,
		"interface": "igb1",
		"direction": "in",
		"rule": "1000000103",
		"pri": "134",
		"ident": "filterlog"
	}`)

	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("ingest expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Query with PIECE 3 filter on action (and protocol). An admin token exists,
	// so the read gate (beta-gate B6) now requires a bearer on GET /events; admin
	// satisfies read.
	req = httptest.NewRequest("GET", "/api/v1/events?action=block&protocol=udp&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("query failed: %d", w.Code)
	}

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	eventsIface, _ := result["events"].([]interface{})
	if len(eventsIface) < 1 {
		t.Fatalf("expected >=1 firewall event from ingest, got %d", len(eventsIface))
	}

	// Check fields are in the returned event's metadata (preserved, filterable)
	evtMap := eventsIface[0].(map[string]any)
	metaStr, _ := evtMap["metadata"].(string)
	var meta map[string]any
	json.Unmarshal([]byte(metaStr), &meta)
	if meta["action"] != "block" || meta["protocol"] != "udp" || meta["src_ip"] != "198.51.100.1" || meta["interface"] != "igb1" {
		t.Errorf("firewall fields not preserved in metadata or not filterable: %+v", meta)
	}
}
