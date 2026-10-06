package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func securityArtifactObservation(id string, now time.Time) iotsecurity.Observation {
	return iotsecurity.Observation{ObservationID: id, Timestamp: now, SubjectIP: "192.0.2.10", Kind: iotsecurity.KindHostAudit,
		Files: []iotsecurity.FileEvidence{{Path: "/root/.cling", Size: 512, SHA256: "90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2"}}}
}

func postSecurity(t *testing.T, router http.Handler, token, sensorID string, observations []iotsecurity.Observation) *httptest.ResponseRecorder {
	t.Helper()
	return requestJSON(t, router, http.MethodPost, "/api/v1/sensor/security", token, sensorSecurityRequest{SensorID: sensorID, Observations: observations})
}

func assertSecurityCounts(t *testing.T, response *httptest.ResponseRecorder, status, accepted, duplicates, failed int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	var counts struct{ Accepted, Duplicates, Failed int }
	if err := json.Unmarshal(response.Body.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Accepted != accepted || counts.Duplicates != duplicates || counts.Failed != failed {
		t.Fatalf("counts = %+v, want %d/%d/%d", counts, accepted, duplicates, failed)
	}
}

func securityTableCount(t *testing.T, db *store.DB, table string) int {
	t.Helper()
	// Test-only literal table selection; no request material reaches this SQL.
	query := map[string]string{"events": "SELECT COUNT(*) FROM events", "findings": "SELECT COUNT(*) FROM findings", "evidence": "SELECT COUNT(*) FROM event_detection_evidence"}[table]
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSensorSecurityRequiresExactScopeAndBoundActiveSensor(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-auth-sensor"
	sensorToken := registerTestSensor(t, router, sensorID)
	if err := db.RegisterSensor(models.Sensor{SensorID: "removed-sensor", Hostname: "synthetic-removed", OS: "linux", Arch: "amd64", CIDR: "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RemoveSensor("removed-sensor", "test", "synthetic removed sensor"); err != nil {
		t.Fatal(err)
	}
	observation := securityArtifactObservation("auth-observation", time.Now().UTC())
	for _, test := range []struct {
		name, token, sensorID string
		status                int
	}{
		{"no token", "", sensorID, http.StatusUnauthorized},
		{"read token", createTestToken(t, db, auth.ScopeRead, ""), sensorID, http.StatusForbidden},
		{"ingest token", createTestToken(t, db, auth.ScopeIngest, ""), sensorID, http.StatusForbidden},
		{"admin token", createTestToken(t, db, auth.ScopeAdmin, ""), sensorID, http.StatusForbidden},
		{"unbound sensor", createTestToken(t, db, auth.ScopeSensor, ""), sensorID, http.StatusForbidden},
		{"another sensor", sensorToken, "different-sensor", http.StatusForbidden},
		{"inactive sensor", createTestToken(t, db, auth.ScopeSensor, "removed-sensor"), "removed-sensor", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := postSecurity(t, router, test.token, test.sensorID, []iotsecurity.Observation{observation})
			if response.Code != test.status {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
		})
	}
	if securityTableCount(t, db, "events") != 0 {
		t.Fatal("unauthorized request persisted events")
	}
	assertSecurityCounts(t, postSecurity(t, router, sensorToken, sensorID, []iotsecurity.Observation{observation}), http.StatusOK, 1, 0, 0)
}

func TestSensorSecurityReplayIsScopedAndDoesNotMutateAcceptedFacts(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-replay-one"
	token := registerTestSensor(t, router, sensorID)
	observation := securityArtifactObservation("same-occurrence", time.Now().UTC())
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, []iotsecurity.Observation{observation}), http.StatusOK, 1, 0, 0)
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, []iotsecurity.Observation{observation}), http.StatusOK, 0, 1, 0)
	altered := observation
	altered.Timestamp = altered.Timestamp.Add(time.Minute)
	altered.SubjectIP = "192.0.2.11"
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, []iotsecurity.Observation{altered}), http.StatusOK, 0, 1, 0)
	var subject string
	if err := db.QueryRow("SELECT source_ip FROM events WHERE event_id = ?", sensorSecurityEventID(sensorID, observation.ObservationID)).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != observation.SubjectIP {
		t.Fatalf("replay mutated subject to %q", subject)
	}
	var occurrences int
	if err := db.QueryRow("SELECT occurrence_count FROM findings").Scan(&occurrences); err != nil {
		t.Fatal(err)
	}
	if occurrences != 1 {
		t.Fatalf("replay occurrence count = %d", occurrences)
	}

	otherID := "security-replay-two"
	if err := db.RegisterSensor(models.Sensor{SensorID: otherID, Hostname: "synthetic-sensor", OS: "linux", Arch: "amd64", CIDR: "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	otherToken := createTestToken(t, db, auth.ScopeSensor, otherID)
	assertSecurityCounts(t, postSecurity(t, router, otherToken, otherID, []iotsecurity.Observation{observation}), http.StatusOK, 1, 0, 0)
	if securityTableCount(t, db, "events") != 2 {
		t.Fatal("two authenticated sensors collided on one observation ID")
	}
}

func TestSensorSecurityRejectsWholeInvalidBatchBeforePersistence(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-invalid-sensor"
	token := registerTestSensor(t, router, sensorID)
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		modify func(*iotsecurity.Observation)
	}{
		{"invalid subject", func(o *iotsecurity.Observation) { o.SubjectIP = "router.example" }},
		{"missing timestamp", func(o *iotsecurity.Observation) { o.Timestamp = time.Time{} }},
		{"future timestamp", func(o *iotsecurity.Observation) { o.Timestamp = now.Add(2 * time.Hour) }},
		{"invalid file path", func(o *iotsecurity.Observation) { o.Files[0].Path = "/etc/shadow" }},
		{"bad digest", func(o *iotsecurity.Observation) { o.Files[0].SHA256 = "not-a-digest" }},
		{"unsupported kind", func(o *iotsecurity.Observation) { o.Kind = "confirmed_compromise" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			valid := securityArtifactObservation("valid-first", now)
			invalid := securityArtifactObservation("invalid-second", now)
			test.modify(&invalid)
			response := postSecurity(t, router, token, sensorID, []iotsecurity.Observation{valid, invalid})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if securityTableCount(t, db, "events") != 0 {
				t.Fatal("valid prefix of invalid batch persisted")
			}
		})
	}
	valid := securityArtifactObservation("valid-first", now)
	tooMany := make([]iotsecurity.Observation, iotsecurity.MaxBatchObservations+1)
	for i := range tooMany {
		tooMany[i] = valid
	}
	if response := postSecurity(t, router, token, sensorID, tooMany); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch status = %d", response.Code)
	}
}

func TestSensorSecurityJSONBoundaryRejectsUnknownTrailingAndOversizedData(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-json-sensor"
	token := registerTestSensor(t, router, sensorID)
	valid, _ := json.Marshal(sensorSecurityRequest{SensorID: sensorID, Observations: []iotsecurity.Observation{securityArtifactObservation("json-fixture", time.Now().UTC())}})
	unknown := strings.Replace(string(valid), `"kind":"host_audit"`, `"kind":"host_audit","anomaly_score":1`, 1)
	for _, test := range []struct {
		name, raw string
		status    int
	}{
		{"unknown verdict field", unknown, http.StatusBadRequest},
		{"unknown origin", strings.Replace(string(valid), `"observations":`, `"origin":"sensor_security","observations":`, 1), http.StatusBadRequest},
		{"trailing JSON", string(valid) + ` {}`, http.StatusBadRequest},
		{"oversized trailing whitespace", string(valid) + strings.Repeat(" ", iotsecurity.MaxRequestBytes), http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/security", strings.NewReader(test.raw))
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != test.status {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSensorSecurityPartialPersistenceRetryPreservesOccurrences(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-partial-sensor"
	token := registerTestSensor(t, router, sensorID)
	first := securityArtifactObservation("first-occurrence", time.Now().UTC())
	second := securityArtifactObservation("second-occurrence", first.Timestamp)
	second.SubjectIP = "192.0.2.99"
	if _, err := db.Exec(`CREATE TRIGGER fail_security_observation BEFORE INSERT ON events WHEN NEW.source_ip = '192.0.2.99' BEGIN SELECT RAISE(ABORT, 'synthetic persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	batch := []iotsecurity.Observation{first, second}
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, batch), http.StatusServiceUnavailable, 1, 0, 1)
	if _, err := db.Exec("DROP TRIGGER fail_security_observation"); err != nil {
		t.Fatal(err)
	}
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, batch), http.StatusOK, 1, 1, 0)
	if securityTableCount(t, db, "events") != 2 || securityTableCount(t, db, "evidence") != 2 {
		t.Fatal("partial batch replay duplicated or lost evidence")
	}
	var maximum int
	if err := db.QueryRow("SELECT MAX(occurrence_count) FROM findings").Scan(&maximum); err != nil {
		t.Fatal(err)
	}
	if maximum != 1 {
		t.Fatalf("partial retry inflated occurrence count to %d", maximum)
	}
}

func TestSensorSecurityAttemptAssociatesTargetAndRetainsSuppressedEvidence(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "security-target-sensor"
	token := registerTestSensor(t, router, sensorID)
	now := time.Now().UTC().Add(-time.Minute)
	if _, err := db.ObserveDevice(store.DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: "192.0.2.10", MACAddress: "00:00:5E:00:53:10", Status: "up", DiscoverySource: "passive_arp"},
		Segment: "default", SensorID: sensorID, ObservedAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	device, err := db.GetDeviceByIP("192.0.2.10")
	if err != nil || device == nil {
		t.Fatalf("target device: %v", err)
	}
	observation := iotsecurity.Observation{ObservationID: "target-attempt", Timestamp: now, SubjectIP: "192.0.2.10", Kind: iotsecurity.KindRealtekExploit,
		Packets: []iotsecurity.PacketEvidence{{Timestamp: now, SourceIP: "198.51.100.2", DestinationIP: "192.0.2.10", SourcePort: 42000, DestinationPort: 9034, PayloadHex: "6f72663b", PayloadLength: 20}}}
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, []iotsecurity.Observation{observation}), http.StatusOK, 1, 0, 0)
	var findingID, associatedID, origin, outcome string
	if err := db.QueryRow("SELECT finding_id, device_id FROM findings").Scan(&findingID, &associatedID); err != nil {
		t.Fatal(err)
	}
	if associatedID != device.DeviceID {
		t.Fatalf("attack attributed to %q instead of target %q", associatedID, device.DeviceID)
	}
	if err := db.QueryRow("SELECT origin, outcome FROM events").Scan(&origin, &outcome); err != nil {
		t.Fatal(err)
	}
	if origin != "sensor_security" || outcome != "observed" {
		t.Fatalf("event provenance/outcome = %s/%s", origin, outcome)
	}
	if _, err := db.SuppressFinding(context.Background(), findingID, "synthetic investigation acknowledged", "test"); err != nil {
		t.Fatal(err)
	}
	observation.ObservationID = "target-attempt-repeat"
	observation.Timestamp = now.Add(time.Second)
	observation.Packets[0].Timestamp = observation.Timestamp
	assertSecurityCounts(t, postSecurity(t, router, token, sensorID, []iotsecurity.Observation{observation}), http.StatusOK, 1, 0, 0)
	var disposition string
	var occurrences int
	if err := db.QueryRow("SELECT disposition, occurrence_count FROM findings WHERE finding_id = ?", findingID).Scan(&disposition, &occurrences); err != nil {
		t.Fatal(err)
	}
	if disposition != "suppressed" || occurrences != 2 || securityTableCount(t, db, "evidence") != 2 {
		t.Fatalf("suppression lost evidence: %s/%d", disposition, occurrences)
	}
}

func TestCollectorCannotManufactureSensorSecurityOrigin(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	now := time.Now().UTC()
	metadata, _ := json.Marshal(map[string]any{"iot_observation": securityArtifactObservation("collector-spoof", now), "origin": "sensor_security", "sensor_id": "sensor-forged"})
	event := models.Event{EventID: "collector-spoof", Timestamp: now, EventType: "anomaly", SourceIP: "192.0.2.10", Origin: "sensor_security", SensorID: "sensor-forged",
		Tags: []string{iotsecurity.DetectorArtifact, "cling_compromised", "known_bad"}, AnomalyScore: 1.0, Metadata: string(metadata)}
	response := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", admin, event)
	if response.Code != http.StatusAccepted {
		t.Fatalf("collector status = %d: %s", response.Code, response.Body.String())
	}
	if securityTableCount(t, db, "events") != 1 || securityTableCount(t, db, "findings") != 0 || securityTableCount(t, db, "evidence") != 0 {
		t.Fatal("collector manufactured sensor detector evidence")
	}
	var raw []byte
	if err := db.QueryRow("SELECT tags FROM events").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(iotsecurity.DetectorArtifact)) || bytes.Contains(raw, []byte("cling_compromised")) {
		t.Fatalf("forged detector tags survived: %s", raw)
	}
}
