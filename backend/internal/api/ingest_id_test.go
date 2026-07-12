package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func postIngestPayload(t *testing.T, router http.Handler, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHandleIngestMissingIDReplayIsIdempotentAndIgnoresCallerHash(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	first := []byte(`{
		"timestamp":"2025-07-12T10:11:12.123Z",
		"event_type":"dns_query",
		"source_hash":"192.0.2.10",
		"source_ip":"192.0.2.10",
		"dns_source":"pihole",
		"domain":"Replay.Example.",
		"query_type":"a"
	}`)
	second := []byte(`{
		"query_type":"A",
		"domain":"replay.example",
		"dns_source":"PIHOLE",
		"source_ip":"192.0.2.10",
		"source_hash":"attacker-chosen",
		"event_type":"dns_query",
		"timestamp":"2025-07-12T10:11:12.123000000Z"
	}`)

	if w := postIngestPayload(t, router, first); w.Code != http.StatusAccepted {
		t.Fatalf("first ingest = %d: %s", w.Code, w.Body.String())
	}
	if w := postIngestPayload(t, router, second); w.Code != http.StatusAccepted {
		t.Fatalf("replay ingest = %d: %s", w.Code, w.Body.String())
	} else {
		var response map[string]any
		_ = json.NewDecoder(w.Body).Decode(&response)
		if response["duplicates"] != float64(1) || response["inserted"] != float64(0) {
			t.Fatalf("replay response = %#v", response)
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "replay.example"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("replay created %d rows, want 1", result.Total)
	}
	if result.Events[0].SourceHash == "192.0.2.10" || result.Events[0].SourceHash == "attacker-chosen" {
		t.Fatalf("caller source_hash was trusted: %q", result.Events[0].SourceHash)
	}
}

func TestHandleIngestFluentBitPairTimestampReplayIsIdempotent(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	payload := []byte(`[[1773310272.125,{"event_type":"firewall_log","source_ip":"192.0.2.44","blocked":true,"raw_log":"synthetic stable record"}]]`)
	for attempt := 0; attempt < 2; attempt++ {
		if w := postIngestPayload(t, router, payload); w.Code != http.StatusAccepted {
			t.Fatalf("attempt %d = %d: %s", attempt+1, w.Code, w.Body.String())
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{Type: "firewall_log"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("pair replay created %d rows, want 1", result.Total)
	}
	want := time.Unix(1773310272, 125_000_000).UTC()
	if delta := result.Events[0].Timestamp.Sub(want); delta < -time.Microsecond || delta > time.Microsecond {
		t.Fatalf("pair timestamp = %s, want %s", result.Events[0].Timestamp, want)
	}
}

func TestHandleIngestRejectsRecordWithoutTimestampOrUpstreamID(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	w := postIngestPayload(t, router, []byte(`{"event_type":"dns_query","source_ip":"192.0.2.9","domain":"no-boundary.example"}`))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ingest = %d: %s", w.Code, w.Body.String())
	}
	var response map[string]any
	_ = json.NewDecoder(w.Body).Decode(&response)
	if response["accepted"] != float64(0) || response["rejected"] != float64(1) || response["missing_event_identity"] != float64(1) {
		t.Fatalf("response = %#v", response)
	}
	result, err := db.QueryEvents(store.EventQueryParams{})
	if err != nil || result.Total != 0 {
		t.Fatalf("identity-less record persisted: total=%d err=%v", result.Total, err)
	}
}

func TestHandleIngestUpstreamIDWithoutTimestampHasStableNamespacedReplay(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	payload := []byte(`{"event_id":"upstream-42","event_type":"firewall_log","source_ip":"192.0.2.40","blocked":true,"raw_log":"synthetic record"}`)
	for attempt := 0; attempt < 2; attempt++ {
		w := postIngestPayload(t, router, payload)
		if w.Code != http.StatusAccepted {
			t.Fatalf("attempt %d = %d: %s", attempt+1, w.Code, w.Body.String())
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{Type: "firewall_log"})
	if err != nil || result.Total != 1 {
		t.Fatalf("upstream replay total=%d err=%v", result.Total, err)
	}
	if result.Events[0].EventID == "upstream-42" {
		t.Fatal("caller-controlled upstream ID became the database key")
	}
}

func TestHandleIngestSameUpstreamIDDifferentContentDoesNotCollide(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	for _, domain := range []string{"first.example", "second.example"} {
		payload, _ := json.Marshal(map[string]any{
			"event_id": "reused-upstream-id", "timestamp": "2025-07-12T10:11:12Z",
			"event_type": "dns_query", "source_ip": "192.0.2.41", "domain": domain, "query_type": "A",
		})
		if w := postIngestPayload(t, router, payload); w.Code != http.StatusAccepted {
			t.Fatalf("%s = %d: %s", domain, w.Code, w.Body.String())
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{})
	if err != nil || result.Total != 2 || result.Events[0].EventID == result.Events[1].EventID {
		t.Fatalf("different records collided: total=%d err=%v events=%+v", result.Total, err, result.Events)
	}
}

func TestHandleIngestCollectorObservationIDsPreserveSameSecondOccurrencesAndRetries(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	payload := []byte(`[
		{"event_id":"unifi-boot-1","timestamp":"2025-07-12T10:11:12Z","event_type":"firewall_log","source_ip":"192.0.2.41","blocked":true,"metadata":"{\"action\":\"block\",\"dst_ip\":\"203.0.113.7\",\"rule\":\"synthetic\"}"},
		{"event_id":"unifi-boot-2","timestamp":"2025-07-12T10:11:12Z","event_type":"firewall_log","source_ip":"192.0.2.41","blocked":true,"metadata":"{\"action\":\"block\",\"dst_ip\":\"203.0.113.7\",\"rule\":\"synthetic\"}"}
	]`)
	first := postIngestPayload(t, router, payload)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first occurrences = %d: %s", first.Code, first.Body.String())
	}
	second := postIngestPayload(t, router, payload)
	if second.Code != http.StatusAccepted {
		t.Fatalf("exact retry = %d: %s", second.Code, second.Body.String())
	}
	var replay map[string]any
	_ = json.NewDecoder(second.Body).Decode(&replay)
	if replay["inserted"] != float64(0) || replay["duplicates"] != float64(2) {
		t.Fatalf("exact retry response = %#v", replay)
	}
	result, err := db.QueryEvents(store.EventQueryParams{Type: "firewall_log"})
	if err != nil || result.Total != 2 {
		t.Fatalf("same-second occurrences total=%d err=%v", result.Total, err)
	}
	seenUpstream := map[string]bool{}
	for _, event := range result.Events {
		if event.EventID == "unifi-boot-1" || event.EventID == "unifi-boot-2" {
			t.Fatalf("upstream observation ID was not Core-namespaced: %q", event.EventID)
		}
		var metadata map[string]any
		if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
			t.Fatal(err)
		}
		if upstream, _ := metadata["event_id"].(string); upstream != "" {
			seenUpstream[upstream] = true
		}
	}
	if !seenUpstream["unifi-boot-1"] || !seenUpstream["unifi-boot-2"] {
		t.Fatalf("collector observation IDs missing from source metadata: %#v", seenUpstream)
	}
}

func TestHandleIngestCannotPreseedAuthenticatedSensorEventID(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-event-domain"
	observed := time.UnixMilli(1_773_310_272_123).UTC()
	sensorEvent := models.Event{
		Timestamp: observed, EventType: "dns_query", SourceIP: "192.0.2.77", ServerIP: "192.0.2.53",
		Domain: "domain-separated.example", QueryType: "A", ResolvedIP: "198.51.100.10", DNSSource: "passive_capture",
	}
	predictedSensorID := deterministicSensorDNSEventID(sensorID, observed, sensorEvent, []string{"198.51.100.10"}, "", "", "")
	collector, _ := json.Marshal(map[string]any{
		"event_id": predictedSensorID, "timestamp": observed, "event_type": "dns_query",
		"source_ip": "192.0.2.77", "domain": "collector-copy.example", "query_type": "A",
	})
	if w := postIngestPayload(t, router, collector); w.Code != http.StatusAccepted {
		t.Fatalf("collector seed = %d: %s", w.Code, w.Body.String())
	}

	token := registerTestSensor(t, router, sensorID)
	sensorPayload := []byte(`{"sensor_id":"sensor-event-domain","queries":[{"timestamp":1773310272123,"domain":"domain-separated.example","query_type":"A","client_ip":"192.0.2.77","response_ip":"198.51.100.10","server_ip":"192.0.2.53","source":"passive_capture","answers":["198.51.100.10"]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/dns", bytes.NewReader(sensorPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Sensor-ID", sensorID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sensor event = %d: %s", w.Code, w.Body.String())
	}

	result, err := db.QueryEvents(store.EventQueryParams{})
	if err != nil || result.Total != 2 {
		t.Fatalf("collector preseed suppressed sensor event: total=%d err=%v", result.Total, err)
	}
	foundSensorKey := false
	for _, event := range result.Events {
		if event.EventID == predictedSensorID && event.Origin == "sensor_dns" {
			foundSensorKey = true
		}
	}
	if !foundSensorKey {
		t.Fatalf("authenticated sensor event key missing: %+v", result.Events)
	}
}

func TestHandleIngestPartialFailureReturnsRetryableAndCommittedSiblingDeduplicates(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	if _, err := db.Exec(`
		CREATE TRIGGER fail_replay_event
		BEFORE INSERT ON events
		WHEN NEW.domain = 'fail-retry.example'
		BEGIN SELECT RAISE(ABORT, 'synthetic processing failure'); END
	`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	payload := []byte(`[
		{"timestamp":"2025-07-12T10:11:12Z","event_type":"dns_query","source_ip":"192.0.2.8","domain":"committed-retry.example","query_type":"A"},
		{"timestamp":"2025-07-12T10:11:13Z","event_type":"dns_query","source_ip":"192.0.2.8","domain":"fail-retry.example","query_type":"A"}
	]`)

	for attempt := 0; attempt < 2; attempt++ {
		w := postIngestPayload(t, router, payload)
		if w.Code < 500 || w.Code > 599 {
			t.Fatalf("failed batch attempt %d returned %d, want retryable 5xx: %s", attempt+1, w.Code, w.Body.String())
		}
		result, err := db.QueryEvents(store.EventQueryParams{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != 1 {
			t.Fatalf("attempt %d left %d rows, want the one committed sibling", attempt+1, result.Total)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER fail_replay_event`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	w := postIngestPayload(t, router, payload)
	if w.Code != http.StatusAccepted {
		t.Fatalf("successful retry = %d: %s", w.Code, w.Body.String())
	}
	var response map[string]any
	_ = json.NewDecoder(w.Body).Decode(&response)
	if response["inserted"] != float64(1) || response["duplicates"] != float64(1) || response["accepted"] != float64(2) {
		t.Fatalf("successful partial retry response = %#v", response)
	}
	result, err := db.QueryEvents(store.EventQueryParams{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Fatalf("successful retry left %d rows, want 2", result.Total)
	}
}

func TestHandleSensorDNSReplayUsesAuthenticatedSensorIdentity(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	token := registerTestSensor(t, router, "sensor-idempotency")
	payload := []byte(`{
		"sensor_id":"sensor-idempotency",
		"queries":[{
			"timestamp":1773310272123,
			"domain":"sensor-replay.example",
			"query_type":"A",
			"client_ip":"192.0.2.77",
			"response_ip":"198.51.100.10",
			"server_ip":"192.0.2.53",
			"source":"passive_capture",
			"answers":["198.51.100.10"]
		}]
	}`)
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/dns", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Sensor-ID", "sensor-idempotency")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := post(); w.Code != http.StatusOK {
		t.Fatalf("first sensor push = %d: %s", w.Code, w.Body.String())
	}
	if w := post(); w.Code != http.StatusOK {
		t.Fatalf("sensor replay = %d: %s", w.Code, w.Body.String())
	} else {
		var response map[string]any
		_ = json.NewDecoder(w.Body).Decode(&response)
		if response["duplicates"] != float64(1) || response["inserted"] != float64(0) {
			t.Fatalf("sensor replay response = %#v", response)
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "sensor-replay.example"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("sensor replay created %d rows, want 1", result.Total)
	}
}

func TestHandleSensorDNSObservationIDsPreserveSameMillisecondOccurrencesAndRetries(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-occurrences"
	token := registerTestSensor(t, router, sensorID)
	payload := []byte(`{
		"sensor_id":"sensor-occurrences",
		"queries":[
			{"observation_id":"dns-observation-a","timestamp":1773310272123,"domain":"repeat.example","query_type":"A","client_ip":"192.0.2.77","server_ip":"192.0.2.53","direction":"response","response_code":"NOERROR","source":"passive_capture","answers":["198.51.100.10"]},
			{"observation_id":"dns-observation-b","timestamp":1773310272123,"domain":"repeat.example","query_type":"A","client_ip":"192.0.2.77","server_ip":"192.0.2.53","direction":"response","response_code":"NOERROR","source":"passive_capture","answers":["198.51.100.10"]}
		]
	}`)
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/dns", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Sensor-ID", sensorID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if first := post(); first.Code != http.StatusOK {
		t.Fatalf("first occurrences = %d: %s", first.Code, first.Body.String())
	}
	second := post()
	if second.Code != http.StatusOK {
		t.Fatalf("exact retry = %d: %s", second.Code, second.Body.String())
	}
	var replay map[string]any
	_ = json.NewDecoder(second.Body).Decode(&replay)
	if replay["inserted"] != float64(0) || replay["duplicates"] != float64(2) {
		t.Fatalf("exact retry response = %#v", replay)
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "repeat.example"})
	if err != nil || result.Total != 2 {
		t.Fatalf("same-millisecond occurrences total=%d err=%v", result.Total, err)
	}
	seen := map[string]bool{}
	for _, event := range result.Events {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
			t.Fatal(err)
		}
		if observation, _ := metadata["observation_id"].(string); observation != "" {
			seen[observation] = true
		}
	}
	if !seen["dns-observation-a"] || !seen["dns-observation-b"] {
		t.Fatalf("observation IDs missing from source metadata: %#v", seen)
	}

	legacy := models.Event{SourceIP: "192.0.2.77", ServerIP: "192.0.2.53", Domain: "repeat.example", QueryType: "A", DNSSource: "passive_capture"}
	observed := time.UnixMilli(1_773_310_272_123).UTC()
	if got, want := deterministicSensorDNSObservationEventID(sensorID, observed, legacy, nil, "", "", "", ""), deterministicSensorDNSEventID(sensorID, observed, legacy, nil, "", "", ""); got != want {
		t.Fatalf("legacy no-observation ID changed: %q != %q", got, want)
	}
}

func TestHandleSensorDNSDirectionAndResponseCodeAreStableMetadataAndIDMaterial(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-wire-semantics"
	token := registerTestSensor(t, router, sensorID)
	payload := []byte(`{
		"sensor_id":"sensor-wire-semantics",
		"queries":[
			{"timestamp":1751000000000,"domain":"missing.example","query_type":"A","client_ip":"192.0.2.25","server_ip":"192.0.2.53","direction":"query","source":"passive_capture","process":"synthetic-resolver"},
			{"timestamp":1751000000025,"domain":"missing.example","query_type":"A","client_ip":"192.0.2.25","server_ip":"192.0.2.53","direction":"response","response_code":"NXDOMAIN","source":"passive_capture"}
		]
	}`)
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/dns", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Sensor-ID", sensorID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := post(); w.Code != http.StatusOK {
		t.Fatalf("first explicit exchange = %d: %s", w.Code, w.Body.String())
	}
	if w := post(); w.Code != http.StatusOK {
		t.Fatalf("explicit exchange replay = %d: %s", w.Code, w.Body.String())
	} else {
		var response map[string]any
		_ = json.NewDecoder(w.Body).Decode(&response)
		if response["duplicates"] != float64(1) || response["inserted"] != float64(0) {
			t.Fatalf("explicit replay was not idempotent: %#v", response)
		}
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "missing.example"})
	if err != nil || result.Total != 1 {
		t.Fatalf("load explicit exchange: total=%d err=%v", result.Total, err)
	}
	event := result.Events[0]
	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
		t.Fatalf("decode event metadata: %v", err)
	}
	if metadata["dns_direction"] != "response" || metadata["dns_response_code"] != "NXDOMAIN" || metadata["process"] != "synthetic-resolver" {
		t.Fatalf("wire semantics not preserved: %#v", metadata)
	}
	if event.ResolvedIP != "" {
		t.Fatalf("answerless NXDOMAIN gained a synthetic resolution: %+v", event)
	}

	base := models.Event{SourceIP: "192.0.2.25", ServerIP: "192.0.2.53", Domain: "missing.example", QueryType: "A", DNSSource: "passive_capture"}
	observed := time.UnixMilli(1_751_000_000_025).UTC()
	queryID := deterministicSensorDNSEventID(sensorID, observed, base, nil, "", "query", "")
	responseID := deterministicSensorDNSEventID(sensorID, observed, base, nil, "", "response", "NXDOMAIN")
	if queryID == responseID {
		t.Fatal("direction/response code were omitted from deterministic event ID material")
	}
}

func TestHandleSensorDNSDelayedEventUsesEventTimeAddressOwner(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-temporal-route"
	token := registerTestSensor(t, router, sensorID)
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	ip := "192.0.2.88"

	if _, err := db.ObserveDevice(store.DeviceObservation{Host: discovery.DiscoveredHost{
		IPAddress: ip, MACAddress: "00:00:5E:00:53:81", Hostname: "older-camera",
	}, Segment: "lan", SensorID: sensorID, ObservedAt: base}); err != nil {
		t.Fatalf("observe event-time owner: %v", err)
	}
	oldOwner, err := db.GetDeviceByIP(ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ObserveDevice(store.DeviceObservation{Host: discovery.DiscoveredHost{
		IPAddress: ip, MACAddress: "00:00:5E:00:53:82", Hostname: "current-camera",
	}, Segment: "iot", SensorID: sensorID, ObservedAt: base.Add(2 * time.Hour)}); err != nil {
		t.Fatalf("observe current owner: %v", err)
	}

	payload, err := json.Marshal(map[string]any{
		"sensor_id": sensorID,
		"queries": []map[string]any{{
			"timestamp": base.Add(30 * time.Minute).UnixMilli(), "domain": "delayed-owner.example",
			"query_type": "A", "client_ip": ip, "source": "passive_capture",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/dns", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Sensor-ID", sensorID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delayed sensor event = %d: %s", w.Code, w.Body.String())
	}

	result, err := db.QueryEvents(store.EventQueryParams{Domain: "delayed-owner.example"})
	if err != nil || result.Total != 1 {
		t.Fatalf("load delayed event: total=%d err=%v", result.Total, err)
	}
	got := result.Events[0]
	if got.DeviceID != oldOwner.DeviceID || got.NetworkSegment != "default" || got.IdentityReason != "unique_unscoped_address_binding" {
		t.Fatalf("delayed event used current-IP context: event=%+v old_owner=%s", got, oldOwner.DeviceID)
	}
}
