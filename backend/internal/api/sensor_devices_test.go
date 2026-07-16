package api

// Spec 004 T4.1/T4.2 API integration tests: the sensor-devices endpoint accepts
// both the old payload (no friendly_name) and the new additive payload, and
// GET /devices surfaces display_name, friendly_name, segments, and signals.
//
// Synthetic values only: RFC 5737 IPs, 00:00:5E:00:53:xx MACs.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func postSensorDevices(t *testing.T, router http.Handler, token, sensorID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/sensor/devices", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Sensor-ID", sensorID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHandleSensorDevices_OldPayloadCompat(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-old"
	token := registerTestSensor(t, router, sensorID)

	// Old payload: no friendly_name field at all.
	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "default",
		"hosts": []map[string]any{
			{"ip_address": "192.0.2.10", "mac_address": "00:00:5E:00:53:01", "hostname": "old-host", "discovery_source": "passive_arp"},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("old payload: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	dev, err := db.GetDeviceByIP("192.0.2.10")
	if err != nil || dev == nil {
		t.Fatalf("device not stored: %v", err)
	}
	if dev.FriendlyName != "" {
		t.Errorf("friendly_name = %q, want empty for old payload", dev.FriendlyName)
	}
	if dev.DisplayName == "" {
		t.Error("display_name should be derived even without friendly_name")
	}
}

func TestHandleSensorDevices_NewPayloadFriendlyName(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-new"
	token := registerTestSensor(t, router, sensorID)

	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "lan",
		"hosts": []map[string]any{
			{
				"ip_address":       "192.0.2.20",
				"mac_address":      "00:00:5E:00:53:02",
				"hostname":         "chromecast-hall",
				"model":            "Chromecast Ultra",
				"friendly_name":    "Living Room TV",
				"services":         []string{"_googlecast._tcp"},
				"discovery_source": "passive_mdns",
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("new payload: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// GET /devices must return display_name, friendly_name, segments, signals.
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /devices: expected 200, got %d", rec.Code)
	}
	var resp struct {
		Devices []struct {
			DisplayName  string   `json:"display_name"`
			FriendlyName string   `json:"friendly_name"`
			Segments     []string `json:"segments"`
			Signals      []struct {
				Field  string `json:"field"`
				Source string `json:"source"`
			} `json:"signals"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode devices: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(resp.Devices))
	}
	d := resp.Devices[0]
	if d.FriendlyName != "Living Room TV" {
		t.Errorf("friendly_name = %q, want %q", d.FriendlyName, "Living Room TV")
	}
	if d.DisplayName != "Living Room TV" {
		t.Errorf("display_name = %q, want friendly name to win", d.DisplayName)
	}
	if len(d.Segments) != 1 || d.Segments[0] != "lan" {
		t.Errorf("segments = %v, want [lan]", d.Segments)
	}
	if len(d.Signals) == 0 {
		t.Error("expected non-empty signals provenance")
	}
}

func TestHandleSensorDevicesPreservesPerHostObservationTime(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-host-time"
	token := registerTestSensor(t, router, sensorID)
	observed := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "lan",
		"scan_time": observed.Add(12 * time.Hour),
		"hosts": []map[string]any{{
			"ip_address": "203.0.113.24", "mac_address": "00:00:5E:00:53:24",
			"status": "observed", "discovery_source": "arp_cache", "observed_at": observed,
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("device report: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var lastSeen time.Time
	if err := db.QueryRow(`SELECT last_seen FROM devices WHERE ip_address='203.0.113.24'`).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if !lastSeen.Equal(observed) {
		t.Fatalf("device last_seen = %s, want host observed_at %s (not batch retry time)", lastSeen, observed)
	}
}

// Core may be upgraded before an already-installed Windows sensor. beta.2's
// driver-free scanner sent an unbound ICMP result with an ARP-cache MAC as
// `native_icmp`, and cache-only neighbors as `arp`. Those exact legacy wire
// forms must inherit the hardened source contract instead of becoming strong
// canonical identity or descriptive evidence.
func TestHandleSensorDevicesCoreFirstUpgradeConstrainsLegacyWindowsSources(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "legacy-windows-sensor"
	token := registerTestSensor(t, router, sensorID)
	observed := time.Now().UTC().Add(-time.Minute)

	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "lan",
		"scan_time": observed,
		"hosts": []map[string]any{
			{
				"ip_address": "192.0.2.180", "mac_address": "00:00:5E:00:53:B4",
				"hostname": "spliced-native-name", "vendor": "spliced-vendor",
				"model": "spliced-model", "friendly_name": "spliced-friendly",
				"services": []string{"_spliced._tcp"}, "open_ports": []int{23},
				"status": "up", "discovery_source": "native_icmp",
				"identity_evidence": []map[string]any{{
					"type": "dhcp_client_id", "value": "spliced-client-id",
					"source": "passive_dhcp", "confidence": 1.0,
				}},
			},
			{
				"ip_address": "192.0.2.181", "mac_address": "00:00:5E:00:53:B5",
				"hostname": "spliced-cache-name", "vendor": "spliced-vendor",
				"model": "spliced-model", "friendly_name": "spliced-friendly",
				"services": []string{"_spliced._tcp"}, "open_ports": []int{2323},
				"status": "up", "discovery_source": "arp",
				"identity_evidence": []map[string]any{{
					"type": "ssdp_uuid", "value": "spliced-uuid",
					"source": "passive_ssdp", "confidence": 1.0,
				}},
			},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("legacy Windows report: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	type projection struct {
		mac, hostname, vendor, model, friendly, ports, services, method string
	}
	readProjection := func(ip string) projection {
		t.Helper()
		var got projection
		if err := db.QueryRow(`SELECT mac_address, COALESCE(hostname, ''), COALESCE(vendor, ''),
			COALESCE(model, ''), COALESCE(friendly_name, ''), COALESCE(open_ports, '[]'),
			COALESCE(services, '[]'), discovery_method FROM devices WHERE ip_address = ?`, ip).
			Scan(&got.mac, &got.hostname, &got.vendor, &got.model, &got.friendly,
				&got.ports, &got.services, &got.method); err != nil {
			t.Fatal(err)
		}
		return got
	}
	native := readProjection("192.0.2.180")
	if native.mac != "" || native.hostname != "" || native.vendor != "" || native.model != "" ||
		native.friendly != "" || native.ports != "[]" || native.services != "[]" || native.method != "native_icmp" {
		t.Fatalf("legacy native_icmp escaped IP-only boundary: %+v", native)
	}
	cache := readProjection("192.0.2.181")
	if cache.mac != "" || cache.hostname != "" || cache.vendor != "" || cache.model != "" ||
		cache.friendly != "" || cache.ports != "[]" || cache.services != "[]" || cache.method != "arp_cache" {
		t.Fatalf("legacy arp escaped cache-only boundary: %+v", cache)
	}

	var nativeEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence e
		JOIN devices d ON d.device_id = e.device_id WHERE d.ip_address = '192.0.2.180'`).Scan(&nativeEvidence); err != nil {
		t.Fatal(err)
	}
	if nativeEvidence != 0 {
		t.Fatalf("legacy native_icmp persisted %d identity evidence rows, want none", nativeEvidence)
	}
	var cacheType, cacheSource string
	var cacheConfidence float64
	if err := db.QueryRow(`SELECT e.evidence_type, e.source, e.confidence
		FROM device_identity_evidence e JOIN devices d ON d.device_id = e.device_id
		WHERE d.ip_address = '192.0.2.181'`).Scan(&cacheType, &cacheSource, &cacheConfidence); err != nil {
		t.Fatal(err)
	}
	if cacheType != "mac" || cacheSource != "arp_cache" || cacheConfidence != 0.55 {
		t.Fatalf("legacy arp evidence = type=%q source=%q confidence=%.2f, want weak cache MAC",
			cacheType, cacheSource, cacheConfidence)
	}
}

func TestHandleSensorDevicesExtremeFutureSkewPartialReplayPreservesCacheOrder(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-future-cache-retry"
	token := registerTestSensor(t, router, sensorID)
	// Year 9999 is deliberate: latestUpstream.Sub(now) saturates time.Duration.
	// A common-offset implementation based on that duration leaves persisted
	// observations around year 9707 instead of bringing the batch back to now.
	base := time.Date(9999, 12, 31, 23, 57, 0, 0, time.UTC)
	oldMAC := "00:00:5E:00:53:71"
	newMAC := "00:00:5E:00:53:72"

	// Fail only the unrelated host so Core truthfully returns 207 after accepting
	// both ordered cache edges. The sensor retries the entire idempotent batch.
	if _, err := db.Exec(`CREATE TRIGGER fail_unrelated_future_skew_host
		BEFORE INSERT ON devices WHEN NEW.ip_address = '198.51.100.73'
		BEGIN SELECT RAISE(ABORT, 'synthetic partial device failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	body := map[string]any{
		"sensor_id": sensorID,
		"segment":   "lan",
		"scan_time": base.Add(time.Minute),
		"hosts": []map[string]any{
			{
				"ip_address": "192.0.2.71", "mac_address": oldMAC,
				"status": "observed", "discovery_source": "arp_cache", "observed_at": base,
			},
			{
				"ip_address": "192.0.2.71", "mac_address": newMAC,
				"status": "observed", "discovery_source": "arp_cache", "observed_at": base.Add(time.Minute),
			},
			{
				"ip_address": "198.51.100.73", "mac_address": "00:00:5E:00:53:73",
				"discovery_source": "passive_dhcp", "observed_at": base.Add(30 * time.Second),
			},
		},
	}
	first := postSensorDevices(t, router, token, sensorID, body)
	if first.Code != http.StatusMultiStatus {
		t.Fatalf("first future-skew report: expected 207, got %d: %s", first.Code, first.Body.String())
	}
	var partial struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(first.Body).Decode(&partial); err != nil {
		t.Fatal(err)
	}
	if partial.Accepted != 2 || partial.Failed != 1 {
		t.Fatalf("partial counts = %d/%d, want 2/1", partial.Accepted, partial.Failed)
	}
	firstSeen := make(map[string]time.Time)
	firstRows, err := db.Query(`SELECT address_value, last_seen FROM device_address_history
		WHERE address_type='mac' AND evidence_source='arp_cache'`)
	if err != nil {
		t.Fatal(err)
	}
	for firstRows.Next() {
		var mac string
		var seen time.Time
		if err := firstRows.Scan(&mac, &seen); err != nil {
			firstRows.Close()
			t.Fatal(err)
		}
		firstSeen[strings.ToUpper(mac)] = seen
	}
	if err := firstRows.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_unrelated_future_skew_host`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}

	second := postSensorDevices(t, router, token, sensorID, body)
	if second.Code != http.StatusOK {
		t.Fatalf("replayed future-skew report: expected 200, got %d: %s", second.Code, second.Body.String())
	}
	var success struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(second.Body).Decode(&success); err != nil {
		t.Fatal(err)
	}
	if success.Accepted != 3 || success.Failed != 0 {
		t.Fatalf("replay counts = %d/%d, want 3/0", success.Accepted, success.Failed)
	}

	var canonicalMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address='192.0.2.71'`).Scan(&canonicalMAC); err != nil {
		t.Fatal(err)
	}
	if canonicalMAC != "" {
		t.Fatalf("cache-only replay promoted canonical MAC %q", canonicalMAC)
	}
	lastSeen := make(map[string]time.Time)
	rows, err := db.Query(`SELECT address_value, last_seen FROM device_address_history
		WHERE address_type='mac' AND evidence_source='arp_cache' ORDER BY last_seen DESC`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var mac string
		var seen time.Time
		if err := rows.Scan(&mac, &seen); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		key := strings.ToUpper(mac)
		if _, exists := lastSeen[key]; !exists {
			lastSeen[key] = seen
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	oldSeen, oldOK := lastSeen[strings.ToUpper(oldMAC)]
	newSeen, newOK := lastSeen[strings.ToUpper(newMAC)]
	if !oldOK || !newOK {
		t.Fatalf("cache evidence missing after replay: %+v", lastSeen)
	}
	if !oldSeen.Equal(firstSeen[strings.ToUpper(oldMAC)]) || !newSeen.Equal(firstSeen[strings.ToUpper(newMAC)]) {
		t.Fatalf("replay changed normalized observation times: first=%+v replay=%+v", firstSeen, lastSeen)
	}
	if delta := newSeen.Sub(oldSeen); delta != time.Minute {
		t.Fatalf("future-skew normalization destroyed cache ordering: old=%s new=%s delta=%s, want 1m", oldSeen, newSeen, delta)
	}
	if newSeen.After(time.Now().UTC().Add(maxTimestampSkew)) {
		t.Fatalf("normalized cache evidence remained implausibly future-dated: %s", newSeen)
	}
}

func TestHandleSensorDevicesPrecollapsesSameGenerationCacheConflict(t *testing.T) {
	for _, tc := range []struct {
		name string
		macs []string
	}{
		{name: "different macs", macs: []string{"00:00:5E:00:53:74", "00:00:5E:00:53:75"}},
		{name: "unique then blank", macs: []string{"00:00:5E:00:53:74", ""}},
		{name: "blank then unique", macs: []string{"", "00:00:5E:00:53:74"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, db := setupTestServer(t)
			router := NewRouter(srv)
			sensorID := "sensor-cache-generation-" + strings.ReplaceAll(tc.name, " ", "-")
			token := registerTestSensor(t, router, sensorID)
			base := time.Now().UTC().Truncate(time.Second)
			ip := "192.0.2.74"
			generation := base.Add(time.Minute)
			var epoch string
			if err := db.QueryRow(`SELECT delivery_epoch FROM arp_cache_delivery_epochs
				WHERE sensor_id=? ORDER BY epoch_order DESC LIMIT 1`, sensorID).Scan(&epoch); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{
				"sensor_id": sensorID,
				"segment":   "lan",
				"scan_time": generation,
				"hosts": []map[string]any{
					{
						"ip_address": ip, "status": "up",
						"discovery_source": "native_icmp_bound", "observed_at": base,
					},
					{
						"ip_address": ip, "mac_address": tc.macs[0], "status": "observed",
						"discovery_source": "arp_cache", "observed_at": generation,
						"delivery_epoch": epoch, "delivery_sequence": 1,
					},
					{
						"ip_address": ip, "mac_address": tc.macs[1], "status": "observed",
						"discovery_source": "arp_cache", "observed_at": generation,
						"delivery_epoch": epoch, "delivery_sequence": 1,
					},
				},
			}
			w := postSensorDevices(t, router, token, sensorID, body)
			if w.Code != http.StatusOK {
				t.Fatalf("same-generation conflict: expected 200, got %d: %s", w.Code, w.Body.String())
			}

			var canonical, fusedEvidence int
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE COALESCE(mac_address, '') != ''`).Scan(&canonical); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source='native_icmp_arp'`).Scan(&fusedEvidence); err != nil {
				t.Fatal(err)
			}
			if canonical != 0 || fusedEvidence != 0 {
				t.Fatalf("same-generation conflict fused by input order: canonical=%d evidence=%d", canonical, fusedEvidence)
			}
			var state, macHMAC string
			if err := db.QueryRow(`SELECT state, mac_hmac FROM arp_cache_states
				WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).Scan(&state, &macHMAC); err != nil {
				t.Fatal(err)
			}
			if state != "ambiguous" || macHMAC != "" {
				t.Fatalf("same-generation ledger state=%q hash=%q, want ambiguous/empty", state, macHMAC)
			}
		})
	}
}

func TestHandleSensorDevicesAcknowledgesImmutableCacheMutationWithoutChangingIdentity(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-cache-immutable-api"
	token := registerTestSensor(t, router, sensorID)
	base := time.Now().UTC().Truncate(time.Second)
	ip := "192.0.2.75"
	macA := "00:00:5E:00:53:75"
	macB := "00:00:5E:00:53:76"
	macC := "00:00:5E:00:53:77"
	var epoch string
	if err := db.QueryRow(`SELECT delivery_epoch FROM arp_cache_delivery_epochs
		WHERE sensor_id=? ORDER BY epoch_order DESC LIMIT 1`, sensorID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}

	live := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID, "segment": "lan", "scan_time": base,
		"hosts": []map[string]any{{
			"ip_address": ip, "status": "up", "discovery_source": "native_icmp_bound", "observed_at": base,
		}},
	})
	if live.Code != http.StatusOK {
		t.Fatalf("liveness report = %d: %s", live.Code, live.Body.String())
	}

	firstAt := base.Add(time.Minute)
	cacheBody := func(mac string, observedAt time.Time, sequence uint64) map[string]any {
		return map[string]any{
			"sensor_id": sensorID, "segment": "lan", "scan_time": observedAt,
			"hosts": []map[string]any{{
				"ip_address": ip, "mac_address": mac, "status": "observed",
				"discovery_source": "arp_cache", "observed_at": observedAt,
				"delivery_epoch": epoch, "delivery_sequence": sequence,
			}},
		}
	}
	first := postSensorDevices(t, router, token, sensorID, cacheBody(macA, firstAt, 1))
	if first.Code != http.StatusOK {
		t.Fatalf("first cache generation = %d: %s", first.Code, first.Body.String())
	}
	// An exact duplicate remains an ordinary idempotent success.
	exact := postSensorDevices(t, router, token, sensorID, cacheBody(macA, firstAt, 1))
	if exact.Code != http.StatusOK || strings.Contains(exact.Body.String(), "protocol_conflicts") {
		t.Fatalf("exact cache replay = %d: %s", exact.Code, exact.Body.String())
	}

	var firstState, firstHMAC string
	var firstObserved time.Time
	var firstSequence int64
	if err := db.QueryRow(`SELECT state, mac_hmac, observed_at, delivery_sequence
		FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&firstState, &firstHMAC, &firstObserved, &firstSequence); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name string
		body map[string]any
	}{
		{name: "changed MAC", body: cacheBody(macB, firstAt, 1)},
		{name: "changed observation time", body: cacheBody(macA, firstAt.Add(time.Second), 1)},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			w := postSensorDevices(t, router, token, sensorID, mutation.body)
			if w.Code != http.StatusOK {
				t.Fatalf("changed duplicate = %d: %s", w.Code, w.Body.String())
			}
			var response struct {
				Accepted          int `json:"accepted"`
				Failed            int `json:"failed"`
				ProtocolConflicts int `json:"protocol_conflicts"`
			}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.Accepted != 1 || response.Failed != 0 || response.ProtocolConflicts != 1 {
				t.Fatalf("changed duplicate response=%+v, want acknowledged protocol conflict", response)
			}
		})
	}

	var state, macHMAC string
	var observedAt time.Time
	var sequence int64
	if err := db.QueryRow(`SELECT state, mac_hmac, observed_at, delivery_sequence
		FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&state, &macHMAC, &observedAt, &sequence); err != nil {
		t.Fatal(err)
	}
	if state != firstState || macHMAC != firstHMAC || !observedAt.Equal(firstObserved) || sequence != firstSequence {
		t.Fatalf("protocol conflict mutated ledger: before=%q/%q/%s/%d after=%q/%q/%s/%d",
			firstState, firstHMAC, firstObserved, firstSequence, state, macHMAC, observedAt, sequence)
	}
	var fusedA, fusedB int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=? AND discovery_method='native_icmp_arp'`, macA).Scan(&fusedA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, macB).Scan(&fusedB); err != nil {
		t.Fatal(err)
	}
	if fusedA != 1 || fusedB != 0 {
		t.Fatalf("protocol conflict changed identity projections A/B=%d/%d, want 1/0", fusedA, fusedB)
	}

	// A real transition uses the next sequence and remains valid.
	nextAt := base.Add(2 * time.Minute)
	next := postSensorDevices(t, router, token, sensorID, cacheBody(macB, nextAt, 2))
	if next.Code != http.StatusOK {
		t.Fatalf("next cache generation = %d: %s", next.Code, next.Body.String())
	}
	if err := db.QueryRow(`SELECT mac_hmac, observed_at, delivery_sequence
		FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&macHMAC, &observedAt, &sequence); err != nil {
		t.Fatal(err)
	}
	if macHMAC == firstHMAC || !observedAt.Equal(nextAt) || sequence != 2 {
		t.Fatalf("next generation did not advance ledger: hash=%q at=%s sequence=%d", macHMAC, observedAt, sequence)
	}

	assertStale := func(t *testing.T, body map[string]any) {
		t.Helper()
		w := postSensorDevices(t, router, token, sensorID, body)
		if w.Code != http.StatusOK {
			t.Fatalf("stale delivery = %d: %s", w.Code, w.Body.String())
		}
		var response struct {
			Accepted     int `json:"accepted"`
			Failed       int `json:"failed"`
			StaleReplays int `json:"stale_replays"`
		}
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.Accepted != 1 || response.Failed != 0 || response.StaleReplays != 1 {
			t.Fatalf("stale response=%+v, want terminal acknowledgement", response)
		}
	}
	// A mutated older sequence is terminal and creates no weak/provisional C.
	assertStale(t, cacheBody(macC, firstAt, 1))
	var macCRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, macC).Scan(&macCRows); err != nil {
		t.Fatal(err)
	}
	if macCRows != 0 {
		t.Fatalf("stale sequence created %d MAC-C projections", macCRows)
	}

	// The same rule applies after a later process epoch activates.
	oldEpoch := epoch
	newEpoch, err := db.IssueARPCacheDeliveryEpoch(sensorID)
	if err != nil {
		t.Fatal(err)
	}
	epoch = newEpoch
	newProcessAt := base.Add(3 * time.Minute)
	newProcess := postSensorDevices(t, router, token, sensorID, cacheBody(macB, newProcessAt, 1))
	if newProcess.Code != http.StatusOK {
		t.Fatalf("new process delivery = %d: %s", newProcess.Code, newProcess.Body.String())
	}
	for i := 0; i < 12; i++ {
		if _, err := db.IssueARPCacheDeliveryEpoch(sensorID); err != nil {
			t.Fatal(err)
		}
	}
	var retainedOldEpoch int
	if err := db.QueryRow(`SELECT COUNT(*) FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND delivery_epoch=? AND ever_activated_at IS NOT NULL`, sensorID, oldEpoch).
		Scan(&retainedOldEpoch); err != nil {
		t.Fatal(err)
	}
	if retainedOldEpoch != 1 {
		t.Fatalf("retired epoch was pruned after candidate churn: count=%d", retainedOldEpoch)
	}
	epoch = oldEpoch
	assertStale(t, cacheBody(macC, base.Add(4*time.Minute), 3))
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, macC).Scan(&macCRows); err != nil {
		t.Fatal(err)
	}
	if macCRows != 0 {
		t.Fatalf("retired epoch created %d MAC-C projections", macCRows)
	}
}

func TestHandleSensorDevicesUnknownEpochRemainsProvisional(t *testing.T) {
	for _, epoch := range []string{"unknown-but-well-formed-epoch", "malformed/epoch"} {
		t.Run(strings.ReplaceAll(epoch, "/", "-"), func(t *testing.T) {
			srv, db := setupTestServer(t)
			router := NewRouter(srv)
			sensorID := "sensor-unknown-epoch-" + strings.ReplaceAll(epoch, "/", "-")
			token := registerTestSensor(t, router, sensorID)
			base := time.Now().UTC().Truncate(time.Second)
			ip := "192.0.2.79"
			mac := "00:00:5E:00:53:79"
			w := postSensorDevices(t, router, token, sensorID, map[string]any{
				"sensor_id": sensorID, "segment": "lan", "scan_time": base,
				"hosts": []map[string]any{
					{
						"ip_address": ip, "status": "up",
						"discovery_source": "native_icmp_bound", "observed_at": base,
					},
					{
						"ip_address": ip, "mac_address": mac, "status": "observed",
						"discovery_source": "arp_cache", "observed_at": base.Add(time.Minute),
						"delivery_epoch": epoch, "delivery_sequence": 1,
					},
				},
			})
			if w.Code != http.StatusOK {
				t.Fatalf("unknown epoch report = %d: %s", w.Code, w.Body.String())
			}
			var order, sequence int64
			if err := db.QueryRow(`SELECT delivery_epoch_order, delivery_sequence
				FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
				Scan(&order, &sequence); err != nil {
				t.Fatal(err)
			}
			var canonical, fusedEvidence, provisional int
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, mac).Scan(&canonical); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source='native_icmp_arp'`).Scan(&fusedEvidence); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE discovery_method='arp_cache' AND ip_address=?`, ip).Scan(&provisional); err != nil {
				t.Fatal(err)
			}
			if order != 0 || sequence != 0 || canonical != 0 || fusedEvidence != 0 || provisional != 1 {
				t.Fatalf("unknown epoch state order/seq=%d/%d canonical=%d fused=%d provisional=%d",
					order, sequence, canonical, fusedEvidence, provisional)
			}
		})
	}
}

func TestHandleSensorDevicesDeliverySequenceSurvivesBackwardClockAndPartialRetry(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-cache-sequence-retry"
	token := registerTestSensor(t, router, sensorID)
	base := time.Now().UTC().Truncate(time.Second)
	ip := "192.0.2.76"
	macA := "02:00:5E:00:53:76"
	macB := "02:00:5E:00:53:77"
	var epoch string
	if err := db.QueryRow(`SELECT delivery_epoch FROM arp_cache_delivery_epochs
		WHERE sensor_id=? ORDER BY epoch_order DESC LIMIT 1`, sensorID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TRIGGER fail_cache_sequence_unrelated
		BEFORE INSERT ON devices WHEN NEW.ip_address = '198.51.100.76'
		BEGIN SELECT RAISE(ABORT, 'synthetic partial device failure'); END`); err != nil {
		t.Fatal(err)
	}
	firstBody := map[string]any{
		"sensor_id": sensorID, "segment": "lan", "scan_time": base,
		"hosts": []map[string]any{
			{
				"ip_address": ip, "mac_address": macA, "status": "observed",
				"discovery_source": "arp_cache", "observed_at": base,
				"delivery_epoch": epoch, "delivery_sequence": 1,
			},
			{
				"ip_address": "198.51.100.76", "mac_address": "02:00:5E:00:53:78",
				"discovery_source": "passive_dhcp", "observed_at": base,
			},
		},
	}
	first := postSensorDevices(t, router, token, sensorID, firstBody)
	if first.Code != http.StatusMultiStatus {
		t.Fatalf("first delivery = %d: %s", first.Code, first.Body.String())
	}
	if _, err := db.Exec(`DROP TRIGGER fail_cache_sequence_unrelated`); err != nil {
		t.Fatal(err)
	}

	// The process observes B later, but NTP moves its wall clock backward. The
	// authenticated epoch/sequence, not observed_at, must advance Core's state.
	backwardAt := base.Add(-time.Minute)
	secondBody := map[string]any{
		"sensor_id": sensorID, "segment": "lan", "scan_time": backwardAt,
		"hosts": []map[string]any{{
			"ip_address": ip, "mac_address": macB, "status": "observed",
			"discovery_source": "arp_cache", "observed_at": backwardAt,
			"delivery_epoch": epoch, "delivery_sequence": 2,
		}},
	}
	second := postSensorDevices(t, router, token, sensorID, secondBody)
	if second.Code != http.StatusOK {
		t.Fatalf("backward-clock delivery = %d: %s", second.Code, second.Body.String())
	}
	// Retrying the original partial batch must not let accepted A reclaim state.
	retry := postSensorDevices(t, router, token, sensorID, firstBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("partial retry = %d: %s", retry.Code, retry.Body.String())
	}

	var state string
	var observedAt time.Time
	var epochOrder, sequence int64
	if err := db.QueryRow(`SELECT state, observed_at, delivery_epoch_order, delivery_sequence
		FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&state, &observedAt, &epochOrder, &sequence); err != nil {
		t.Fatal(err)
	}
	if state != "unique" || !observedAt.Equal(backwardAt) || epochOrder <= 0 || sequence != 2 {
		t.Fatalf("Core cache order regressed: state=%q at=%s epoch=%d sequence=%d", state, observedAt, epochOrder, sequence)
	}

	// A later source-bound liveness edge plus an idempotent B replay may use B;
	// the older accepted A must never become the corroborated identity.
	liveAt := base.Add(time.Minute)
	live := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID, "segment": "lan", "scan_time": liveAt,
		"hosts": []map[string]any{{
			"ip_address": ip, "status": "up", "discovery_source": "native_icmp_bound", "observed_at": liveAt,
		}},
	})
	if live.Code != http.StatusOK {
		t.Fatalf("liveness delivery = %d: %s", live.Code, live.Body.String())
	}
	if replayB := postSensorDevices(t, router, token, sensorID, secondBody); replayB.Code != http.StatusOK {
		t.Fatalf("current B replay = %d: %s", replayB.Code, replayB.Body.String())
	}
	var fusedA, fusedB int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=? AND discovery_method='native_icmp_arp'`, macA).Scan(&fusedA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=? AND discovery_method='native_icmp_arp'`, macB).Scan(&fusedB); err != nil {
		t.Fatal(err)
	}
	if fusedA != 0 || fusedB != 1 {
		t.Fatalf("backward-clock identity fusion A/B=%d/%d, want 0/1", fusedA, fusedB)
	}
}

func TestHandleSensorDevicesMixedCutoffPartialReplayPreservesCacheAddressAndEvidenceOrder(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-mixed-cutoff-cache-retry"
	token := registerTestSensor(t, router, sensorID)
	// Keep five minutes of margin on either side of Core's one-hour cutoff so
	// ordinary test execution cannot move both observations onto the same side.
	receivedNear := time.Now().UTC()
	justInside := receivedNear.Add(55 * time.Minute)
	justOutside := receivedNear.Add(65 * time.Minute)
	ip := "192.0.2.81"
	oldMAC := "00:00:5E:00:53:81"
	newMAC := "00:00:5E:00:53:82"

	// Force a truthful 207 after both cache edges commit. The retry exercises the
	// exact persisted timestamp mappings instead of merely repeating one 200 path.
	if _, err := db.Exec(`CREATE TRIGGER fail_mixed_cutoff_unrelated_host
		BEFORE INSERT ON devices WHEN NEW.ip_address = '198.51.100.83'
		BEGIN SELECT RAISE(ABORT, 'synthetic partial device failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	body := map[string]any{
		"sensor_id": sensorID,
		"segment":   "lan",
		"scan_time": justOutside,
		"hosts": []map[string]any{
			{
				"ip_address": ip, "mac_address": oldMAC,
				"status": "observed", "discovery_source": "arp_cache", "observed_at": justInside,
			},
			{
				"ip_address": ip, "mac_address": newMAC,
				"status": "observed", "discovery_source": "arp_cache", "observed_at": justOutside,
			},
			{
				"ip_address": "198.51.100.83", "mac_address": "00:00:5E:00:53:83",
				"status": "up", "discovery_source": "passive_dhcp",
			},
		},
	}
	first := postSensorDevices(t, router, token, sensorID, body)
	if first.Code != http.StatusMultiStatus {
		t.Fatalf("first mixed-cutoff report: expected 207, got %d: %s", first.Code, first.Body.String())
	}
	var partial struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(first.Body).Decode(&partial); err != nil {
		t.Fatal(err)
	}
	if partial.Accepted != 2 || partial.Failed != 1 {
		t.Fatalf("partial counts = %d/%d, want 2/1", partial.Accepted, partial.Failed)
	}

	type cacheTimes struct {
		addressFirst  time.Time
		addressLast   time.Time
		evidenceFirst time.Time
		evidenceLast  time.Time
	}
	readCacheTimes := func() map[string]cacheTimes {
		t.Helper()
		got := make(map[string]cacheTimes)
		rows, err := db.Query(`SELECT h.address_value, h.first_seen, h.last_seen,
			e.first_seen, e.last_seen
			FROM device_address_history h
			JOIN device_identity_evidence e ON e.device_id = h.device_id
			WHERE h.address_type = 'mac' AND h.evidence_source = 'arp_cache'
			  AND e.evidence_type = 'mac' AND e.source = 'arp_cache'
			  AND h.sensor_id = ? AND e.sensor_id = ?`, sensorID, sensorID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var mac string
			var times cacheTimes
			if err := rows.Scan(&mac, &times.addressFirst, &times.addressLast,
				&times.evidenceFirst, &times.evidenceLast); err != nil {
				t.Fatal(err)
			}
			got[strings.ToUpper(mac)] = times
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}
	firstTimes := readCacheTimes()
	oldFirst, oldOK := firstTimes[strings.ToUpper(oldMAC)]
	newFirst, newOK := firstTimes[strings.ToUpper(newMAC)]
	if !oldOK || !newOK {
		t.Fatalf("cache address/evidence missing after partial write: %+v", firstTimes)
	}
	if !oldFirst.addressFirst.Equal(oldFirst.addressLast) ||
		!oldFirst.addressFirst.Equal(oldFirst.evidenceFirst) ||
		!oldFirst.addressFirst.Equal(oldFirst.evidenceLast) {
		t.Fatalf("old cache address/evidence disagree: %+v", oldFirst)
	}
	if !newFirst.addressFirst.Equal(newFirst.addressLast) ||
		!newFirst.addressFirst.Equal(newFirst.evidenceFirst) ||
		!newFirst.addressFirst.Equal(newFirst.evidenceLast) {
		t.Fatalf("new cache address/evidence disagree: %+v", newFirst)
	}
	if delta := newFirst.addressFirst.Sub(oldFirst.addressFirst); delta != 10*time.Minute {
		t.Fatalf("mixed-cutoff address/evidence order = old %s new %s delta %s, want 10m",
			oldFirst.addressFirst, newFirst.addressFirst, delta)
	}
	if newFirst.addressFirst.After(time.Now().UTC().Add(maxTimestampSkew)) {
		t.Fatalf("mixed-cutoff evidence remained implausibly future-dated: %s", newFirst.addressFirst)
	}

	if _, err := db.Exec(`DROP TRIGGER fail_mixed_cutoff_unrelated_host`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	replay := postSensorDevices(t, router, token, sensorID, body)
	if replay.Code != http.StatusOK {
		t.Fatalf("replayed mixed-cutoff report: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}
	var success struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(replay.Body).Decode(&success); err != nil {
		t.Fatal(err)
	}
	if success.Accepted != 3 || success.Failed != 0 {
		t.Fatalf("replay counts = %d/%d, want 3/0", success.Accepted, success.Failed)
	}
	secondTimes := readCacheTimes()
	if len(secondTimes) != len(firstTimes) {
		t.Fatalf("replay changed cache evidence cardinality: first=%+v replay=%+v", firstTimes, secondTimes)
	}
	for mac, firstState := range firstTimes {
		if replayState, ok := secondTimes[mac]; !ok || replayState != firstState {
			t.Fatalf("replay changed cache address/evidence for %s: first=%+v replay=%+v", mac, firstState, replayState)
		}
	}

	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ? AND upstream_time IN (?, ?)`, sensorID,
		justInside.Format(time.RFC3339Nano), justOutside.Format(time.RFC3339Nano)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 2 {
		t.Fatalf("persisted mixed-cutoff mappings = %d, want 2", persisted)
	}
}

// TestHandleSensorDevices_AllUpsertsFailReports500 is the BUG-3 regression: the
// endpoint used to always return 200 "accepted":N and swallow every store error,
// so a total persistence failure looked like a success. We force UpsertDevice to
// fail for every host (by dropping a correlation table it writes inside its tx),
// then assert the API returns 5xx with accepted==0 and a truthful failed count.
func TestHandleSensorDevices_AllUpsertsFailReports500(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-fail"
	token := registerTestSensor(t, router, sensorID)

	// Break the correlation write path: UpsertDevice writes device_identities
	// inside its transaction, so dropping it makes every upsert error out and roll
	// back — the real "all upserts fail" condition.
	if _, err := db.Exec(`DROP TABLE device_identities`); err != nil {
		t.Fatalf("drop device_identities: %v", err)
	}

	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "default",
		"hosts": []map[string]any{
			{"ip_address": "192.0.2.40", "mac_address": "00:00:5E:00:53:40", "hostname": "h1"},
			{"ip_address": "192.0.2.41", "mac_address": "00:00:5E:00:53:41", "hostname": "h2"},
		},
	})

	if w.Code < 500 {
		t.Fatalf("all-upserts-fail: expected 5xx, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted != 0 {
		t.Errorf("accepted = %d, want 0 when every upsert fails", resp.Accepted)
	}
	if resp.Failed != 2 {
		t.Errorf("failed = %d, want 2", resp.Failed)
	}
}

// TestHandleSensorDevices_SuccessReportsRealAcceptedCount confirms the happy path
// still reports a truthful accepted count (BUG-3 counterpart).
func TestHandleSensorDevices_SuccessReportsRealAcceptedCount(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)
	sensorID := "sensor-ok"
	token := registerTestSensor(t, router, sensorID)

	w := postSensorDevices(t, router, token, sensorID, map[string]any{
		"sensor_id": sensorID,
		"segment":   "default",
		"hosts": []map[string]any{
			{"ip_address": "192.0.2.50", "mac_address": "00:00:5E:00:53:50", "hostname": "ok1"},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("success path: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted != 1 || resp.Failed != 0 {
		t.Errorf("accepted/failed = %d/%d, want 1/0", resp.Accepted, resp.Failed)
	}
}

// TestHandleListDevices_EmptyReturnsArrayNotNull is the BUG-4 regression: GET
// /devices and /devices/new must return "devices":[] (not null) when the
// inventory is empty, so JSON clients that iterate the array don't choke.
func TestHandleListDevices_EmptyReturnsArrayNotNull(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	for _, path := range []string{"/api/v1/devices", "/api/v1/devices/new"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, `"devices":null`) {
			t.Errorf("%s returned \"devices\":null, want []: %s", path, body)
		}
		if !strings.Contains(body, `"devices":[]`) {
			t.Errorf("%s did not return \"devices\":[]: %s", path, body)
		}
	}
}
