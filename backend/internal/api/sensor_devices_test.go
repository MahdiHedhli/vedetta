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
