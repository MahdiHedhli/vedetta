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
