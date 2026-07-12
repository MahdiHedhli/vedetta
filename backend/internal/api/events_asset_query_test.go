package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func TestHandleEventsParsesDeviceAndOriginFilters(t *testing.T) {
	srv, db := setupTestServer(t)
	now := time.Now().UTC()
	for _, device := range []struct {
		id, ip, mac string
	}{
		{"api-filter-a", "192.0.2.30", "00:00:5E:00:53:30"},
		{"api-filter-b", "192.0.2.31", "00:00:5E:00:53:31"},
	} {
		if _, err := db.Exec(`INSERT INTO devices
			(device_id, first_seen, last_seen, ip_address, mac_address)
			VALUES (?, ?, ?, ?, ?)`, device.id, now, now, device.ip, device.mac); err != nil {
			t.Fatalf("insert device %s: %v", device.id, err)
		}
	}
	inserted, err := db.InsertEvents([]models.Event{
		{EventID: "api-filter-event-a", Timestamp: now, EventType: "dns_query", SourceHash: "api-a", DeviceID: "api-filter-a", Origin: "sensor_dns"},
		{EventID: "api-filter-event-b", Timestamp: now, EventType: "dns_query", SourceHash: "api-b", DeviceID: "api-filter-b", Origin: "collector"},
	})
	if err != nil || inserted != 2 {
		t.Fatalf("InsertEvents inserted=%d err=%v", inserted, err)
	}

	router := NewRouter(srv)
	assertTotal := func(path string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		var result store.EventQueryResult
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
			t.Fatalf("decode GET %s: %v", path, err)
		}
		if result.Total != want {
			t.Fatalf("GET %s total=%d, want %d", path, result.Total, want)
		}
	}

	assertTotal("/api/v1/events?device_id=api-filter-a&origin=sensor_dns", 1)
	assertTotal("/api/v1/events?device_id=api-filter-a&origin=collector", 0)
}
