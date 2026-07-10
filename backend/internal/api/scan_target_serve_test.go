package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// Issue #7 (serve-side half of the class fix): even if an invalid target is present
// and enabled in the DB, Core must re-validate at the point it hands scan work to a
// sensor, so a planted 0.0.0.0/0 is never dispatched to the root-running sensor.
func TestHandleSensorWork_SkipsInvalidTarget(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	authToken := registerTestSensor(t, router, "sensor-work")

	// Plant one valid and one invalid enabled target directly (store insert does not
	// validate, mirroring a pre-upgrade row).
	good, err := db.CreateScanTarget("lan", "192.168.1.0/24", "default", true, false, "")
	if err != nil {
		t.Fatalf("create good target: %v", err)
	}
	bad, err := db.CreateScanTarget("planted", "0.0.0.0/0", "default", true, false, "")
	if err != nil {
		t.Fatalf("create bad target: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/sensor/work", nil)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Sensor-ID", "sensor-work")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Targets []models.ScanTarget `json:"targets"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode work response: %v", err)
	}

	for _, tg := range resp.Targets {
		if tg.CIDR == "0.0.0.0/0" || tg.TargetID == bad.TargetID {
			t.Fatalf("invalid target %q was served to the sensor", tg.CIDR)
		}
	}
	foundGood := false
	for _, tg := range resp.Targets {
		if tg.TargetID == good.TargetID {
			foundGood = true
		}
	}
	if !foundGood {
		t.Fatalf("valid target %s was not served", good.TargetID)
	}
}

// servableScanTargets is the shared choke point; exercise it directly to prove the
// filter regardless of route wiring.
func TestServableScanTargets_FiltersInvalid(t *testing.T) {
	srv, db := setupTestServer(t)

	if _, err := db.CreateScanTarget("lan", "10.0.0.0/24", "default", true, false, ""); err != nil {
		t.Fatalf("create good: %v", err)
	}
	if _, err := db.CreateScanTarget("planted", "0.0.0.0/0", "default", true, false, ""); err != nil {
		t.Fatalf("create bad: %v", err)
	}

	got, err := srv.servableScanTargets()
	if err != nil {
		t.Fatalf("servableScanTargets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 servable target, got %d", len(got))
	}
	if got[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("expected only the valid target, got %q", got[0].CIDR)
	}
}
