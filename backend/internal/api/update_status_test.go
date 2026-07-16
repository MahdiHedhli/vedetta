package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// With no checker wired the endpoint is reachable under read scope and reports the notice as
// disabled (nil-safe), so the dashboard simply shows nothing.
func TestUpdateStatusEndpoint_NilCheckerReportsDisabled(t *testing.T) {
	_, _, router := setupFindingRouter(t)
	w := requestJSON(t, router, http.MethodGet, "/api/v1/update-status", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("update-status = %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enabled, _ := body["enabled"].(bool); enabled {
		t.Errorf("expected enabled=false with no checker wired, got %v", body)
	}
}
