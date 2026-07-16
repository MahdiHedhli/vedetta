package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/updatecheck"
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

func TestUpdateStatusEndpoint_ReturnsWiredCheckerStatus(t *testing.T) {
	releaseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"tag_name":"v1.3.0","html_url":"https://github.com/o/r/releases/tag/v1.3.0","published_at":"2026-07-16T00:00:00Z"}]`))
	}))
	defer releaseServer.Close()
	checkedAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	checker, err := updatecheck.New(updatecheck.Config{
		Enabled: true, Repo: "o/r", APIBaseURL: releaseServer.URL, CurrentVersion: "v1.2.0",
		Now: func() time.Time { return checkedAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := checker.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	srv, _, _ := setupFindingRouter(t)
	srv.UpdateChecker = checker
	router := NewRouter(srv)
	w := requestJSON(t, router, http.MethodGet, "/api/v1/update-status", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("update-status = %d: %s", w.Code, w.Body.String())
	}
	var got updatecheck.Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := checker.Status(); got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
}
