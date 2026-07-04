package status

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := NewState(true, false)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d, want 200", resp.StatusCode)
	}
	s.SetLive(false)
	resp, _ = http.Get(srv.URL + "/healthz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("healthz dead = %d, want 503", resp.StatusCode)
	}
}

func TestStatusPayloadCountsOnly(t *testing.T) {
	s := NewState(true, true)
	s.Update(func(sn *Snapshot) {
		sn.ReporterRegistered = true
		sn.Cursor = "2026-07-03T14:00:00Z"
		sn.SpoolDepth = 2
		sn.LastBatch = LastBatch{Time: "2026-07-03T14:15:00Z", SignalCount: 3, Result: "accepted"}
	})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/status")
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)

	// Must contain only the documented keys — no domain/signal payload leakage.
	allowed := map[string]bool{
		"opt_in": true, "dry_run": true, "reporter_registered": true, "cursor": true,
		"last_tick": true, "last_batch": true, "spool_depth": true,
		"events_skipped_malformed": true, "last_error": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("unexpected status key %q", k)
		}
	}
	// last_batch must carry counts only.
	lb, _ := m["last_batch"].(map[string]any)
	lbAllowed := map[string]bool{"time": true, "signal_count": true, "result": true}
	for k := range lb {
		if !lbAllowed[k] {
			t.Errorf("last_batch leaked key %q", k)
		}
	}
	if m["opt_in"] != true || m["dry_run"] != true {
		t.Errorf("flags wrong: %+v", m)
	}
}
