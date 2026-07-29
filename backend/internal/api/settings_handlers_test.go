package api

// Tests for the persisted telemetry opt-in setting (issue #37).
// Contract: GET /api/v1/settings/telemetry (read scope) and
// PUT /api/v1/settings/telemetry (admin) return {opt_in, source, effective};
// a persisted setting WINS over VEDETTA_TELEMETRY_OPTIN; with no setting the env
// is used; default effective is true. Synthetic values only.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
)

type telemetrySettingResp struct {
	OptIn     bool   `json:"opt_in"`
	Source    string `json:"source"`
	Effective bool   `json:"effective"`
}

// doPutJSON issues a PUT with a JSON body and an optional bearer token.
func doPutJSON(router http.Handler, path, bearer string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeTelemetrySetting(t *testing.T, w *httptest.ResponseRecorder) telemetrySettingResp {
	t.Helper()
	var resp telemetrySettingResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode telemetry setting response: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

// TestTelemetrySetting_PersistAndReadBack: a PUT persists the opt-in and a
// subsequent GET reads it back with source "setting". Exercised in bootstrap
// (no admin) where both routes are open.
func TestTelemetrySetting_PersistAndReadBack(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "") // PUT is admin-only

	// Persist opt_in=false.
	w := doPutJSON(router, "/api/v1/settings/telemetry", admin, map[string]any{"opt_in": false})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeTelemetrySetting(t, w); got.Source != "setting" || got.OptIn != false || got.Effective != false {
		t.Fatalf("PUT body: want {false,setting,false}, got %+v", got)
	}

	// Read it back (admin satisfies read).
	w = doGet(router, "/api/v1/settings/telemetry", admin)
	if got := decodeTelemetrySetting(t, w); got.Source != "setting" || got.OptIn != false || got.Effective != false {
		t.Fatalf("GET after persist false: want {false,setting,false}, got %+v", got)
	}

	// Flip it back to true.
	_ = doPutJSON(router, "/api/v1/settings/telemetry", admin, map[string]any{"opt_in": true})
	w = doGet(router, "/api/v1/settings/telemetry", admin)
	if got := decodeTelemetrySetting(t, w); got.Source != "setting" || got.Effective != true {
		t.Fatalf("GET after persist true: want effective true / source setting, got %+v", got)
	}
}

// TestTelemetrySetting_EnvFallbackDefault: with no persisted setting and no env
// var, the effective value defaults to true and source is "env".
func TestTelemetrySetting_EnvFallbackDefault(t *testing.T) {
	t.Setenv("VEDETTA_TELEMETRY_OPTIN", "")
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	w := doGet(router, "/api/v1/settings/telemetry", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeTelemetrySetting(t, w); got.Source != "env" || got.Effective != true {
		t.Fatalf("default: want effective true / source env, got %+v", got)
	}
}

// TestTelemetrySetting_EnvFalse: with no persisted setting, an explicit env
// "false" disables telemetry and source is "env".
func TestTelemetrySetting_EnvFalse(t *testing.T) {
	t.Setenv("VEDETTA_TELEMETRY_OPTIN", "false")
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	w := doGet(router, "/api/v1/settings/telemetry", "")
	if got := decodeTelemetrySetting(t, w); got.Source != "env" || got.Effective != false {
		t.Fatalf("env false: want effective false / source env, got %+v", got)
	}
}

// TestTelemetrySetting_PersistWinsOverEnv: a persisted setting overrides the env
// var even when they disagree.
func TestTelemetrySetting_PersistWinsOverEnv(t *testing.T) {
	t.Setenv("VEDETTA_TELEMETRY_OPTIN", "false")
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	// Persist opt_in=true; it must win over env "false".
	if w := doPutJSON(router, "/api/v1/settings/telemetry", admin, map[string]any{"opt_in": true}); w.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w := doGet(router, "/api/v1/settings/telemetry", admin)
	if got := decodeTelemetrySetting(t, w); got.Source != "setting" || got.Effective != true {
		t.Fatalf("persist wins: want effective true / source setting (env was false), got %+v", got)
	}
}

// TestTelemetrySetting_AdminOnlyPut_ReadCanGet: once an admin exists, PUT requires
// admin scope (a read token is 403, unauth is 401) while GET accepts a read token.
func TestTelemetrySetting_AdminOnlyPut_ReadCanGet(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")
	readToken := createTestToken(t, db, auth.ScopeRead, "")

	// A read token may GET.
	if w := doGet(router, "/api/v1/settings/telemetry", readToken); w.Code != http.StatusOK {
		t.Fatalf("GET with read token: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Unauthenticated PUT is rejected (401) now that an admin exists.
	if w := doPutJSON(router, "/api/v1/settings/telemetry", "", map[string]any{"opt_in": false}); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth PUT: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// A read token may NOT PUT (403).
	if w := doPutJSON(router, "/api/v1/settings/telemetry", readToken, map[string]any{"opt_in": false}); w.Code != http.StatusForbidden {
		t.Fatalf("read-token PUT: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// The admin token may PUT.
	w := doPutJSON(router, "/api/v1/settings/telemetry", adminToken, map[string]any{"opt_in": false})
	if w.Code != http.StatusOK {
		t.Fatalf("admin PUT: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeTelemetrySetting(t, w); got.Source != "setting" || got.Effective != false {
		t.Fatalf("admin PUT body: want effective false / source setting, got %+v", got)
	}

	// And the persisted value is visible to the read token.
	w = doGet(router, "/api/v1/settings/telemetry", readToken)
	if got := decodeTelemetrySetting(t, w); got.Effective != false || got.Source != "setting" {
		t.Fatalf("GET after admin persist: want effective false / source setting, got %+v", got)
	}
}

// TestTelemetrySetting_PutRequiresBody: a PUT without opt_in is a 400.
func TestTelemetrySetting_PutRequiresBody(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	if w := doPutJSON(router, "/api/v1/settings/telemetry", admin, map[string]any{}); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT with empty body: expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdvancedDNSHunting_DefaultIsQuietAndPersistedProfileAppliesLive(t *testing.T) {
	srv, db := setupTestServer(t)
	srv.Enricher = dnsintel.NewEnricher(nil)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")

	w := doGet(router, "/api/v1/settings/dns-hunting", read)
	if w.Code != http.StatusOK {
		t.Fatalf("GET default profile: got %d: %s", w.Code, w.Body.String())
	}
	var initial struct {
		Profile dnsintel.AdvancedDNSHuntingProfile `json:"profile"`
		Source  string                             `json:"source"`
	}
	if err := json.NewDecoder(w.Body).Decode(&initial); err != nil {
		t.Fatalf("decode default profile: %v", err)
	}
	if initial.Source != "default" || initial.Profile.Enabled {
		t.Fatalf("default profile must be quiet, got %+v", initial)
	}

	w = doPutJSON(router, "/api/v1/settings/dns-hunting", admin, map[string]any{
		"profile": map[string]any{
			"enabled": true, "tunneling": true, "beaconing": true,
			"dga_nxdomain": true, "answer_churn": false,
			"resolver_bypass": true, "rebinding": true, "internal_recon": false,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT profile: got %d: %s", w.Code, w.Body.String())
	}
	if got := srv.Enricher.AdvancedDNSHuntingProfile(); !got.Enabled || !got.Tunneling || !got.DGANXDomain || !got.ResolverBypass {
		t.Fatalf("live enricher did not receive persisted profile: %+v", got)
	}

	w = doGet(router, "/api/v1/settings/dns-hunting", read)
	var persisted struct {
		Profile dnsintel.AdvancedDNSHuntingProfile `json:"profile"`
		Source  string                             `json:"source"`
	}
	if err := json.NewDecoder(w.Body).Decode(&persisted); err != nil {
		t.Fatalf("decode persisted profile: %v", err)
	}
	if persisted.Source != "setting" || !persisted.Profile.Enabled || !persisted.Profile.Beaconing {
		t.Fatalf("persisted profile mismatch: %+v", persisted)
	}
}

func TestAdvancedDNSHunting_PutRequiresAdminAndRejectsUnknownFields(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")

	if w := doPutJSON(router, "/api/v1/settings/dns-hunting", read, map[string]any{"profile": map[string]any{"enabled": true}}); w.Code != http.StatusForbidden {
		t.Fatalf("read token PUT: got %d: %s", w.Code, w.Body.String())
	}
	if w := doPutJSON(router, "/api/v1/settings/dns-hunting", admin, map[string]any{"profile": map[string]any{"enabled": true, "not_a_detector": true}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown profile field: got %d: %s", w.Code, w.Body.String())
	}
}
