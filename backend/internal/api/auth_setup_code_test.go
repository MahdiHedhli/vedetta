package api

// GHSA-6cmx: bootstrap credential hole. Before any admin exists, POST
// /api/v1/auth/tokens is reachable unauthenticated on the LAN. These tests pin the
// hardened behavior:
//   - during bootstrap, a non-admin scope is rejected (403);
//   - during bootstrap, minting the first admin requires the X-Vedetta-Setup-Code
//     header (missing/wrong → 403; correct → 201, and the code is single-use);
//   - post-bootstrap, an admin bearer still mints tokens (unchanged);
//   - env-provisioned tokens (store.EnsureTokenFromRaw) are unaffected;
//   - during bootstrap, revoke is gated behind the setup code.
//
// Synthetic values only.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// postToken posts a create-token request, optionally with a bearer and/or setup
// code header. An empty header value means "do not send it".
func postToken(t *testing.T, router http.Handler, scope, bearer, setupCode string) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"scope": scope, "label": "test"})
	req := httptest.NewRequest("POST", "/api/v1/auth/tokens", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if setupCode != "" {
		req.Header.Set("X-Vedetta-Setup-Code", setupCode)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func rawTokenOf(w *httptest.ResponseRecorder) string {
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp)
	return resp.Token
}

func TestBootstrap_RejectsNonAdminScope(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	// Even with the correct setup code, only the first ADMIN token may be minted
	// during bootstrap — a request for any other scope is refused.
	for _, scope := range []string{"sensor", "ingest", "read"} {
		w := postToken(t, router, scope, "", testSetupCode)
		if w.Code != http.StatusForbidden {
			t.Errorf("bootstrap scope=%s: expected 403, got %d: %s", scope, w.Code, w.Body.String())
		}
	}
}

func TestBootstrap_FirstAdminRequiresSetupCode(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	// No setup code → rejected.
	if w := postToken(t, router, "admin", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("first admin with no setup code: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	// Wrong setup code → rejected.
	if w := postToken(t, router, "admin", "", "WRONG-CODE"); w.Code != http.StatusForbidden {
		t.Fatalf("first admin with wrong setup code: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	// Correct setup code → minted.
	w := postToken(t, router, "admin", "", testSetupCode)
	if w.Code != http.StatusCreated {
		t.Fatalf("first admin with correct setup code: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if rawTokenOf(w) == "" {
		t.Fatal("expected raw admin token in response")
	}

	// Single-use: the code is burned once the first admin exists. A replay with the
	// same code and no bearer must now be rejected by auth (an admin exists → 401).
	if w := postToken(t, router, "admin", "", testSetupCode); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay after first admin: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBootstrap_SetupCodeConsumedIsReflectedInStatus(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	status := func() map[string]any {
		req := httptest.NewRequest("GET", "/api/v1/auth/setup-status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		return m
	}

	if got := status()["needs_setup_code"]; got != true {
		t.Fatalf("needs_setup_code before first admin: expected true, got %v", got)
	}
	// The status endpoint must never leak the code value itself.
	for k, v := range status() {
		if s, ok := v.(string); ok && s == testSetupCode {
			t.Fatalf("setup-status leaked the setup code in field %q", k)
		}
	}

	if w := postToken(t, router, "admin", "", testSetupCode); w.Code != http.StatusCreated {
		t.Fatalf("first admin: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if got := status()["needs_setup_code"]; got != false {
		t.Fatalf("needs_setup_code after first admin: expected false, got %v", got)
	}
}

func TestPostBootstrap_AdminBearerUnchanged_NoSetupCodeNeeded(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// An admin already exists (bootstrap done). srv.SetupCode is irrelevant now.
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")

	// Admin bearer mints another token WITHOUT any setup code — unchanged behavior.
	w := postToken(t, router, "ingest", adminToken, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("post-bootstrap admin create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnvProvisionedTokensBypassHandler(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// Env-provisioned tokens go straight into the DB (EnsureTokenFromRaw), never
	// through handleCreateToken, so the setup-code gate cannot break them.
	created, err := db.EnsureTokenFromRaw("env-ingest-secret-0001", auth.ScopeIngest, "compose ingest")
	if err != nil {
		t.Fatalf("EnsureTokenFromRaw ingest: %v", err)
	}
	if !created {
		t.Fatal("expected ingest token to be created")
	}

	// The env ingest token authenticates against /ingest (its intended use).
	body := []byte(`{"timestamp":"2025-07-12T10:11:12Z","event_type":"dns_query","source_hash":"h","domain":"env.test"}`)
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer env-ingest-secret-0001")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("env ingest token on /ingest: expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBootstrap_RevokeRequiresAdmin: revocation is strictly admin-gated
// (RequireStrictAdmin), so during bootstrap — before any admin exists — it is
// unavailable regardless of the setup code, closing the LAN-peer machine-token
// revocation DoS (GHSA-6cmx). It works once an admin token exists.
func TestBootstrap_RevokeRequiresAdmin(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// Provision an env ingest token an attacker might try to revoke during bootstrap.
	if _, err := db.EnsureTokenFromRaw("env-ingest-secret-0002", auth.ScopeIngest, "compose ingest"); err != nil {
		t.Fatalf("EnsureTokenFromRaw: %v", err)
	}
	tokens, err := db.ListTokens()
	if err != nil || len(tokens) == 0 {
		t.Fatalf("list tokens: %v (n=%d)", err, len(tokens))
	}
	victimID := tokens[0].TokenID

	revoke := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("DELETE", "/api/v1/auth/tokens/"+victimID, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// During bootstrap (no admin), revoke is unauthenticated -> 401. The setup code
	// no longer applies to this route.
	if w := revoke(""); w.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap revoke without admin: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if w := revoke("bogus-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap revoke with bogus token: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	// With a real admin token, revoke succeeds.
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")
	if w := revoke(adminToken); w.Code != http.StatusOK {
		t.Fatalf("admin revoke: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
