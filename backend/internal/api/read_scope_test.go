package api

// Tests for the read-only scope gate (beta-gate B6). The read endpoints
// (GET /status, /events, /devices, ...) are gated by auth.RequireRead, which
// mirrors RequireAdmin's bootstrap semantics:
//
//   - bootstrap (no active admin): reads are OPEN so first-run setup works;
//   - once an active admin exists: a bearer is required and its scope must
//     satisfy read — admin implies read, a read token qualifies, and sensor /
//     ingest machine tokens do NOT;
//   - a read token may NOT write (admin-gated routes) or reach admin routes.
//
// Synthetic values only.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// doGet issues a GET against the router with an optional bearer token.
func doGet(router http.Handler, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestReadGate_BootstrapOpen: while no admin token exists, reads are open (no
// auth) so the onboarding wizard and first-run setup are not locked out.
func TestReadGate_BootstrapOpen(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	for _, path := range []string{"/api/v1/status", "/api/v1/events", "/api/v1/devices"} {
		if w := doGet(router, path, ""); w.Code != http.StatusOK {
			t.Fatalf("bootstrap: expected 200 for unauthenticated %s, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestReadGate_UnauthRejectedOnceAdminExists: after an admin token is created,
// unauthenticated reads are rejected (401).
func TestReadGate_UnauthRejectedOnceAdminExists(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	_ = createTestToken(t, db, auth.ScopeAdmin, "")

	for _, path := range []string{"/api/v1/status", "/api/v1/events", "/api/v1/devices", "/api/v1/devices/new"} {
		if w := doGet(router, path, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated %s once admin exists, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestReadGate_AdminSatisfiesRead: an admin token satisfies a read-gated route
// (the existing dashboard/admin token must keep working).
func TestReadGate_AdminSatisfiesRead(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")

	for _, path := range []string{"/api/v1/status", "/api/v1/events", "/api/v1/devices"} {
		if w := doGet(router, path, adminToken); w.Code != http.StatusOK {
			t.Fatalf("admin should satisfy read on %s, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestReadGate_ReadTokenAllowedOnReads: a read token satisfies read-gated routes.
func TestReadGate_ReadTokenAllowedOnReads(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	// An admin must exist (otherwise the gate is in bootstrap mode) so the read
	// token is actually exercised against the gate.
	_ = createTestToken(t, db, auth.ScopeAdmin, "")
	readToken := createTestToken(t, db, auth.ScopeRead, "")

	for _, path := range []string{"/api/v1/status", "/api/v1/events", "/api/v1/devices"} {
		if w := doGet(router, path, readToken); w.Code != http.StatusOK {
			t.Fatalf("read token should be allowed on %s, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestReadGate_ReadTokenCannotWrite: a read token must NOT satisfy an
// admin-gated write route (403).
func TestReadGate_ReadTokenCannotWrite(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	_ = createTestToken(t, db, auth.ScopeAdmin, "")
	readToken := createTestToken(t, db, auth.ScopeRead, "")

	// A device-metadata write (PUT /devices/{id}) is admin-gated.
	req := httptest.NewRequest("PUT", "/api/v1/devices/some-device-id",
		bytes.NewReader([]byte(`{"custom_name":"x"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+readToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read token must not write (PUT /devices), expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestReadGate_ReadTokenCannotIngest: a read token must NOT write events via the
// collector ingest path (POST /ingest). DenyReadScope rejects it (403) while
// admin/ingest/sensor tokens still pass the gate (beta-gate B6).
func TestReadGate_ReadTokenCannotIngest(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	_ = createTestToken(t, db, auth.ScopeAdmin, "")
	readToken := createTestToken(t, db, auth.ScopeRead, "")
	ingestToken := createTestToken(t, db, auth.ScopeIngest, "")

	// A read token is rejected by the scope gate before the body is even parsed.
	reqRead := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader([]byte(`[]`)))
	reqRead.Header.Set("Content-Type", "application/json")
	reqRead.Header.Set("Authorization", "Bearer "+readToken)
	wRead := httptest.NewRecorder()
	router.ServeHTTP(wRead, reqRead)
	if wRead.Code != http.StatusForbidden {
		t.Fatalf("read token must not ingest, expected 403, got %d: %s", wRead.Code, wRead.Body.String())
	}

	// An ingest token still passes the scope gate (not 403).
	reqIngest := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader([]byte(`[]`)))
	reqIngest.Header.Set("Content-Type", "application/json")
	reqIngest.Header.Set("Authorization", "Bearer "+ingestToken)
	wIngest := httptest.NewRecorder()
	router.ServeHTTP(wIngest, reqIngest)
	if wIngest.Code == http.StatusForbidden {
		t.Fatalf("ingest token must pass the /ingest scope gate, got 403: %s", wIngest.Body.String())
	}
}

// TestReadGate_ReadTokenCannotReachAdminRoute: a read token must NOT reach an
// admin route such as token management (403).
func TestReadGate_ReadTokenCannotReachAdminRoute(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	_ = createTestToken(t, db, auth.ScopeAdmin, "")
	readToken := createTestToken(t, db, auth.ScopeRead, "")

	// GET /auth/tokens is admin-only (RequireAdmin).
	if w := doGet(router, "/api/v1/auth/tokens", readToken); w.Code != http.StatusForbidden {
		t.Fatalf("read token must not reach admin route GET /auth/tokens, expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// GET /logs is admin-only too.
	if w := doGet(router, "/api/v1/logs", readToken); w.Code != http.StatusForbidden {
		t.Fatalf("read token must not reach admin route GET /logs, expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestReadGate_MintReadToken: an admin can mint a read-scope token via the API
// (operators need least-privilege read tokens).
func TestReadGate_MintReadToken(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	adminToken := createTestToken(t, db, auth.ScopeAdmin, "")

	req := httptest.NewRequest("POST", "/api/v1/auth/tokens",
		bytes.NewReader([]byte(`{"scope":"read","label":"viewer"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("admin should be able to mint a read token, expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestScopeSatisfies exercises the hierarchy helper directly.
func TestScopeSatisfies(t *testing.T) {
	cases := []struct {
		have, need auth.TokenScope
		want       bool
	}{
		{auth.ScopeAdmin, auth.ScopeRead, true},   // admin implies read
		{auth.ScopeAdmin, auth.ScopeAdmin, true},  // admin implies admin
		{auth.ScopeAdmin, auth.ScopeIngest, true}, // admin is superuser
		{auth.ScopeRead, auth.ScopeRead, true},    // read satisfies read
		{auth.ScopeRead, auth.ScopeAdmin, false},  // read never admin
		{auth.ScopeRead, auth.ScopeIngest, false}, // read is not ingest
		{auth.ScopeSensor, auth.ScopeRead, false}, // sensor is not read
		{auth.ScopeIngest, auth.ScopeRead, false}, // ingest is not read
	}
	for _, c := range cases {
		if got := auth.ScopeSatisfies(c.have, c.need); got != c.want {
			t.Errorf("ScopeSatisfies(%q, %q) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}
