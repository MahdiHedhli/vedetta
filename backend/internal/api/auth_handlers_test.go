package api

// Regression tests for BUG-2: token creation was permanently broken after
// bootstrap. POST /api/v1/auth/tokens used to be registered OUTSIDE any auth
// middleware, so once >=1 token existed handleCreateToken saw an empty scope
// (nothing populated the context) and returned 403 "only admins can create
// tokens" even with a valid admin bearer — you could never mint a second token.
//
// These tests exercise the REAL router path (NewRouter → RequireAdmin → handler):
//   - bootstrap: first admin token creatable with NO auth → 201;
//   - after bootstrap: second token creatable WITH an admin bearer → 201;
//   - after bootstrap: create with NO token → 401;
//   - after bootstrap: create with a NON-admin (sensor) token → 403.
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

// createTokenRequest posts to /api/v1/auth/tokens. If bearer is non-empty it is
// sent as the Authorization header. Returns the recorder and the parsed raw token.
func createTokenRequest(t *testing.T, router http.Handler, bearer, scope string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"scope": scope, "label": "test"})
	req := httptest.NewRequest("POST", "/api/v1/auth/tokens", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp)
	return w, resp.Token
}

func TestHandleCreateToken_BootstrapThenAdminCanMintSecond(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	// 1. Bootstrap: zero tokens exist, so the first admin token is creatable with
	//    NO auth. This is the RequireAdmin bootstrap-bypass path.
	w, adminToken := createTokenRequest(t, router, "", "admin")
	if w.Code != http.StatusCreated {
		t.Fatalf("bootstrap admin token: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if adminToken == "" {
		t.Fatal("bootstrap admin token: no raw token returned")
	}

	// 2. After bootstrap: minting a SECOND token WITH the admin bearer must now
	//    succeed. This is the exact case BUG-2 broke (403 with a valid admin token).
	w2, sensorToken := createTokenRequest(t, router, adminToken, "sensor")
	if w2.Code != http.StatusCreated {
		t.Fatalf("second token with admin bearer: expected 201, got %d: %s", w2.Code, w2.Body.String())
	}
	if sensorToken == "" {
		t.Fatal("second token: no raw token returned")
	}
}

func TestHandleCreateToken_RejectsUnauthedAndNonAdminAfterBootstrap(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	// Establish auth state: at least one token exists (bootstrap done). The
	// sensor-scoped token uses an empty sensor_id to avoid the sensors FK.
	adminToken := createTestToken(t, db, "admin", "")
	nonAdminToken := createTestToken(t, db, "sensor", "")

	// No bearer at all → 401 (auth is configured, header missing/invalid).
	w, _ := createTokenRequest(t, router, "", "sensor")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no-auth create after bootstrap: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// Valid but non-admin (sensor) token → 403.
	w2, _ := createTokenRequest(t, router, nonAdminToken, "sensor")
	if w2.Code != http.StatusForbidden {
		t.Errorf("non-admin create after bootstrap: expected 403, got %d: %s", w2.Code, w2.Body.String())
	}

	// Sanity: the admin token still works (control for the two negatives above).
	w3, _ := createTokenRequest(t, router, adminToken, "ingest")
	if w3.Code != http.StatusCreated {
		t.Errorf("admin create after bootstrap: expected 201, got %d: %s", w3.Code, w3.Body.String())
	}
}

// TestSensorRegistrationDoesNotCloseAdminBootstrap is the regression test for
// beta-gate B1b: a sensor auto-issues a token on registration, which previously
// bumped the total token count and permanently closed the first-admin window,
// locking the operator out. Bootstrap now gates on the absence of an ACTIVE
// ADMIN, so the operator can still create the first admin after a sensor enrolls.
func TestSensorRegistrationDoesNotCloseAdminBootstrap(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	_ = registerTestSensor(t, router, "sensor-boot") // mints a sensor-scoped token

	// First admin still creatable with no auth (no active admin yet).
	w, adminToken := createTokenRequest(t, router, "", "admin")
	if w.Code != http.StatusCreated {
		t.Fatalf("first admin after sensor registration: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if adminToken == "" {
		t.Fatal("expected raw admin token in response")
	}

	// Now that an admin exists, bootstrap is closed: an unauthenticated create fails.
	w2, _ := createTokenRequest(t, router, "", "admin")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("unauth create after admin exists: expected 401, got %d: %s", w2.Code, w2.Body.String())
	}
}

// TestCannotRevokeLastActiveAdmin is the regression test for the beta-gate B1a
// lockout: revoking the only admin would leave the deployment unmanageable with
// no recovery path, so it must be refused until a second admin exists.
func TestCannotRevokeLastActiveAdmin(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	raw1, tok1, err := auth.GenerateToken(auth.ScopeAdmin, "", "admin-1")
	if err != nil {
		t.Fatalf("generate admin-1: %v", err)
	}
	if err := db.CreateToken(tok1); err != nil {
		t.Fatalf("store admin-1: %v", err)
	}

	revoke := func(id, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("DELETE", "/api/v1/auth/tokens/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Revoking the only admin must be refused (409) — no lockout.
	if w := revoke(tok1.TokenID, raw1); w.Code != http.StatusConflict {
		t.Fatalf("revoke last admin: expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// Add a second admin; now the first is revocable.
	raw2, tok2, err := auth.GenerateToken(auth.ScopeAdmin, "", "admin-2")
	if err != nil {
		t.Fatalf("generate admin-2: %v", err)
	}
	if err := db.CreateToken(tok2); err != nil {
		t.Fatalf("store admin-2: %v", err)
	}
	if w := revoke(tok1.TokenID, raw2); w.Code != http.StatusOK {
		t.Fatalf("revoke non-last admin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	_ = raw2
}
