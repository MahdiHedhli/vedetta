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
