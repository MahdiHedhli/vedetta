package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

func TestEnrollmentStore(t *testing.T) {
	s := NewEnrollmentStore()
	code, _ := s.Generate()
	if code == "" {
		t.Fatal("expected a non-empty code")
	}
	if !s.Consume(code) {
		t.Fatal("a freshly generated code should consume once")
	}
	if s.Consume(code) {
		t.Fatal("a code must be single-use")
	}
	if s.Consume("NOPE-NOPE-NOPE-NOPE") {
		t.Fatal("an unknown code must not consume")
	}
	if s.Consume("") {
		t.Fatal("an empty code must not consume")
	}
}

// TestSensorEnrollmentRequiredAfterAdmin is the beta-gate B1a regression: once an
// admin exists, a brand-new sensor cannot register without an admin bearer or a
// valid single-use enrollment code.
func TestSensorEnrollmentRequiredAfterAdmin(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	admin := createTestToken(t, db, auth.ScopeAdmin, "") // an admin now exists

	body := func(id string) []byte {
		return []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
	}
	ipN := 0
	register := func(id, bearer, code string) *httptest.ResponseRecorder {
		ipN++
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body(id)))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", 10+ipN) // distinct IP: dodge the 5/min limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// 1. New sensor, no admin bearer, no code, but an admin exists -> rejected.
	if w := register("sensor-a", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 registering a new sensor without a code once an admin exists, got %d: %s", w.Code, w.Body.String())
	}

	// 2. An admin bearer may enroll a new sensor with no code.
	if w := register("sensor-b", admin, ""); w.Code != http.StatusOK {
		t.Fatalf("expected 200 enrolling with an admin bearer, got %d: %s", w.Code, w.Body.String())
	}

	// 3. A minted enrollment code works once, then is single-use.
	code := mintEnrollmentCode(t, router, admin)
	if w := register("sensor-c", "", code); w.Code != http.StatusOK {
		t.Fatalf("expected 200 enrolling with a valid code, got %d: %s", w.Code, w.Body.String())
	}
	if w := register("sensor-d", "", code); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 reusing a consumed code, got %d: %s", w.Code, w.Body.String())
	}
}

// TestEnrollmentIdempotentReplay is the Issue #44 regression: Core consumes the
// single-use code and mints the sensor's only raw bearer before the HTTP response
// reaches the sensor. If that first response is lost, a retry with the SAME code
// must return the SAME raw token (200), not a 401 — otherwise the first sensor is
// permanently stranded. A DIFFERENT caller replaying the code must still be denied.
func TestEnrollmentIdempotentReplay(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	admin := createTestToken(t, db, auth.ScopeAdmin, "") // an admin now exists

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", 10+ipN) // distinct IP: dodge the 5/min limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var m map[string]any
		if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
			t.Fatalf("decode register response: %v", err)
		}
		tok, _ := m["auth_token"].(string)
		return tok
	}

	code := mintEnrollmentCode(t, router, admin)

	// First registration succeeds and mints the sensor's only raw token.
	w1 := register("sensor-idem", code)
	if w1.Code != http.StatusOK {
		t.Fatalf("first register: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	tok1 := tokenOf(w1)
	if tok1 == "" {
		t.Fatal("first register did not return an auth_token")
	}

	// The sensor "lost" that response. It retries with the SAME code and SAME
	// sensor_id — it must recover the SAME token, not a 401.
	w2 := register("sensor-idem", code)
	if w2.Code != http.StatusOK {
		t.Fatalf("idempotent retry: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	tok2 := tokenOf(w2)
	if tok2 != tok1 {
		t.Fatalf("idempotent retry returned a different token: %q vs %q", tok2, tok1)
	}

	// The recovered token must actually authenticate.
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok2); err != nil {
		t.Fatalf("recovered token does not validate: %v", err)
	}

	// Single-use against a DIFFERENT caller is preserved: another sensor_id
	// replaying the same consumed code gets nothing.
	if w := register("sensor-other", code); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a different sensor replaying a consumed code, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSensorReset_ViaFreshEnrollmentCode is the Issue #44 RECOVERY regression: a
// sensor stranded (--reset, a lost response past the idempotency window, a Core
// restart, or local token corruption) has no local token while the server-side
// token still exists. It must be able to re-enroll by presenting a FRESH
// admin-minted single-use enrollment code — Core revokes the stale token and
// issues a new one, so recovery needs no hidden admin reset API. A bogus code
// must NOT reset it or revoke the real token.
func TestSensorReset_ViaFreshEnrollmentCode(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 10+ipN) // distinct IP: dodge the limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		tok, _ := m["auth_token"].(string)
		return tok
	}

	// Enroll the sensor for the first time.
	tok1 := tokenOf(register("sensor-reset", mintEnrollmentCode(t, router, admin)))
	if tok1 == "" {
		t.Fatal("first enroll returned no token")
	}

	// Stranded: no local token, but the server token still exists. Re-register with
	// nothing -> 401 (not silently reset); a BOGUS code -> 401 and the real token
	// must survive (no revoke-before-validate DoS).
	if w := register("sensor-reset", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranded re-register with nothing: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if w := register("sensor-reset", "WRONG-WRONG-WRONG-WRONG"); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranded re-register with a bogus code: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok1); err != nil {
		t.Fatalf("original token must survive a failed reset attempt: %v", err)
	}

	// A FRESH admin-minted code recovers: revoke the stale token, issue a NEW one.
	w2 := register("sensor-reset", mintEnrollmentCode(t, router, admin))
	if w2.Code != http.StatusOK {
		t.Fatalf("reset via fresh code: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	tok2 := tokenOf(w2)
	if tok2 == "" || tok2 == tok1 {
		t.Fatalf("reset must issue a NEW token: tok1=%q tok2=%q", tok1, tok2)
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok2); err != nil {
		t.Fatalf("new token must validate: %v", err)
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok1); err == nil {
		t.Fatal("the stale token must be revoked after a successful reset")
	}
}

func mintEnrollmentCode(t *testing.T, router http.Handler, adminBearer string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/enrollment-codes", nil)
	req.Header.Set("Authorization", "Bearer "+adminBearer)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint enrollment code: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.NewDecoder(w.Body).Decode(&m)
	code, _ := m["enrollment_code"].(string)
	if code == "" {
		t.Fatal("expected an enrollment_code in the response")
	}
	return code
}
