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
