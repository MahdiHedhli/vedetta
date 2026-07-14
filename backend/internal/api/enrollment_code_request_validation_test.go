package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestEnrollmentCodeRequestRejectsAmbiguousJSON(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	for _, test := range []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{"sensor_id":`},
		{name: "trailing object", body: `{}` + "\n" + `{}`},
		{name: "JSON null", body: `null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-codes", strings.NewReader(test.body))
			req.Header.Set("Authorization", "Bearer "+admin)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("ambiguous enrollment request: want 400, got %d: %s", w.Code, w.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if _, ok := response["enrollment_code"]; ok {
				t.Fatal("rejected enrollment request returned an enrollment code")
			}
		})
	}
}

func TestEnrollmentCodeRequestPreservesGenericAndExactResetTypes(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	if err := db.RegisterSensor(models.Sensor{
		SensorID: "existing-sensor",
		Hostname: "existing-host",
		OS:       "linux",
		Arch:     "amd64",
		CIDR:     "192.0.2.0/24",
		Version:  "test",
	}); err != nil {
		t.Fatalf("register existing sensor identity: %v", err)
	}

	post := func(body []byte) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-codes", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("mint enrollment code: want 201, got %d: %s", w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode enrollment response: %v", err)
		}
		if response["enrollment_code"] == "" {
			t.Fatal("successful enrollment request returned no code")
		}
		return response
	}

	generic := post(nil)
	if got := generic["type"]; got != "new_sensor" {
		t.Fatalf("empty body enrollment type = %#v, want new_sensor", got)
	}
	if _, ok := generic["sensor_id"]; ok {
		t.Fatalf("generic enrollment unexpectedly bound to sensor_id %#v", generic["sensor_id"])
	}

	reset := post([]byte(`{"sensor_id":"existing-sensor"}`))
	if got := reset["type"]; got != "reset" {
		t.Fatalf("bound enrollment type = %#v, want reset", got)
	}
	if got := reset["sensor_id"]; got != "existing-sensor" {
		t.Fatalf("bound enrollment sensor_id = %#v, want existing-sensor", got)
	}
}
