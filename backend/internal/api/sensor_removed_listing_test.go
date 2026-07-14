package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

func TestSensorListSeparatesActiveAndRemovedWithoutCredentialMetadata(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	adminRaw, adminToken, err := auth.GenerateToken(auth.ScopeAdmin, "", "listing-admin")
	if err != nil {
		t.Fatalf("generate admin token: %v", err)
	}
	if err := db.CreateToken(adminToken); err != nil {
		t.Fatalf("store admin token: %v", err)
	}

	register := func(sensorID, hostname, code string) *httptest.ResponseRecorder {
		t.Helper()
		body := []byte(fmt.Sprintf(
			`{"sensor_id":%q,"hostname":%q,"os":"linux","arch":"amd64","cidr":"192.0.2.0/24","version":"test"}`,
			sensorID, hostname,
		))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Vedetta-Enrollment-Code", code)
		req.RemoteAddr = "198.51.100.10:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	list := func() (map[string]any, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensor/list", nil)
		req.Header.Set("Authorization", "Bearer "+adminRaw)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list sensors: want 200, got %d: %s", w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode sensor list: %v", err)
		}
		return response, w.Body.String()
	}

	if w := register("primary-sensor", "primary-host", mintEnrollmentCode(t, router, adminRaw)); w.Code != http.StatusOK {
		t.Fatalf("register primary: got %d: %s", w.Code, w.Body.String())
	}
	if w := register("retired-sensor", "retired-host", mintEnrollmentCode(t, router, adminRaw)); w.Code != http.StatusOK {
		t.Fatalf("register removable sensor: got %d: %s", w.Code, w.Body.String())
	}

	remove := httptest.NewRequest(http.MethodDelete, "/api/v1/sensor/retired-sensor", nil)
	remove.Header.Set("Authorization", "Bearer "+adminRaw)
	removed := httptest.NewRecorder()
	router.ServeHTTP(removed, remove)
	if removed.Code != http.StatusOK {
		t.Fatalf("remove sensor: want 200, got %d: %s", removed.Code, removed.Body.String())
	}

	response, rawResponse := list()
	assertSensorListIDs(t, response, []string{"primary-sensor"}, []string{"retired-sensor"})
	assertNoSensorListSecrets(t, response)
	for _, secret := range []string{adminRaw, adminToken.TokenID, adminToken.TokenHash} {
		if secret != "" && strings.Contains(rawResponse, secret) {
			t.Fatalf("sensor list leaked credential material %q", secret)
		}
	}

	resetCode := mintResetCode(t, router, adminRaw, "retired-sensor")
	if w := register("retired-sensor", "restored-host", resetCode); w.Code != http.StatusOK {
		t.Fatalf("reactivate with bound reset: want 200, got %d: %s", w.Code, w.Body.String())
	}

	response, _ = list()
	assertSensorListIDs(t, response, []string{"primary-sensor", "retired-sensor"}, nil)
}

func assertSensorListIDs(t *testing.T, response map[string]any, wantActive, wantRemoved []string) {
	t.Helper()
	collect := func(field string) []string {
		t.Helper()
		if response[field] == nil {
			return nil
		}
		items, ok := response[field].([]any)
		if !ok {
			t.Fatalf("sensor list field %q has type %T, want array", field, response[field])
		}
		ids := make([]string, 0, len(items))
		for _, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("sensor list %q item has type %T, want object", field, item)
			}
			id, ok := object["sensor_id"].(string)
			if !ok {
				t.Fatalf("sensor list %q item has invalid sensor_id: %#v", field, object["sensor_id"])
			}
			ids = append(ids, id)
		}
		return ids
	}

	active := collect("sensors")
	removed := collect("removed_sensors")
	if !sameStringSet(active, wantActive) {
		t.Fatalf("active sensor IDs = %v, want %v", active, wantActive)
	}
	if !sameStringSet(removed, wantRemoved) {
		t.Fatalf("removed sensor IDs = %v, want %v", removed, wantRemoved)
	}
	activeTotal, ok := response["total"].(float64)
	if !ok {
		t.Fatalf("active total has type %T, want number", response["total"])
	}
	if got := int(activeTotal); got != len(wantActive) {
		t.Fatalf("active total = %d, want %d", got, len(wantActive))
	}
	removedTotal, ok := response["removed_total"].(float64)
	if !ok {
		t.Fatalf("removed total has type %T, want number", response["removed_total"])
	}
	if got := int(removedTotal); got != len(wantRemoved) {
		t.Fatalf("removed total = %d, want %d", got, len(wantRemoved))
	}
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[string]int, len(want))
	for _, value := range want {
		counts[value]++
	}
	for _, value := range got {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func assertNoSensorListSecrets(t *testing.T, value any) {
	t.Helper()
	forbidden := map[string]bool{
		"actor":               true,
		"auth_token":          true,
		"enrollment_code":     true,
		"removed_by_token_id": true,
		"token":               true,
		"token_hash":          true,
		"token_id":            true,
	}
	var visit func(any)
	visit = func(current any) {
		switch current := current.(type) {
		case map[string]any:
			for key, child := range current {
				if forbidden[strings.ToLower(key)] {
					t.Errorf("sensor list exposed forbidden credential field %q", key)
				}
				visit(child)
			}
		case []any:
			for _, child := range current {
				visit(child)
			}
		}
	}
	visit(value)
}
