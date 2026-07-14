package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

func TestRemoveSensorPreservesIdentityAndRequiresBoundReset(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, hostname, code string) *httptest.ResponseRecorder {
		t.Helper()
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":%q,"os":"linux","arch":"amd64","cidr":"192.0.2.0/24","version":"t"}`, id, hostname))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", 100+ipN)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	decodeToken := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var response struct {
			Token string `json:"auth_token"`
		}
		if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&response); err != nil {
			t.Fatalf("decode registration response: %v", err)
		}
		return response.Token
	}
	remove := func(id string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sensor/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if w := register("primary", "primary", mintEnrollmentCode(t, router, admin)); w.Code != http.StatusOK {
		t.Fatalf("enroll primary: %d %s", w.Code, w.Body.String())
	}
	originalCode := mintEnrollmentCode(t, router, admin)
	targetEnroll := register("removed-target", "original-host", originalCode)
	if targetEnroll.Code != http.StatusOK {
		t.Fatalf("enroll target: %d %s", targetEnroll.Code, targetEnroll.Body.String())
	}
	oldRawToken := decodeToken(targetEnroll)

	if w := remove("primary"); w.Code != http.StatusConflict {
		t.Fatalf("remove current primary: want 409, got %d: %s", w.Code, w.Body.String())
	}
	w := remove("removed-target")
	if w.Code != http.StatusOK {
		t.Fatalf("remove target: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Status    string `json:"status"`
		SensorID  string `json:"sensor_id"`
		RemovedAt string `json:"removed_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode removal response: %v", err)
	}
	if response.Status != "removed" || response.SensorID != "removed-target" || response.RemovedAt == "" {
		t.Fatalf("unexpected removal response: %#v", response)
	}

	var removed sql.NullTime
	var hostname string
	if err := db.QueryRow(`SELECT removed_at, hostname FROM sensors WHERE sensor_id='removed-target'`).Scan(&removed, &hostname); err != nil {
		t.Fatalf("read removed identity: %v", err)
	}
	if !removed.Valid || hostname != "original-host" {
		t.Fatalf("bad tombstone: removed=%v hostname=%q", removed, hostname)
	}
	if n := activeSensorTokenCount(t, db, "removed-target"); n != 0 {
		t.Fatalf("removed sensor has %d active tokens", n)
	}

	// The old sensor credential is revoked at the API boundary.
	heartbeat := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/heartbeat", nil)
	heartbeat.Header.Set("Authorization", "Bearer "+oldRawToken)
	heartbeat.Header.Set("X-Sensor-ID", "removed-target")
	heartbeatResult := httptest.NewRecorder()
	router.ServeHTTP(heartbeatResult, heartbeat)
	if heartbeatResult.Code != http.StatusUnauthorized {
		t.Fatalf("removed credential heartbeat: want 401, got %d", heartbeatResult.Code)
	}

	// Replaying the original enrollment code must not return its remembered,
	// newly-revoked token.
	if replay := register("removed-target", "attacker-host", originalCode); replay.Code != http.StatusUnauthorized {
		t.Fatalf("replay after removal: want 401, got %d: %s", replay.Code, replay.Body.String())
	}

	// A fresh generic code is refused for the retained identity without being
	// spent, and can still enroll a genuinely new sensor.
	generic := mintEnrollmentCode(t, router, admin)
	if refused := register("removed-target", "attacker-host", generic); refused.Code != http.StatusUnauthorized {
		t.Fatalf("generic reclaim of tombstone: want 401, got %d: %s", refused.Code, refused.Body.String())
	}
	if err := db.QueryRow(`SELECT hostname FROM sensors WHERE sensor_id='removed-target'`).Scan(&hostname); err != nil || hostname != "original-host" {
		t.Fatalf("generic reclaim changed metadata: hostname=%q err=%v", hostname, err)
	}
	if fresh := register("brand-new", "new-host", generic); fresh.Code != http.StatusOK {
		t.Fatalf("refused generic code was spent: got %d: %s", fresh.Code, fresh.Body.String())
	}

	// A bound reset is the explicit reactivation path.
	bound := mintResetCode(t, router, admin, "removed-target")
	if reset := register("removed-target", "restored-host", bound); reset.Code != http.StatusOK {
		t.Fatalf("bound reactivation: want 200, got %d: %s", reset.Code, reset.Body.String())
	}
	if n := activeSensorTokenCount(t, db, "removed-target"); n != 1 {
		t.Fatalf("reactivated sensor active tokens=%d, want 1", n)
	}
	if err := db.QueryRow(`SELECT removed_at, hostname FROM sensors WHERE sensor_id='removed-target'`).Scan(&removed, &hostname); err != nil {
		t.Fatalf("read reactivated identity: %v", err)
	}
	if removed.Valid || hostname != "restored-host" {
		t.Fatalf("bound reset did not reactivate: removed=%v hostname=%q", removed, hostname)
	}
}
