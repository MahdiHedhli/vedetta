package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func TestTombstonedSensorRejectsLegacyActiveTokenOnHeartbeat(t *testing.T) {
	srv, db := setupTestServer(t)

	primary := models.Sensor{
		SensorID: "sensor-primary", Hostname: "primary", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test",
	}
	removed := models.Sensor{
		SensorID: "sensor-removed", Hostname: "removed", OS: "linux", Arch: "arm64",
		CIDR: "198.51.100.0/24", Version: "test",
	}
	if err := db.RegisterSensor(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := db.RegisterSensor(removed); err != nil {
		t.Fatalf("register removable sensor: %v", err)
	}
	if _, err := db.RemoveSensor(removed.SensorID, "admin-test", "retired"); err != nil {
		t.Fatalf("remove sensor: %v", err)
	}

	// Simulate a credential created by an old binary or a manual database edit
	// after the identity was tombstoned. The route must enforce identity state in
	// addition to accepting the otherwise-valid bearer.
	rawToken, token, err := auth.GenerateToken(auth.ScopeSensor, removed.SensorID, "legacy-manual")
	if err != nil {
		t.Fatalf("generate legacy token: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO api_tokens
			(token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, token.TokenID, token.TokenHash, token.Scope, token.SensorID, token.Label, token.CreatedAt, token.LastUsed); err != nil {
		t.Fatalf("insert legacy active sensor token: %v", err)
	}

	router := NewRouter(srv)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("X-Sensor-ID", removed.SensorID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("tombstoned sensor heartbeat = %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "sensor identity is not active") {
		t.Fatalf("tombstoned sensor heartbeat returned an unclear error: %s", w.Body.String())
	}

	var status string
	var active int
	if err := db.QueryRow(`
		SELECT status, removed_at IS NULL FROM sensors WHERE sensor_id = ?
	`, removed.SensorID).Scan(&status, &active); err != nil {
		t.Fatalf("read sensor after refused heartbeat: %v", err)
	}
	if status != "offline" || active != 0 {
		t.Fatalf("refused heartbeat changed tombstone: status=%q active=%d", status, active)
	}
}

func TestConcurrentDistinctNewSensorEnrollmentsDoNotLoseConsumedCodes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "concurrent-new-enrollment.db"))
	if err != nil {
		t.Fatalf("open file-backed database: %v", err)
	}
	defer db.Close()

	adminRaw, adminToken, err := auth.GenerateToken(auth.ScopeAdmin, "", "concurrency-admin")
	if err != nil {
		t.Fatalf("generate admin token: %v", err)
	}
	if err := db.CreateToken(adminToken); err != nil {
		t.Fatalf("store admin token: %v", err)
	}

	srv := &Server{DB: db, Enroll: NewEnrollmentStore()}
	router := NewRouter(srv)

	const enrollmentCount = 16
	type enrollment struct {
		sensorID string
		code     string
		body     []byte
	}
	enrollments := make([]enrollment, enrollmentCount)
	for i := range enrollments {
		sensorID := fmt.Sprintf("sensor-new-%02d", i)
		body, err := json.Marshal(map[string]any{
			"sensor_id": sensorID,
			"hostname":  fmt.Sprintf("sensor-host-%02d", i),
			"os":        "linux",
			"arch":      "arm64",
			"cidr":      "203.0.113.0/24",
			"version":   "test",
		})
		if err != nil {
			t.Fatalf("marshal registration %d: %v", i, err)
		}
		enrollments[i] = enrollment{
			sensorID: sensorID,
			code:     mintEnrollmentCode(t, router, adminRaw),
			body:     body,
		}
	}

	type result struct {
		status int
		body   string
	}
	results := make([]result, enrollmentCount)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range enrollments {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			e := enrollments[i]
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor/register", bytes.NewReader(e.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Vedetta-Enrollment-Code", e.code)
			// Registration is intentionally rate-limited per source address. Use
			// distinct RFC 5737 addresses so this exercises database contention,
			// not the unrelated anti-abuse limit.
			req.RemoteAddr = fmt.Sprintf("198.51.100.%d:12345", i+1)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results[i] = result{status: w.Code, body: w.Body.String()}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, got := range results {
		if got.status != http.StatusOK {
			t.Errorf("enrollment %s = %d, want 200: %s", enrollments[i].sensorID, got.status, got.body)
			continue
		}
		var response sensorRegistrationResponse
		if err := json.Unmarshal([]byte(got.body), &response); err != nil {
			t.Errorf("decode enrollment %s response: %v", enrollments[i].sensorID, err)
			continue
		}
		if response.SensorID != enrollments[i].sensorID || response.AuthToken == "" {
			t.Errorf("enrollment %s returned incomplete credential response: %+v", enrollments[i].sensorID, response)
		}
	}
	if t.Failed() {
		return
	}

	var sensorCount, activeTokenCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE removed_at IS NULL`).Scan(&sensorCount); err != nil {
		t.Fatalf("count enrolled sensors: %v", err)
	}
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM api_tokens
		WHERE scope = ? AND revoked = 0
	`, auth.ScopeSensor).Scan(&activeTokenCount); err != nil {
		t.Fatalf("count active sensor tokens: %v", err)
	}
	if sensorCount != enrollmentCount || activeTokenCount != enrollmentCount {
		t.Fatalf("committed enrollments: sensors=%d active tokens=%d, want %d/%d",
			sensorCount, activeTokenCount, enrollmentCount, enrollmentCount)
	}

	for _, e := range enrollments {
		var activeForSensor int
		if err := db.QueryRow(`
			SELECT COUNT(*) FROM api_tokens
			WHERE sensor_id = ? AND scope = ? AND revoked = 0
		`, e.sensorID, auth.ScopeSensor).Scan(&activeForSensor); err != nil {
			t.Fatalf("count active token for %s: %v", e.sensorID, err)
		}
		if activeForSensor != 1 {
			t.Errorf("active tokens for %s = %d, want 1", e.sensorID, activeForSensor)
		}
	}
}
