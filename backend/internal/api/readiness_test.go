package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// readyTestDB opens a fresh file-backed store for readiness tests. A file (not
// :memory:) keeps every pooled connection — including the background deep-check
// goroutine's — pointed at the same database.
func readyTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("open readiness test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func getReadyz(t *testing.T, h http.Handler) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz body %q: %v", w.Body.String(), err)
	}
	return w, body
}

func TestReadyz_HealthyReturns200(t *testing.T) {
	db := readyTestDB(t)
	router := NewRouter(&Server{DB: db})

	w, body := getReadyz(t, router)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /readyz = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if body["ready"] != true {
		t.Errorf("ready = %v, want true", body["ready"])
	}
	if body["schema_migration"] != store.ExpectedSchemaMigration {
		t.Errorf("schema_migration = %v, want %q", body["schema_migration"], store.ExpectedSchemaMigration)
	}
}

func TestReadyz_BehindSchemaReturns503(t *testing.T) {
	db := readyTestDB(t)
	router := NewRouter(&Server{DB: db})

	// Simulate a behind / un-migrated DB: drop the recorded migration head.
	if _, err := db.Exec(`DELETE FROM schema_migrations`); err != nil {
		t.Fatalf("clear schema_migrations: %v", err)
	}

	w, body := getReadyz(t, router)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz on behind DB = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if body["ready"] != false {
		t.Errorf("ready = %v, want false", body["ready"])
	}
	if body["reason"] != "schema not at expected migration" {
		t.Errorf("reason = %v, want schema-mismatch reason", body["reason"])
	}
	if body["expected"] != store.ExpectedSchemaMigration {
		t.Errorf("expected = %v, want %q", body["expected"], store.ExpectedSchemaMigration)
	}
}

func TestReadyz_UnreachableDBReturns503(t *testing.T) {
	db := readyTestDB(t)
	router := NewRouter(&Server{DB: db})

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	w, body := getReadyz(t, router)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz on closed DB = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if body["reason"] != "database unreachable" {
		t.Errorf("reason = %v, want \"database unreachable\"", body["reason"])
	}
}

// TestReadyz_CachedIntegrityFailureReturns503 verifies the deep-check dimension gates
// readiness: a fresh, non-stale unhealthy cache must produce a 503 even though the
// cheap checks pass. The cache is set directly (same package) so the result does not
// depend on background-goroutine timing.
func TestReadyz_CachedIntegrityFailureReturns503(t *testing.T) {
	db := readyTestDB(t)
	m := NewReadinessMonitor(db)
	m.deep = deepCheckResult{healthy: false, reason: "integrity_check: malformed", at: time.Now().UTC()}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	m.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with cached integrity failure = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["reason"] != "integrity_check: malformed" {
		t.Errorf("reason = %v, want the cached integrity reason", body["reason"])
	}
}

// TestReadyz_NilDBReturns503 guards the unconditional route registration: with no DB
// there is no monitor, and a probe must see 503 "not ready" — never 404.
func TestReadyz_NilDBReturns503(t *testing.T) {
	router := NewRouter(&Server{})

	w, body := getReadyz(t, router)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with no DB = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if body["reason"] != "database not configured" {
		t.Errorf("reason = %v, want \"database not configured\"", body["reason"])
	}
}

// TestReadyz_HeadRequest verifies HEAD is served (chi does not fall back HEAD→GET):
// HEAD-based probers like GNU wget --spider or curl -I must see the status code, not 405.
func TestReadyz_HeadRequest(t *testing.T) {
	db := readyTestDB(t)
	router := NewRouter(&Server{DB: db})

	req := httptest.NewRequest(http.MethodHead, "/readyz", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HEAD /readyz = %d, want 200", w.Code)
	}
}

// TestReadyz_CorruptDBFirstProbeNotReady is the Codex P1 scenario: a DB whose schema
// head is correct but whose referential integrity is broken BEFORE the process starts.
// The FIRST probe must already be 503 — a single startup 200 would let compose mark
// the container healthy and start dependents against the corrupt DB.
func TestReadyz_CorruptDBFirstProbeNotReady(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corrupt-first.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Plant the FK orphan before any probe (FK enforcement off on a raw connection).
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=off&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.Exec(`INSERT INTO device_signals
		(device_id, field, value, source, confidence, first_observed, last_observed)
		VALUES ('ghost-device', 'hostname', 'x', 'test', 0, ?, ?)`, now, now); err != nil {
		raw.Close()
		t.Fatalf("plant orphan: %v", err)
	}
	raw.Close()

	router := NewRouter(&Server{DB: db})
	w, body := getReadyz(t, router)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("FIRST GET /readyz on corrupt DB = %d, want 503 (body %s) — startup false-green", w.Code, w.Body.String())
	}
	if body["ready"] != false {
		t.Errorf("ready = %v, want false", body["ready"])
	}
}

// TestReadyz_InitialDeepCheckPendingReturns503 verifies the bounded wait: while the
// very first deep check is still running, a probe whose context expires reports NOT
// ready rather than guessing healthy.
func TestReadyz_InitialDeepCheckPendingReturns503(t *testing.T) {
	db := readyTestDB(t)
	m := NewReadinessMonitor(db)
	// Simulate an in-flight first scan: refreshing set, no result stored. deepStatus
	// must not start another goroutine and must wait until the request context ends.
	m.refreshing = true

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	m.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz during initial scan = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["reason"] != "initial integrity check still running" {
		t.Errorf("reason = %v, want pending-scan reason", body["reason"])
	}
}

// TestRunDeepCheck_DetectsForeignKeyViolation exercises the real deep check against a
// planted orphan, proving the monitor surfaces FK corruption (not just a healthy stub).
func TestRunDeepCheck_DetectsForeignKeyViolation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corrupt.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	m := NewReadinessMonitor(db)

	// Healthy first.
	if res := m.runDeepCheck(context.Background()); !res.healthy {
		t.Fatalf("clean DB deep check unhealthy: %s", res.reason)
	}

	// Plant an orphan with FK enforcement OFF on a separate connection.
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=off&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.Exec(`INSERT INTO device_signals
		(device_id, field, value, source, confidence, first_observed, last_observed)
		VALUES ('ghost-device', 'hostname', 'x', 'test', 0, ?, ?)`, now, now); err != nil {
		raw.Close()
		t.Fatalf("plant orphan: %v", err)
	}
	raw.Close()

	res := m.runDeepCheck(context.Background())
	if res.healthy {
		t.Fatal("deep check reported healthy despite a foreign key violation")
	}
}

// TestHealthzStillLivenessOnly guards the requirement that /healthz remains a pure
// liveness probe: it must answer 200 even when /readyz would 503 (here, a behind DB).
func TestHealthzStillLivenessOnly(t *testing.T) {
	db := readyTestDB(t)
	router := NewRouter(&Server{DB: db})
	if _, err := db.Exec(`DELETE FROM schema_migrations`); err != nil {
		t.Fatalf("clear schema_migrations: %v", err)
	}

	// /readyz is unhealthy...
	wReady := httptest.NewRecorder()
	router.ServeHTTP(wReady, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if wReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", wReady.Code)
	}

	// ...but /healthz is still up.
	wLive := httptest.NewRecorder()
	router.ServeHTTP(wLive, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if wLive.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 (liveness must not touch the DB)", wLive.Code)
	}
}
