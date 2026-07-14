package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestExpectedSchemaMigrationMatchesLatestFile is the drift guard: the runtime
// ExpectedSchemaMigration constant (what /readyz treats as "current") MUST equal the
// highest-numbered migration file the binary ships. Add 027_*.sql without bumping the
// constant and this fails — which is the whole point, because otherwise a fresh,
// fully-migrated DB would read as "ahead" of the constant and /readyz would 503.
func TestExpectedSchemaMigrationMatchesLatestFile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	migDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "siem", "migrations")
	entries, err := os.ReadDir(migDir)
	if err != nil {
		t.Fatalf("read migrations dir %s: %v", migDir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		t.Fatalf("no .sql migrations found in %s", migDir)
	}
	sort.Strings(files)
	latest := files[len(files)-1]
	if latest != ExpectedSchemaMigration {
		t.Fatalf("ExpectedSchemaMigration = %q, but latest migration file is %q — bump the constant (and the inline schema) in lockstep",
			ExpectedSchemaMigration, latest)
	}
}

// TestSchemaHead_InlineFallbackStampsExpected verifies that a DB brought up via the
// inline fallback (the path store tests hit — no migration dir resolves) reports the
// expected head, so /readyz treats it as current rather than "behind".
func TestSchemaHead_InlineFallbackStampsExpected(t *testing.T) {
	db := testDB(t)
	head, err := db.SchemaHead(context.Background())
	if err != nil {
		t.Fatalf("SchemaHead: %v", err)
	}
	if head != ExpectedSchemaMigration {
		t.Errorf("inline-fallback SchemaHead = %q, want %q", head, ExpectedSchemaMigration)
	}
}

func TestSchemaHead_EmptyWhenUnrecorded(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`DELETE FROM schema_migrations`); err != nil {
		t.Fatalf("clear schema_migrations: %v", err)
	}
	head, err := db.SchemaHead(context.Background())
	if err != nil {
		t.Fatalf("SchemaHead: %v", err)
	}
	if head != "" {
		t.Errorf("SchemaHead on empty table = %q, want empty", head)
	}
}

func TestVerifyReadable(t *testing.T) {
	db := testDB(t)
	if err := db.VerifyReadable(context.Background()); err != nil {
		t.Fatalf("VerifyReadable on open DB: %v", err)
	}
	// After Close, a query must fail so a probe reports 503 rather than false-green.
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := db.VerifyReadable(context.Background()); err == nil {
		t.Error("VerifyReadable on closed DB = nil, want error")
	}
}

func TestIntegrityCheck_Healthy(t *testing.T) {
	db := testDB(t)
	ok, detail, err := db.IntegrityCheck(context.Background())
	if err != nil {
		t.Fatalf("IntegrityCheck: %v", err)
	}
	if !ok || detail != "ok" {
		t.Errorf("IntegrityCheck = (ok=%v, detail=%q), want (true, \"ok\")", ok, detail)
	}
}

func TestForeignKeyViolations(t *testing.T) {
	// A file DB (not :memory:) so a second connection with FK enforcement OFF can
	// plant an orphan the store DB then detects.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fk.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Clean DB: no violations.
	violations, err := db.ForeignKeyViolations(context.Background())
	if err != nil {
		t.Fatalf("ForeignKeyViolations (clean): %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("clean DB reported %d violation(s): %v", len(violations), violations)
	}

	// Plant an orphan: device_signals.device_id references devices(device_id). Insert
	// with foreign_keys OFF on a separate connection so enforcement doesn't block it.
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
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	violations, err = db.ForeignKeyViolations(context.Background())
	if err != nil {
		t.Fatalf("ForeignKeyViolations (orphaned): %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("planted orphan not detected by foreign_key_check")
	}
	if !strings.Contains(violations[0], "device_signals") {
		t.Errorf("violation %q does not name the offending table", violations[0])
	}
}
