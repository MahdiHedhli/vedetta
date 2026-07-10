package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSplitSQLStatements guards the migration-splitter that lets the runner apply
// statements one at a time. The tricky case is a semicolon INSIDE a string
// literal (migration 017 has one) — a naive split would corrupt that INSERT.
func TestSplitSQLStatements(t *testing.T) {
	script := `-- header comment
ALTER TABLE devices ADD COLUMN a TEXT DEFAULT '';
INSERT INTO x (c) VALUES ('has ; a semicolon; inside it');
/* block ; comment */
CREATE TABLE y (id TEXT); -- trailing line comment
`
	got := splitSQLStatements(script)
	// Expect: the ALTER, the INSERT, and the CREATE. Comment-only fragments do not
	// count as executable statements.
	var exec []string
	for _, s := range got {
		if !isNoOpSQL(s) {
			exec = append(exec, s)
		}
	}
	if len(exec) != 3 {
		t.Fatalf("expected 3 executable statements, got %d: %#v", len(exec), exec)
	}
	if !strings.Contains(exec[1], "has ; a semicolon; inside it") {
		t.Errorf("semicolons inside a string literal must not split the statement: %q", exec[1])
	}
}

// TestFreshMigrationsProduceCompleteSchema runs the REAL migration files against
// a fresh DB and asserts a final-schema manifest — the check that was missing and
// let migration 012 silently skip suppression_rules (beta-gate B3). It also
// verifies the exact query that regressed (SELECT ... FROM suppression_rules).
func TestFreshMigrationsProduceCompleteSchema(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	migDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "siem", "migrations")
	if _, err := os.Stat(migDir); err != nil {
		t.Skipf("real migrations dir not found (%s): %v", migDir, err)
	}
	t.Setenv("VEDETTA_MIGRATIONS_DIR", migDir)

	dbPath := filepath.Join(t.TempDir(), "manifest.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open fresh DB with real migrations: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	wantTables := []string{
		"events", "devices", "sensors", "api_tokens", "scan_targets",
		"threat_indicators", "whitelist_rules", "suppression_rules",
		"schema_migrations",
	}
	for _, tbl := range wantTables {
		var name string
		if err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name); err != nil {
			t.Errorf("expected table %q to exist after fresh migrations: %v", tbl, err)
		}
	}

	// The endpoint that returned 500 must now work: querying suppression_rules
	// must not fail with "no such table".
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM suppression_rules`).Scan(&count); err != nil {
		t.Errorf("SELECT from suppression_rules failed (the B3 regression): %v", err)
	}
}
