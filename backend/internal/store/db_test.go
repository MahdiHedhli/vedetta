package store

import (
	"os"
	"path/filepath"
	"testing"
)

// testDB creates a temporary in-memory SQLite database for testing.
func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpen_InMemory(t *testing.T) {
	db := testDB(t)

	// Verify core tables exist
	tables := []string{"events", "devices", "retention_config", "scan_targets", "sensors", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist: %v", table, err)
		}
	}
}

func TestMigrate_SequentialRunner(t *testing.T) {
	// Create a temp directory with migration files
	dir := t.TempDir()
	migDir := filepath.Join(dir, "siem", "migrations")
	os.MkdirAll(migDir, 0o755)

	// Write two migration files
	os.WriteFile(filepath.Join(migDir, "001_init.sql"), []byte(`
		CREATE TABLE IF NOT EXISTS test_one (id TEXT PRIMARY KEY);
	`), 0o644)
	os.WriteFile(filepath.Join(migDir, "002_second.sql"), []byte(`
		CREATE TABLE IF NOT EXISTS test_two (id TEXT PRIMARY KEY, val TEXT);
	`), 0o644)

	// Open DB from temp dir so it finds migrations
	dbPath := filepath.Join(dir, "test.db")
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	// Both tables should exist
	var name string
	if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_one'").Scan(&name); err != nil {
		t.Error("test_one table should exist after migration 001")
	}
	if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_two'").Scan(&name); err != nil {
		t.Error("test_two table should exist after migration 002")
	}

	// schema_migrations should have both entries
	var count int
	db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 migrations recorded, got %d", count)
	}

	// Re-opening should not re-apply migrations (idempotent)
	db2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
	}
	defer db2.Close()

	db2.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 migrations after re-open, got %d", count)
	}
}

func TestMigrate_InlineFallback(t *testing.T) {
	// When no migration dir is found, inline fallback should work
	db := testDB(t)

	// events table should have the correct columns
	_, err := db.Exec("INSERT INTO events (event_id, timestamp, event_type, source_hash) VALUES ('test', '2026-01-01T00:00:00Z', 'dns_query', 'hash123')")
	if err != nil {
		t.Errorf("failed to insert into events: %v", err)
	}

	// scan_targets should exist (this was the bug — inline fallback now includes it)
	_, err = db.Exec("INSERT INTO scan_targets (target_id, name, cidr, created_at) VALUES ('t1', 'Test', '10.0.0.0/24', '2026-01-01T00:00:00Z')")
	if err != nil {
		t.Errorf("failed to insert into scan_targets: %v", err)
	}

	// sensors should exist
	_, err = db.Exec("INSERT INTO sensors (sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen) VALUES ('s1', 'test', 'linux', 'amd64', '10.0.0.0/24', '0.1.0', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
	if err != nil {
		t.Errorf("failed to insert into sensors: %v", err)
	}
}
