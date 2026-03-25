package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite connection.
type DB struct {
	*sql.DB
}

// Open opens (or creates) the SQLite database and runs migrations.
func Open(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = "/data/vedetta.db"
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DB{db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	log.Printf("Database opened: %s", dbPath)
	return store, nil
}

// migrate runs the SQL migration files.
func (db *DB) migrate() error {
	// Read migration from embedded path or fallback
	migrationPaths := []string{
		"/app/siem/migrations/001_init.sql",
		"siem/migrations/001_init.sql",
		"../siem/migrations/001_init.sql",
	}

	var migrationSQL []byte
	var err error
	for _, p := range migrationPaths {
		migrationSQL, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}

	if err != nil {
		// Inline fallback — ensures DB works even without migration file
		migrationSQL = []byte(inlineMigration)
	}

	_, err = db.Exec(string(migrationSQL))
	if err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	log.Println("Database migrations applied")
	return nil
}

const inlineMigration = `
CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY,
    timestamp      TIMESTAMP NOT NULL,
    event_type     TEXT NOT NULL,
    source_hash    TEXT NOT NULL,
    domain         TEXT,
    query_type     TEXT,
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',
    geo            TEXT,
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events (event_type);

CREATE TABLE IF NOT EXISTS devices (
    device_id    TEXT PRIMARY KEY,
    first_seen   TIMESTAMP NOT NULL,
    last_seen    TIMESTAMP NOT NULL,
    ip_address   TEXT NOT NULL,
    mac_address  TEXT NOT NULL,
    hostname     TEXT,
    vendor       TEXT,
    open_ports   TEXT DEFAULT '[]',
    segment      TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_devices_mac  ON devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_last ON devices (last_seen);

CREATE TABLE IF NOT EXISTS retention_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO retention_config (key, value) VALUES ('retention_days', '90');

CREATE TABLE IF NOT EXISTS scan_targets (
    target_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    segment     TEXT NOT NULL DEFAULT 'default',
    scan_ports  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL,
    last_scan   TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_targets_enabled ON scan_targets (enabled);
`
