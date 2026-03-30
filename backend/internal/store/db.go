package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// migrate runs all SQL migration files sequentially, tracking applied
// migrations in a schema_migrations table.
func (db *DB) migrate() error {
	// Create the schema_migrations tracking table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id         TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Locate the migrations directory
	migrationDir := ""
	candidates := []string{
		"/app/siem/migrations",
		"siem/migrations",
		"../siem/migrations",
	}
	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			migrationDir = dir
			break
		}
	}

	if migrationDir == "" {
		// Inline fallback — ensures DB works even without migration files
		log.Println("Migration directory not found — applying inline fallback")
		return db.applyInlineFallback()
	}

	// Read all .sql files, sorted by filename (001_, 002_, etc.)
	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var sqlFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			sqlFiles = append(sqlFiles, e.Name())
		}
	}
	sort.Strings(sqlFiles)

	if len(sqlFiles) == 0 {
		log.Println("No migration files found — applying inline fallback")
		return db.applyInlineFallback()
	}

	// Apply each migration that hasn't been applied yet
	for _, filename := range sqlFiles {
		var applied int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE id = ?", filename).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", filename, err)
		}
		if applied > 0 {
			continue
		}

		// Read the migration file
		sqlBytes, err := os.ReadFile(filepath.Join(migrationDir, filename))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}

		// Execute in a transaction
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", filename, err)
		}

		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute migration %s: %w", filename, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)",
			filename, time.Now().UTC()); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", filename, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", filename, err)
		}

		log.Printf("Migration applied: %s", filename)
	}

	log.Printf("Database migrations complete (%d files)", len(sqlFiles))
	return nil
}

// applyInlineFallback applies the hardcoded schema when migration files
// are not available (e.g. during development or tests).
func (db *DB) applyInlineFallback() error {
	_, err := db.Exec(inlineMigration)
	if err != nil {
		return fmt.Errorf("inline migration failed: %w", err)
	}
	log.Println("Inline fallback migration applied")
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
CREATE INDEX IF NOT EXISTS idx_devices_ip_segment ON devices (ip_address, segment);

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

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    arch        TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    version     TEXT NOT NULL,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL,
    status      TEXT NOT NULL DEFAULT 'online',
    is_primary  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator  TEXT NOT NULL,
    type       TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash')),
    source     TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    tags       TEXT DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    ttl_hours  INTEGER NOT NULL DEFAULT 168,
    PRIMARY KEY (indicator, source)
);
CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator);
`
