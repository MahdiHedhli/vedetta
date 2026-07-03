package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
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
		"../../siem/migrations",
	}
	if _, sourceFile, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(sourceFile), "..", "..", "siem", "migrations"))
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

	// Compat shim: earlier dev builds added the 017 columns at runtime via
	// pragma probes instead of a migration file. If this database already has
	// any of them, bring it fully to the 017 state and record the migration as
	// applied so the plain ALTERs in 017 don't fail with "duplicate column name".
	db.ensureSensorActionability()

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

// sensorActionabilityMigration is the migration file that adds
// events.server_ip and devices.services.
const sensorActionabilityMigration = "017_sensor_actionability.sql"

// ensureSensorActionability handles databases that were touched by earlier
// dev builds which added the 017 columns via runtime ALTER probes rather than
// a migration file. If any of those columns already exist, the remaining ones
// are added and 017 is recorded as applied, so the migration file (whose plain
// ALTER statements would otherwise fail) is skipped. On a fresh or normally
// migrated database (no such columns yet) this is a no-op.
func (db *DB) ensureSensorActionability() {
	hasServerIP := db.columnExists("events", "server_ip")
	hasServices := db.columnExists("devices", "services")
	if !hasServerIP && !hasServices {
		return // fresh or pre-017 database: the migration file handles it
	}
	if !hasServerIP {
		db.Exec(`ALTER TABLE events ADD COLUMN server_ip TEXT DEFAULT ''`)
	}
	if !hasServices {
		db.Exec(`ALTER TABLE devices ADD COLUMN services TEXT DEFAULT '[]'`)
	}
	db.Exec(`INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
		sensorActionabilityMigration, time.Now().UTC())
}

// columnExists reports whether the given table has the given column.
func (db *DB) columnExists(table, column string) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		return false
	}
	return n > 0
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
    source_ip      TEXT,
    server_ip      TEXT DEFAULT '',
    domain         TEXT,
    query_type     TEXT,
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',
    geo            TEXT,
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default',
    dns_source     TEXT DEFAULT '',
    threat_desc    TEXT DEFAULT '',
    metadata       TEXT DEFAULT '{}',
    acknowledged   BOOLEAN NOT NULL DEFAULT FALSE,
    ack_reason     TEXT DEFAULT ''
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
    segment      TEXT DEFAULT 'default',
    device_type  TEXT DEFAULT '',
    os_family    TEXT DEFAULT '',
    os_version   TEXT DEFAULT '',
    model        TEXT DEFAULT '',
    discovery_method TEXT DEFAULT 'nmap_active',
    fingerprint_confidence REAL NOT NULL DEFAULT 0.0,
    custom_name  TEXT DEFAULT '',
    notes        TEXT DEFAULT '',
    eol_risk     INTEGER DEFAULT 0,
    eol_model    TEXT DEFAULT '',
    risk_category TEXT DEFAULT '',
    risk_model   TEXT DEFAULT '',
    risk_reasons TEXT DEFAULT '[]',
    services     TEXT DEFAULT '[]'
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
    last_scan   TIMESTAMP,
    dns_capture BOOLEAN NOT NULL DEFAULT FALSE,
    dns_interface TEXT DEFAULT ''
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
    is_primary  BOOLEAN NOT NULL DEFAULT FALSE,
    interfaces  TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS api_tokens (
    token_id     TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL DEFAULT 'sensor',
    sensor_id    TEXT,
    label        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used    TEXT NOT NULL DEFAULT (datetime('now')),
    revoked      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id)
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_sensor ON api_tokens(sensor_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked ON api_tokens(revoked);

CREATE TABLE IF NOT EXISTS suppression_rules (
    rule_id     TEXT PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain      TEXT DEFAULT '',
    source_ip   TEXT DEFAULT '',
    tags        TEXT DEFAULT '[]',
    reason      TEXT DEFAULT '',
    active      BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS whitelist_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    domain_pattern TEXT DEFAULT '',
    source_ip_pattern TEXT DEFAULT '',
    tag_match TEXT DEFAULT '',
    category TEXT DEFAULT 'custom',
    is_default BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_whitelist_enabled ON whitelist_rules (enabled);

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
