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
	candidates := []string{}
	// Explicit override (used by tests to exercise the real migration files, and
	// by operators with a non-standard layout).
	if envDir := strings.TrimSpace(os.Getenv("VEDETTA_MIGRATIONS_DIR")); envDir != "" {
		candidates = append(candidates, envDir)
	}
	candidates = append(candidates,
		"/app/siem/migrations",
		"siem/migrations",
		"../siem/migrations",
		"../../siem/migrations",
	)
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

		// Execute the migration statement-by-statement. Per-STATEMENT tolerance
		// (rather than executing the whole file at once) is essential: an
		// already-applied statement — e.g. an ALTER for a column another migration
		// already added — must NOT abort the statements that FOLLOW it in the same
		// file. Whole-file exec stops at the first error, so a redundant leading
		// ALTER used to silently skip a later CREATE TABLE while the migration was
		// still recorded as applied, leaving the schema incomplete (beta-gate B3:
		// suppression_rules never created). Any UNEXPECTED error still rolls back.
		for _, stmt := range splitSQLStatements(string(sqlBytes)) {
			if isNoOpSQL(stmt) {
				continue
			}
			if _, execErr := tx.Exec(stmt); execErr != nil {
				if isAlreadyAppliedErr(execErr) {
					log.Printf("Migration %s: statement already applied (%v) — skipping, continuing with the rest", filename, execErr)
					continue
				}
				tx.Rollback()
				return fmt.Errorf("execute migration %s: %w", filename, execErr)
			}
		}

		// Record as applied. Use OR IGNORE to be extra safe if the record was partially created.
		if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
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

	// Ensure actionability columns for richer sensor data (post initial schema).
	// server_ip: DNS server / destination side from sensor responses (user-requested source/dest visibility).
	// services: for passive host identification (model/services/discovery_source from mDNS etc.).
	// risk_* : from migration 016.
	// All use the same portable pragma + plain ALTER pattern for older sqlite3 CLI compat.
	// Run at every Open so List/loads work immediately after restart (hot-paths in InsertEvents/UpsertDevice also ensure on first write).
	// These are the safety net for old DBs; migrations (001 + 016) own the declared schema for new DBs.
	var serverIPColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'server_ip'`).Scan(&serverIPColCount); err == nil && serverIPColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN server_ip TEXT DEFAULT ''`)
	}
	// Match-provenance columns (GHSA-hx86, migration 022): safety net for old DBs.
	var matchedIndicatorColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'matched_indicator'`).Scan(&matchedIndicatorColCount); err == nil && matchedIndicatorColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN matched_indicator TEXT DEFAULT ''`)
	}
	var matchTypeColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'match_type'`).Scan(&matchTypeColCount); err == nil && matchTypeColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN match_type TEXT DEFAULT ''`)
	}
	var servicesColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'services'`).Scan(&servicesColCount); err == nil && servicesColCount == 0 {
		db.Exec(`ALTER TABLE devices ADD COLUMN services TEXT DEFAULT '[]'`)
	}
	// Guarded ensures for the 016 risk columns as well (migrations own them, but runtime belt-and-suspenders for old DBs).
	var riskCategoryColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'risk_category'`).Scan(&riskCategoryColCount); err == nil && riskCategoryColCount == 0 {
		db.Exec(`ALTER TABLE devices ADD COLUMN risk_category TEXT DEFAULT ''`)
	}
	var riskModelColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'risk_model'`).Scan(&riskModelColCount); err == nil && riskModelColCount == 0 {
		db.Exec(`ALTER TABLE devices ADD COLUMN risk_model TEXT DEFAULT ''`)
	}
	var riskReasonsColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'risk_reasons'`).Scan(&riskReasonsColCount); err == nil && riskReasonsColCount == 0 {
		db.Exec(`ALTER TABLE devices ADD COLUMN risk_reasons TEXT DEFAULT ''`)
	}

	// suppression_rules is declared only in migration 012. A redundant leading
	// ALTER in that file used to abort it before this CREATE ran on fresh DBs, so
	// the table could be missing while 012 was recorded as applied — leaving
	// GET /api/v1/suppression returning 500 "no such table". This idempotent ensure
	// guarantees the table on every Open and self-heals already-broken DBs (B3).
	db.Exec(suppressionRulesDDL)

	// settings is declared only in migration 023 (issue #37). Runtime-ensure it on
	// every Open so the telemetry opt-in setting store works immediately, and so an
	// older DB that predates 023 self-heals without waiting for the migration pass.
	db.Exec(settingsDDL)

	return nil
}

// settingsDDL is the runtime-ensure definition of the generic key/value settings
// table; keep it in sync with migration 023 and the inline fallback below.
const settingsDDL = `CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

// suppressionRulesDDL is the runtime-ensure definition of the suppression_rules
// table; keep it in sync with migration 012 and the inline fallback below.
const suppressionRulesDDL = `CREATE TABLE IF NOT EXISTS suppression_rules (
    rule_id     TEXT PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain      TEXT DEFAULT '',
    source_ip   TEXT DEFAULT '',
    tags        TEXT DEFAULT '[]',
    reason      TEXT DEFAULT '',
    active      BOOLEAN DEFAULT TRUE
)`

// splitSQLStatements splits a migration script into individual statements on
// top-level semicolons, correctly ignoring semicolons inside single-quoted
// string literals (” escape) and -- line / /* */ block comments. Migrations run
// statement-by-statement so an already-applied statement does not abort the rest
// of the file (see migrate()).
func splitSQLStatements(script string) []string {
	var (
		stmts []string
		b     strings.Builder
		runes = []rune(script)
		n     = len(runes)
		inStr bool
	)
	for i := 0; i < n; i++ {
		c := runes[i]
		switch {
		case inStr:
			b.WriteRune(c)
			if c == '\'' {
				if i+1 < n && runes[i+1] == '\'' { // '' escape stays in the string
					b.WriteRune(runes[i+1])
					i++
				} else {
					inStr = false
				}
			}
		case c == '\'':
			inStr = true
			b.WriteRune(c)
		case c == '-' && i+1 < n && runes[i+1] == '-': // -- line comment
			for i < n && runes[i] != '\n' {
				b.WriteRune(runes[i])
				i++
			}
			if i < n {
				b.WriteRune(runes[i]) // keep the newline
			}
		case c == '/' && i+1 < n && runes[i+1] == '*': // /* block comment */
			b.WriteString("/*")
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				b.WriteRune(runes[i])
				i++
			}
			if i+1 < n {
				b.WriteString("*/")
				i++
			}
		case c == ';':
			if s := strings.TrimSpace(b.String()); s != "" {
				stmts = append(stmts, s)
			}
			b.Reset()
		default:
			b.WriteRune(c)
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

// isNoOpSQL reports whether a fragment has no executable SQL — every line is
// blank or an -- comment (e.g. a trailing comment after the final ';').
func isNoOpSQL(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		return false
	}
	return true
}

// isAlreadyAppliedErr reports whether a statement failed only because its schema
// change is already present (idempotent re-run / partial prior run).
func isAlreadyAppliedErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "duplicate column name") ||
		strings.Contains(s, "already exists") ||
		strings.Contains(s, "duplicate table")
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
    ack_reason     TEXT DEFAULT '',
    matched_indicator TEXT DEFAULT '',
    match_type     TEXT DEFAULT ''
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
    services     TEXT DEFAULT '[]',
    risk_category TEXT DEFAULT '',
    risk_model    TEXT DEFAULT '',
    risk_reasons  TEXT DEFAULT '',
    eol_risk  INTEGER DEFAULT 0,
    eol_model TEXT DEFAULT '',
    display_name  TEXT DEFAULT '',
    friendly_name TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_devices_mac  ON devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_last ON devices (last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_ip_segment ON devices (ip_address, segment);

-- Spec 004 (migration 018): per-field provenance, identity aliases, multi-network attachments.
CREATE TABLE IF NOT EXISTS device_signals (
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    field          TEXT NOT NULL,
    value          TEXT NOT NULL,
    source         TEXT NOT NULL,
    confidence     REAL NOT NULL DEFAULT 0.0,
    first_observed TIMESTAMP NOT NULL,
    last_observed  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, field, source)
);
CREATE INDEX IF NOT EXISTS idx_device_signals_device ON device_signals(device_id);

CREATE TABLE IF NOT EXISTS device_identities (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    id_type    TEXT NOT NULL,
    id_value   TEXT NOT NULL,
    segment    TEXT NOT NULL DEFAULT 'default',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (id_type, id_value, segment)
);
CREATE INDEX IF NOT EXISTS idx_device_identities_device ON device_identities(device_id);

CREATE TABLE IF NOT EXISTS device_networks (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    segment    TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    sensor_id  TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, segment)
);
CREATE INDEX IF NOT EXISTS idx_device_networks_segment ON device_networks(segment);

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
    scope        TEXT NOT NULL DEFAULT 'sensor' CHECK(scope IN ('sensor', 'admin', 'ingest', 'read')),
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
CREATE INDEX IF NOT EXISTS idx_whitelist_category ON whitelist_rules (category);

CREATE TABLE IF NOT EXISTS suppression_rules (
    rule_id     TEXT PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain      TEXT DEFAULT '',
    source_ip   TEXT DEFAULT '',
    tags        TEXT DEFAULT '[]',
    reason      TEXT DEFAULT '',
    active      BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
