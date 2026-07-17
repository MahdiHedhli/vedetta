package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite connection.
type DB struct {
	*sql.DB
	identityKeyMu      sync.RWMutex
	identityKey        []byte
	corpusProjectionMu sync.RWMutex
}

// Open opens (or creates) the SQLite database and runs migrations.
func Open(dbPath string) (*DB, error) {
	return openWith(dbPath, sql.Open)
}

type sqlOpenFunc func(driverName, dataSourceName string) (*sql.DB, error)

func openWith(dbPath string, opener sqlOpenFunc) (*DB, error) {
	if dbPath == "" {
		dbPath = "/data/vedetta.db"
	}

	db, err := opener("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", errors.Join(err, db.Close()))
	}

	store := &DB{DB: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", errors.Join(err, db.Close()))
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

	if err := db.applyFileMigrations(context.Background(), migrationDir, sqlFiles); err != nil {
		return err
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

	// One active sensor token per sensor (migration 024, beta-gate B1a). Ensure it
	// on every Open so an older DB that already accumulated duplicate active tokens
	// self-heals even without the migration files present.
	db.ensureSingleActiveSensorToken()

	// Spec 007 is additive, but the binary is also distributed without the SQL
	// migration directory. Keep the runtime and inline schemas at exact parity,
	// and self-heal an older database whose migration files were unavailable.
	if err := db.ensureAssetCenteredSchema(); err != nil {
		return fmt.Errorf("ensure asset-centered schema: %w", err)
	}
	if err := db.ensureSensorLifecycleSchema(); err != nil {
		return fmt.Errorf("ensure sensor lifecycle schema: %w", err)
	}
	if err := db.ensureSensorReportTimeSchema(); err != nil {
		return err
	}

	return nil
}

// applyFileMigrations runs the filesystem migration chain on one reserved
// connection. SQLite PRAGMAs are connection-local, and foreign_keys cannot be
// changed from inside the transaction used for each migration file. Keep that
// connection FK-relaxed only for the migration pass, validate the resulting
// graph, restore both migration-sensitive PRAGMAs on every exit, and release the
// connection before migrate continues with db-level runtime ensures. Releasing
// here is essential for :memory: databases: a db-level query while this connection
// is reserved would make database/sql open an independent empty SQLite database.
func (db *DB) applyFileMigrations(ctx context.Context, migrationDir string, sqlFiles []string) (retErr error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration connection: %w", err)
	}
	defer func() {
		// Do not use ctx for cleanup: a cancelled caller must not return a pooled
		// connection with migration PRAGMAs still relaxed.
		cleanupCtx := context.Background()
		var cleanupErr error
		if _, err := conn.ExecContext(cleanupCtx, `PRAGMA legacy_alter_table = OFF`); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("restore legacy_alter_table after migration: %w", err))
		}
		if _, err := conn.ExecContext(cleanupCtx, `PRAGMA foreign_keys = ON`); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("restore foreign keys after migration: %w", err))
		}
		if err := conn.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("release migration connection: %w", err))
		}
		retErr = errors.Join(retErr, cleanupErr)
	}()

	// A prior failed schema rebuild could have left a pooled connection with this
	// enabled. Start from the normal default as well as restoring it on return.
	if _, err := conn.ExecContext(ctx, `PRAGMA legacy_alter_table = OFF`); err != nil {
		return fmt.Errorf("reset legacy_alter_table before migration: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("relax foreign keys for migration: %w", err)
	}

	for _, filename := range sqlFiles {
		var applied int
		if err := conn.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE id = ?", filename).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", filename, err)
		}
		if applied > 0 {
			continue
		}

		sqlBytes, err := os.ReadFile(filepath.Join(migrationDir, filename))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		if err := applyMigrationFile(ctx, conn, filename, string(sqlBytes)); err != nil {
			return err
		}
		log.Printf("Migration applied: %s", filename)
	}

	violations, err := migrationForeignKeyViolations(ctx, conn)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return fmt.Errorf("post-migration foreign_key_check found %d violation(s): %s",
			len(violations), strings.Join(violations, ", "))
	}
	return nil
}

func applyMigrationFile(ctx context.Context, conn *sql.Conn, filename, script string) (retErr error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for %s: %w", filename, err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			retErr = errors.Join(retErr, fmt.Errorf("rollback migration %s: %w", filename, err))
		}
	}()
	if filename == "028_asset_identity_strength_history.sql" {
		if err := validateAssetTemporalParents(ctx, tx); err != nil {
			return fmt.Errorf("preflight %s: %w", filename, err)
		}
	}

	// Execute statement-by-statement. Per-statement tolerance is essential: an
	// already-applied ALTER must not skip later statements in the same file.
	for _, stmt := range splitSQLStatements(script) {
		if isNoOpSQL(stmt) {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			if isAlreadyAppliedErr(err) {
				log.Printf("Migration %s: statement already applied (%v) — skipping, continuing with the rest", filename, err)
				continue
			}
			return fmt.Errorf("execute migration %s: %w", filename, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
		filename, time.Now().UTC()); err != nil {
		return fmt.Errorf("record migration %s: %w", filename, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", filename, err)
	}
	return nil
}

func migrationForeignKeyViolations(ctx context.Context, conn *sql.Conn) (violations []string, retErr error) {
	rows, err := conn.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return nil, fmt.Errorf("foreign_key_check: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close foreign_key_check rows: %w", err))
		}
	}()
	return scanForeignKeyViolations(rows)
}

// ensureSingleActiveSensorToken collapses any duplicate active sensor tokens
// (keeping the most recently inserted one per sensor) and enforces the
// one-active-token-per-sensor invariant with a partial unique index. Idempotent
// and safe to run on every Open. The dedup MUST precede the index: a partial
// UNIQUE index cannot be created while the table already violates it.
func (db *DB) ensureSingleActiveSensorToken() {
	if _, err := db.Exec(`UPDATE api_tokens SET revoked = 1
		WHERE scope = 'sensor' AND revoked = 0 AND rowid NOT IN (
			SELECT MAX(rowid) FROM api_tokens
			WHERE scope = 'sensor' AND revoked = 0 GROUP BY sensor_id)`); err != nil {
		log.Printf("ensureSingleActiveSensorToken: dedup of active sensor tokens failed: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS ux_api_tokens_active_sensor
		ON api_tokens (sensor_id) WHERE scope = 'sensor' AND revoked = 0`); err != nil {
		log.Printf("ensureSingleActiveSensorToken: creating the unique sensor-token index failed: %v", err)
	}
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
	// The inline path returns before the migrate() safety-net runs, so enforce the
	// one-active-token-per-sensor invariant (migration 024) here too.
	db.ensureSingleActiveSensorToken()
	if err := db.ensureAssetCenteredSchema(); err != nil {
		return fmt.Errorf("ensure inline asset-centered schema: %w", err)
	}
	if err := db.ensureSensorLifecycleSchema(); err != nil {
		return fmt.Errorf("ensure inline sensor lifecycle schema: %w", err)
	}
	if err := db.ensureSensorReportTimeSchema(); err != nil {
		return err
	}
	// Record the schema head so a successful inline build reports the same migration
	// head as the file-migration path. The readiness probe (GET /readyz) requires
	// schema_migrations' MAX(id) to equal ExpectedSchemaMigration; without this an
	// inline-built database would read as "behind" forever. INSERT OR IGNORE keeps
	// re-opens idempotent, and stamping the latest id also means a later open WITH the
	// migration files present skips re-applying it.
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
		ExpectedSchemaMigration, time.Now().UTC()); err != nil {
		return fmt.Errorf("record inline schema head: %w", err)
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
