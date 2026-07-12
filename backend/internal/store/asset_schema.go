package store

import (
	"context"
	"fmt"
	"strings"
)

// ensureAssetCenteredSchema mirrors migration 025 for binary-only installs and
// repairs an older inline database without backfilling identity from a current
// IP projection. Keep its DDL in lockstep with
// siem/migrations/025_asset_centered_findings.sql.
func (db *DB) ensureAssetCenteredSchema() error {
	eventsOK, err := db.schemaTableExists("events")
	if err != nil {
		return err
	}
	devicesOK, err := db.schemaTableExists("devices")
	if err != nil {
		return err
	}
	// Custom migration directories used by tests may intentionally contain no
	// Vedetta schema. Do not manufacture child tables with dangling references.
	if !eventsOK || !devicesOK {
		return nil
	}

	eventColumns := []struct{ name, ddl string }{
		{"device_id", `ALTER TABLE events ADD COLUMN device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL`},
		{"identity_confidence", `ALTER TABLE events ADD COLUMN identity_confidence REAL NOT NULL DEFAULT 0.0`},
		{"identity_reason", `ALTER TABLE events ADD COLUMN identity_reason TEXT NOT NULL DEFAULT ''`},
		{"identity_evidence", `ALTER TABLE events ADD COLUMN identity_evidence TEXT NOT NULL DEFAULT '{}'`},
		{"origin", `ALTER TABLE events ADD COLUMN origin TEXT NOT NULL DEFAULT ''`},
		{"sensor_id", `ALTER TABLE events ADD COLUMN sensor_id TEXT`},
		{"outcome", `ALTER TABLE events ADD COLUMN outcome TEXT NOT NULL DEFAULT 'observed'`},
		{"disposition", `ALTER TABLE events ADD COLUMN disposition TEXT NOT NULL DEFAULT 'active'`},
		{"suppression_rule_id", `ALTER TABLE events ADD COLUMN suppression_rule_id TEXT NOT NULL DEFAULT ''`},
	}
	for _, col := range eventColumns {
		if err := db.ensureSchemaColumn("events", col.name, col.ddl); err != nil {
			return err
		}
	}
	if err := db.ensureOpenEventQueryType(); err != nil {
		return err
	}

	// The action table must exist before devices.merge_action_id gains its FK.
	if _, err := db.Exec(assetIdentityTablesDDL); err != nil {
		return fmt.Errorf("create asset identity tables: %w", err)
	}

	deviceColumns := []struct{ name, ddl string }{
		{"merged_into_device_id", `ALTER TABLE devices ADD COLUMN merged_into_device_id TEXT REFERENCES devices(device_id)`},
		{"merge_action_id", `ALTER TABLE devices ADD COLUMN merge_action_id TEXT REFERENCES device_identity_actions(action_id)`},
		{"merged_at", `ALTER TABLE devices ADD COLUMN merged_at TIMESTAMP`},
	}
	for _, col := range deviceColumns {
		if err := db.ensureSchemaColumn("devices", col.name, col.ddl); err != nil {
			return err
		}
	}

	if _, err := db.Exec(assetFindingsTablesDDL); err != nil {
		return fmt.Errorf("create findings tables: %w", err)
	}
	if err := db.ensureSchemaColumn("findings", "observed_count",
		`ALTER TABLE findings ADD COLUMN observed_count INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	if err := db.ensureSchemaColumn("finding_suppression_rules", "fallback_identity",
		`ALTER TABLE finding_suppression_rules ADD COLUMN fallback_identity TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	return db.ensureIdentityHMACKey()
}

// ensureOpenEventQueryType repairs databases created by migrations 001/009/019,
// whose events.query_type CHECK rejected valid DNS types such as SOA, NS, SVCB,
// and HTTPS. Migration 025 performs the same rebuild before creating event child
// tables; this runtime path also self-heals binary-only and partially upgraded
// installations.
func (db *DB) ensureOpenEventQueryType() error {
	var schema string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='events'`).Scan(&schema); err != nil {
		return fmt.Errorf("inspect events schema: %w", err)
	}
	compact := strings.Join(strings.Fields(strings.ToLower(schema)), " ")
	if !strings.Contains(compact, "query_type text check") {
		return nil
	}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve events schema connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable events rebuild foreign keys: %w", err)
	}
	rebuildErr := func() error {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin events query-type rebuild: %w", err)
		}
		defer tx.Rollback()
		statements := []string{
			`PRAGMA legacy_alter_table = ON`,
			`ALTER TABLE events RENAME TO events_old_query_type`,
			eventsOpenQueryTypeCreateDDL,
			eventsOpenQueryTypeCopyDDL,
			`DROP TABLE events_old_query_type`,
			`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
			`CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)`,
			`CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_hash)`,
			`CREATE INDEX IF NOT EXISTS idx_events_anomaly ON events(anomaly_score)`,
			`CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain)`,
			`CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, timestamp)`,
			`CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)`,
			`CREATE INDEX IF NOT EXISTS idx_events_ack ON events(acknowledged)`,
			`CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, timestamp DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_origin_time ON events(origin, timestamp DESC)`,
			`PRAGMA legacy_alter_table = OFF`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("rebuild open query-type events schema: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit events query-type rebuild: %w", err)
		}
		return nil
	}()
	// These pragmas are connection-local. Restore them even after a rollback
	// before releasing the connection back to database/sql's pool.
	_, legacyErr := conn.ExecContext(ctx, `PRAGMA legacy_alter_table = OFF`)
	_, foreignKeyErr := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`)
	if rebuildErr != nil {
		return rebuildErr
	}
	if legacyErr != nil {
		return fmt.Errorf("restore legacy_alter_table: %w", legacyErr)
	}
	if foreignKeyErr != nil {
		return fmt.Errorf("restore foreign keys: %w", foreignKeyErr)
	}
	return nil
}

const eventsOpenQueryTypeCreateDDL = `CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('dns_query', 'encrypted_dns_detected', 'nmap_discovery', 'firewall_log', 'anomaly')),
    source_hash TEXT NOT NULL,
    source_ip TEXT,
    server_ip TEXT DEFAULT '',
    domain TEXT,
    query_type TEXT,
    resolved_ip TEXT,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score REAL NOT NULL DEFAULT 0.0,
    tags TEXT DEFAULT '[]',
    geo TEXT,
    device_vendor TEXT,
    network_segment TEXT DEFAULT 'default',
    dns_source TEXT DEFAULT '',
    threat_desc TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ack_reason TEXT DEFAULT '',
    matched_indicator TEXT DEFAULT '',
    match_type TEXT DEFAULT '',
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    identity_confidence REAL NOT NULL DEFAULT 0.0,
    identity_reason TEXT NOT NULL DEFAULT '',
    identity_evidence TEXT NOT NULL DEFAULT '{}',
    origin TEXT NOT NULL DEFAULT '',
    sensor_id TEXT,
    outcome TEXT NOT NULL DEFAULT 'observed',
    disposition TEXT NOT NULL DEFAULT 'active',
    suppression_rule_id TEXT NOT NULL DEFAULT ''
)`

const eventsOpenQueryTypeCopyDDL = `INSERT INTO events (
    event_id, timestamp, event_type, source_hash, source_ip, server_ip, domain,
    query_type, resolved_ip, blocked, anomaly_score, tags, geo, device_vendor,
    network_segment, dns_source, threat_desc, metadata, acknowledged, ack_reason,
    matched_indicator, match_type, device_id, identity_confidence, identity_reason,
    identity_evidence, origin, sensor_id, outcome, disposition, suppression_rule_id
)
SELECT
    event_id, timestamp, event_type, source_hash, source_ip, server_ip, domain,
    query_type, resolved_ip, blocked, anomaly_score, tags, geo, device_vendor,
    network_segment, dns_source, threat_desc, metadata, acknowledged, ack_reason,
    matched_indicator, match_type, device_id, identity_confidence, identity_reason,
    identity_evidence, origin, sensor_id, outcome, disposition, suppression_rule_id
FROM events_old_query_type`

func (db *DB) schemaTableExists(table string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return n > 0, nil
}

func (db *DB) ensureSchemaColumn(table, column, ddl string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&n); err != nil {
		return fmt.Errorf("inspect column %s.%s: %w", table, column, err)
	}
	if n > 0 {
		return nil
	}
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

const assetIdentityTablesDDL = `
CREATE TABLE IF NOT EXISTS device_address_history (
    binding_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    address_type TEXT NOT NULL,
    address_value TEXT NOT NULL,
    segment TEXT NOT NULL DEFAULT 'default',
    sensor_id TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP,
    evidence_source TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_address_lookup
    ON device_address_history(address_type, address_value, segment, sensor_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_device_address_device_time
    ON device_address_history(device_id, valid_from DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_address_current_owner
    ON device_address_history(address_type, address_value, segment, sensor_id)
    WHERE valid_until IS NULL;

CREATE TABLE IF NOT EXISTS device_identity_evidence (
    evidence_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    evidence_type TEXT NOT NULL,
    value_hmac TEXT NOT NULL,
    value_display TEXT NOT NULL DEFAULT '',
    segment TEXT NOT NULL DEFAULT 'default',
    sensor_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP,
    operator_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_id, evidence_type, value_hmac, segment, sensor_id)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_lookup
    ON device_identity_evidence(evidence_type, value_hmac, segment, sensor_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_device
    ON device_identity_evidence(device_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS device_identity_actions (
    action_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    source_device_id TEXT REFERENCES devices(device_id),
    target_device_id TEXT REFERENCES devices(device_id),
    evidence_id TEXT REFERENCES device_identity_evidence(evidence_id),
    actor TEXT NOT NULL DEFAULT 'system',
    reason TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL,
    undone_by_action_id TEXT REFERENCES device_identity_actions(action_id)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_actions_source
    ON device_identity_actions(source_device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_identity_actions_target
    ON device_identity_actions(target_device_id, created_at DESC);
`

const assetFindingsTablesDDL = `
CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_origin_time ON events(origin, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_devices_merged_into ON devices(merged_into_device_id);

CREATE TABLE IF NOT EXISTS event_detection_evidence (
    evidence_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    detector TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    threat_source TEXT NOT NULL DEFAULT '',
    source_confidence REAL NOT NULL DEFAULT 0,
    feed_freshness TIMESTAMP,
    feed_stale BOOLEAN NOT NULL DEFAULT FALSE,
    rationale TEXT NOT NULL DEFAULT '',
    score_contribution REAL NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL DEFAULT 'observed',
    device_context TEXT NOT NULL DEFAULT '{}',
    details TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_detection_evidence_event
    ON event_detection_evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_event_detection_evidence_detector_observable
    ON event_detection_evidence(detector, observable_type, observable_value);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    finding_key TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    previous_finding_id TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    fallback_identity TEXT NOT NULL DEFAULT '',
    detector TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    primary_observable_type TEXT NOT NULL,
    primary_observable TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    maximum_score REAL NOT NULL,
    current_priority TEXT NOT NULL,
    allowed_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    observed_count INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    reason TEXT NOT NULL DEFAULT '',
    recommended_action TEXT NOT NULL DEFAULT '',
    last_event_id TEXT REFERENCES events(event_id) ON DELETE SET NULL,
    evidence TEXT NOT NULL DEFAULT '{}',
    disposition TEXT NOT NULL DEFAULT 'active',
    suppression_rule_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP,
    resolution_reason TEXT NOT NULL DEFAULT '',
    UNIQUE(finding_key, generation)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_active_key
    ON findings(finding_key) WHERE status <> 'resolved';
CREATE INDEX IF NOT EXISTS idx_findings_status_priority
    ON findings(status, current_priority, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS finding_events (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    linked_at TIMESTAMP NOT NULL,
    PRIMARY KEY(finding_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_events_event ON finding_events(event_id);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES event_detection_evidence(evidence_id) ON DELETE CASCADE,
    linked_at TIMESTAMP NOT NULL,
    PRIMARY KEY(finding_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence ON finding_evidence(evidence_id);

CREATE TABLE IF NOT EXISTS finding_status_history (
    history_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    from_status TEXT NOT NULL DEFAULT '',
    to_status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT 'system',
    changed_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_status_history_finding
    ON finding_status_history(finding_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS finding_suppression_rules (
    rule_id TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    detector TEXT NOT NULL DEFAULT '',
    observable_type TEXT NOT NULL DEFAULT '',
    observable_value TEXT NOT NULL DEFAULT '',
    device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    fallback_identity TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_finding_suppression_active
    ON finding_suppression_rules(active, detector, observable_type);

CREATE TABLE IF NOT EXISTS finding_suppression_history (
    history_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES finding_suppression_rules(rule_id),
    finding_id TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT 'system',
    changed_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_suppression_history_rule
    ON finding_suppression_history(rule_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS collection_source_health (
    source_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    last_attempt TIMESTAMP,
    last_success TIMESTAMP,
    item_count INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collection_source_health_status
    ON collection_source_health(status, updated_at DESC);
`
