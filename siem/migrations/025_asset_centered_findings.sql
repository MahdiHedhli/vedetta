-- Spec 007: Asset-Centered Findings and Detection Fusion.
--
-- This migration is forward-only and data-preserving. Existing events remain
-- unresolved; current device/IP projections are not used to guess historical
-- ownership. The events table is rebuilt once only to remove its obsolete
-- query_type enum CHECK; all rows and indexes are copied forward.

-- Event identity, ingestion provenance, and server-side suppression disposition.
ALTER TABLE events ADD COLUMN device_id TEXT REFERENCES devices(device_id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN identity_confidence REAL NOT NULL DEFAULT 0.0;
ALTER TABLE events ADD COLUMN identity_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN identity_evidence TEXT NOT NULL DEFAULT '{}';
ALTER TABLE events ADD COLUMN origin TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN sensor_id TEXT;
ALTER TABLE events ADD COLUMN outcome TEXT NOT NULL DEFAULT 'observed';
ALTER TABLE events ADD COLUMN disposition TEXT NOT NULL DEFAULT 'active';
ALTER TABLE events ADD COLUMN suppression_rule_id TEXT NOT NULL DEFAULT '';

-- Migrations 001/009/019 constrained query_type to a short legacy enum. Real
-- DNS carries additional standard types (SOA, NS, SPF, HTTPS, SVCB, and more),
-- so rebuild the table without that CHECK while preserving every existing and
-- newly-added column. This runs before findings introduce event foreign keys.
PRAGMA legacy_alter_table = ON;
ALTER TABLE events RENAME TO events_old_025;
CREATE TABLE events (
    event_id            TEXT PRIMARY KEY,
    timestamp           TIMESTAMP NOT NULL,
    event_type          TEXT NOT NULL CHECK (event_type IN ('dns_query', 'encrypted_dns_detected', 'nmap_discovery', 'firewall_log', 'anomaly')),
    source_hash         TEXT NOT NULL,
    source_ip           TEXT,
    server_ip           TEXT DEFAULT '',
    domain              TEXT,
    query_type          TEXT,
    resolved_ip         TEXT,
    blocked             BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score       REAL NOT NULL DEFAULT 0.0,
    tags                TEXT DEFAULT '[]',
    geo                 TEXT,
    device_vendor       TEXT,
    network_segment     TEXT DEFAULT 'default',
    dns_source          TEXT DEFAULT '',
    threat_desc         TEXT DEFAULT '',
    metadata            TEXT DEFAULT '{}',
    acknowledged        BOOLEAN NOT NULL DEFAULT FALSE,
    ack_reason          TEXT DEFAULT '',
    matched_indicator   TEXT DEFAULT '',
    match_type          TEXT DEFAULT '',
    device_id           TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    identity_confidence REAL NOT NULL DEFAULT 0.0,
    identity_reason     TEXT NOT NULL DEFAULT '',
    identity_evidence   TEXT NOT NULL DEFAULT '{}',
    origin              TEXT NOT NULL DEFAULT '',
    sensor_id           TEXT,
    outcome             TEXT NOT NULL DEFAULT 'observed',
    disposition         TEXT NOT NULL DEFAULT 'active',
    suppression_rule_id TEXT NOT NULL DEFAULT ''
);
INSERT INTO events (
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
FROM events_old_025;
DROP TABLE events_old_025;
PRAGMA legacy_alter_table = OFF;

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_hash);
CREATE INDEX IF NOT EXISTS idx_events_anomaly ON events(anomaly_score);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_ack ON events(acknowledged);
CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_origin_time ON events(origin, timestamp DESC);

-- Append-only address ownership intervals. valid_until is exclusive; NULL means
-- the binding is current. sensor_id is part of an observation's network context.
CREATE TABLE IF NOT EXISTS device_address_history (
    binding_id      TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(device_id),
    address_type    TEXT NOT NULL,
    address_value   TEXT NOT NULL,
    segment         TEXT NOT NULL DEFAULT 'default',
    sensor_id       TEXT NOT NULL DEFAULT '',
    first_seen      TIMESTAMP NOT NULL,
    last_seen       TIMESTAMP NOT NULL,
    valid_from      TIMESTAMP NOT NULL,
    valid_until     TIMESTAMP,
    evidence_source TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.0,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_address_lookup
    ON device_address_history(address_type, address_value, segment, sensor_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_device_address_device_time
    ON device_address_history(device_id, valid_from DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_address_current_owner
    ON device_address_history(address_type, address_value, segment, sensor_id)
    WHERE valid_until IS NULL;

-- Many-to-many identity evidence. value_hmac is a local keyed HMAC; enumerable
-- identifiers such as DHCP client IDs and SSDP UUIDs are never stored raw here.
-- value_display is restricted by the store to non-sensitive allowlisted context.
CREATE TABLE IF NOT EXISTS device_identity_evidence (
    evidence_id       TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL REFERENCES devices(device_id),
    evidence_type     TEXT NOT NULL,
    value_hmac        TEXT NOT NULL,
    value_display     TEXT NOT NULL DEFAULT '',
    segment           TEXT NOT NULL DEFAULT 'default',
    sensor_id         TEXT NOT NULL DEFAULT '',
    source            TEXT NOT NULL DEFAULT '',
    confidence        REAL NOT NULL DEFAULT 0.0,
    first_seen        TIMESTAMP NOT NULL,
    last_seen         TIMESTAMP NOT NULL,
    valid_from        TIMESTAMP NOT NULL,
    valid_until       TIMESTAMP,
    operator_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    metadata          TEXT NOT NULL DEFAULT '{}',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_id, evidence_type, value_hmac, segment, sensor_id)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_lookup
    ON device_identity_evidence(evidence_type, value_hmac, segment, sensor_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_device
    ON device_identity_evidence(device_id, last_seen DESC);

-- Operator and automatic identity actions. Merge is a reversible redirect, not
-- a row deletion. A split action points back to the merge through metadata and
-- undone_by_action_id, preserving the full audit chain.
CREATE TABLE IF NOT EXISTS device_identity_actions (
    action_id           TEXT PRIMARY KEY,
    action_type         TEXT NOT NULL,
    source_device_id    TEXT REFERENCES devices(device_id),
    target_device_id    TEXT REFERENCES devices(device_id),
    evidence_id         TEXT REFERENCES device_identity_evidence(evidence_id),
    actor               TEXT NOT NULL DEFAULT 'system',
    reason              TEXT NOT NULL DEFAULT '',
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          TIMESTAMP NOT NULL,
    undone_by_action_id TEXT REFERENCES device_identity_actions(action_id)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_actions_source
    ON device_identity_actions(source_device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_identity_actions_target
    ON device_identity_actions(target_device_id, created_at DESC);

ALTER TABLE devices ADD COLUMN merged_into_device_id TEXT REFERENCES devices(device_id);
ALTER TABLE devices ADD COLUMN merge_action_id TEXT REFERENCES device_identity_actions(action_id);
ALTER TABLE devices ADD COLUMN merged_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_devices_merged_into ON devices(merged_into_device_id);

-- Typed immutable detector evidence attached to a persisted raw event.
CREATE TABLE IF NOT EXISTS event_detection_evidence (
    evidence_id        TEXT PRIMARY KEY,
    event_id           TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    detector           TEXT NOT NULL,
    category           TEXT NOT NULL DEFAULT '',
    observable_type    TEXT NOT NULL,
    observable_value   TEXT NOT NULL,
    threat_source      TEXT NOT NULL DEFAULT '',
    source_confidence  REAL NOT NULL DEFAULT 0,
    feed_freshness     TIMESTAMP,
    feed_stale         BOOLEAN NOT NULL DEFAULT FALSE,
    rationale          TEXT NOT NULL DEFAULT '',
    score_contribution REAL NOT NULL DEFAULT 0,
    outcome            TEXT NOT NULL DEFAULT 'observed',
    device_context     TEXT NOT NULL DEFAULT '{}',
    details            TEXT NOT NULL DEFAULT '{}',
    created_at         TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_detection_evidence_event
    ON event_detection_evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_event_detection_evidence_detector_observable
    ON event_detection_evidence(detector, observable_type, observable_value);

-- Durable finding generations. A partial unique index permits only one active
-- (open or investigating) finding for a stable key under concurrent ingestion.
CREATE TABLE IF NOT EXISTS findings (
    finding_id              TEXT PRIMARY KEY,
    finding_key             TEXT NOT NULL,
    generation              INTEGER NOT NULL DEFAULT 1,
    previous_finding_id     TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
    device_id               TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    fallback_identity       TEXT NOT NULL DEFAULT '',
    detector                TEXT NOT NULL,
    category                TEXT NOT NULL DEFAULT '',
    primary_observable_type TEXT NOT NULL,
    primary_observable      TEXT NOT NULL,
    first_seen              TIMESTAMP NOT NULL,
    last_seen               TIMESTAMP NOT NULL,
    occurrence_count        INTEGER NOT NULL DEFAULT 1,
    maximum_score           REAL NOT NULL,
    current_priority        TEXT NOT NULL,
    allowed_count           INTEGER NOT NULL DEFAULT 0,
    blocked_count           INTEGER NOT NULL DEFAULT 0,
    observed_count          INTEGER NOT NULL DEFAULT 0,
    outcome                 TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'open',
    reason                  TEXT NOT NULL DEFAULT '',
    recommended_action      TEXT NOT NULL DEFAULT '',
    last_event_id           TEXT REFERENCES events(event_id) ON DELETE SET NULL,
    evidence                TEXT NOT NULL DEFAULT '{}',
    disposition             TEXT NOT NULL DEFAULT 'active',
    suppression_rule_id     TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMP NOT NULL,
    updated_at              TIMESTAMP NOT NULL,
    resolved_at             TIMESTAMP,
    resolution_reason       TEXT NOT NULL DEFAULT '',
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
    event_id   TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    linked_at  TIMESTAMP NOT NULL,
    PRIMARY KEY(finding_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_events_event ON finding_events(event_id);

-- Exact evidence membership for each finding. An event may support several
-- independent findings, so joining by event_id alone would cross-contaminate
-- their explanations.
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES event_detection_evidence(evidence_id) ON DELETE CASCADE,
    linked_at TIMESTAMP NOT NULL,
    PRIMARY KEY(finding_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence ON finding_evidence(evidence_id);

CREATE TABLE IF NOT EXISTS finding_status_history (
    history_id  TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    from_status TEXT NOT NULL DEFAULT '',
    to_status   TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT 'system',
    changed_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_status_history_finding
    ON finding_status_history(finding_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS finding_suppression_rules (
    rule_id          TEXT PRIMARY KEY,
    created_at       TIMESTAMP NOT NULL,
    updated_at       TIMESTAMP NOT NULL,
    detector         TEXT NOT NULL DEFAULT '',
    observable_type  TEXT NOT NULL DEFAULT '',
    observable_value TEXT NOT NULL DEFAULT '',
    device_id        TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    fallback_identity TEXT NOT NULL DEFAULT '',
    reason           TEXT NOT NULL DEFAULT '',
    active           BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_finding_suppression_active
    ON finding_suppression_rules(active, detector, observable_type);

-- Suppression is an operator policy, separate from incident resolution. Rules
-- are deactivated rather than deleted and every transition remains auditable.
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
    source_id    TEXT PRIMARY KEY,
    source_type  TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL,
    last_attempt TIMESTAMP,
    last_success TIMESTAMP,
    item_count   INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collection_source_health_status
    ON collection_source_health(status, updated_at DESC);
