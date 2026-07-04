-- Add encrypted_dns_detected to the event_type CHECK constraint.
-- SQLite doesn't support altering CHECK constraints, so we recreate the table.
--
-- Fresh-install correctness (VED-015): 001_init.sql now ships the FINAL 19-column
-- events schema (source_ip, server_ip, metadata, acknowledged, ack_reason baked
-- in). The original version of this migration recreated events with only the
-- 14-column intermediate shape and copied rows with `INSERT ... SELECT * FROM
-- events_old`, which fails on a fresh DB with "table events has 14 columns but
-- 19 values were supplied". This version instead:
--   * recreates events with the EXPLICIT final 19-column schema (matching 001),
--     changing only the event_type CHECK to add 'encrypted_dns_detected';
--   * copies rows with an EXPLICIT shared column list (the 14 columns that exist
--     in every historical events shape), so it works whether events_old has the
--     14-column intermediate shape (legacy incremental path) or the 19-column
--     final shape (fresh install). The extra columns take their declared DEFAULTs.
--
-- DBs that already ran the original incremental 008..016 have 009 recorded in
-- schema_migrations and will not re-run this. For them, 011/012 already added
-- source_ip/metadata/acknowledged/ack_reason; for fresh 001-final DBs those
-- columns are present here and 011/012's ADD COLUMNs are no-ops (duplicate-column,
-- swallowed by the runner) — the net event_type CHECK ends up identical.

PRAGMA foreign_keys = OFF;

-- Rename the existing table
ALTER TABLE events RENAME TO events_old;

-- Create the new events table with the updated CHECK constraint and the FINAL
-- 19-column schema (mirrors 001_init.sql exactly, plus encrypted_dns_detected).
CREATE TABLE events (
    event_id       TEXT PRIMARY KEY,
    timestamp      TIMESTAMP NOT NULL,
    event_type     TEXT NOT NULL CHECK (event_type IN ('dns_query', 'encrypted_dns_detected', 'nmap_discovery', 'firewall_log', 'anomaly')),
    source_hash    TEXT NOT NULL,
    source_ip      TEXT,
    server_ip      TEXT DEFAULT '',
    domain         TEXT,
    query_type     TEXT CHECK (query_type IN ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV', 'PTR', NULL)),
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',
    geo            TEXT,
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default' CHECK (network_segment IN ('default', 'iot', 'guest')),
    dns_source     TEXT DEFAULT '',
    metadata       TEXT DEFAULT '{}',
    acknowledged   BOOLEAN NOT NULL DEFAULT FALSE,
    ack_reason     TEXT DEFAULT ''
);

-- Copy data using an EXPLICIT shared column list. These 14 columns exist in every
-- historical events shape (001-original + 008.dns_source, and 001-final), so the
-- copy succeeds whether events_old has 14 or 19 columns. The 5 remaining columns
-- (source_ip, server_ip, metadata, acknowledged, ack_reason) take their DEFAULTs;
-- on the legacy incremental path they are then populated by later migrations,
-- and on a fresh install the table is empty so no data is lost either way.
INSERT INTO events (
    event_id, timestamp, event_type, source_hash, domain, query_type,
    resolved_ip, blocked, anomaly_score, tags, geo, device_vendor,
    network_segment, dns_source
)
SELECT
    event_id, timestamp, event_type, source_hash, domain, query_type,
    resolved_ip, blocked, anomaly_score, tags, geo, device_vendor,
    network_segment, dns_source
FROM events_old;

-- Drop old table
DROP TABLE events_old;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type         ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_source       ON events (source_hash);
CREATE INDEX IF NOT EXISTS idx_events_anomaly      ON events (anomaly_score);
CREATE INDEX IF NOT EXISTS idx_events_domain       ON events (domain);
CREATE INDEX IF NOT EXISTS idx_events_type_time    ON events (event_type, timestamp);

PRAGMA foreign_keys = ON;
