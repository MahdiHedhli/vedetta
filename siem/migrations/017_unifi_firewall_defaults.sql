-- Spec 001 (UniFi Log Ingestion): SNR defaults + ingest token scope.
--
-- Two concerns, both belonging to the UniFi firewall ingestion feature:
--   1. Seed default whitelist rules that keep the new firewall event source
--      quiet by default (WAN-scan rollups, multicast/broadcast blocks, and a
--      disabled self-scan template). All is_default = TRUE, category 'firewall',
--      user-disableable in the existing whitelist UI.
--   2. Widen the api_tokens.scope CHECK constraint to allow the new 'ingest'
--      scope (FR-8). SQLite cannot ALTER a CHECK in place, so the table is
--      rebuilt preserving all existing rows and indexes.
--
-- All values are synthetic / documentation-reserved per the constitution.
-- Idempotent: INSERT OR IGNORE on fixed rule_ids; the table rebuild is guarded
-- by the migration runner (recorded in schema_migrations, applied once).

-- 1. Default firewall whitelist rules ------------------------------------------

INSERT OR IGNORE INTO whitelist_rules
    (rule_id, name, description, domain_pattern, source_ip_pattern, tag_match, category, is_default, enabled, created_at)
VALUES
    ('wl-fw-wan-scan-rollup',
     'WAN scan noise rollup',
     'Suppress aggregated WAN inbound scan-drop rollup events (internet background radiation). Individual WAN drops are already rolled up at the collector; this keeps the rollup out of the anomaly feed while remaining queryable.',
     '', '', 'wan_scan_noise', 'firewall', TRUE, TRUE, CURRENT_TIMESTAMP),

    ('wl-fw-multicast-broadcast',
     'Multicast/broadcast firewall blocks',
     'Suppress well-known multicast/broadcast firewall blocks (mDNS 224.0.0.251, SSDP 239.255.255.250, broadcast). Tagged fw:multicast by the collector transform.',
     '', '', 'fw:multicast', 'firewall', TRUE, TRUE, CURRENT_TIMESTAMP),

    -- Disabled template: the setup guide instructs users to set source_ip_pattern
    -- to their Vedetta Core/sensor host IP so its own discovery traffic tripping
    -- gateway rules is suppressed. Shipped disabled (enabled = FALSE) with an
    -- empty pattern so it never matches until configured.
    ('wl-fw-self-scan',
     'Vedetta self-scan (template)',
     'Template: set source_ip_pattern to your Vedetta Core/sensor host IP to suppress firewall blocks caused by Vedetta''s own discovery traffic. Disabled until configured.',
     '', '', '', 'firewall', TRUE, FALSE, CURRENT_TIMESTAMP);

-- 2. Widen api_tokens.scope CHECK to include 'ingest' --------------------------

CREATE TABLE IF NOT EXISTS api_tokens_new (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'sensor' CHECK(scope IN ('sensor', 'admin', 'ingest')),
    sensor_id TEXT,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used TEXT NOT NULL DEFAULT (datetime('now')),
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id)
);

INSERT INTO api_tokens_new (token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked)
    SELECT token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_new RENAME TO api_tokens;

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_sensor ON api_tokens(sensor_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked ON api_tokens(revoked);
