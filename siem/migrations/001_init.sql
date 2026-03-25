-- Vedetta SIEM Storage Layer — Initial Schema
-- Supports SQLite (single node) and PostgreSQL (SMB deployments)
-- Every field earns its place.

CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY,
    timestamp      TIMESTAMP NOT NULL,
    event_type     TEXT NOT NULL CHECK (event_type IN ('dns_query', 'nmap_discovery', 'firewall_log', 'anomaly')),
    source_hash    TEXT NOT NULL,
    domain         TEXT,
    query_type     TEXT CHECK (query_type IN ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV', 'PTR', NULL)),
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',  -- JSON array, indexed via generated column or application layer
    geo            TEXT,               -- ISO 3166-1 alpha-2 country code
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default' CHECK (network_segment IN ('default', 'iot', 'guest'))
);

-- Indexes: optimized for SIEM-style queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type         ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_source       ON events (source_hash);
CREATE INDEX IF NOT EXISTS idx_events_anomaly      ON events (anomaly_score);
CREATE INDEX IF NOT EXISTS idx_events_domain       ON events (domain);
CREATE INDEX IF NOT EXISTS idx_events_type_time    ON events (event_type, timestamp);

-- Device registry
CREATE TABLE IF NOT EXISTS devices (
    device_id    TEXT PRIMARY KEY,
    first_seen   TIMESTAMP NOT NULL,
    last_seen    TIMESTAMP NOT NULL,
    ip_address   TEXT NOT NULL,
    mac_address  TEXT NOT NULL,
    hostname     TEXT,
    vendor       TEXT,
    open_ports   TEXT DEFAULT '[]',  -- JSON array
    segment      TEXT DEFAULT 'default' CHECK (segment IN ('default', 'iot', 'guest'))
);

CREATE INDEX IF NOT EXISTS idx_devices_mac     ON devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_last    ON devices (last_seen);

-- Retention metadata
CREATE TABLE IF NOT EXISTS retention_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO retention_config (key, value) VALUES ('retention_days', '90');
