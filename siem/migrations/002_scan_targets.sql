-- Scan targets: named subnets for multi-VLAN scanning
-- The default CIDR from env var is always scanned; these are additional targets.

CREATE TABLE IF NOT EXISTS scan_targets (
    target_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,                -- e.g. "IoT Network", "Guest WiFi"
    cidr        TEXT NOT NULL,                -- e.g. "10.0.50.0/24"
    segment     TEXT NOT NULL DEFAULT 'default' CHECK (segment IN ('default', 'iot', 'guest')),
    scan_ports  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL,
    last_scan   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_targets_enabled ON scan_targets (enabled);
