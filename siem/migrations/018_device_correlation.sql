-- Spec 004: Passive Discovery Correlation, Labeling & Multi-Network Handling.
--
-- Adds a canonical display label + friendly name to the device row, and three
-- new tables that back multi-signal identity resolution, per-field provenance,
-- and multi-network attachments. Nothing in earlier migrations (001-017) is
-- edited; this is a purely additive sequential migration.
--
-- Backfill decision (T2.2): the identity/network/display_name backfill for
-- PRE-EXISTING devices runs here in SQL (not first-boot Go). Rationale: the seed
-- is a deterministic projection of existing devices columns, runs exactly once
-- inside the migration transaction, and needs no application types. Ongoing
-- (post-migration) maintenance of these tables happens in Go on every upsert
-- (backend/internal/store/devices_correlate.go). display_name backfill uses the
-- same precedence as the Go label deriver's non-user, non-friendly-name levels
-- (model+vendor > cleaned hostname > vendor > ip_address); friendly_name is not
-- known for historical rows so it is left empty and recomputed on next report.
-- first_seen is intentionally NOT touched, so no upgrade-time new_device wave.

-- Canonical display label + friendly name on the device row (cheap list queries).
ALTER TABLE devices ADD COLUMN display_name TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN friendly_name TEXT DEFAULT '';

-- Per-field provenance: which source last set each canonical field, at what confidence.
CREATE TABLE device_signals (
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    field          TEXT NOT NULL,   -- vendor|model|hostname|friendly_name|os_family|device_type
    value          TEXT NOT NULL,
    source         TEXT NOT NULL,   -- user_corrected|mdns_txt|mdns_ptr|ssdp|dhcp_hostname|dhcp_vendor_class|hostname_pattern|oui|nmap
    confidence     REAL NOT NULL DEFAULT 0.0,
    first_observed TIMESTAMP NOT NULL,
    last_observed  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, field, source)
);
CREATE INDEX idx_device_signals_device ON device_signals(device_id);

-- Identity aliases used by the resolver (survives DHCP churn).
CREATE TABLE device_identities (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    id_type    TEXT NOT NULL,       -- mac|hostname|mdns_name
    id_value   TEXT NOT NULL,
    segment    TEXT NOT NULL DEFAULT 'default',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (id_type, id_value, segment)
);
CREATE INDEX idx_device_identities_device ON device_identities(device_id);

-- Multi-network attachments: one device on N segments.
CREATE TABLE device_networks (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    segment    TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    sensor_id  TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, segment)
);
CREATE INDEX idx_device_networks_segment ON device_networks(segment);

-- Backfill identity aliases from existing devices.mac_address / hostname.
-- MAC aliases are segment-independent in spirit, but the PK includes segment, so
-- we key them to the device's current segment (the only segment we know for a
-- historical row). Empty MAC/hostname values are skipped.
INSERT OR IGNORE INTO device_identities (device_id, id_type, id_value, segment, first_seen, last_seen)
SELECT device_id, 'mac', mac_address, COALESCE(NULLIF(segment, ''), 'default'), first_seen, last_seen
FROM devices
WHERE mac_address IS NOT NULL AND mac_address != '';

INSERT OR IGNORE INTO device_identities (device_id, id_type, id_value, segment, first_seen, last_seen)
SELECT device_id, 'hostname', hostname, COALESCE(NULLIF(segment, ''), 'default'), first_seen, last_seen
FROM devices
WHERE hostname IS NOT NULL AND hostname != '';

-- Backfill network attachments from existing devices(segment, ip_address).
INSERT OR IGNORE INTO device_networks (device_id, segment, ip_address, sensor_id, first_seen, last_seen)
SELECT device_id, COALESCE(NULLIF(segment, ''), 'default'), COALESCE(ip_address, ''), '', first_seen, last_seen
FROM devices;

-- Backfill an initial display_name from existing columns using the same
-- precedence as the Go label deriver (excluding user custom_name / friendly_name
-- which are handled at read/upsert time, and the vendor+MAC-suffix level which
-- requires MAC-octet formatting best done in Go — vendor-only is used here as a
-- cheap approximation, superseded on next report).
UPDATE devices SET display_name = CASE
    WHEN COALESCE(model, '') != '' AND COALESCE(vendor, '') != '' THEN model || ' (' || vendor || ')'
    WHEN COALESCE(model, '') != '' THEN model
    WHEN COALESCE(hostname, '') != '' THEN hostname
    WHEN COALESCE(vendor, '') != '' THEN vendor
    ELSE COALESCE(ip_address, '')
END
WHERE COALESCE(display_name, '') = '';
