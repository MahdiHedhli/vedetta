-- BUG-1 repair: rebuild the device-correlation child tables with CORRECT
-- foreign keys back to devices(device_id).
--
-- Background: migration 018 created device_signals / device_identities /
-- device_networks with `REFERENCES devices(device_id)`. Migration 019 rebuilt the
-- `devices` table via `ALTER TABLE devices RENAME TO devices_old_019; CREATE new
-- devices; ...; DROP devices_old_019`. Because the store opens SQLite with
-- _foreign_keys=on and the pre-fix 019 could not actually disable FK enforcement
-- inside the migration transaction (PRAGMA foreign_keys is a no-op inside a tx),
-- the RENAME rewrote the three child tables' FKs to REFERENCE "devices_old_019",
-- which 019 then dropped — leaving DANGLING foreign keys. At runtime UpsertDevice
-- runs in one transaction: the devices INSERT succeeds but the follow-up
-- identity/network/signal upserts fail with `no such table:
-- main.devices_old_019`, so `defer tx.Rollback()` discards the whole device.
-- Result: every POST /api/v1/sensor/devices and every LAN scan silently fails and
-- GET /api/v1/devices returns total:0.
--
-- This migration REPAIRS both situations idempotently:
--   * a DB that already applied the broken 019 (child FKs point at
--     devices_old_019) — rebuilt here with correct FKs;
--   * a fresh install where 019 has been fixed (child FKs already correct) —
--     rebuilt to the identical shape, a harmless no-op in effect.
-- It rebuilds each child table from a clean CREATE that references devices, copies
-- all rows, drops the old table, renames the new one into place, and recreates the
-- indexes. Columns, data, primary keys and indexes are all preserved exactly.
--
-- We set legacy_alter_table = ON for the same reason as the fixed 019: it DOES
-- take effect inside a transaction (unlike PRAGMA foreign_keys) and stops the
-- RENAME from chasing references, so rebuilding these tables cannot re-orphan
-- anything. The child tables have no children of their own, so this is safe.
PRAGMA legacy_alter_table = ON;

-- ── device_signals ──────────────────────────────────────────────────────────────
CREATE TABLE device_signals_new_020 (
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    field          TEXT NOT NULL,
    value          TEXT NOT NULL,
    source         TEXT NOT NULL,
    confidence     REAL NOT NULL DEFAULT 0.0,
    first_observed TIMESTAMP NOT NULL,
    last_observed  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, field, source)
);
INSERT INTO device_signals_new_020
    (device_id, field, value, source, confidence, first_observed, last_observed)
SELECT device_id, field, value, source, confidence, first_observed, last_observed
FROM device_signals;
DROP TABLE device_signals;
ALTER TABLE device_signals_new_020 RENAME TO device_signals;
CREATE INDEX IF NOT EXISTS idx_device_signals_device ON device_signals(device_id);

-- ── device_identities ───────────────────────────────────────────────────────────
CREATE TABLE device_identities_new_020 (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    id_type    TEXT NOT NULL,
    id_value   TEXT NOT NULL,
    segment    TEXT NOT NULL DEFAULT 'default',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (id_type, id_value, segment)
);
INSERT INTO device_identities_new_020
    (device_id, id_type, id_value, segment, first_seen, last_seen)
SELECT device_id, id_type, id_value, segment, first_seen, last_seen
FROM device_identities;
DROP TABLE device_identities;
ALTER TABLE device_identities_new_020 RENAME TO device_identities;
CREATE INDEX IF NOT EXISTS idx_device_identities_device ON device_identities(device_id);

-- ── device_networks ─────────────────────────────────────────────────────────────
CREATE TABLE device_networks_new_020 (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    segment    TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    sensor_id  TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, segment)
);
INSERT INTO device_networks_new_020
    (device_id, segment, ip_address, sensor_id, first_seen, last_seen)
SELECT device_id, segment, ip_address, sensor_id, first_seen, last_seen
FROM device_networks;
DROP TABLE device_networks;
ALTER TABLE device_networks_new_020 RENAME TO device_networks;
CREATE INDEX IF NOT EXISTS idx_device_networks_segment ON device_networks(segment);

PRAGMA legacy_alter_table = OFF;
