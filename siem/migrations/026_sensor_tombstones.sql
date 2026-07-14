-- 026: preserve removed sensor identities and their audit history.
--
-- A sensor_id is security state: once it has existed, generic enrollment must
-- never be able to claim it again. Removal therefore tombstones the row instead
-- of deleting it. Existing installations remain active because removed_at is
-- NULL for every pre-migration row.

ALTER TABLE sensors ADD COLUMN removed_at TIMESTAMP;
ALTER TABLE sensors ADD COLUMN removed_by_token_id TEXT;
ALTER TABLE sensors ADD COLUMN removal_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sensors_active_last_seen
  ON sensors (is_primary DESC, last_seen DESC)
  WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS sensor_lifecycle_events (
    event_id       TEXT PRIMARY KEY,
    sensor_id      TEXT NOT NULL REFERENCES sensors(sensor_id),
    event_type     TEXT NOT NULL CHECK(event_type IN ('removed', 'reactivated')),
    actor          TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    details        TEXT NOT NULL DEFAULT '{}',
    created_at     TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sensor_lifecycle_sensor_time
  ON sensor_lifecycle_events (sensor_id, created_at DESC);
