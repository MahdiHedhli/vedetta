package store

import "fmt"

// ensureSensorLifecycleSchema mirrors migration 026 for binary-only installs
// and repairs databases that previously started without the migration files.
// Removed sensor rows are identity tombstones: they must remain present so a
// generic enrollment code can never reclaim an old, guessable sensor_id.
func (db *DB) ensureSensorLifecycleSchema() error {
	sensorsOK, err := db.schemaTableExists("sensors")
	if err != nil {
		return err
	}
	if !sensorsOK {
		return nil
	}

	columns := []struct{ name, ddl string }{
		{"removed_at", `ALTER TABLE sensors ADD COLUMN removed_at TIMESTAMP`},
		{"removed_by_token_id", `ALTER TABLE sensors ADD COLUMN removed_by_token_id TEXT`},
		{"removal_reason", `ALTER TABLE sensors ADD COLUMN removal_reason TEXT NOT NULL DEFAULT ''`},
	}
	for _, col := range columns {
		if err := db.ensureSchemaColumn("sensors", col.name, col.ddl); err != nil {
			return err
		}
	}

	if _, err := db.Exec(sensorLifecycleDDL); err != nil {
		return fmt.Errorf("create sensor lifecycle schema: %w", err)
	}
	return nil
}

const sensorLifecycleDDL = `
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
  ON sensor_lifecycle_events (sensor_id, created_at DESC);`
