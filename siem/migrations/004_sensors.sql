-- Sensor registry: tracks remote sensors that report device data to Core.

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    arch        TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    version     TEXT NOT NULL,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL,
    status      TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online', 'offline'))
);

CREATE INDEX IF NOT EXISTS idx_sensors_status ON sensors (status);
