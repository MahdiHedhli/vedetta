-- 027: make implausibly future sensor inventory timestamps replay-idempotent.
--
-- A partial device batch is retried in full. Mapping a broken sensor clock to
-- request time on every attempt would make the same observation appear newer on
-- every replay and could restore stale address ownership. Persist the first
-- server-side normalization by authenticated sensor and exact upstream time.

CREATE TABLE IF NOT EXISTS sensor_report_time_normalizations (
    sensor_id       TEXT NOT NULL,
    upstream_time   TEXT NOT NULL,
    normalized_time TIMESTAMP NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    PRIMARY KEY (sensor_id, upstream_time)
);

CREATE INDEX IF NOT EXISTS idx_sensor_report_time_normalizations_created
    ON sensor_report_time_normalizations(created_at);

CREATE INDEX IF NOT EXISTS idx_sensor_report_time_normalizations_sensor_created
    ON sensor_report_time_normalizations(sensor_id, created_at);
