-- 029: preserve receipt-plausible raw timestamp classifications without one
-- row per report. Each sensor keeps bounded/rotating raw-acceptance epochs;
-- exact broken-clock normalizations remain in the migration-027 table.

CREATE TABLE IF NOT EXISTS sensor_report_time_raw_epochs (
    epoch_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id     TEXT NOT NULL,
    raw_min       TIMESTAMP NOT NULL,
    raw_max       TIMESTAMP NOT NULL,
    last_raw      TIMESTAMP NOT NULL,
    last_receipt  TIMESTAMP NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL,
    CHECK (raw_max >= raw_min),
    CHECK (last_raw >= raw_min AND last_raw <= raw_max)
);

CREATE INDEX IF NOT EXISTS idx_sensor_report_time_raw_epochs_lookup
    ON sensor_report_time_raw_epochs(sensor_id, raw_min, raw_max);

CREATE INDEX IF NOT EXISTS idx_sensor_report_time_raw_epochs_updated
    ON sensor_report_time_raw_epochs(updated_at);

-- One bounded row per sensor makes receipt order monotonic even when requests
-- capture wall time before contending for SQLite's writer lock in reverse order.
CREATE TABLE IF NOT EXISTS sensor_report_time_receipts (
    sensor_id    TEXT PRIMARY KEY,
    last_receipt TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sensor_report_time_receipts_updated
    ON sensor_report_time_receipts(updated_at);
