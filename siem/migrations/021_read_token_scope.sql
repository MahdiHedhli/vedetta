-- Beta-gate B6 (read-only token scope): widen the api_tokens.scope CHECK
-- constraint to allow the new 'read' scope.
--
-- The read endpoints (GET /status, /events, /devices, ...) are now gated to
-- require at least read scope once an active admin token exists. Operators mint
-- least-privilege 'read' tokens (a dashboard viewer, a status probe, or the
-- telemetry reader) that can query but never write or reach admin routes.
--
-- SQLite cannot ALTER a CHECK constraint in place, so the table is rebuilt
-- preserving all existing rows and indexes — the same recipe migration 017 used
-- to add 'ingest'. Idempotent: recorded in schema_migrations, applied once.

CREATE TABLE IF NOT EXISTS api_tokens_new (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'sensor' CHECK(scope IN ('sensor', 'admin', 'ingest', 'read')),
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
