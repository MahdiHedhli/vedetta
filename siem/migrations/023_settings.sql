-- Issue #37 (telemetry opt-in as a real persisted setting): a minimal, generic
-- key/value settings store owned by Core. The first consumer is the telemetry
-- opt-in toggle (key 'telemetry_opt_in'), surfaced via
-- GET/PUT /api/v1/settings/telemetry, but the table is intentionally generic so
-- future dashboard-controllable settings reuse it.
--
-- Effective-value rule (enforced in the API layer, not here): a persisted row
-- WINS over the VEDETTA_TELEMETRY_OPTIN env var; with no row, env is used;
-- default effective is true (opt-out). This migration only provides storage —
-- it deliberately seeds NO default row so "no persisted setting" stays
-- distinguishable from an explicit choice.
--
-- Additive and idempotent: recorded in schema_migrations, applied once.

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
