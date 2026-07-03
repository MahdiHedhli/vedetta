-- threat-network service-local schema (schema_version 1)
-- Sequential migration chain, mirroring Core's schema_migrations pattern.
-- NEVER edit a committed migration; add a new sequential file instead.
-- All stored data is aggregate/count-only: no operator identity, no source IPs,
-- no asset identifiers. See specs/003-threat-network/plan.md.

CREATE TABLE IF NOT EXISTS reporters (
    reporter_id     TEXT PRIMARY KEY,
    secret_hash     TEXT NOT NULL,
    capabilities    TEXT NOT NULL DEFAULT '[]',
    vedetta_version TEXT,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    denylist_reason TEXT
);

CREATE TABLE IF NOT EXISTS nonces (
    reporter_id TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    seen_at     TEXT NOT NULL,
    PRIMARY KEY (reporter_id, nonce)
);

CREATE TABLE IF NOT EXISTS ingest_receipts (
    batch_id       TEXT PRIMARY KEY,
    reporter_id    TEXT NOT NULL,
    received_at    TEXT NOT NULL,
    signal_count   INTEGER NOT NULL,
    accepted_count INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signals (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id          TEXT NOT NULL,
    kind                 TEXT NOT NULL,
    indicator_key        TEXT NOT NULL,
    domain               TEXT,
    etld_plus_one        TEXT,
    behavior             TEXT,
    time_bucket          TEXT NOT NULL,
    local_confidence     REAL NOT NULL,
    local_reasons        TEXT NOT NULL DEFAULT '[]',
    observation_count    INTEGER NOT NULL DEFAULT 0,
    distinct_asset_count INTEGER NOT NULL DEFAULT 0,
    blocked_count        INTEGER NOT NULL DEFAULT 0,
    received_at          TEXT NOT NULL,
    UNIQUE(reporter_id, kind, indicator_key, time_bucket)
);

CREATE TABLE IF NOT EXISTS signal_aggregates (
    kind               TEXT NOT NULL,
    indicator_key      TEXT NOT NULL,
    distinct_reporters INTEGER NOT NULL,
    aggregate_confidence REAL NOT NULL,
    total_observations INTEGER NOT NULL,
    reasons            TEXT NOT NULL DEFAULT '[]',
    has_known_bad      INTEGER NOT NULL DEFAULT 0,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    computed_at        TEXT NOT NULL,
    PRIMARY KEY (kind, indicator_key)
);

CREATE TABLE IF NOT EXISTS feed_items (
    feed_id          TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    indicator        TEXT NOT NULL,
    indicator_type   TEXT NOT NULL,
    confidence       REAL NOT NULL,
    severity         TEXT NOT NULL,
    sources_required INTEGER NOT NULL,
    sources_observed INTEGER NOT NULL,
    reasons          TEXT NOT NULL DEFAULT '[]',
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    published_at     TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    revoked_at       TEXT,
    UNIQUE(kind, indicator)
);

CREATE TABLE IF NOT EXISTS reporter_counters (
    reporter_id         TEXT NOT NULL,
    day                 TEXT NOT NULL,
    batches_accepted    INTEGER NOT NULL DEFAULT 0,
    signals_accepted    INTEGER NOT NULL DEFAULT 0,
    distinct_indicators INTEGER NOT NULL DEFAULT 0,
    allowlist_flags     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (reporter_id, day)
);

CREATE TABLE IF NOT EXISTS allowlist_domains (
    etld_plus_one TEXT PRIMARY KEY,
    rank          INTEGER,
    loaded_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signals_indicator_received ON signals(indicator_key, received_at);
CREATE INDEX IF NOT EXISTS idx_signals_reporter_received ON signals(reporter_id, received_at);
CREATE INDEX IF NOT EXISTS idx_feed_items_updated ON feed_items(updated_at);
CREATE INDEX IF NOT EXISTS idx_nonces_seen ON nonces(seen_at);
