-- Threat intelligence indicator storage.
-- Populated by automated feed downloads (abuse.ch, GreyNoise, etc.)
-- Queried during event ingest for real-time enrichment.

CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator TEXT NOT NULL,
    type      TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash')),
    source    TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    tags      TEXT DEFAULT '[]',  -- JSON array
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    ttl_hours  INTEGER NOT NULL DEFAULT 168,  -- 7 days
    PRIMARY KEY (indicator, source)
);

CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator);
CREATE INDEX IF NOT EXISTS idx_ti_source    ON threat_indicators(source);
CREATE INDEX IF NOT EXISTS idx_ti_last_seen ON threat_indicators(last_seen);
