-- Add encrypted_dns_detected to the event_type CHECK constraint
-- SQLite doesn't support altering CHECK constraints, so we recreate the table

PRAGMA foreign_keys = OFF;

-- Rename the existing table
ALTER TABLE events RENAME TO events_old;

-- Create the new events table with the updated CHECK constraint
CREATE TABLE events (
    event_id       TEXT PRIMARY KEY,
    timestamp      TIMESTAMP NOT NULL,
    event_type     TEXT NOT NULL CHECK (event_type IN ('dns_query', 'encrypted_dns_detected', 'nmap_discovery', 'firewall_log', 'anomaly')),
    source_hash    TEXT NOT NULL,
    domain         TEXT,
    query_type     TEXT CHECK (query_type IN ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV', 'PTR', NULL)),
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',
    geo            TEXT,
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default' CHECK (network_segment IN ('default', 'iot', 'guest')),
    dns_source     TEXT DEFAULT ''
);

-- Copy data from old table
INSERT INTO events SELECT * FROM events_old;

-- Drop old table
DROP TABLE events_old;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type         ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_source       ON events (source_hash);
CREATE INDEX IF NOT EXISTS idx_events_anomaly      ON events (anomaly_score);
CREATE INDEX IF NOT EXISTS idx_events_domain       ON events (domain);
CREATE INDEX IF NOT EXISTS idx_events_type_time    ON events (event_type, timestamp);

PRAGMA foreign_keys = ON;
