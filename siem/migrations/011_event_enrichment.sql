-- Add source_ip, threat description, and detection metadata to events.
-- source_ip: raw client IP for local network attribution (home SIEM — it's your own network)
-- threat_desc: human-readable explanation of why something was flagged
-- metadata: JSON blob with detection algorithm details (entropy, signals, CV, etc.)

ALTER TABLE events ADD COLUMN source_ip TEXT DEFAULT '';
ALTER TABLE events ADD COLUMN threat_desc TEXT DEFAULT '';
ALTER TABLE events ADD COLUMN metadata TEXT DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
