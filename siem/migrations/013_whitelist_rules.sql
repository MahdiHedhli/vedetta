-- Known-traffic whitelist rules to reduce false positives from normal home network activity.

CREATE TABLE IF NOT EXISTS whitelist_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    domain_pattern TEXT DEFAULT '',      -- glob pattern: *.apple.com, *.local
    source_ip_pattern TEXT DEFAULT '',   -- glob or exact: 192.168.1.1, 10.0.0.*
    tag_match TEXT DEFAULT '',           -- match events with this tag: beaconing, known_bad
    category TEXT DEFAULT 'custom',      -- mdns, apple, gateway, os_updates, cloud, iot, custom
    is_default BOOLEAN DEFAULT FALSE,    -- shipped with Vedetta vs user-created
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_whitelist_enabled ON whitelist_rules (enabled);
CREATE INDEX IF NOT EXISTS idx_whitelist_category ON whitelist_rules (category);
