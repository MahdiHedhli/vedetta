-- Add user-editable device fields and event acknowledgment system.
-- custom_name: user-assigned device label (e.g., "Mahdi's MacBook Pro")
-- notes: freeform notes about the device
-- Events: acknowledged flag and suppression rules for filtering

ALTER TABLE devices ADD COLUMN custom_name TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN notes TEXT DEFAULT '';

-- Event acknowledgment: mark events as reviewed
ALTER TABLE events ADD COLUMN acknowledged BOOLEAN DEFAULT FALSE;
ALTER TABLE events ADD COLUMN ack_reason TEXT DEFAULT '';

-- Suppression rules: user-defined filters to auto-hide matching events
CREATE TABLE IF NOT EXISTS suppression_rules (
    rule_id     TEXT PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain      TEXT DEFAULT '',          -- exact domain match (empty = any)
    source_ip   TEXT DEFAULT '',          -- exact source IP match (empty = any)
    tags        TEXT DEFAULT '[]',        -- JSON array of tags to match (any = match)
    reason      TEXT DEFAULT '',          -- user's reason for suppressing
    active      BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_events_ack ON events (acknowledged);
