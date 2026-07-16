-- Durable latest-state ordering for cache-only ARP observations.
--
-- A blank MAC means the sensor saw conflicting/proxy rows for this scoped IP.
-- Device projections are mutable, so they cannot safely carry that negative
-- transition. This ledger stores only a node-local HMAC of a unique MAC and is
-- never exported by telemetry.
CREATE TABLE IF NOT EXISTS arp_cache_delivery_epochs (
    epoch_order INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    delivery_epoch TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    activated_at TIMESTAMP,
    ever_activated_at TIMESTAMP,
    UNIQUE (sensor_id, delivery_epoch)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_arp_cache_delivery_active_sensor
    ON arp_cache_delivery_epochs(sensor_id) WHERE activated_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS arp_cache_states (
    sensor_id TEXT NOT NULL DEFAULT '',
    segment TEXT NOT NULL DEFAULT 'default',
    ip_address TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('unique', 'ambiguous')),
    mac_hmac TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMP NOT NULL,
    delivery_epoch_order INTEGER NOT NULL DEFAULT 0 CHECK (delivery_epoch_order >= 0),
    delivery_sequence INTEGER NOT NULL DEFAULT 0 CHECK (delivery_sequence >= 0),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sensor_id, segment, ip_address),
    CHECK ((state = 'unique' AND mac_hmac != '') OR (state = 'ambiguous' AND mac_hmac = ''))
);

CREATE INDEX IF NOT EXISTS idx_arp_cache_states_observed
    ON arp_cache_states(observed_at);
