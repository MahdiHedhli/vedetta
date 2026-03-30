-- Support cross-subnet device identity (no MAC available via ARP).
-- When MAC is empty, UpsertDevice matches by IP + segment instead.
CREATE INDEX IF NOT EXISTS idx_devices_ip_segment ON devices (ip_address, segment);
