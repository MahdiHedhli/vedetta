-- Device Fingerprinting Enhancement
-- Enriches device discovery with OS family, device type, model, and confidence scores

ALTER TABLE devices ADD COLUMN device_type TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN os_family TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN os_version TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN model TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN discovery_method TEXT DEFAULT 'nmap_active';
ALTER TABLE devices ADD COLUMN fingerprint_confidence REAL DEFAULT 0.0;
