-- Add DNS capture config to scan targets and interfaces to sensors
ALTER TABLE scan_targets ADD COLUMN dns_capture BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_targets ADD COLUMN dns_interface TEXT DEFAULT '';
ALTER TABLE sensors ADD COLUMN interfaces TEXT DEFAULT '[]';
