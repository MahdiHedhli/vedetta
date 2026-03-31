-- Add dns_source column to track which DNS capture method generated each event
ALTER TABLE events ADD COLUMN dns_source TEXT DEFAULT '';
