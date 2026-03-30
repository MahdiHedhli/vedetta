-- Add is_primary flag to sensors.
-- First sensor to register defaults to primary; user can reassign via UI.

ALTER TABLE sensors ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT FALSE;
