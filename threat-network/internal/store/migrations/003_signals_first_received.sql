-- Anchor signal retention to an immutable first_received_at.
--
-- UpsertSignal merges a re-sent hour-bucket signal by bumping received_at to the
-- merge time (received_at = excluded.received_at). Retention purges on
-- received_at < now-30d, so an attacker (or a chatty reporter) that re-sends the
-- same (reporter_id, kind, indicator_key, time_bucket) row before each purge can
-- keep received_at fresh forever, pinning a raw row in the store indefinitely —
-- past the 30-day retention the constitution promises.
--
-- Add an immutable first_received_at stamped once at insert and NEVER updated on
-- merge. Retention is re-anchored to first_received_at so a row ages out 30 days
-- after it was FIRST seen regardless of later merge bumps. received_at is kept as
-- the "last merged" timestamp for the consensus window query, which intentionally
-- wants recently-updated signals.
--
-- SQLite cannot add a NOT NULL column without a constant default to an existing
-- table, so backfill existing rows from received_at (their best-known first-seen)
-- in a follow-up UPDATE.

ALTER TABLE signals ADD COLUMN first_received_at TEXT NOT NULL DEFAULT '';

UPDATE signals SET first_received_at = received_at WHERE first_received_at = '';

CREATE INDEX IF NOT EXISTS idx_signals_first_received ON signals(first_received_at);
