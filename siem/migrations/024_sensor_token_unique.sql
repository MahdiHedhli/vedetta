-- 024: guarantee at most ONE active (non-revoked) sensor-scoped token per sensor.
--
-- Before 024, re-enrolling an already-enrolled sensor revoked and re-issued its
-- token without a transaction or a uniqueness guarantee, so concurrent resets
-- could leave several valid tokens live for one sensor_id (beta-gate B1a
-- concurrent-reset probe: 20 codes -> 7 simultaneously-valid tokens).
--
-- First collapse any pre-existing duplicates — keep the most recently inserted
-- active token per sensor (highest rowid) and revoke the rest — because a
-- partial UNIQUE index cannot be created while the table already violates it.
-- Then enforce the invariant so the database itself rejects a second active
-- sensor token.

UPDATE api_tokens
SET revoked = 1
WHERE scope = 'sensor'
  AND revoked = 0
  AND rowid NOT IN (
    SELECT MAX(rowid)
    FROM api_tokens
    WHERE scope = 'sensor' AND revoked = 0
    GROUP BY sensor_id
  );

CREATE UNIQUE INDEX IF NOT EXISTS ux_api_tokens_active_sensor
  ON api_tokens (sensor_id)
  WHERE scope = 'sensor' AND revoked = 0;
