-- Rekey idempotency on (reporter_id, batch_id) instead of batch_id alone.
--
-- The original ingest_receipts PK was batch_id, so reporter B submitting a batch
-- whose UUID collided with a batch_id already recorded for reporter A was treated
-- as a duplicate: B received A's accepted/rejected counts (cross-reporter count
-- disclosure) and B's signals were silently dropped. An attacker who guessed a
-- victim's batch_id could also pre-register it to blackhole the victim's batch of
-- that id. Idempotency is a per-reporter property, so the key must include the
-- reporter. See specs/002-telemetry-service and specs/003-threat-network.
--
-- SQLite cannot alter a PRIMARY KEY in place, so rebuild the table.

CREATE TABLE ingest_receipts_new (
    reporter_id    TEXT NOT NULL,
    batch_id       TEXT NOT NULL,
    received_at    TEXT NOT NULL,
    signal_count   INTEGER NOT NULL,
    accepted_count INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL,
    PRIMARY KEY (reporter_id, batch_id)
);

INSERT INTO ingest_receipts_new
    (reporter_id, batch_id, received_at, signal_count, accepted_count, rejected_count)
SELECT reporter_id, batch_id, received_at, signal_count, accepted_count, rejected_count
FROM ingest_receipts;

DROP TABLE ingest_receipts;
ALTER TABLE ingest_receipts_new RENAME TO ingest_receipts;
