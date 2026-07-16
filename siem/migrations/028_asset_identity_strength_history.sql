-- 028: preserve strength and observation freshness known at event time.
--
-- device_address_history and device_identity_evidence intentionally remain in
-- place: current inventory projections and audited identity actions reference
-- their stable row IDs. Their confidence/source columns remain the best current
-- aggregate. These additive child tables are the event-time truth used by
-- ResolveDeviceAt, preventing later corroboration or refresh from changing an
-- older event. Validity windows merge continuous observations, so 30-second ARP
-- polling remains one compact row rather than one row per scan.

CREATE TABLE IF NOT EXISTS device_address_binding_strength (
    binding_id  TEXT NOT NULL REFERENCES device_address_history(binding_id) ON DELETE CASCADE,
    observed_at TIMESTAMP NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (binding_id, observed_at, source, confidence)
);
CREATE INDEX IF NOT EXISTS idx_device_address_binding_strength_time
    ON device_address_binding_strength(binding_id, observed_at);

CREATE TABLE IF NOT EXISTS device_address_binding_validity (
    binding_id  TEXT NOT NULL REFERENCES device_address_history(binding_id) ON DELETE CASCADE,
    valid_from  TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (binding_id, valid_from),
    CHECK (valid_until >= valid_from)
);
CREATE INDEX IF NOT EXISTS idx_device_address_binding_validity_time
    ON device_address_binding_validity(binding_id, valid_from, valid_until);

CREATE TABLE IF NOT EXISTS device_identity_evidence_strength (
    evidence_id        TEXT NOT NULL REFERENCES device_identity_evidence(evidence_id) ON DELETE CASCADE,
    observed_at        TIMESTAMP NOT NULL,
    source             TEXT NOT NULL DEFAULT '',
    confidence         REAL NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    operator_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (evidence_id, observed_at, source, confidence, operator_confirmed)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_strength_time
    ON device_identity_evidence_strength(evidence_id, observed_at);

CREATE TABLE IF NOT EXISTS device_identity_evidence_validity (
    evidence_id TEXT NOT NULL REFERENCES device_identity_evidence(evidence_id) ON DELETE CASCADE,
    valid_from  TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (evidence_id, valid_from),
    CHECK (valid_until >= valid_from)
);
CREATE INDEX IF NOT EXISTS idx_device_identity_evidence_validity_time
    ON device_identity_evidence_validity(evidence_id, valid_from, valid_until);

-- A deployed 027 database contains only the aggregate. The timestamps of any
-- prior promotions are unknowable, so preserve its existing behavior by
-- treating that aggregate as the baseline at valid_from. All post-upgrade
-- strength changes are recorded at their actual observation timestamps.
-- Older schemas kept only first/last-seen aggregates, so gaps between prior
-- observations cannot be reconstructed. Preserve their prior behavior with one
-- conservative baseline window. Runtime writes use compact unions of exact
-- post-upgrade observation windows and never fill a later gap on reopen. The
-- missing-child joins also make this migration safe when a binary-only install
-- first created and populated the inline fallback schema, then later gained the
-- filesystem migration chain without a 028 ledger entry.
-- Malformed valid_from/last_seen values intentionally yield NULL below. The
-- child columns are NOT NULL, so SQLite aborts and rolls back migration 028
-- instead of silently omitting a parent or poisoning event-time history.
INSERT INTO device_address_binding_validity
    (binding_id, valid_from, valid_until, created_at)
SELECT h.binding_id,
       CASE WHEN strftime('%Y', h.valid_from) IS NULL THEN NULL ELSE h.valid_from END,
       CASE WHEN strftime('%Y', h.last_seen) IS NULL THEN NULL
            ELSE COALESCE(
                strftime('%Y-%m-%d %H:%M:%f+00:00', h.last_seen, '+24 hours'),
                '9999-12-31 23:59:59.999+00:00')
       END, h.created_at
FROM device_address_history h
LEFT JOIN device_address_binding_validity v ON v.binding_id = h.binding_id
WHERE v.binding_id IS NULL;

INSERT INTO device_identity_evidence_validity
    (evidence_id, valid_from, valid_until, created_at)
SELECT e.evidence_id,
       CASE WHEN strftime('%Y', e.valid_from) IS NULL THEN NULL ELSE e.valid_from END,
       CASE WHEN strftime('%Y', e.last_seen) IS NULL THEN NULL
            ELSE COALESCE(
                strftime('%Y-%m-%d %H:%M:%f+00:00', e.last_seen, '+7 days'),
                '9999-12-31 23:59:59.999+00:00')
       END, e.created_at
FROM device_identity_evidence e
LEFT JOIN device_identity_evidence_validity v ON v.evidence_id = e.evidence_id
WHERE v.evidence_id IS NULL;

INSERT INTO device_address_binding_strength
    (binding_id, observed_at, source, confidence, created_at)
SELECT h.binding_id,
       CASE WHEN strftime('%Y', h.valid_from) IS NULL THEN NULL ELSE h.valid_from END,
       h.evidence_source, h.confidence, h.created_at
FROM device_address_history h
LEFT JOIN device_address_binding_strength s ON s.binding_id = h.binding_id
WHERE s.binding_id IS NULL;

INSERT INTO device_identity_evidence_strength
    (evidence_id, observed_at, source, confidence, operator_confirmed, created_at)
SELECT e.evidence_id,
       CASE WHEN strftime('%Y', e.valid_from) IS NULL THEN NULL ELSE e.valid_from END,
       e.source, e.confidence, e.operator_confirmed, e.created_at
FROM device_identity_evidence e
LEFT JOIN device_identity_evidence_strength s ON s.evidence_id = e.evidence_id
WHERE s.evidence_id IS NULL;
