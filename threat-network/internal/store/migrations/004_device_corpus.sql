-- Privacy-reduced, manually curated device fingerprint corpus (schema v1).
-- This is a separate content plane from reporter telemetry and community feed data.
-- Published records are immutable; curator corrections create new revisions.

CREATE TABLE IF NOT EXISTS device_corpus_state (
    singleton               INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version          INTEGER NOT NULL CHECK (schema_version = 1),
    current_revision        INTEGER NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    current_snapshot_sha256 TEXT NOT NULL DEFAULT '',
    updated_at              TEXT NOT NULL
);

INSERT OR IGNORE INTO device_corpus_state
    (singleton, schema_version, current_revision, current_snapshot_sha256, updated_at)
VALUES (1, 1, 0, '', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

-- Stable product identity. Human-readable labels live in immutable revisions.
CREATE TABLE IF NOT EXISTS device_corpus_profiles (
    profile_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_corpus_profile_revisions (
    profile_revision_id           TEXT PRIMARY KEY,
    profile_id                    TEXT NOT NULL REFERENCES device_corpus_profiles(profile_id) ON DELETE RESTRICT,
    revision                      INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_profile_revision_id TEXT REFERENCES device_corpus_profile_revisions(profile_revision_id) ON DELETE RESTRICT,
    label_key                     TEXT NOT NULL CHECK (length(label_key) = 64),
    manufacturer                  TEXT NOT NULL,
    model                         TEXT NOT NULL,
    product_family                TEXT NOT NULL DEFAULT '',
    device_type                   TEXT NOT NULL,
    os_family                     TEXT NOT NULL DEFAULT '',
    status                        TEXT NOT NULL CHECK (status IN ('draft','published','superseded','retired')),
    created_at                    TEXT NOT NULL,
    published_at                  TEXT,
    retired_at                    TEXT,
    UNIQUE (profile_id, revision)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_device_corpus_profile_one_draft
    ON device_corpus_profile_revisions(profile_id) WHERE status = 'draft';
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_corpus_profile_one_published
    ON device_corpus_profile_revisions(profile_id) WHERE status = 'published';
CREATE INDEX IF NOT EXISTS idx_device_corpus_profile_labels
    ON device_corpus_profile_revisions(status, manufacturer, model, device_type);
CREATE INDEX IF NOT EXISTS idx_device_corpus_profile_label_key
    ON device_corpus_profile_revisions(label_key, status);

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_identity_unique_insert
BEFORE INSERT ON device_corpus_profile_revisions
WHEN NEW.status IN ('draft','published') AND EXISTS (
    SELECT 1 FROM device_corpus_profile_revisions existing
    WHERE existing.label_key = NEW.label_key
      AND existing.profile_id <> NEW.profile_id
      AND existing.status IN ('draft','published')
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate active device corpus profile identity');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_identity_unique_update
BEFORE UPDATE OF status ON device_corpus_profile_revisions
WHEN NEW.status IN ('draft','published') AND EXISTS (
    SELECT 1 FROM device_corpus_profile_revisions existing
    WHERE existing.label_key = NEW.label_key
      AND existing.profile_id <> NEW.profile_id
      AND existing.status IN ('draft','published')
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate active device corpus profile identity');
END;

-- Deduplicated, fixed-schema signal shapes. The hash is a content address only;
-- privacy comes from the structural allowlist enforced before this table.
CREATE TABLE IF NOT EXISTS device_corpus_shapes (
    shape_hash          TEXT PRIMARY KEY CHECK (length(shape_hash) = 64),
    schema_version      INTEGER NOT NULL CHECK (schema_version = 1),
    canonical_json      TEXT NOT NULL,
    signal_family_count INTEGER NOT NULL CHECK (signal_family_count >= 1),
    created_at          TEXT NOT NULL
);

-- One logical external firmware/hardware lineage. predecessor_variant_id means
-- real product evolution; it is deliberately separate from curator revision links.
CREATE TABLE IF NOT EXISTS device_corpus_variants (
    variant_id             TEXT PRIMARY KEY,
    profile_id             TEXT NOT NULL REFERENCES device_corpus_profiles(profile_id) ON DELETE RESTRICT,
    variant_key            TEXT NOT NULL,
    predecessor_variant_id TEXT REFERENCES device_corpus_variants(variant_id) ON DELETE RESTRICT,
    created_at             TEXT NOT NULL,
    UNIQUE (profile_id, variant_key)
);

CREATE INDEX IF NOT EXISTS idx_device_corpus_variants_profile
    ON device_corpus_variants(profile_id, created_at);

-- One curator revision of a logical variant. supersedes_revision_id is a data
-- correction; older firmware remains a separate published variant series.
CREATE TABLE IF NOT EXISTS device_corpus_variant_revisions (
    variant_revision_id  TEXT PRIMARY KEY,
    variant_id           TEXT NOT NULL REFERENCES device_corpus_variants(variant_id) ON DELETE RESTRICT,
    revision             INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_revision_id TEXT REFERENCES device_corpus_variant_revisions(variant_revision_id) ON DELETE RESTRICT,
    shape_hash           TEXT NOT NULL REFERENCES device_corpus_shapes(shape_hash) ON DELETE RESTRICT,
    confidence_bp        INTEGER NOT NULL CHECK (confidence_bp BETWEEN 0 AND 10000),
    status               TEXT NOT NULL CHECK (status IN ('draft','published','superseded','withdrawn')),
    created_at           TEXT NOT NULL,
    published_at         TEXT,
    withdrawn_at         TEXT,
    UNIQUE (variant_id, revision)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_device_corpus_variant_one_draft
    ON device_corpus_variant_revisions(variant_id) WHERE status = 'draft';
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_corpus_variant_one_published
    ON device_corpus_variant_revisions(variant_id) WHERE status = 'published';
CREATE INDEX IF NOT EXISTS idx_device_corpus_variant_shape
    ON device_corpus_variant_revisions(shape_hash, status);

CREATE TABLE IF NOT EXISTS device_corpus_sources (
    source_id            TEXT PRIMARY KEY,
    variant_revision_id  TEXT NOT NULL REFERENCES device_corpus_variant_revisions(variant_revision_id) ON DELETE RESTRICT,
    kind                 TEXT NOT NULL CHECK (kind IN
        ('vendor_doc','standards','security_advisory','lab_observation','manual_curation','import')),
    title                TEXT NOT NULL DEFAULT '',
    public_url           TEXT NOT NULL DEFAULT '',
    retrieved_at         TEXT,
    license_code         TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_corpus_sources_revision
    ON device_corpus_sources(variant_revision_id, kind);

CREATE TABLE IF NOT EXISTS device_corpus_version_facts (
    fact_id              TEXT PRIMARY KEY,
    variant_revision_id  TEXT NOT NULL REFERENCES device_corpus_variant_revisions(variant_revision_id) ON DELETE RESTRICT,
    attribute            TEXT NOT NULL CHECK (attribute IN
        ('firmware_version','os_version','hardware_revision','model_number','software_version')),
    relation             TEXT NOT NULL CHECK (relation IN ('exact','range','family')),
    value                TEXT NOT NULL,
    value_end            TEXT NOT NULL DEFAULT '',
    confidence_bp        INTEGER NOT NULL CHECK (confidence_bp BETWEEN 0 AND 10000),
    source_id            TEXT NOT NULL REFERENCES device_corpus_sources(source_id) ON DELETE RESTRICT,
    created_at           TEXT NOT NULL,
    UNIQUE (variant_revision_id, attribute, relation, value, value_end, source_id)
);

CREATE INDEX IF NOT EXISTS idx_device_corpus_version_facts_revision
    ON device_corpus_version_facts(variant_revision_id, attribute);

CREATE TABLE IF NOT EXISTS device_corpus_audit (
    audit_id       TEXT PRIMARY KEY,
    actor          TEXT NOT NULL,
    entity_type    TEXT NOT NULL CHECK (entity_type IN ('profile','variant','release')),
    entity_id      TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN
        ('create','revise','publish','supersede','withdraw','retire','restore')),
    reason_code    TEXT NOT NULL CHECK (reason_code IN
        ('new_profile','new_variant','label_correction','signal_correction','firmware_evolution',
         'source_update','publish_reviewed','privacy_withdrawal','obsolete_product','restore_reviewed')),
    before_hash    TEXT NOT NULL DEFAULT '',
    after_hash     TEXT NOT NULL DEFAULT '',
    request_id     TEXT NOT NULL DEFAULT '',
    corpus_revision INTEGER,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_corpus_audit_created
    ON device_corpus_audit(created_at DESC, entity_type, entity_id);

-- Complete immutable public snapshots. Release bytes never change; restoring an
-- older snapshot is an explicit operator/database recovery action.
CREATE TABLE IF NOT EXISTS device_corpus_releases (
    corpus_revision INTEGER PRIMARY KEY CHECK (corpus_revision >= 1),
    schema_version  INTEGER NOT NULL CHECK (schema_version = 1),
    snapshot_sha256 TEXT NOT NULL UNIQUE CHECK (length(snapshot_sha256) = 64),
    snapshot_json   TEXT NOT NULL,
    profile_count   INTEGER NOT NULL CHECK (profile_count >= 0),
    variant_count   INTEGER NOT NULL CHECK (variant_count >= 0),
    created_at      TEXT NOT NULL
);

-- Immutable-content and append-only guards. Revision content never changes;
-- lifecycle state changes in place. A never-published stable variant may correct
-- only its predecessor before restart, and the next trigger freezes it forever
-- after first publication.
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_content_immutable
BEFORE UPDATE OF profile_id, revision, supersedes_profile_revision_id, label_key,
    manufacturer, model, product_family, device_type, os_family, created_at
ON device_corpus_profile_revisions
BEGIN
    SELECT RAISE(ABORT, 'device corpus profile revision content is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_status_transition
BEFORE UPDATE OF status ON device_corpus_profile_revisions
WHEN NOT (
    (OLD.status = 'draft' AND NEW.status IN ('published','superseded','retired')) OR
    (OLD.status = 'published' AND NEW.status IN ('superseded','retired'))
)
  OR (NEW.status = 'published' AND NEW.published_at IS NULL)
  OR (NEW.status = 'retired' AND NEW.retired_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'invalid device corpus profile status transition');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_variant_content_immutable
BEFORE UPDATE OF variant_id, revision, supersedes_revision_id, shape_hash,
    confidence_bp, created_at
ON device_corpus_variant_revisions
BEGIN
    SELECT RAISE(ABORT, 'device corpus variant revision content is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_variant_status_transition
BEFORE UPDATE OF status ON device_corpus_variant_revisions
WHEN NOT (
    (OLD.status = 'draft' AND NEW.status IN ('published','superseded','withdrawn')) OR
    (OLD.status = 'published' AND NEW.status IN ('superseded','withdrawn'))
)
  OR (NEW.status = 'published' AND NEW.published_at IS NULL)
  OR (NEW.status = 'withdrawn' AND NEW.withdrawn_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'invalid device corpus variant status transition');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_variant_identity_immutable
BEFORE UPDATE OF profile_id, variant_key, predecessor_variant_id, created_at
ON device_corpus_variants
WHEN OLD.profile_id <> NEW.profile_id
  OR OLD.variant_key <> NEW.variant_key
  OR OLD.created_at <> NEW.created_at
  OR EXISTS (
      SELECT 1 FROM device_corpus_variant_revisions vr
      WHERE vr.variant_id = OLD.variant_id AND vr.published_at IS NOT NULL
  )
BEGIN
    SELECT RAISE(ABORT, 'published device corpus variant identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_shapes_immutable
BEFORE UPDATE ON device_corpus_shapes
BEGIN
    SELECT RAISE(ABORT, 'device corpus shape is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_profile_delete
BEFORE DELETE ON device_corpus_profiles
BEGIN SELECT RAISE(ABORT, 'device corpus profiles are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_profile_revision_delete
BEFORE DELETE ON device_corpus_profile_revisions
BEGIN SELECT RAISE(ABORT, 'device corpus profile revisions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_shape_delete
BEFORE DELETE ON device_corpus_shapes
BEGIN SELECT RAISE(ABORT, 'device corpus shapes are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_variant_delete
BEFORE DELETE ON device_corpus_variants
BEGIN SELECT RAISE(ABORT, 'device corpus variants are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_variant_revision_delete
BEFORE DELETE ON device_corpus_variant_revisions
BEGIN SELECT RAISE(ABORT, 'device corpus variant revisions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_source_update
BEFORE UPDATE ON device_corpus_sources
BEGIN SELECT RAISE(ABORT, 'device corpus sources are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_source_delete
BEFORE DELETE ON device_corpus_sources
BEGIN SELECT RAISE(ABORT, 'device corpus sources are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_fact_update
BEFORE UPDATE ON device_corpus_version_facts
BEGIN SELECT RAISE(ABORT, 'device corpus version facts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_fact_delete
BEFORE DELETE ON device_corpus_version_facts
BEGIN SELECT RAISE(ABORT, 'device corpus version facts are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_audit_update
BEFORE UPDATE ON device_corpus_audit
BEGIN SELECT RAISE(ABORT, 'device corpus audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_audit_delete
BEFORE DELETE ON device_corpus_audit
BEGIN SELECT RAISE(ABORT, 'device corpus audit is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_release_update
BEFORE UPDATE ON device_corpus_releases
BEGIN SELECT RAISE(ABORT, 'device corpus releases are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_release_delete
BEFORE DELETE ON device_corpus_releases
BEGIN SELECT RAISE(ABORT, 'device corpus releases are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_state_monotonic
BEFORE UPDATE ON device_corpus_state
WHEN NEW.schema_version <> OLD.schema_version
  OR NEW.current_revision < OLD.current_revision
  OR (NEW.current_revision > 0 AND NOT EXISTS (
      SELECT 1 FROM device_corpus_releases r
      WHERE r.corpus_revision = NEW.current_revision
        AND r.snapshot_sha256 = NEW.current_snapshot_sha256
  ))
BEGIN
    SELECT RAISE(ABORT, 'invalid device corpus state transition');
END;
