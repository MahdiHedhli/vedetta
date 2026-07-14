-- Close storage-level paths that could mutate revision evidence or lifecycle
-- metadata without creating a reviewed draft and audit entry.

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_revision_starts_draft
BEFORE INSERT ON device_corpus_profile_revisions
WHEN NEW.status <> 'draft'
  OR NEW.published_at IS NOT NULL
  OR NEW.retired_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'device corpus profile revisions must start as drafts');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_variant_revision_starts_draft
BEFORE INSERT ON device_corpus_variant_revisions
WHEN NEW.status <> 'draft'
  OR NEW.published_at IS NOT NULL
  OR NEW.withdrawn_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'device corpus variant revisions must start as drafts');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_profile_lifecycle_timestamps
BEFORE UPDATE OF published_at, retired_at ON device_corpus_profile_revisions
WHEN (
    NEW.published_at IS NOT OLD.published_at
    AND NOT (
        OLD.status = 'draft'
        AND NEW.status = 'published'
        AND OLD.published_at IS NULL
        AND NEW.published_at IS NOT NULL
    )
) OR (
    NEW.retired_at IS NOT OLD.retired_at
    AND NOT (
        OLD.status IN ('draft', 'published')
        AND NEW.status = 'retired'
        AND OLD.retired_at IS NULL
        AND NEW.retired_at IS NOT NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'device corpus profile lifecycle timestamps are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_variant_lifecycle_timestamps
BEFORE UPDATE OF published_at, withdrawn_at ON device_corpus_variant_revisions
WHEN (
    NEW.published_at IS NOT OLD.published_at
    AND NOT (
        OLD.status = 'draft'
        AND NEW.status = 'published'
        AND OLD.published_at IS NULL
        AND NEW.published_at IS NOT NULL
    )
) OR (
    NEW.withdrawn_at IS NOT OLD.withdrawn_at
    AND NOT (
        OLD.status IN ('draft', 'published')
        AND NEW.status = 'withdrawn'
        AND OLD.withdrawn_at IS NULL
        AND NEW.withdrawn_at IS NOT NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'device corpus variant lifecycle timestamps are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_source_requires_draft
BEFORE INSERT ON device_corpus_sources
WHEN NOT EXISTS (
    SELECT 1
    FROM device_corpus_variant_revisions revision
    WHERE revision.variant_revision_id = NEW.variant_revision_id
      AND revision.status = 'draft'
)
BEGIN
    SELECT RAISE(ABORT, 'device corpus evidence requires a draft revision');
END;

CREATE TRIGGER IF NOT EXISTS trg_device_corpus_fact_requires_draft_source
BEFORE INSERT ON device_corpus_version_facts
WHEN NOT EXISTS (
    SELECT 1
    FROM device_corpus_variant_revisions revision
    WHERE revision.variant_revision_id = NEW.variant_revision_id
      AND revision.status = 'draft'
) OR NOT EXISTS (
    SELECT 1
    FROM device_corpus_sources source
    WHERE source.source_id = NEW.source_id
      AND source.variant_revision_id = NEW.variant_revision_id
)
BEGIN
    SELECT RAISE(ABORT, 'device corpus fact source must belong to the same draft revision');
END;

-- INSERT OR REPLACE performs an implicit DELETE before its INSERT. DB.Open
-- enables recursive triggers so the existing append-only DELETE guards fire
-- for every corpus table; protect the mutable singleton as well so replacement
-- cannot reset the monotonic release pointer.
CREATE TRIGGER IF NOT EXISTS trg_device_corpus_no_state_delete
BEFORE DELETE ON device_corpus_state
BEGIN
    SELECT RAISE(ABORT, 'device corpus state cannot be deleted');
END;
