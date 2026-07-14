-- Support source-parent foreign-key checks and source-to-fact lookups without
-- scanning the complete device corpus version-fact table.
CREATE INDEX IF NOT EXISTS idx_device_corpus_version_facts_source
    ON device_corpus_version_facts(source_id);
