-- Support lineage-dependent withdrawal/discard checks and self-referential
-- foreign-key enforcement without scanning every corpus variant.
CREATE INDEX IF NOT EXISTS idx_device_corpus_variants_predecessor
    ON device_corpus_variants(predecessor_variant_id);
