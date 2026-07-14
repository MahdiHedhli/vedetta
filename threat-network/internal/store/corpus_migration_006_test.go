package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigration006AddsPredecessorIndexToExistingCorpusDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus-upgrade.db")
	raw, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"001_init.sql", "002_receipts_per_reporter.sql", "003_signals_first_received.sql",
		"004_device_corpus.sql", "005_device_corpus_fact_source_index.sql",
	} {
		body, readErr := migrationsFS.ReadFile("migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = raw.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		version := int(name[2] - '0')
		if _, err = raw.Exec(`INSERT INTO schema_migrations(version, applied_at)
			VALUES (?, '2026-01-01T00:00:00Z')`, version); err != nil {
			t.Fatal(err)
		}
	}
	var indexes int
	if err = raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'idx_device_corpus_variants_predecessor'`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != 0 {
		t.Fatal("migration-005 fixture unexpectedly contains migration-006 index")
	}
	if _, err = raw.Exec(`
		INSERT INTO device_corpus_profiles (profile_id, created_at)
		VALUES ('upgrade-profile', '2026-01-01T00:00:00Z');
		INSERT INTO device_corpus_variants
			(variant_id, profile_id, variant_key, predecessor_variant_id, created_at)
		VALUES ('upgrade-base', 'upgrade-profile', 'base', NULL, '2026-01-01T00:00:00Z');
		INSERT INTO device_corpus_variants
			(variant_id, profile_id, variant_key, predecessor_variant_id, created_at)
		VALUES ('upgrade-child', 'upgrade-profile', 'child', 'upgrade-base', '2026-01-01T00:00:00Z');`); err != nil {
		t.Fatalf("seed migration-005 corpus lineage: %v", err)
	}
	shapeHash := strings.Repeat("a", 64)
	if _, err = raw.Exec(`
		INSERT INTO device_corpus_shapes
			(shape_hash, schema_version, canonical_json, signal_family_count, created_at)
		VALUES (?, 1, '{"schema_version":1,"mdns_models":["Upgrade Camera"]}', 1,
			'2026-01-01T00:00:00Z');
		INSERT INTO device_corpus_variant_revisions
			(variant_revision_id, variant_id, revision, shape_hash, confidence_bp, status, created_at)
		VALUES ('upgrade-base-revision', 'upgrade-base', 1, ?, 9000, 'draft',
			'2026-01-01T00:00:00Z');
		INSERT INTO device_corpus_variant_revisions
			(variant_revision_id, variant_id, revision, shape_hash, confidence_bp, status, created_at)
		VALUES ('upgrade-child-revision', 'upgrade-child', 1, ?, 9000, 'draft',
			'2026-01-01T00:00:00Z');`, shapeHash, shapeHash, shapeHash); err != nil {
		t.Fatalf("seed migration-005 active revisions: %v", err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err = db.QueryRow(`SELECT name FROM sqlite_master
		WHERE type = 'index' AND name = 'idx_device_corpus_variants_predecessor'`).Scan(&name); err != nil {
		t.Fatalf("migration 006 did not create predecessor index: %v", err)
	}
	if name != "idx_device_corpus_variants_predecessor" {
		t.Fatalf("unexpected migration-006 index name: %q", name)
	}
	indexRows, err := db.Query(`PRAGMA index_info('idx_device_corpus_variants_predecessor')`)
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for indexRows.Next() {
		var sequence, columnID int
		var column string
		if err = indexRows.Scan(&sequence, &columnID, &column); err != nil {
			indexRows.Close()
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err = indexRows.Err(); err != nil {
		indexRows.Close()
		t.Fatal(err)
	}
	if err = indexRows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(columns) != 1 || columns[0] != "predecessor_variant_id" {
		t.Fatalf("migration-006 index columns = %v, want [predecessor_variant_id]", columns)
	}
	var predecessor string
	if err = db.QueryRow(`SELECT predecessor_variant_id FROM device_corpus_variants
		WHERE variant_id = 'upgrade-child'`).Scan(&predecessor); err != nil {
		t.Fatalf("migration 006 lost existing lineage: %v", err)
	}
	if predecessor != "upgrade-base" {
		t.Fatalf("retained predecessor = %q, want upgrade-base", predecessor)
	}
	planRows, err := db.Query(`EXPLAIN QUERY PLAN SELECT COUNT(DISTINCT child.variant_id)
		FROM device_corpus_variants child
		JOIN device_corpus_variant_revisions revision ON revision.variant_id = child.variant_id
		WHERE child.predecessor_variant_id = ? AND revision.status IN ('draft','published')`, "upgrade-base")
	if err != nil {
		t.Fatal(err)
	}
	var planDetails []string
	for planRows.Next() {
		var id, parent, unused int
		var detail string
		if err = planRows.Scan(&id, &parent, &unused, &detail); err != nil {
			planRows.Close()
			t.Fatal(err)
		}
		planDetails = append(planDetails, detail)
	}
	if err = planRows.Err(); err != nil {
		planRows.Close()
		t.Fatal(err)
	}
	if err = planRows.Close(); err != nil {
		t.Fatal(err)
	}
	if plan := strings.Join(planDetails, " | "); !strings.Contains(plan, name) {
		t.Fatalf("predecessor lookup does not use migration-006 index: %s", plan)
	}
	var applied int
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 6`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 006 application count = %d, want 1", applied)
	}
	foreignKeys, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if foreignKeys.Next() {
		foreignKeys.Close()
		t.Fatal("foreign_key_check reported a violation after migration 006")
	}
	if err = foreignKeys.Err(); err != nil {
		foreignKeys.Close()
		t.Fatal(err)
	}
	if err = foreignKeys.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.migrate(); err != nil {
		t.Fatalf("migration 006 was not idempotent: %v", err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 6`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("idempotent migration-006 application count = %d, want 1", applied)
	}
}
