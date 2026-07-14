package store

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func TestMigration007GuardsRevisionEvidenceAndLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	var recursiveTriggers int
	if err := db.QueryRow(`PRAGMA recursive_triggers`).Scan(&recursiveTriggers); err != nil {
		t.Fatal(err)
	}
	if recursiveTriggers != 1 {
		t.Fatalf("recursive_triggers = %d, want 1 so replacement honors append-only guards", recursiveTriggers)
	}

	profile, err := db.CreateCorpusProfile(ctx, corpusProfileRequest(), CorpusMutation{Actor: "guard-test"})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(ctx, profile.ProfileID, corpusVariantRequest("guard-a"),
		CorpusMutation{Actor: "guard-test", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(ctx, profile.ProfileID, corpusVariantRequest("guard-b"),
		CorpusMutation{Actor: "guard-test", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variantA := corpusVariantByKey(t, profile, "guard-a")
	variantB := corpusVariantByKey(t, profile, "guard-b")
	profileRevisionID := profile.Draft.ProfileRevisionID
	revisionA := variantA.Draft.VariantRevisionID
	revisionB := variantB.Draft.VariantRevisionID
	sourceA := variantA.Draft.Sources[0].SourceID
	factA := variantA.Draft.VersionFacts[0].FactID

	for name, testCase := range map[string]struct {
		query string
		args  []any
		want  string
	}{
		"profile published timestamp without transition": {
			`UPDATE device_corpus_profile_revisions SET published_at = ? WHERE profile_revision_id = ?`,
			[]any{"2026-07-13T12:00:00Z", profileRevisionID}, "profile lifecycle timestamps are immutable",
		},
		"profile retired timestamp without transition": {
			`UPDATE device_corpus_profile_revisions SET retired_at = ? WHERE profile_revision_id = ?`,
			[]any{"2026-07-13T12:00:00Z", profileRevisionID}, "profile lifecycle timestamps are immutable",
		},
		"variant published timestamp without transition": {
			`UPDATE device_corpus_variant_revisions SET published_at = ? WHERE variant_revision_id = ?`,
			[]any{"2026-07-13T12:00:00Z", revisionA}, "variant lifecycle timestamps are immutable",
		},
		"variant withdrawn timestamp without transition": {
			`UPDATE device_corpus_variant_revisions SET withdrawn_at = ? WHERE variant_revision_id = ?`,
			[]any{"2026-07-13T12:00:00Z", revisionA}, "variant lifecycle timestamps are immutable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireCorpusSQLRejected(t, db, testCase.want, testCase.query, testCase.args...)
		})
	}

	requireCorpusSQLRejected(t, db, "same draft revision", `INSERT INTO device_corpus_version_facts
		(fact_id, variant_revision_id, attribute, relation, value, value_end,
		 confidence_bp, source_id, created_at)
		VALUES ('00000000-0000-4000-8000-000000000701', ?, 'firmware_version',
		 'exact', '9.9.9', '', 9000, ?, '2026-07-13T12:00:00Z')`, revisionB, sourceA)

	// Recursive triggers must make every replacement conflict execute the
	// original append-only DELETE guard. These statements reproduce the bypass
	// that existed when recursive_triggers used SQLite's default OFF setting.
	requireCorpusSQLRejected(t, db, "profiles are append-only", `INSERT OR REPLACE INTO device_corpus_profiles
		(profile_id, created_at)
		SELECT profile_id, '2026-07-13T12:00:00Z'
		FROM device_corpus_profiles WHERE profile_id = ?`, profile.ProfileID)
	requireCorpusSQLRejected(t, db, "profile revisions are append-only", `INSERT OR REPLACE INTO device_corpus_profile_revisions
		(profile_revision_id, profile_id, revision, supersedes_profile_revision_id,
		 label_key, manufacturer, model, product_family, device_type, os_family,
		 status, created_at, published_at, retired_at)
		SELECT profile_revision_id, profile_id, revision, supersedes_profile_revision_id,
		 label_key, manufacturer, 'replacement model', product_family, device_type, os_family,
		 'draft', created_at, NULL, NULL
		FROM device_corpus_profile_revisions WHERE profile_revision_id = ?`, profileRevisionID)
	requireCorpusSQLRejected(t, db, "profile revisions are append-only", `INSERT OR REPLACE INTO device_corpus_profile_revisions
		(profile_revision_id, profile_id, revision, supersedes_profile_revision_id,
		 label_key, manufacturer, model, product_family, device_type, os_family,
		 status, created_at, published_at, retired_at)
		SELECT '00000000-0000-4000-8000-000000000709', profile_id, revision,
		 supersedes_profile_revision_id, label_key, manufacturer, model, product_family,
		 device_type, os_family, 'draft', created_at, NULL, NULL
		FROM device_corpus_profile_revisions WHERE profile_revision_id = ?`, profileRevisionID)
	requireCorpusSQLRejected(t, db, "shapes are append-only", `INSERT OR REPLACE INTO device_corpus_shapes
		(shape_hash, schema_version, canonical_json, signal_family_count, created_at)
		SELECT shape_hash, schema_version, canonical_json, signal_family_count,
		 '2026-07-13T12:00:00Z'
		FROM device_corpus_shapes WHERE shape_hash =
		 (SELECT shape_hash FROM device_corpus_variant_revisions WHERE variant_revision_id = ?)`, revisionA)
	requireCorpusSQLRejected(t, db, "variants are append-only", `INSERT OR REPLACE INTO device_corpus_variants
		(variant_id, profile_id, variant_key, predecessor_variant_id, created_at)
		SELECT variant_id, profile_id, variant_key, predecessor_variant_id,
		 '2026-07-13T12:00:00Z'
		FROM device_corpus_variants WHERE variant_id = ?`, variantA.VariantID)
	requireCorpusSQLRejected(t, db, "variant revisions are append-only", `INSERT OR REPLACE INTO device_corpus_variant_revisions
		(variant_revision_id, variant_id, revision, supersedes_revision_id, shape_hash,
		 confidence_bp, status, created_at, published_at, withdrawn_at)
		SELECT variant_revision_id, variant_id, revision, supersedes_revision_id, shape_hash,
		 1, 'draft', created_at, NULL, NULL
		FROM device_corpus_variant_revisions WHERE variant_revision_id = ?`, revisionA)
	requireCorpusSQLRejected(t, db, "variant revisions are append-only", `INSERT OR REPLACE INTO device_corpus_variant_revisions
		(variant_revision_id, variant_id, revision, supersedes_revision_id, shape_hash,
		 confidence_bp, status, created_at, published_at, withdrawn_at)
		SELECT '00000000-0000-4000-8000-000000000710', variant_id, revision,
		 supersedes_revision_id, shape_hash, confidence_bp, 'draft', created_at, NULL, NULL
		FROM device_corpus_variant_revisions WHERE variant_revision_id = ?`, revisionA)
	requireCorpusSQLRejected(t, db, "sources are append-only", `INSERT OR REPLACE INTO device_corpus_sources
		(source_id, variant_revision_id, kind, title, public_url, retrieved_at, license_code, created_at)
		SELECT source_id, variant_revision_id, kind, 'replacement source', public_url,
		 retrieved_at, license_code, created_at
		FROM device_corpus_sources WHERE source_id = ?`, sourceA)
	requireCorpusSQLRejected(t, db, "version facts are append-only", `INSERT OR REPLACE INTO device_corpus_version_facts
		(fact_id, variant_revision_id, attribute, relation, value, value_end,
		 confidence_bp, source_id, created_at)
		SELECT fact_id, variant_revision_id, attribute, relation, 'replacement fact', value_end,
		 confidence_bp, source_id, created_at
		FROM device_corpus_version_facts WHERE fact_id = ?`, factA)
	requireCorpusSQLRejected(t, db, "version facts are append-only", `INSERT OR REPLACE INTO device_corpus_version_facts
		(fact_id, variant_revision_id, attribute, relation, value, value_end,
		 confidence_bp, source_id, created_at)
		SELECT '00000000-0000-4000-8000-000000000711', variant_revision_id, attribute,
		 relation, value, value_end, confidence_bp, source_id, created_at
		FROM device_corpus_version_facts WHERE fact_id = ?`, factA)
	var auditID string
	if err = db.QueryRow(`SELECT audit_id FROM device_corpus_audit ORDER BY created_at, audit_id LIMIT 1`).Scan(&auditID); err != nil {
		t.Fatal(err)
	}
	requireCorpusSQLRejected(t, db, "audit is append-only", `INSERT OR REPLACE INTO device_corpus_audit
		(audit_id, actor, entity_type, entity_id, action, reason_code, before_hash,
		 after_hash, request_id, corpus_revision, created_at)
		SELECT audit_id, 'replacement actor', entity_type, entity_id, action, reason_code,
		 before_hash, after_hash, request_id, corpus_revision, created_at
		FROM device_corpus_audit WHERE audit_id = ?`, auditID)

	if _, err = db.Exec(`INSERT INTO device_corpus_profiles (profile_id, created_at)
		VALUES ('00000000-0000-4000-8000-000000000702', '2026-07-13T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	requireCorpusSQLRejected(t, db, "profile revisions must start as drafts", `INSERT INTO device_corpus_profile_revisions
		(profile_revision_id, profile_id, revision, label_key, manufacturer, model,
		 product_family, device_type, os_family, status, created_at, published_at)
		VALUES ('00000000-0000-4000-8000-000000000703',
		 '00000000-0000-4000-8000-000000000702', 1, ?, 'Direct', 'Publish', '',
		 'camera', 'embedded', 'published', '2026-07-13T12:00:00Z',
		 '2026-07-13T12:00:00Z')`, strings.Repeat("7", 64))
	var shapeHash string
	if err = db.QueryRow(`SELECT shape_hash FROM device_corpus_variant_revisions
		WHERE variant_revision_id = ?`, revisionA).Scan(&shapeHash); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO device_corpus_variants
		(variant_id, profile_id, variant_key, created_at)
		VALUES ('00000000-0000-4000-8000-000000000704',
		 '00000000-0000-4000-8000-000000000702', 'direct-publish',
		 '2026-07-13T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	requireCorpusSQLRejected(t, db, "variant revisions must start as drafts", `INSERT INTO device_corpus_variant_revisions
		(variant_revision_id, variant_id, revision, shape_hash, confidence_bp,
		 status, created_at, published_at)
		VALUES ('00000000-0000-4000-8000-000000000705',
		 '00000000-0000-4000-8000-000000000704', 1, ?, 9000, 'published',
		 '2026-07-13T12:00:00Z', '2026-07-13T12:00:00Z')`, shapeHash)

	profile, err = db.PublishCorpusProfile(ctx, profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{Actor: "guard-test", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatalf("normal draft publication failed under migration 007: %v", err)
	}
	variantA = corpusVariantByKey(t, profile, "guard-a")
	revisionA = variantA.Published.VariantRevisionID
	sourceA = variantA.Published.Sources[0].SourceID

	requireCorpusSQLRejected(t, db, "evidence requires a draft revision", `INSERT INTO device_corpus_sources
		(source_id, variant_revision_id, kind, title, public_url, created_at)
		VALUES ('00000000-0000-4000-8000-000000000706', ?, 'vendor_doc',
		 'late source', 'https://docs.example.com/late', '2026-07-13T12:00:00Z')`, revisionA)
	requireCorpusSQLRejected(t, db, "same draft revision", `INSERT INTO device_corpus_version_facts
		(fact_id, variant_revision_id, attribute, relation, value, value_end,
		 confidence_bp, source_id, created_at)
		VALUES ('00000000-0000-4000-8000-000000000707', ?, 'firmware_version',
		 'exact', '9.9.9', '', 9000, ?, '2026-07-13T12:00:00Z')`, revisionA, sourceA)
	requireCorpusSQLRejected(t, db, "profile lifecycle timestamps are immutable", `UPDATE device_corpus_profile_revisions
		SET published_at = '2026-07-13T12:00:00Z' WHERE profile_revision_id = ?`,
		profile.Published.ProfileRevisionID)
	requireCorpusSQLRejected(t, db, "variant lifecycle timestamps are immutable", `UPDATE device_corpus_variant_revisions
		SET published_at = '2026-07-13T12:00:00Z' WHERE variant_revision_id = ?`, revisionA)
	requireCorpusSQLRejected(t, db, "releases are append-only", `INSERT OR REPLACE INTO device_corpus_releases
		(corpus_revision, schema_version, snapshot_sha256, snapshot_json,
		 profile_count, variant_count, created_at)
		SELECT corpus_revision, schema_version, snapshot_sha256, snapshot_json,
		 profile_count, variant_count, created_at
		FROM device_corpus_releases WHERE corpus_revision = 1`)
	requireCorpusSQLRejected(t, db, "releases are append-only", `INSERT OR REPLACE INTO device_corpus_releases
		(corpus_revision, schema_version, snapshot_sha256, snapshot_json,
		 profile_count, variant_count, created_at)
		SELECT 99, schema_version, snapshot_sha256, snapshot_json,
		 profile_count, variant_count, created_at
		FROM device_corpus_releases WHERE corpus_revision = 1`)
	requireCorpusSQLRejected(t, db, "state cannot be deleted", `INSERT OR REPLACE INTO device_corpus_state
		(singleton, schema_version, current_revision, current_snapshot_sha256, updated_at)
		SELECT singleton, schema_version, 0, '', updated_at
		FROM device_corpus_state WHERE singleton = 1`)

	profile, err = db.WithdrawCorpusVariant(ctx, variantA.VariantID,
		corpusLifecycleRequest("privacy_withdrawal", 1), CorpusMutation{Actor: "guard-test", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatalf("normal published-to-withdrawn transition failed under migration 007: %v", err)
	}
	variantA = corpusVariantByKey(t, profile, "guard-a")
	requireCorpusSQLRejected(t, db, "variant lifecycle timestamps are immutable", `UPDATE device_corpus_variant_revisions
		SET withdrawn_at = '2026-07-13T12:00:00Z' WHERE variant_revision_id = ?`,
		variantA.History[0].VariantRevisionID)

	profile, err = db.RetireCorpusProfile(ctx, profile.ProfileID,
		corpusLifecycleRequest("obsolete_product", 2), CorpusMutation{Actor: "guard-test", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatalf("normal published-to-retired transition failed under migration 007: %v", err)
	}
	requireCorpusSQLRejected(t, db, "profile lifecycle timestamps are immutable", `UPDATE device_corpus_profile_revisions
		SET retired_at = '2026-07-13T12:00:00Z' WHERE profile_revision_id = ?`,
		profile.History[0].ProfileRevisionID)
}

func TestMigration007UpgradesPublishedCorpusWithoutDataLoss(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "corpus-v6.db")
	legacy := openCorpusMigrationFixture(t, path, 6)
	profile, err := legacy.CreateCorpusProfile(ctx, corpusProfileRequest(), CorpusMutation{Actor: "v6-curator"})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = legacy.CreateCorpusVariant(ctx, profile.ProfileID, corpusVariantRequest("v6-published"),
		CorpusMutation{Actor: "v6-curator", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = legacy.PublishCorpusProfile(ctx, profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{Actor: "v6-curator", ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profileID := profile.ProfileID
	variantID := profile.Variants[0].VariantID
	oldRevisionID := profile.Variants[0].Published.VariantRevisionID
	oldSnapshot, oldManifest, err := legacy.CurrentCorpusSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var migration007 int
	if err = legacy.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 7`).Scan(&migration007); err != nil {
		t.Fatal(err)
	}
	if migration007 != 0 {
		t.Fatal("migration-006 fixture unexpectedly contains migration 007")
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 7`).Scan(&migration007); err != nil {
		t.Fatal(err)
	}
	if migration007 != 1 {
		t.Fatalf("migration 007 application count = %d, want 1", migration007)
	}
	upgraded, err := db.GetCorpusProfile(ctx, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Published == nil || upgraded.Variants[0].Published == nil ||
		upgraded.Variants[0].Published.VariantRevisionID != oldRevisionID {
		t.Fatalf("migration 007 did not preserve published corpus state: %+v", upgraded)
	}
	newSnapshot, newManifest, err := db.CurrentCorpusSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newSnapshot, oldSnapshot) || newManifest != oldManifest {
		t.Fatalf("migration 007 changed the current release: old=%+v new=%+v", oldManifest, newManifest)
	}
	requireCorpusSQLRejected(t, db, "evidence requires a draft revision", `INSERT INTO device_corpus_sources
		(source_id, variant_revision_id, kind, title, public_url, created_at)
		VALUES ('00000000-0000-4000-8000-000000000708', ?, 'vendor_doc',
		 'late upgraded source', 'https://docs.example.com/late-upgrade',
		 '2026-07-13T12:00:00Z')`, oldRevisionID)

	clean := corpusVariantRequest("unused")
	upgraded, err = db.ReviseCorpusVariant(ctx, variantID, corpus.ReviseVariantRequest{
		ConfidenceBP: 9300,
		Shape:        clean.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "source_update",
	}, CorpusMutation{Actor: "v7-curator", ExpectedETag: upgraded.ETag})
	if err != nil {
		t.Fatalf("normal revision failed after migration 007: %v", err)
	}
	upgraded, err = db.PublishCorpusProfile(ctx, profileID, corpusPublishRequest(1),
		CorpusMutation{Actor: "v7-curator", ExpectedETag: upgraded.ETag})
	if err != nil {
		t.Fatalf("normal publication failed after migration 007: %v", err)
	}
	upgraded, err = db.WithdrawCorpusVariant(ctx, variantID,
		corpusLifecycleRequest("privacy_withdrawal", 2), CorpusMutation{Actor: "v7-curator", ExpectedETag: upgraded.ETag})
	if err != nil {
		t.Fatalf("normal withdrawal failed after migration 007: %v", err)
	}
	upgraded, err = db.RetireCorpusProfile(ctx, profileID,
		corpusLifecycleRequest("obsolete_product", 3), CorpusMutation{Actor: "v7-curator", ExpectedETag: upgraded.ETag})
	if err != nil {
		t.Fatalf("normal retirement failed after migration 007: %v", err)
	}
	if upgraded.History[0].Status != "retired" {
		t.Fatalf("retired upgraded profile status = %q", upgraded.History[0].Status)
	}

	if err = db.migrate(); err != nil {
		t.Fatalf("migration 007 was not idempotent: %v", err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 7`).Scan(&migration007); err != nil {
		t.Fatal(err)
	}
	if migration007 != 1 {
		t.Fatalf("idempotent migration-007 application count = %d, want 1", migration007)
	}
	foreignKeys, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignKeys.Close()
	if foreignKeys.Next() {
		t.Fatal("foreign_key_check reported a violation after migration 007")
	}
	if err = foreignKeys.Err(); err != nil {
		t.Fatal(err)
	}
}

func openCorpusMigrationFixture(t *testing.T, path string, maxVersion int) *DB {
	t.Helper()
	raw, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	if _, err = raw.Exec(`CREATE TABLE schema_migrations
		(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, parseErr := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if parseErr != nil {
			raw.Close()
			t.Fatal(parseErr)
		}
		if version > maxVersion {
			continue
		}
		body, readErr := migrationsFS.ReadFile("migrations/" + name)
		if readErr != nil {
			raw.Close()
			t.Fatal(readErr)
		}
		if _, err = raw.Exec(string(body)); err != nil {
			raw.Close()
			t.Fatalf("apply %s: %v", name, err)
		}
		if _, err = raw.Exec(`INSERT INTO schema_migrations(version, applied_at)
			VALUES (?, '2026-01-01T00:00:00Z')`, version); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	return &DB{DB: raw, corpusLoadGate: make(chan struct{}, 1)}
}

func corpusVariantByKey(t *testing.T, profile *corpus.Profile, key string) corpus.Variant {
	t.Helper()
	for _, variant := range profile.Variants {
		if variant.VariantKey == key {
			return variant
		}
	}
	t.Fatalf("profile %s has no variant %q", profile.ProfileID, key)
	return corpus.Variant{}
}

func requireCorpusSQLRejected(t *testing.T, db *DB, want string, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err == nil {
		t.Fatalf("SQL unexpectedly succeeded; wanted error containing %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Fatalf("SQL error = %q, want substring %q", err, want)
	}
}
