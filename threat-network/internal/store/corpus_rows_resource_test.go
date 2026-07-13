package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Open configures SQLite with one connection. A corpus iterator left open on
// an error therefore pins the entire store. Keep the assertion bounded so a
// regression fails clearly instead of hanging the suite.
func assertCorpusConnectionUsable(t *testing.T, db *DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var one int
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("corpus read error left the only database connection pinned: %v", err)
	}
	if one != 1 {
		t.Fatalf("connection probe = %d, want 1", one)
	}
}

func TestCorpusReadErrorsReleaseSingleConnection(t *testing.T) {
	t.Run("management timestamp", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_profile_content_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE device_corpus_profile_revisions SET created_at = 'not-a-time'
			WHERE profile_id = ?`, profile.ProfileID); err != nil {
			t.Fatal(err)
		}
		if _, err = db.GetCorpusProfile(profile.ProfileID); err == nil || !strings.Contains(err.Error(), "timestamp") {
			t.Fatalf("corrupt management timestamp error = %v", err)
		}
		assertCorpusConnectionUsable(t, db)
	})

	t.Run("preview shape", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.CreateCorpusVariant(profile.ProfileID, corpusVariantRequest("preview-corrupt"),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_shapes_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE device_corpus_shapes SET canonical_json = '{'`); err != nil {
			t.Fatal(err)
		}
		if _, err = buildCorpusPreviewSnapshot(db, profile.ProfileID, 1, time.Now().UTC()); err == nil ||
			!strings.Contains(err.Error(), "decode stored preview shape") {
			t.Fatalf("corrupt preview shape error = %v", err)
		}
		assertCorpusConnectionUsable(t, db)
	})

	t.Run("public shape", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.CreateCorpusVariant(profile.ProfileID, corpusVariantRequest("public-corrupt"),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.PublishCorpusProfile(profile.ProfileID, corpusPublishRequest(0),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_shapes_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE device_corpus_shapes SET canonical_json = '{'`); err != nil {
			t.Fatal(err)
		}
		if _, err = buildPublicCorpusSnapshot(db, 2, time.Now().UTC()); err == nil ||
			!strings.Contains(err.Error(), "decode stored public shape") {
			t.Fatalf("corrupt public shape error = %v", err)
		}
		assertCorpusConnectionUsable(t, db)
	})

	t.Run("publication row scan", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.CreateCorpusVariant(profile.ProfileID, corpusVariantRequest("quality-corrupt"),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_shapes_immutable`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`PRAGMA ignore_check_constraints = ON`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE device_corpus_shapes SET signal_family_count = 'broken'`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.PublishCorpusProfile(profile.ProfileID, corpusPublishRequest(0),
			CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
			t.Fatal("corrupt publication row unexpectedly published")
		}
		assertCorpusConnectionUsable(t, db)
	})

	t.Run("audit timestamp", func(t *testing.T) {
		db := newTestDB(t)
		if _, err := db.Exec(`INSERT INTO device_corpus_audit
			(audit_id, actor, entity_type, entity_id, action, reason_code, created_at)
			VALUES ('audit-corrupt', 'admin', 'profile', 'profile-corrupt', 'create', 'new_profile', 'not-a-time')`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.PageCorpusAudit(10, 0); err == nil || !strings.Contains(err.Error(), "timestamp") {
			t.Fatalf("corrupt audit timestamp error = %v", err)
		}
		assertCorpusConnectionUsable(t, db)
	})

	t.Run("release timestamp", func(t *testing.T) {
		db := newTestDB(t)
		if _, err := db.Exec(`INSERT INTO device_corpus_releases
			(corpus_revision, schema_version, snapshot_sha256, snapshot_json,
			 profile_count, variant_count, created_at)
			VALUES (1, 1, ?, '{}', 0, 0, 'not-a-time')`, strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.PageCorpusReleases(10, 0); err == nil || !strings.Contains(err.Error(), "timestamp") {
			t.Fatalf("corrupt release timestamp error = %v", err)
		}
		assertCorpusConnectionUsable(t, db)
	})
}
