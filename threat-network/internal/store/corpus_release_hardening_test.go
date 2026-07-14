package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCurrentCorpusSnapshotReturnsCallerOwnedBytes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *DB)
	}{
		{name: "bootstrap"},
		{
			name: "published release",
			setup: func(t *testing.T, db *DB) {
				profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
				if err != nil {
					t.Fatal(err)
				}
				profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("cache-copy"),
					CorpusMutation{ExpectedETag: profile.ETag})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
					CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newTestDB(t)
			if tt.setup != nil {
				tt.setup(t, db)
			}
			first, manifest, err := db.CurrentCorpusSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(first)
			if len(first) == 0 {
				t.Fatal("snapshot unexpectedly empty")
			}
			first[0] ^= 0xff

			second, secondManifest, err := db.CurrentCorpusSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(second, want) || secondManifest != manifest {
				t.Fatalf("caller mutation corrupted cached snapshot or manifest")
			}
			second[len(second)-1] ^= 0xff
			third, thirdManifest, err := db.CurrentCorpusSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(third, want) || thirdManifest != manifest {
				t.Fatalf("cache-hit mutation corrupted a later snapshot or manifest")
			}
		})
	}
}

func TestCurrentCorpusSnapshotDoesNotRegressNewerCache(t *testing.T) {
	olderDB := newTestDB(t)
	olderData, olderManifest, err := olderDB.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	newerDB := newTestDB(t)
	createPublishedCorpusTestProfile(t, newerDB, "Newer Cache Release", 0)
	newerData, newerManifest, err := newerDB.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if newerManifest.CorpusRevision <= olderManifest.CorpusRevision {
		t.Fatalf("fixture revisions older=%d newer=%d", olderManifest.CorpusRevision, newerManifest.CorpusRevision)
	}

	// Model an older reader that captured olderManifest before waiting for the
	// load gate, after a newer reader has already populated the shared cache.
	olderDB.corpusCacheMu.Lock()
	olderDB.corpusCache = &corpusSnapshotCache{
		data: bytes.Clone(newerData), manifest: newerManifest,
	}
	olderDB.corpusCacheMu.Unlock()

	gotData, gotManifest, err := olderDB.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotManifest != olderManifest || !bytes.Equal(gotData, olderData) {
		t.Fatalf("stale reader returned mismatched pair: manifest=%+v data=%q", gotManifest, gotData)
	}
	gotData[0] ^= 0xff

	olderDB.corpusCacheMu.RLock()
	cached := olderDB.corpusCache
	if cached == nil || cached.manifest != newerManifest || !bytes.Equal(cached.data, newerData) {
		olderDB.corpusCacheMu.RUnlock()
		t.Fatalf("older completion regressed newer cache: %+v", cached)
	}
	olderDB.corpusCacheMu.RUnlock()
}

func installSyntheticCorpusRelease(t *testing.T, db *DB, raw string, profileCount, variantCount int, createdAt string) {
	t.Helper()
	digest := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(digest[:])
	if _, err := db.Exec(`INSERT INTO device_corpus_releases
        (corpus_revision, schema_version, snapshot_sha256, snapshot_json,
         profile_count, variant_count, created_at)
        VALUES (1, 1, ?, ?, ?, ?, ?)`, hash, raw, profileCount, variantCount, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_corpus_state SET current_revision = 1,
        current_snapshot_sha256 = ?, updated_at = ? WHERE singleton = 1`, hash, createdAt); err != nil {
		t.Fatal(err)
	}
}

func TestStoredCorpusReleaseMetadataMustMatchSnapshot(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		profiles  int
		variants  int
		createdAt string
	}{
		{
			name:      "revision mismatch",
			raw:       `{"schema_version":1,"corpus_revision":2,"generated_at":"2026-07-13T16:00:00Z","profiles":[]}`,
			createdAt: "2026-07-13T16:00:00Z",
		},
		{
			name:      "profile count mismatch",
			raw:       `{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[]}`,
			profiles:  1,
			createdAt: "2026-07-13T16:00:00Z",
		},
		{
			name:      "created time mismatch",
			raw:       `{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[]}`,
			createdAt: "2026-07-13T16:00:01Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newTestDB(t)
			installSyntheticCorpusRelease(t, db, tt.raw, tt.profiles, tt.variants, tt.createdAt)
			if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err == nil {
				t.Fatal("current snapshot served despite release metadata mismatch")
			}
			if _, _, err := db.GetCorpusRelease(context.Background(), 1); err == nil {
				t.Fatal("historical snapshot served despite release metadata mismatch")
			}
		})
	}
}

func TestOversizedStoredCorpusReleaseRejectedBeforeDecode(t *testing.T) {
	db := newTestDB(t)
	raw := `{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[],"padding":"` +
		strings.Repeat("x", maxCorpusSnapshotBytes) + `"}`
	installSyntheticCorpusRelease(t, db, raw, 0, 0, "2026-07-13T16:00:00Z")
	if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("oversized current snapshot error=%v", err)
	}
	if _, _, err := db.GetCorpusRelease(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("oversized historical snapshot error=%v", err)
	}
}

func TestStoredCorpusReleaseSizeLimitCountsUTF8Bytes(t *testing.T) {
	const prefix = `{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[],"padding":"`
	const suffix = `"}`
	// SQLite length(TEXT) counts Unicode code points, not encoded bytes. Build a
	// value whose character count is below the publication ceiling but whose
	// UTF-8 representation is just over it, exercising the database-side guard
	// before Go allocates or decodes the stored body.
	paddingRunes := (maxCorpusSnapshotBytes-len(prefix)-len(suffix))/2 + 1
	raw := prefix + strings.Repeat("é", paddingRunes) + suffix
	if !utf8.ValidString(raw) {
		t.Fatal("test snapshot is not valid UTF-8")
	}
	if utf8.RuneCountInString(raw) > maxCorpusSnapshotBytes {
		t.Fatalf("test requires character count below limit, got %d", utf8.RuneCountInString(raw))
	}
	if len(raw) <= maxCorpusSnapshotBytes {
		t.Fatalf("test requires encoded bytes over limit, got %d", len(raw))
	}

	db := newTestDB(t)
	installSyntheticCorpusRelease(t, db, raw, 0, 0, "2026-07-13T16:00:00Z")
	var textLength, byteLength int
	if err := db.QueryRow(`SELECT length(snapshot_json), length(CAST(snapshot_json AS BLOB))
		FROM device_corpus_releases WHERE corpus_revision = 1`).Scan(&textLength, &byteLength); err != nil {
		t.Fatal(err)
	}
	if textLength > maxCorpusSnapshotBytes || byteLength <= maxCorpusSnapshotBytes {
		t.Fatalf("unexpected SQLite lengths: text=%d bytes=%d", textLength, byteLength)
	}
	var guardedBytes int
	var guardedRaw sql.NullString
	if err := db.QueryRow(`SELECT `+boundedCorpusSnapshotColumns+`
		FROM device_corpus_releases WHERE corpus_revision = 1`, maxCorpusSnapshotBytes).
		Scan(&guardedBytes, &guardedRaw); err != nil {
		t.Fatal(err)
	}
	if guardedBytes != byteLength || guardedRaw.Valid {
		t.Fatalf("byte guard returned bytes=%d raw.valid=%v, want bytes=%d raw.valid=false",
			guardedBytes, guardedRaw.Valid, byteLength)
	}

	t.Run("current release", func(t *testing.T) {
		if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "16 MiB") {
			t.Fatalf("multibyte oversized current snapshot error=%v", err)
		}
	})
	t.Run("historical release", func(t *testing.T) {
		if _, _, err := db.GetCorpusRelease(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "16 MiB") {
			t.Fatalf("multibyte oversized historical snapshot error=%v", err)
		}
	})
}
