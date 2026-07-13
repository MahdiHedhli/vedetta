package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

const corpusSnapshotPath = "/api/v1/device-corpus/snapshot"
const maxCorpusSnapshotBytes = 16 << 20

// SQLite length(TEXT) counts Unicode code points. Casting to BLOB makes both
// the reported size and the projection guard use the encoded UTF-8 byte count
// enforced by the publication and decode paths.
const boundedCorpusSnapshotColumns = `length(CAST(snapshot_json AS BLOB)),
	CASE WHEN length(CAST(snapshot_json AS BLOB)) <= ? THEN snapshot_json ELSE NULL END`

// corpusSnapshotCache holds a release only after its hash, canonical encoding,
// privacy constraints, and database metadata have all been verified. Releases
// are immutable, so the revision/hash pair is a safe cache key.
type corpusSnapshotCache struct {
	data     []byte
	manifest corpus.Manifest
}

func createCorpusReleaseTx(tx *sql.Tx, now string) (int, string, error) {
	var current int
	if err := tx.QueryRow(`SELECT current_revision FROM device_corpus_state WHERE singleton = 1`).Scan(&current); err != nil {
		return 0, "", err
	}
	revision := current + 1
	generatedAt, err := parseCorpusTime(now)
	if err != nil {
		return 0, "", err
	}
	snapshot, err := buildPublicCorpusSnapshot(tx, revision, generatedAt)
	if err != nil {
		return 0, "", err
	}
	if err := corpus.ValidatePublicSnapshot(snapshot); err != nil {
		return 0, "", fmt.Errorf("device corpus privacy gate: %w", err)
	}
	bytes, err := json.Marshal(snapshot)
	if err != nil {
		return 0, "", err
	}
	if len(bytes) > maxCorpusSnapshotBytes {
		return 0, "", corpusValidationf("device corpus snapshot exceeds 16 MiB publication limit")
	}
	digest := sha256.Sum256(bytes)
	hash := hex.EncodeToString(digest[:])
	variants := 0
	for _, profile := range snapshot.Profiles {
		variants += len(profile.Variants)
	}
	if _, err = tx.Exec(`INSERT INTO device_corpus_releases
        (corpus_revision, schema_version, snapshot_sha256, snapshot_json,
         profile_count, variant_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`, revision, corpus.SchemaVersion, hash,
		string(bytes), len(snapshot.Profiles), variants, now); err != nil {
		return 0, "", err
	}
	if _, err = tx.Exec(`UPDATE device_corpus_state SET current_revision = ?,
        current_snapshot_sha256 = ?, updated_at = ? WHERE singleton = 1`, revision, hash, now); err != nil {
		return 0, "", err
	}
	return revision, hash, nil
}

func buildPublicCorpusSnapshot(q corpusQuerier, revision int, generatedAt time.Time) (corpus.PublicSnapshot, error) {
	snapshot := corpus.PublicSnapshot{
		SchemaVersion: corpus.SchemaVersion, CorpusRevision: revision,
		GeneratedAt: generatedAt.UTC(), Profiles: []corpus.PublicProfile{},
	}
	rows, err := q.Query(`SELECT p.profile_id, pr.revision, pr.manufacturer, pr.model,
        pr.product_family, pr.device_type, pr.os_family
        FROM device_corpus_profiles p
        JOIN device_corpus_profile_revisions pr ON pr.profile_id = p.profile_id
        WHERE pr.status = 'published'
        ORDER BY lower(pr.manufacturer), lower(pr.model), p.profile_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var profile corpus.PublicProfile
		if err = rows.Scan(&profile.ProfileID, &profile.Revision,
			&profile.Labels.Manufacturer, &profile.Labels.Model, &profile.Labels.ProductFamily,
			&profile.Labels.DeviceType, &profile.Labels.OSFamily); err != nil {
			rows.Close()
			return snapshot, err
		}
		profile.Variants = []corpus.PublicVariant{}
		snapshot.Profiles = append(snapshot.Profiles, profile)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return snapshot, err
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}

	filtered := snapshot.Profiles[:0]
	for i := range snapshot.Profiles {
		profile := &snapshot.Profiles[i]
		rows, err = q.Query(`SELECT v.variant_id, v.variant_key,
            COALESCE(v.predecessor_variant_id, ''), vr.revision, vr.shape_hash,
            s.canonical_json, vr.confidence_bp, vr.variant_revision_id
            FROM device_corpus_variants v
            JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
            JOIN device_corpus_shapes s ON s.shape_hash = vr.shape_hash
            WHERE v.profile_id = ? AND vr.status = 'published'
            ORDER BY v.variant_key, v.variant_id`, profile.ProfileID)
		if err != nil {
			return snapshot, err
		}
		type publicWithRevision struct {
			value      corpus.PublicVariant
			revisionID string
		}
		var variants []publicWithRevision
		for rows.Next() {
			var item publicWithRevision
			var shapeJSON string
			if err = rows.Scan(&item.value.VariantID, &item.value.VariantKey,
				&item.value.PredecessorVariantID, &item.value.Revision, &item.value.ShapeHash,
				&shapeJSON, &item.value.ConfidenceBP, &item.revisionID); err != nil {
				rows.Close()
				return snapshot, err
			}
			if err = json.Unmarshal([]byte(shapeJSON), &item.value.Shape); err != nil {
				rows.Close()
				return snapshot, fmt.Errorf("decode stored public shape: %w", err)
			}
			variants = append(variants, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return snapshot, err
		}
		if err = rows.Close(); err != nil {
			return snapshot, err
		}
		for _, item := range variants {
			managementRevision := corpus.VariantRevision{}
			if err = loadCorpusEvidence(q, item.revisionID, &managementRevision); err != nil {
				return snapshot, err
			}
			item.value.Sources = managementRevision.Sources
			item.value.VersionFacts = managementRevision.VersionFacts
			profile.Variants = append(profile.Variants, item.value)
		}
		if len(profile.Variants) > 0 {
			filtered = append(filtered, *profile)
		}
	}
	snapshot.Profiles = filtered
	return snapshot, nil
}

// CorpusManifest reads only release metadata. It deliberately does not load or
// decode snapshot_json, which keeps status, manifests, and conditional snapshot
// requests cheap even when the corpus approaches its publication size limit.
func (db *DB) CorpusManifest() (corpus.Manifest, error) {
	var revision int
	var hash, updated string
	if err := db.QueryRow(`SELECT current_revision, current_snapshot_sha256, updated_at
        FROM device_corpus_state WHERE singleton = 1`).Scan(&revision, &hash, &updated); err != nil {
		return corpus.Manifest{}, err
	}
	if revision == 0 {
		generatedAt, err := parseCorpusTime(updated)
		if err != nil {
			return corpus.Manifest{}, err
		}
		snapshot := corpus.PublicSnapshot{SchemaVersion: corpus.SchemaVersion,
			CorpusRevision: 0, GeneratedAt: generatedAt, Profiles: []corpus.PublicProfile{}}
		if err = corpus.ValidatePublicSnapshot(snapshot); err != nil {
			return corpus.Manifest{}, err
		}
		data, err := json.Marshal(snapshot)
		if err != nil {
			return corpus.Manifest{}, err
		}
		digest := sha256.Sum256(data)
		hash = hex.EncodeToString(digest[:])
		return corpus.Manifest{SchemaVersion: corpus.SchemaVersion, CorpusRevision: 0,
			SnapshotSHA256: hash, ProfileCount: 0, VariantCount: 0,
			GeneratedAt: generatedAt, SnapshotPath: corpusSnapshotPath}, nil
	}
	var created string
	var profiles, variants, schemaVersion int
	err := db.QueryRow(`SELECT schema_version, profile_count, variant_count, created_at
        FROM device_corpus_releases WHERE corpus_revision = ? AND snapshot_sha256 = ?`, revision, hash).
		Scan(&schemaVersion, &profiles, &variants, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return corpus.Manifest{}, fmt.Errorf("current device corpus release is missing")
	}
	if err != nil {
		return corpus.Manifest{}, err
	}
	generatedAt, err := parseCorpusTime(created)
	if err != nil {
		return corpus.Manifest{}, err
	}
	if schemaVersion != corpus.SchemaVersion || profiles < 0 || variants < 0 || hash == "" {
		return corpus.Manifest{}, fmt.Errorf("invalid device corpus release metadata")
	}
	return corpus.Manifest{SchemaVersion: schemaVersion, CorpusRevision: revision,
		SnapshotSHA256: hash, ProfileCount: profiles, VariantCount: variants,
		GeneratedAt: generatedAt, SnapshotPath: corpusSnapshotPath}, nil
}

// CurrentCorpusSnapshot returns the exact bytes and metadata of the current
// immutable release. Revision zero is a deterministic empty bootstrap snapshot.
// The returned bytes are immutable and must not be modified by callers.
func (db *DB) CurrentCorpusSnapshot() ([]byte, corpus.Manifest, error) {
	manifest, err := db.CorpusManifest()
	if err != nil {
		return nil, corpus.Manifest{}, err
	}
	db.corpusCacheMu.RLock()
	cached := db.corpusCache
	if cached != nil && cached.manifest.CorpusRevision == manifest.CorpusRevision &&
		cached.manifest.SnapshotSHA256 == manifest.SnapshotSHA256 {
		data := cached.data
		db.corpusCacheMu.RUnlock()
		return data, cached.manifest, nil
	}
	db.corpusCacheMu.RUnlock()

	// Collapse a cold-cache stampede after publication or process start. The
	// first reader validates and caches the immutable release; waiters re-check
	// the key and reuse it rather than loading the same 16 MiB body repeatedly.
	db.corpusLoadMu.Lock()
	defer db.corpusLoadMu.Unlock()
	db.corpusCacheMu.RLock()
	cached = db.corpusCache
	if cached != nil && cached.manifest.CorpusRevision == manifest.CorpusRevision &&
		cached.manifest.SnapshotSHA256 == manifest.SnapshotSHA256 {
		data := cached.data
		db.corpusCacheMu.RUnlock()
		return data, cached.manifest, nil
	}
	db.corpusCacheMu.RUnlock()

	var data []byte
	if manifest.CorpusRevision == 0 {
		snapshot := corpus.PublicSnapshot{SchemaVersion: corpus.SchemaVersion,
			CorpusRevision: 0, GeneratedAt: manifest.GeneratedAt, Profiles: []corpus.PublicProfile{}}
		data, err = json.Marshal(snapshot)
		if err != nil {
			return nil, corpus.Manifest{}, err
		}
	} else {
		var raw sql.NullString
		var storedBytes int64
		err = db.QueryRow(`SELECT `+boundedCorpusSnapshotColumns+`
	            FROM device_corpus_releases
            WHERE corpus_revision = ? AND snapshot_sha256 = ?`, maxCorpusSnapshotBytes,
			manifest.CorpusRevision, manifest.SnapshotSHA256).Scan(&storedBytes, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, corpus.Manifest{}, fmt.Errorf("current device corpus release is missing")
		}
		if err != nil {
			return nil, corpus.Manifest{}, err
		}
		if storedBytes > maxCorpusSnapshotBytes || !raw.Valid {
			return nil, corpus.Manifest{}, fmt.Errorf("device corpus snapshot exceeds 16 MiB publication limit")
		}
		data = []byte(raw.String)
	}
	if _, err = validateStoredCorpusReleaseSnapshot(data, manifest); err != nil {
		return nil, corpus.Manifest{}, err
	}

	db.corpusCacheMu.Lock()
	// A concurrent reader may have filled the same immutable release. Either
	// validated value is equivalent; keeping the existing slice avoids churn.
	if db.corpusCache != nil && db.corpusCache.manifest.CorpusRevision == manifest.CorpusRevision &&
		db.corpusCache.manifest.SnapshotSHA256 == manifest.SnapshotSHA256 {
		data = db.corpusCache.data
		manifest = db.corpusCache.manifest
	} else {
		db.corpusCache = &corpusSnapshotCache{data: data, manifest: manifest}
	}
	db.corpusCacheMu.Unlock()
	return data, manifest, nil
}

func validateStoredCorpusSnapshot(raw []byte, expectedHash string) (corpus.PublicSnapshot, error) {
	if len(raw) > maxCorpusSnapshotBytes {
		return corpus.PublicSnapshot{}, fmt.Errorf("device corpus snapshot exceeds 16 MiB publication limit")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedHash {
		return corpus.PublicSnapshot{}, fmt.Errorf("device corpus snapshot hash mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot corpus.PublicSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return snapshot, fmt.Errorf("decode device corpus snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return snapshot, fmt.Errorf("device corpus snapshot contains trailing data")
	}
	if err := corpus.ValidatePublicSnapshot(snapshot); err != nil {
		return snapshot, err
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return snapshot, err
	}
	if !bytes.Equal(canonical, raw) {
		return snapshot, fmt.Errorf("device corpus snapshot bytes are not canonical")
	}
	return snapshot, nil
}

func validateStoredCorpusReleaseSnapshot(raw []byte, manifest corpus.Manifest) (corpus.PublicSnapshot, error) {
	snapshot, err := validateStoredCorpusSnapshot(raw, manifest.SnapshotSHA256)
	if err != nil {
		return snapshot, err
	}
	if snapshot.SchemaVersion != manifest.SchemaVersion || snapshot.CorpusRevision != manifest.CorpusRevision ||
		!snapshot.GeneratedAt.Equal(manifest.GeneratedAt) || len(snapshot.Profiles) != manifest.ProfileCount {
		return snapshot, fmt.Errorf("device corpus snapshot metadata mismatch")
	}
	variants := 0
	for _, profile := range snapshot.Profiles {
		variants += len(profile.Variants)
	}
	if variants != manifest.VariantCount {
		return snapshot, fmt.Errorf("device corpus snapshot metadata mismatch")
	}
	return snapshot, nil
}
