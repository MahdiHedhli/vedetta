package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

// CorpusPreview is a transactionally consistent view of the release that
// would result from publishing one profile's current draft set. The ETag is the
// precondition that must still be supplied to PublishCorpusProfile.
type CorpusPreview struct {
	ETag                   string                `json:"etag"`
	CurrentCorpusRevision  int                   `json:"current_corpus_revision"`
	ProposedCorpusRevision int                   `json:"proposed_corpus_revision"`
	Snapshot               corpus.PublicSnapshot `json:"snapshot"`
}

// PreviewCorpusProfile builds a proposed public release without mutating the
// database. All reads and the ETag check occur in one transaction, so the
// response cannot combine revisions from different curator states.
func (db *DB) PreviewCorpusProfile(ctx context.Context, profileID string, meta CorpusMutation) (CorpusPreview, error) {
	meta = normalizeMutation(meta)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CorpusPreview{}, err
	}
	defer tx.Rollback()

	etag, err := requireCorpusETag(ctx, tx, profileID, meta)
	if err != nil {
		return CorpusPreview{}, err
	}
	if err = validateCorpusPreviewEligibility(ctx, tx, profileID); err != nil {
		return CorpusPreview{}, err
	}
	var currentRevision int
	if err = tx.QueryRowContext(ctx, `SELECT current_revision FROM device_corpus_state WHERE singleton = 1`).Scan(&currentRevision); err != nil {
		return CorpusPreview{}, err
	}
	generatedAt, err := parseCorpusTime(nowRFC3339())
	if err != nil {
		return CorpusPreview{}, err
	}
	snapshot, err := buildCorpusPreviewSnapshot(ctx, tx, profileID, currentRevision+1, generatedAt)
	if err != nil {
		return CorpusPreview{}, err
	}
	if err = corpus.ValidatePublicSnapshot(snapshot); err != nil {
		return CorpusPreview{}, fmt.Errorf("device corpus preview privacy gate: %w", err)
	}
	previewBytes, err := json.Marshal(snapshot)
	if err != nil {
		return CorpusPreview{}, err
	}
	if len(previewBytes) > maxCorpusSnapshotBytes {
		return CorpusPreview{}, corpusValidationf("device corpus snapshot exceeds 16 MiB publication limit")
	}
	return CorpusPreview{
		ETag:                   etag,
		CurrentCorpusRevision:  currentRevision,
		ProposedCorpusRevision: currentRevision + 1,
		Snapshot:               snapshot,
	}, nil
}

func validateCorpusPreviewEligibility(ctx context.Context, tx *sql.Tx, profileID string) error {
	var draftProfiles, draftVariants int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_corpus_profile_revisions
		WHERE profile_id = ? AND status = 'draft'`, profileID).Scan(&draftProfiles); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_corpus_variants v
		JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		WHERE v.profile_id = ? AND vr.status = 'draft'`, profileID).Scan(&draftVariants); err != nil {
		return err
	}
	if draftProfiles == 0 && draftVariants == 0 {
		return ErrCorpusNoChanges
	}

	return validateCorpusPublishReadiness(ctx, tx, profileID)
}

// buildCorpusPreviewSnapshot mirrors publication selection: the target
// profile and its variants prefer drafts, while every other profile is read
// strictly from published revisions.
func buildCorpusPreviewSnapshot(ctx context.Context, q corpusQuerier, targetProfileID string, revision int, generatedAt time.Time) (corpus.PublicSnapshot, error) {
	snapshot := corpus.PublicSnapshot{
		SchemaVersion: corpus.SchemaVersion, CorpusRevision: revision,
		GeneratedAt: generatedAt.UTC(), Profiles: []corpus.PublicProfile{},
	}
	type profileCandidate struct {
		profile corpus.PublicProfile
		status  string
	}
	selected := map[string]profileCandidate{}
	rows, err := q.QueryContext(ctx, `SELECT p.profile_id, pr.revision, pr.manufacturer, pr.model,
		pr.product_family, pr.device_type, pr.os_family, pr.status
		FROM device_corpus_profiles p
		JOIN device_corpus_profile_revisions pr ON pr.profile_id = p.profile_id
		WHERE pr.status = 'published' OR (p.profile_id = ? AND pr.status = 'draft')`, targetProfileID)
	if err != nil {
		return snapshot, err
	}
	defer rows.Close() // panic backstop; explicit close precedes nested variant loads
	for rows.Next() {
		var candidate profileCandidate
		if err = rows.Scan(&candidate.profile.ProfileID, &candidate.profile.Revision,
			&candidate.profile.Labels.Manufacturer, &candidate.profile.Labels.Model,
			&candidate.profile.Labels.ProductFamily, &candidate.profile.Labels.DeviceType,
			&candidate.profile.Labels.OSFamily, &candidate.status); err != nil {
			rows.Close()
			return snapshot, err
		}
		candidate.profile.Variants = []corpus.PublicVariant{}
		current, exists := selected[candidate.profile.ProfileID]
		if !exists || (candidate.profile.ProfileID == targetProfileID && candidate.status == "draft" && current.status != "draft") {
			selected[candidate.profile.ProfileID] = candidate
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return snapshot, err
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}
	for _, candidate := range selected {
		snapshot.Profiles = append(snapshot.Profiles, candidate.profile)
	}
	sort.Slice(snapshot.Profiles, func(i, j int) bool {
		left, right := snapshot.Profiles[i], snapshot.Profiles[j]
		leftManufacturer, rightManufacturer := strings.ToLower(left.Labels.Manufacturer), strings.ToLower(right.Labels.Manufacturer)
		if leftManufacturer != rightManufacturer {
			return leftManufacturer < rightManufacturer
		}
		leftModel, rightModel := strings.ToLower(left.Labels.Model), strings.ToLower(right.Labels.Model)
		if leftModel != rightModel {
			return leftModel < rightModel
		}
		return left.ProfileID < right.ProfileID
	})

	filtered := snapshot.Profiles[:0]
	for i := range snapshot.Profiles {
		profile := &snapshot.Profiles[i]
		if err = loadCorpusPreviewVariants(ctx, q, profile, profile.ProfileID == targetProfileID); err != nil {
			return snapshot, err
		}
		if len(profile.Variants) > 0 {
			filtered = append(filtered, *profile)
		}
	}
	snapshot.Profiles = filtered
	return snapshot, nil
}

func loadCorpusPreviewVariants(ctx context.Context, q corpusQuerier, profile *corpus.PublicProfile, preferDraft bool) error {
	type variantCandidate struct {
		value      corpus.PublicVariant
		revisionID string
		status     string
	}
	selected := map[string]variantCandidate{}
	rows, err := q.QueryContext(ctx, `SELECT v.variant_id, v.variant_key,
		COALESCE(v.predecessor_variant_id, ''), vr.revision, vr.shape_hash,
		s.canonical_json, vr.confidence_bp, vr.variant_revision_id, vr.status
		FROM device_corpus_variants v
		JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		JOIN device_corpus_shapes s ON s.shape_hash = vr.shape_hash
		WHERE v.profile_id = ? AND (vr.status = 'published' OR (? AND vr.status = 'draft'))`,
		profile.ProfileID, preferDraft)
	if err != nil {
		return err
	}
	defer rows.Close() // panic backstop; explicit close precedes nested evidence loads
	for rows.Next() {
		var candidate variantCandidate
		var shapeJSON string
		if err = rows.Scan(&candidate.value.VariantID, &candidate.value.VariantKey,
			&candidate.value.PredecessorVariantID, &candidate.value.Revision,
			&candidate.value.ShapeHash, &shapeJSON, &candidate.value.ConfidenceBP,
			&candidate.revisionID, &candidate.status); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal([]byte(shapeJSON), &candidate.value.Shape); err != nil {
			rows.Close()
			return fmt.Errorf("decode stored preview shape: %w", err)
		}
		current, exists := selected[candidate.value.VariantID]
		if !exists || (preferDraft && candidate.status == "draft" && current.status != "draft") {
			selected[candidate.value.VariantID] = candidate
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	variants := make([]variantCandidate, 0, len(selected))
	for _, candidate := range selected {
		variants = append(variants, candidate)
	}
	sort.Slice(variants, func(i, j int) bool {
		if variants[i].value.VariantKey != variants[j].value.VariantKey {
			return variants[i].value.VariantKey < variants[j].value.VariantKey
		}
		return variants[i].value.VariantID < variants[j].value.VariantID
	})
	revisionIDs := make([]string, 0, len(variants))
	for _, candidate := range variants {
		revisionIDs = append(revisionIDs, candidate.revisionID)
	}
	evidence, err := loadCorpusEvidenceBatch(ctx, q, revisionIDs)
	if err != nil {
		return err
	}
	for _, candidate := range variants {
		loaded := evidence[candidate.revisionID]
		candidate.value.Sources = loaded.Sources
		candidate.value.VersionFacts = loaded.VersionFacts
		profile.Variants = append(profile.Variants, candidate.value)
	}
	return nil
}
