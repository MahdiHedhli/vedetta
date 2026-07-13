package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func validateExpectedCorpusRevision(expected *int) error {
	if expected == nil || *expected < 0 {
		return corpusValidationf("expected_corpus_revision is required and must not be negative")
	}
	return nil
}

func requireExpectedCorpusRevision(tx *sql.Tx, expected *int) error {
	var current int
	if err := tx.QueryRow(`SELECT current_revision FROM device_corpus_state WHERE singleton = 1`).Scan(&current); err != nil {
		return err
	}
	if current != *expected {
		return ErrCorpusRevisionConflict
	}
	return nil
}

// PublishCorpusProfile atomically promotes the profile draft and every variant
// draft, then emits a complete immutable public release.
func (db *DB) PublishCorpusProfile(profileID string, req corpus.PublishRequest, meta CorpusMutation) (*corpus.Profile, error) {
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	if err = validateExpectedCorpusRevision(req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}
	meta = normalizeMutation(meta)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	before, err := requireCorpusETag(tx, profileID, meta)
	if err != nil {
		return nil, err
	}
	if err = requireExpectedCorpusRevision(tx, req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}

	var draftProfileID, publishedProfileID sql.NullString
	if err = tx.QueryRow(`SELECT
        MAX(CASE WHEN status = 'draft' THEN profile_revision_id END),
        MAX(CASE WHEN status = 'published' THEN profile_revision_id END)
        FROM device_corpus_profile_revisions WHERE profile_id = ?`, profileID).
		Scan(&draftProfileID, &publishedProfileID); err != nil {
		return nil, err
	}
	if !draftProfileID.Valid && !publishedProfileID.Valid {
		return nil, ErrCorpusNotFound
	}
	var draftVariants int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_variants v
        JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
        WHERE v.profile_id = ? AND vr.status = 'draft'`, profileID).Scan(&draftVariants); err != nil {
		return nil, err
	}
	if !draftProfileID.Valid && draftVariants == 0 {
		return nil, ErrCorpusNoChanges
	}

	if err = validateCorpusPublishReadiness(tx, profileID); err != nil {
		return nil, err
	}

	now := nowRFC3339()
	if draftProfileID.Valid {
		if publishedProfileID.Valid {
			if _, err = tx.Exec(`UPDATE device_corpus_profile_revisions SET status = 'superseded'
                WHERE profile_revision_id = ?`, publishedProfileID.String); err != nil {
				return nil, err
			}
		}
		if _, err = tx.Exec(`UPDATE device_corpus_profile_revisions
            SET status = 'published', published_at = ? WHERE profile_revision_id = ?`, now, draftProfileID.String); err != nil {
			return nil, err
		}
	}

	rows, err := tx.Query(`SELECT v.variant_id, draft.variant_revision_id,
        (SELECT published.variant_revision_id FROM device_corpus_variant_revisions published
         WHERE published.variant_id = v.variant_id AND published.status = 'published')
        FROM device_corpus_variants v
        JOIN device_corpus_variant_revisions draft ON draft.variant_id = v.variant_id AND draft.status = 'draft'
        WHERE v.profile_id = ? ORDER BY v.variant_id`, profileID)
	if err != nil {
		return nil, err
	}
	type promotion struct {
		variantID, draftID string
		publishedID        sql.NullString
	}
	var promotions []promotion
	for rows.Next() {
		var p promotion
		if err = rows.Scan(&p.variantID, &p.draftID, &p.publishedID); err != nil {
			rows.Close()
			return nil, err
		}
		promotions = append(promotions, p)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for _, p := range promotions {
		if p.publishedID.Valid {
			if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions SET status = 'superseded'
                WHERE variant_revision_id = ?`, p.publishedID.String); err != nil {
				return nil, err
			}
		}
		if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions
            SET status = 'published', published_at = ? WHERE variant_revision_id = ?`, now, p.draftID); err != nil {
			return nil, err
		}
	}

	revision, snapshotHash, err := createCorpusReleaseTx(tx, now)
	if err != nil {
		return nil, err
	}
	after, err := corpusProfileETag(tx, profileID)
	if err != nil {
		return nil, err
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	if err = insertCorpusAudit(tx, auditID, meta, "profile", profileID, "publish", reason,
		before, snapshotHash+":"+after, &revision, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// validateCorpusPublishReadiness is the single publishability gate shared by
// preview and the mutating publish transaction. Keeping both paths on the same
// checks prevents a curator from receiving a successful preview for content
// that publication would subsequently reject (or vice versa).
func validateCorpusPublishReadiness(tx *sql.Tx, profileID string) error {
	// A published profile without a fingerprint would create a misleading empty
	// identity claim. Draft and already-published variants both count here.
	var usableVariants int
	if err := tx.QueryRow(`SELECT COUNT(DISTINCT v.variant_id)
		FROM device_corpus_variants v
		JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		WHERE v.profile_id = ? AND vr.status IN ('draft','published')`, profileID).Scan(&usableVariants); err != nil {
		return err
	}
	if usableVariants == 0 {
		return corpusValidationf("publish requires at least one fingerprint variant")
	}

	// Every fingerprint needs explicit curated provenance. A lab observation may
	// be URL-less, but it is still recorded as such rather than inferred.
	var unsourced int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_variants v
		JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		WHERE v.profile_id = ? AND vr.status IN ('draft','published')
		  AND NOT EXISTS (SELECT 1 FROM device_corpus_sources s
		                  WHERE s.variant_revision_id = vr.variant_revision_id)`, profileID).Scan(&unsourced); err != nil {
		return err
	}
	if unsourced > 0 {
		return corpusValidationf("publish requires at least one source per variant")
	}
	return validateCorpusPublishQuality(tx, profileID)
}

func validateCorpusPublishQuality(tx *sql.Tx, profileID string) error {
	rows, err := tx.Query(`SELECT vr.variant_revision_id, s.signal_family_count, s.canonical_json
		FROM device_corpus_variants v
		JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		JOIN device_corpus_shapes s ON s.shape_hash = vr.shape_hash
		WHERE v.profile_id = ? AND vr.status IN ('draft','published')`, profileID)
	if err != nil {
		return err
	}
	type candidate struct {
		revisionID string
		families   int
		shapeJSON  string
	}
	var candidates []candidate
	for rows.Next() {
		var candidate candidate
		if err = rows.Scan(&candidate.revisionID, &candidate.families, &candidate.shapeJSON); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, candidate := range candidates {
		var shape corpus.CanonicalShapeV1
		if err = json.Unmarshal([]byte(candidate.shapeJSON), &shape); err != nil {
			return fmt.Errorf("decode corpus shape for publication: %w", err)
		}
		canonicalShape, _, _, families, canonicalErr := corpus.CanonicalizeShape(shape)
		if canonicalErr != nil {
			return fmt.Errorf("validate corpus shape for publication: %w", canonicalErr)
		}
		if candidate.families != families {
			return fmt.Errorf("stored signal family count does not match canonical shape")
		}
		// OUI and open-port combinations are vendor/context hints, not a product
		// identity. Require at least one constrained product-specific signature so
		// correlated generic observations cannot become a confident corpus entry.
		hasProductSignal := len(canonicalShape.DHCPVendorClasses) > 0 || len(canonicalShape.HostnameTemplates) > 0 ||
			len(canonicalShape.MDNSModels) > 0 || len(canonicalShape.SSDPServerTokens) > 0
		if !hasProductSignal {
			return corpusValidationf("publish requires a product-specific fingerprint signature")
		}
		if families >= 2 {
			continue
		}
		var citations int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_sources
			WHERE variant_revision_id = ? AND public_url <> ''
			  AND kind IN ('vendor_doc','standards','security_advisory')`, candidate.revisionID).Scan(&citations); err != nil {
			return err
		}
		if citations == 0 {
			return corpusValidationf("single-family product signatures require a public authoritative citation")
		}
	}
	return nil
}

// RetireCorpusProfile removes a published product and all of its variants from
// the next snapshot without deleting its immutable history.
func (db *DB) RetireCorpusProfile(profileID string, req corpus.LifecycleRequest, meta CorpusMutation) (*corpus.Profile, error) {
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	if err = validateExpectedCorpusRevision(req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}
	meta = normalizeMutation(meta)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	before, err := requireCorpusETag(tx, profileID, meta)
	if err != nil {
		return nil, err
	}
	var published int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_profile_revisions
        WHERE profile_id = ? AND status = 'published'`, profileID).Scan(&published); err != nil {
		return nil, err
	}
	var active int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_profile_revisions
        WHERE profile_id = ? AND status IN ('draft','published')`, profileID).Scan(&active); err != nil {
		return nil, err
	}
	if active == 0 {
		return nil, ErrCorpusNotFound
	}
	// The ETag protects only this profile. Bind this release-producing action to
	// the complete public snapshot the curator reviewed as well, and check it in
	// the same transaction immediately before any state is changed.
	if err = requireExpectedCorpusRevision(tx, req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}
	now := nowRFC3339()
	if _, err = tx.Exec(`UPDATE device_corpus_profile_revisions
        SET status = 'retired', retired_at = ?
        WHERE profile_id = ? AND status IN ('draft','published')`, now, profileID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions
        SET status = 'withdrawn', withdrawn_at = ?
        WHERE status IN ('draft','published') AND variant_id IN
          (SELECT variant_id FROM device_corpus_variants WHERE profile_id = ?)`, now, profileID); err != nil {
		return nil, err
	}
	var revisionPtr *int
	after := before
	if published > 0 {
		revision, snapshotHash, releaseErr := createCorpusReleaseTx(tx, now)
		if releaseErr != nil {
			return nil, releaseErr
		}
		revisionPtr = &revision
		after = snapshotHash
	} else {
		after, err = corpusProfileETag(tx, profileID)
		if err != nil {
			return nil, err
		}
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	if err = insertCorpusAudit(tx, auditID, meta, "profile", profileID, "retire", reason,
		before, after, revisionPtr, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// WithdrawCorpusVariant removes one logical variant from the next snapshot.
func (db *DB) WithdrawCorpusVariant(variantID string, req corpus.LifecycleRequest, meta CorpusMutation) (*corpus.Profile, error) {
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	if err = validateExpectedCorpusRevision(req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}
	meta = normalizeMutation(meta)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var profileID string
	if err = tx.QueryRow(`SELECT profile_id FROM device_corpus_variants WHERE variant_id = ?`, variantID).Scan(&profileID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNotFound
	} else if err != nil {
		return nil, err
	}
	before, err := requireCorpusETag(tx, profileID, meta)
	if err != nil {
		return nil, err
	}
	var published, active int
	if err = tx.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'published' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('draft','published') THEN 1 ELSE 0 END), 0)
		FROM device_corpus_variant_revisions WHERE variant_id = ?`, variantID).Scan(&published, &active); err != nil {
		return nil, err
	}
	if active == 0 {
		return nil, ErrCorpusNotFound
	}
	if err = ensureNoActiveCorpusVariantChildren(tx, variantID); err != nil {
		return nil, err
	}
	if err = requireExpectedCorpusRevision(tx, req.ExpectedCorpusRevision); err != nil {
		return nil, err
	}
	now := nowRFC3339()
	if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions
        SET status = 'withdrawn', withdrawn_at = ?
        WHERE variant_id = ? AND status IN ('draft','published')`, now, variantID); err != nil {
		return nil, err
	}
	var revisionPtr *int
	after, err := corpusProfileETag(tx, profileID)
	if err != nil {
		return nil, err
	}
	if published > 0 {
		revision, snapshotHash, releaseErr := createCorpusReleaseTx(tx, now)
		if releaseErr != nil {
			return nil, releaseErr
		}
		revisionPtr = &revision
		after = snapshotHash + ":" + after
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	if err = insertCorpusAudit(tx, auditID, meta, "variant", variantID, "withdraw", reason,
		before, after, revisionPtr, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// DiscardCorpusVariantDraft abandons only the pending curator correction. Any
// published revision remains active and public; the discarded draft is retained
// as withdrawn history for auditability.
func (db *DB) DiscardCorpusVariantDraft(variantID string, req corpus.LifecycleRequest, meta CorpusMutation) (*corpus.Profile, error) {
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	meta = normalizeMutation(meta)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var profileID string
	if err = tx.QueryRow(`SELECT profile_id FROM device_corpus_variants WHERE variant_id = ?`, variantID).Scan(&profileID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNotFound
	} else if err != nil {
		return nil, err
	}
	before, err := requireCorpusETag(tx, profileID, meta)
	if err != nil {
		return nil, err
	}
	var draftID string
	if err = tx.QueryRow(`SELECT variant_revision_id FROM device_corpus_variant_revisions
		WHERE variant_id = ? AND status = 'draft'`, variantID).Scan(&draftID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNoChanges
	} else if err != nil {
		return nil, err
	}
	var published int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_variant_revisions
		WHERE variant_id = ? AND status = 'published'`, variantID).Scan(&published); err != nil {
		return nil, err
	}
	if published == 0 {
		if err = ensureNoActiveCorpusVariantChildren(tx, variantID); err != nil {
			return nil, err
		}
	}
	now := nowRFC3339()
	if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions
		SET status = 'withdrawn', withdrawn_at = ? WHERE variant_revision_id = ?`, now, draftID); err != nil {
		return nil, err
	}
	after, err := corpusProfileETag(tx, profileID)
	if err != nil {
		return nil, err
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	if err = insertCorpusAudit(tx, auditID, meta, "variant", variantID, "withdraw", reason,
		before, after, nil, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

func ensureNoActiveCorpusVariantChildren(q corpusQuerier, variantID string) error {
	var descendants int
	err := q.QueryRow(`SELECT COUNT(DISTINCT child.variant_id)
		FROM device_corpus_variants child
		JOIN device_corpus_variant_revisions revision ON revision.variant_id = child.variant_id
		WHERE child.predecessor_variant_id = ? AND revision.status IN ('draft','published')`, variantID).
		Scan(&descendants)
	if err != nil {
		return err
	}
	if descendants > 0 {
		return ErrCorpusHasDependents
	}
	return nil
}
