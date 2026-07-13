package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

var (
	ErrCorpusNotFound         = errors.New("device corpus entity not found")
	ErrCorpusConflict         = errors.New("device corpus state conflict")
	ErrCorpusPrecondition     = errors.New("device corpus If-Match precondition required")
	ErrCorpusNoChanges        = errors.New("device corpus has no draft changes")
	ErrCorpusHasDependents    = errors.New("device corpus variant has active descendants")
	ErrCorpusRevisionConflict = errors.New("device corpus public revision changed")
	ErrCorpusValidation       = errors.New("device corpus validation failed")
)

// corpusValidationError gives the HTTP boundary a stable classification for
// curator-input failures without relying on mutable error text. Privacy errors
// retain their narrower type so callers can return FORBIDDEN_CONTENT instead.
func corpusValidationError(err error) error {
	if err == nil {
		return nil
	}
	var privacyErr *corpus.CorpusPrivacyError
	if errors.As(err, &privacyErr) || errors.Is(err, ErrCorpusValidation) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrCorpusValidation, err)
}

func corpusValidationf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorpusValidation, fmt.Sprintf(format, args...))
}

// CorpusMutation identifies a management action without storing an operator's
// personal identity. Actor is deliberately a coarse deployment label.
type CorpusMutation struct {
	Actor        string
	ExpectedETag string
}

type corpusQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

type normalizedVariant struct {
	shape      corpus.CanonicalShapeV1
	canonical  []byte
	shapeHash  string
	families   int
	confidence int
	sources    []corpus.Source
	facts      []corpus.VersionFact
}

func normalizeVariant(shape corpus.CanonicalShapeV1, confidence int, sources []corpus.Source, facts []corpus.VersionFact) (normalizedVariant, error) {
	if confidence < 0 || confidence > 10000 {
		return normalizedVariant{}, corpusValidationf("confidence_bp must be 0..10000")
	}
	// Source and fact IDs are response-only identifiers assigned when evidence
	// is persisted. Keeping that rule at the write boundary prevents clients
	// from selecting IDs that could be mistaken for trusted stored evidence,
	// while the corpus package remains able to validate published snapshots.
	for _, source := range sources {
		if source.SourceID != "" {
			return normalizedVariant{}, corpusValidationf("source.source_id is server-assigned and cannot be supplied")
		}
	}
	for _, fact := range facts {
		if fact.FactID != "" {
			return normalizedVariant{}, corpusValidationf("version_fact.fact_id is server-assigned and cannot be supplied")
		}
		if fact.SourceID != "" {
			return normalizedVariant{}, corpusValidationf("version_fact.source_id is server-assigned and cannot be supplied")
		}
		if strings.TrimSpace(fact.SourceRef) == "" {
			return normalizedVariant{}, corpusValidationf("version_fact.source_ref is required for write requests")
		}
	}
	canonicalShape, canonicalJSON, shapeHash, families, err := corpus.CanonicalizeShape(shape)
	if err != nil {
		return normalizedVariant{}, corpusValidationError(err)
	}
	normalizedSources, err := corpus.NormalizeSources(sources)
	if err != nil {
		return normalizedVariant{}, corpusValidationError(err)
	}
	refs := make(map[string]bool, len(normalizedSources))
	for _, source := range normalizedSources {
		if source.SourceRef != "" {
			refs[source.SourceRef] = true
		}
	}
	normalizedFacts, err := corpus.NormalizeVersionFacts(facts, refs)
	if err != nil {
		return normalizedVariant{}, corpusValidationError(err)
	}
	return normalizedVariant{
		shape: canonicalShape, canonical: canonicalJSON, shapeHash: shapeHash,
		families: families, confidence: confidence, sources: normalizedSources, facts: normalizedFacts,
	}, nil
}

func normalizeMutation(meta CorpusMutation) CorpusMutation {
	// The current management plane has one coarse role. Never turn an upstream
	// username, email, or tailnet identity into durable corpus metadata.
	meta.Actor = "admin"
	meta.ExpectedETag = strings.Trim(strings.TrimSpace(meta.ExpectedETag), `"`)
	return meta
}

func newCorpusID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func hashCorpusValue(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func corpusProfileLabelKey(labels corpus.ProfileLabels) string {
	identity := strings.ToLower(labels.Manufacturer) + "\x00" + strings.ToLower(labels.Model)
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func ensureCorpusProfileIdentityAvailable(q corpusQuerier, labelKey, profileID string) error {
	var count int
	err := q.QueryRow(`SELECT COUNT(*) FROM device_corpus_profile_revisions
		WHERE label_key = ? AND profile_id <> ? AND status IN ('draft','published')`,
		labelKey, profileID).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrCorpusConflict
	}
	return nil
}

func requireCorpusETag(q corpusQuerier, profileID string, meta CorpusMutation) (string, error) {
	meta = normalizeMutation(meta)
	if meta.ExpectedETag == "" {
		return "", ErrCorpusPrecondition
	}
	current, err := corpusProfileETag(q, profileID)
	if err != nil {
		return "", err
	}
	if current != meta.ExpectedETag {
		return "", ErrCorpusConflict
	}
	return current, nil
}

// CreateCorpusProfile creates a stable product identity and its first draft.
func (db *DB) CreateCorpusProfile(req corpus.CreateProfileRequest, meta CorpusMutation) (*corpus.Profile, error) {
	labels, err := corpus.ValidateLabels(req.Labels)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	profileID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	revisionID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	meta = normalizeMutation(meta)
	now := nowRFC3339()
	labelKey := corpusProfileLabelKey(labels)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = ensureCorpusProfileIdentityAvailable(tx, labelKey, profileID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO device_corpus_profiles (profile_id, created_at) VALUES (?, ?)`, profileID, now); err != nil {
		return nil, fmt.Errorf("insert corpus profile: %w", err)
	}
	if _, err = tx.Exec(`INSERT INTO device_corpus_profile_revisions
		(profile_revision_id, profile_id, revision, label_key, manufacturer, model, product_family,
		 device_type, os_family, status, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 'draft', ?)`, revisionID, profileID, labelKey,
		labels.Manufacturer, labels.Model, labels.ProductFamily, labels.DeviceType, labels.OSFamily, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate active device corpus profile") {
			return nil, ErrCorpusConflict
		}
		return nil, fmt.Errorf("insert corpus profile revision: %w", err)
	}
	if err = insertCorpusAudit(tx, auditID, meta, "profile", profileID, "create", reason, "", hashCorpusValue(labels), nil, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// ReviseCorpusProfile creates a new immutable draft based on the current draft
// or published revision. The published revision remains live until publication.
func (db *DB) ReviseCorpusProfile(profileID string, req corpus.ReviseProfileRequest, meta CorpusMutation) (*corpus.Profile, error) {
	labels, err := corpus.ValidateLabels(req.Labels)
	if err != nil {
		return nil, corpusValidationError(err)
	}
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
	before, err := requireCorpusETag(tx, profileID, meta)
	if err != nil {
		return nil, err
	}
	labelKey := corpusProfileLabelKey(labels)
	if err = ensureCorpusProfileIdentityAvailable(tx, labelKey, profileID); err != nil {
		return nil, err
	}
	var baseID, baseStatus string
	var baseRevision int
	err = tx.QueryRow(`SELECT profile_revision_id, revision, status
        FROM device_corpus_profile_revisions
        WHERE profile_id = ? AND status IN ('draft','published')
        ORDER BY CASE status WHEN 'draft' THEN 0 ELSE 1 END LIMIT 1`, profileID).
		Scan(&baseID, &baseRevision, &baseStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNotFound
	}
	if err != nil {
		return nil, err
	}
	if baseStatus == "draft" {
		if _, err = tx.Exec(`UPDATE device_corpus_profile_revisions SET status = 'superseded' WHERE profile_revision_id = ?`, baseID); err != nil {
			return nil, err
		}
	}
	revisionID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	now := nowRFC3339()
	if _, err = tx.Exec(`INSERT INTO device_corpus_profile_revisions
		(profile_revision_id, profile_id, revision, supersedes_profile_revision_id, label_key,
		 manufacturer, model, product_family, device_type, os_family, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)`, revisionID, profileID,
		baseRevision+1, baseID, labelKey, labels.Manufacturer, labels.Model, labels.ProductFamily,
		labels.DeviceType, labels.OSFamily, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate active device corpus profile") {
			return nil, ErrCorpusConflict
		}
		return nil, fmt.Errorf("insert corpus profile revision: %w", err)
	}
	after, err := corpusProfileETag(tx, profileID)
	if err != nil {
		return nil, err
	}
	auditID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	if err = insertCorpusAudit(tx, auditID, meta, "profile", profileID, "revise", reason, before, after, nil, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// CreateCorpusVariant adds a new firmware/hardware lineage as a draft.
func (db *DB) CreateCorpusVariant(profileID string, req corpus.CreateVariantRequest, meta CorpusMutation) (*corpus.Profile, error) {
	variantKey, err := corpus.ValidateVariantKey(req.VariantKey)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	nv, err := normalizeVariant(req.Shape, req.ConfidenceBP, req.Sources, req.VersionFacts)
	if err != nil {
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
	var active int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_profile_revisions
        WHERE profile_id = ? AND status IN ('draft','published')`, profileID).Scan(&active); err != nil {
		return nil, err
	}
	if active == 0 {
		return nil, ErrCorpusNotFound
	}
	if req.PredecessorVariantID != "" {
		if err = requireActiveCorpusVariantPredecessor(tx, profileID, req.PredecessorVariantID); err != nil {
			return nil, err
		}
	}
	variantID := ""
	revisionNumber := 1
	auditAction := "create"
	var everPublished int
	err = tx.QueryRow(`SELECT v.variant_id,
		(SELECT COUNT(*) FROM device_corpus_variant_revisions vr
		 WHERE vr.variant_id = v.variant_id AND vr.status IN ('draft','published')),
		(SELECT COUNT(*) FROM device_corpus_variant_revisions vr
		 WHERE vr.variant_id = v.variant_id AND vr.published_at IS NOT NULL),
		(SELECT COALESCE(MAX(vr.revision), 0) FROM device_corpus_variant_revisions vr
		 WHERE vr.variant_id = v.variant_id)
		FROM device_corpus_variants v WHERE v.profile_id = ? AND v.variant_key = ?`, profileID, variantKey).
		Scan(&variantID, &active, &everPublished, &revisionNumber)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		variantID, err = newCorpusID()
		if err != nil {
			return nil, err
		}
		revisionNumber = 1
	case err != nil:
		return nil, err
	case active > 0 || everPublished > 0:
		return nil, ErrCorpusConflict
	default:
		// An abandoned, never-published series can be restarted under the same
		// stable identity. This is the only window in which its predecessor may
		// be corrected; once published the database trigger freezes it.
		revisionNumber++
		auditAction = "restore"
		cycle, cycleErr := corpusVariantCycle(tx, variantID, req.PredecessorVariantID)
		if cycleErr != nil {
			return nil, cycleErr
		}
		if cycle {
			return nil, corpusValidationf("predecessor_variant_id would create a lineage cycle")
		}
		if _, err = tx.Exec(`UPDATE device_corpus_variants SET predecessor_variant_id = NULLIF(?, '')
			WHERE variant_id = ?`, req.PredecessorVariantID, variantID); err != nil {
			return nil, err
		}
	}
	expectedReason := "new_variant"
	if auditAction == "restore" {
		expectedReason = "restore_reviewed"
	} else if req.PredecessorVariantID != "" {
		expectedReason = "firmware_evolution"
	}
	if reason != expectedReason {
		return nil, corpusValidationf("reason_code must be %s for this variant creation", expectedReason)
	}
	revisionID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	now := nowRFC3339()
	if err = insertCorpusShape(tx, nv, now); err != nil {
		return nil, err
	}
	if auditAction == "create" {
		if _, err = tx.Exec(`INSERT INTO device_corpus_variants
			(variant_id, profile_id, variant_key, predecessor_variant_id, created_at)
			VALUES (?, ?, ?, NULLIF(?, ''), ?)`, variantID, profileID, variantKey, req.PredecessorVariantID, now); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return nil, ErrCorpusConflict
			}
			return nil, err
		}
	}
	if _, err = tx.Exec(`INSERT INTO device_corpus_variant_revisions
		(variant_revision_id, variant_id, revision, shape_hash, confidence_bp, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'draft', ?)`, revisionID, variantID, revisionNumber, nv.shapeHash, nv.confidence, now); err != nil {
		return nil, err
	}
	if err = insertCorpusEvidence(tx, revisionID, nv, now); err != nil {
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
	if err = insertCorpusAudit(tx, auditID, meta, "variant", variantID, auditAction, reason, before, after, nil, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

// requireActiveCorpusVariantPredecessor prevents a new lineage from pointing at
// an abandoned or withdrawn identity. Such links could never produce a valid
// public snapshot, so reject them before creating a stable variant identity or
// changing the profile ETag.
func requireActiveCorpusVariantPredecessor(tx *sql.Tx, profileID, predecessorID string) error {
	var predecessorProfile string
	var active int
	err := tx.QueryRow(`SELECT v.profile_id,
		EXISTS (SELECT 1 FROM device_corpus_variant_revisions vr
			WHERE vr.variant_id = v.variant_id AND vr.status IN ('draft','published'))
		FROM device_corpus_variants v WHERE v.variant_id = ?`, predecessorID).
		Scan(&predecessorProfile, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("predecessor_variant_id: %w", ErrCorpusNotFound)
	}
	if err != nil {
		return err
	}
	if predecessorProfile != profileID {
		return corpusValidationf("predecessor_variant_id belongs to another profile")
	}
	if active == 0 {
		return corpusValidationf("predecessor_variant_id must have an active draft or published revision")
	}
	return nil
}

func corpusVariantCycle(tx *sql.Tx, variantID, predecessorID string) (bool, error) {
	current := predecessorID
	for depth := 0; current != "" && depth < 1024; depth++ {
		if current == variantID {
			return true, nil
		}
		var next sql.NullString
		err := tx.QueryRow(`SELECT predecessor_variant_id FROM device_corpus_variants WHERE variant_id = ?`, current).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrCorpusNotFound
		}
		if err != nil {
			return false, err
		}
		current = next.String
	}
	if current != "" {
		return true, corpusValidationf("variant lineage exceeds maximum depth")
	}
	return false, nil
}

// ReviseCorpusVariant creates a curator correction; it never changes the
// product-evolution predecessor link.
func (db *DB) ReviseCorpusVariant(variantID string, req corpus.ReviseVariantRequest, meta CorpusMutation) (*corpus.Profile, error) {
	reason, err := corpus.ValidateReasonCode(req.ReasonCode)
	if err != nil {
		return nil, corpusValidationError(err)
	}
	if reason != "signal_correction" && reason != "source_update" {
		return nil, corpusValidationf("reason_code must describe a curator correction, not product evolution")
	}
	nv, err := normalizeVariant(req.Shape, req.ConfidenceBP, req.Sources, req.VersionFacts)
	if err != nil {
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
	var baseID, baseStatus string
	var baseRevision int
	err = tx.QueryRow(`SELECT variant_revision_id, revision, status
        FROM device_corpus_variant_revisions
        WHERE variant_id = ? AND status IN ('draft','published')
        ORDER BY CASE status WHEN 'draft' THEN 0 ELSE 1 END LIMIT 1`, variantID).
		Scan(&baseID, &baseRevision, &baseStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNotFound
	}
	if err != nil {
		return nil, err
	}
	if baseStatus == "draft" {
		if _, err = tx.Exec(`UPDATE device_corpus_variant_revisions SET status = 'superseded' WHERE variant_revision_id = ?`, baseID); err != nil {
			return nil, err
		}
	}
	revisionID, err := newCorpusID()
	if err != nil {
		return nil, err
	}
	now := nowRFC3339()
	if err = insertCorpusShape(tx, nv, now); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO device_corpus_variant_revisions
        (variant_revision_id, variant_id, revision, supersedes_revision_id,
         shape_hash, confidence_bp, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'draft', ?)`, revisionID, variantID,
		baseRevision+1, baseID, nv.shapeHash, nv.confidence, now); err != nil {
		return nil, err
	}
	if err = insertCorpusEvidence(tx, revisionID, nv, now); err != nil {
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
	if err = insertCorpusAudit(tx, auditID, meta, "variant", variantID, "revise", reason, before, after, nil, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCorpusProfile(profileID)
}

func insertCorpusShape(tx *sql.Tx, nv normalizedVariant, now string) error {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO device_corpus_shapes
        (shape_hash, schema_version, canonical_json, signal_family_count, created_at)
        VALUES (?, ?, ?, ?, ?)`, nv.shapeHash, corpus.SchemaVersion, string(nv.canonical), nv.families, now); err != nil {
		return err
	}
	var existing string
	if err := tx.QueryRow(`SELECT canonical_json FROM device_corpus_shapes WHERE shape_hash = ?`, nv.shapeHash).Scan(&existing); err != nil {
		return err
	}
	if existing != string(nv.canonical) {
		return fmt.Errorf("device corpus shape digest collision")
	}
	return nil
}

func insertCorpusEvidence(tx *sql.Tx, revisionID string, nv normalizedVariant, now string) error {
	refIDs := make(map[string]string, len(nv.sources))
	for _, source := range nv.sources {
		sourceID, err := newCorpusID()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO device_corpus_sources
            (source_id, variant_revision_id, kind, title, public_url, retrieved_at, license_code, created_at)
            VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, sourceID, revisionID, source.Kind,
			source.Title, source.PublicURL, source.RetrievedAt, source.LicenseCode, now); err != nil {
			return err
		}
		if source.SourceRef != "" {
			refIDs[source.SourceRef] = sourceID
		}
	}
	for _, fact := range nv.facts {
		factID, err := newCorpusID()
		if err != nil {
			return err
		}
		sourceID := refIDs[fact.SourceRef]
		if _, err = tx.Exec(`INSERT INTO device_corpus_version_facts
            (fact_id, variant_revision_id, attribute, relation, value, value_end,
             confidence_bp, source_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, factID, revisionID,
			fact.Attribute, fact.Relation, fact.Value, fact.ValueEnd, fact.ConfidenceBP, sourceID, now); err != nil {
			return err
		}
	}
	return nil
}

func insertCorpusAudit(tx *sql.Tx, auditID string, meta CorpusMutation, entityType, entityID, action, reason, before, after string, corpusRevision *int, now string) error {
	// The request correlation ID is service-generated. Never persist an
	// arbitrary caller value that could encode operator/site data.
	requestID := auditID
	_, err := tx.Exec(`INSERT INTO device_corpus_audit
        (audit_id, actor, entity_type, entity_id, action, reason_code, before_hash,
         after_hash, request_id, corpus_revision, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auditID, meta.Actor, entityType,
		entityID, action, reason, before, after, requestID, corpusRevision, now)
	if err != nil {
		return fmt.Errorf("insert device corpus audit: %w", err)
	}
	return nil
}
