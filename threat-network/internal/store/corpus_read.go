package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

type CorpusReleaseSummary struct {
	CorpusRevision int       `json:"corpus_revision"`
	SchemaVersion  int       `json:"schema_version"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	ProfileCount   int       `json:"profile_count"`
	VariantCount   int       `json:"variant_count"`
	CreatedAt      time.Time `json:"created_at"`
}

func parseCorpusTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid corpus timestamp: %w", err)
	}
	return t.UTC(), nil
}

func parseOptionalCorpusTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	t, err := parseCorpusTime(value.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (db *DB) GetCorpusProfile(profileID string) (*corpus.Profile, error) {
	return getCorpusProfile(db, profileID)
}

func getCorpusProfile(q corpusQuerier, profileID string) (*corpus.Profile, error) {
	var createdRaw string
	if err := q.QueryRow(`SELECT created_at FROM device_corpus_profiles WHERE profile_id = ?`, profileID).Scan(&createdRaw); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCorpusNotFound
	} else if err != nil {
		return nil, err
	}
	createdAt, err := parseCorpusTime(createdRaw)
	if err != nil {
		return nil, err
	}
	result := &corpus.Profile{ProfileID: profileID, CreatedAt: createdAt, Variants: []corpus.Variant{}}

	rows, err := q.Query(`SELECT profile_revision_id, revision,
        COALESCE(supersedes_profile_revision_id, ''), manufacturer, model,
        product_family, device_type, os_family, status, created_at, published_at, retired_at
        FROM device_corpus_profile_revisions WHERE profile_id = ? ORDER BY revision DESC`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rev corpus.ProfileRevision
		var created string
		var published, retired sql.NullString
		if err = rows.Scan(&rev.ProfileRevisionID, &rev.Revision, &rev.SupersedesID,
			&rev.Labels.Manufacturer, &rev.Labels.Model, &rev.Labels.ProductFamily,
			&rev.Labels.DeviceType, &rev.Labels.OSFamily, &rev.Status, &created,
			&published, &retired); err != nil {
			rows.Close()
			return nil, err
		}
		if rev.CreatedAt, err = parseCorpusTime(created); err != nil {
			rows.Close()
			return nil, err
		}
		if rev.PublishedAt, err = parseOptionalCorpusTime(published); err != nil {
			rows.Close()
			return nil, err
		}
		if rev.RetiredAt, err = parseOptionalCorpusTime(retired); err != nil {
			rows.Close()
			return nil, err
		}
		copyRev := rev
		if rev.Status == "draft" {
			result.Draft = &copyRev
		}
		if rev.Status == "published" {
			result.Published = &copyRev
		}
		result.History = append(result.History, rev)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}

	rows, err = q.Query(`SELECT variant_id, variant_key, COALESCE(predecessor_variant_id, ''), created_at
        FROM device_corpus_variants WHERE profile_id = ? ORDER BY created_at, variant_key`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v corpus.Variant
		var created string
		if err = rows.Scan(&v.VariantID, &v.VariantKey, &v.PredecessorVariantID, &created); err != nil {
			rows.Close()
			return nil, err
		}
		if v.CreatedAt, err = parseCorpusTime(created); err != nil {
			rows.Close()
			return nil, err
		}
		result.Variants = append(result.Variants, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range result.Variants {
		if err = loadCorpusVariantRevisions(q, &result.Variants[i]); err != nil {
			return nil, err
		}
	}
	result.ETag, err = corpusProfileETag(q, profileID)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func loadCorpusVariantRevisions(q corpusQuerier, variant *corpus.Variant) error {
	rows, err := q.Query(`SELECT vr.variant_revision_id, vr.revision,
        COALESCE(vr.supersedes_revision_id, ''), vr.shape_hash, s.canonical_json,
        vr.confidence_bp, vr.status, vr.created_at, vr.published_at, vr.withdrawn_at
        FROM device_corpus_variant_revisions vr
        JOIN device_corpus_shapes s ON s.shape_hash = vr.shape_hash
        WHERE vr.variant_id = ? ORDER BY vr.revision DESC`, variant.VariantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rev corpus.VariantRevision
		var shapeJSON, created string
		var published, withdrawn sql.NullString
		if err = rows.Scan(&rev.VariantRevisionID, &rev.Revision, &rev.SupersedesID,
			&rev.ShapeHash, &shapeJSON, &rev.ConfidenceBP, &rev.Status, &created,
			&published, &withdrawn); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal([]byte(shapeJSON), &rev.Shape); err != nil {
			rows.Close()
			return fmt.Errorf("decode stored corpus shape: %w", err)
		}
		if rev.CreatedAt, err = parseCorpusTime(created); err != nil {
			rows.Close()
			return err
		}
		if rev.PublishedAt, err = parseOptionalCorpusTime(published); err != nil {
			rows.Close()
			return err
		}
		if rev.WithdrawnAt, err = parseOptionalCorpusTime(withdrawn); err != nil {
			rows.Close()
			return err
		}
		variant.History = append(variant.History, rev)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for i := range variant.History {
		if err = loadCorpusEvidence(q, variant.History[i].VariantRevisionID, &variant.History[i]); err != nil {
			return err
		}
		copyRev := variant.History[i]
		if copyRev.Status == "draft" {
			variant.Draft = &copyRev
		}
		if copyRev.Status == "published" {
			variant.Published = &copyRev
		}
	}
	return nil
}

func loadCorpusEvidence(q corpusQuerier, revisionID string, rev *corpus.VariantRevision) error {
	rev.Sources = []corpus.Source{}
	rev.VersionFacts = []corpus.VersionFact{}
	sourceRows, err := q.Query(`SELECT source_id, kind, title, public_url,
        COALESCE(retrieved_at, ''), license_code FROM device_corpus_sources
        WHERE variant_revision_id = ? ORDER BY kind, title, source_id`, revisionID)
	if err != nil {
		return err
	}
	defer sourceRows.Close()
	for sourceRows.Next() {
		var source corpus.Source
		if err = sourceRows.Scan(&source.SourceID, &source.Kind, &source.Title, &source.PublicURL,
			&source.RetrievedAt, &source.LicenseCode); err != nil {
			sourceRows.Close()
			return err
		}
		rev.Sources = append(rev.Sources, source)
	}
	if err = sourceRows.Err(); err != nil {
		sourceRows.Close()
		return err
	}
	if err = sourceRows.Close(); err != nil {
		return err
	}
	factRows, err := q.Query(`SELECT fact_id, attribute, relation, value, value_end,
        confidence_bp, COALESCE(source_id, '') FROM device_corpus_version_facts
        WHERE variant_revision_id = ? ORDER BY attribute, value, fact_id`, revisionID)
	if err != nil {
		return err
	}
	defer factRows.Close()
	for factRows.Next() {
		var fact corpus.VersionFact
		if err = factRows.Scan(&fact.FactID, &fact.Attribute, &fact.Relation, &fact.Value,
			&fact.ValueEnd, &fact.ConfidenceBP, &fact.SourceID); err != nil {
			factRows.Close()
			return err
		}
		rev.VersionFacts = append(rev.VersionFacts, fact)
	}
	if err = factRows.Err(); err != nil {
		factRows.Close()
		return err
	}
	return factRows.Close()
}

func corpusProfileETag(q corpusQuerier, profileID string) (string, error) {
	parts := []string{"profile:" + profileID}
	rows, err := q.Query(`SELECT profile_revision_id, status FROM device_corpus_profile_revisions
        WHERE profile_id = ? ORDER BY revision`, profileID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	seen := false
	for rows.Next() {
		seen = true
		var id, status string
		if err = rows.Scan(&id, &status); err != nil {
			rows.Close()
			return "", err
		}
		parts = append(parts, "p:"+id+":"+status)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	if err = rows.Close(); err != nil {
		return "", err
	}
	if !seen {
		return "", ErrCorpusNotFound
	}
	rows, err = q.Query(`SELECT v.variant_id, v.variant_key, COALESCE(v.predecessor_variant_id, ''),
        vr.variant_revision_id, vr.status
        FROM device_corpus_variants v
        JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
        WHERE v.profile_id = ? ORDER BY v.variant_id, vr.revision`, profileID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var variantID, key, predecessor, revisionID, status string
		if err = rows.Scan(&variantID, &key, &predecessor, &revisionID, &status); err != nil {
			rows.Close()
			return "", err
		}
		parts = append(parts, "v:"+variantID+":"+key+":"+predecessor+":"+revisionID+":"+status)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	if err = rows.Close(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

type CorpusProfilePage struct {
	Items  []corpus.ProfileSummary `json:"items"`
	Total  int                     `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

type CorpusAuditPage struct {
	Items  []corpus.AuditEntry `json:"items"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

type CorpusReleasePage struct {
	Items  []CorpusReleaseSummary `json:"items"`
	Total  int                    `json:"total"`
	Limit  int                    `json:"limit"`
	Offset int                    `json:"offset"`
}

// PageCorpusProfiles returns one stable page ordered by the most recent
// profile or variant revision. Search is applied before pagination so Total is
// the complete filtered result count rather than the current page length.
func (db *DB) PageCorpusProfiles(search string, limit, offset int) (CorpusProfilePage, error) {
	page := CorpusProfilePage{Items: []corpus.ProfileSummary{}, Limit: limit, Offset: offset}
	search = strings.ToLower(strings.TrimSpace(search))
	if limit < 1 || limit > 100 || offset < 0 || len(search) > 128 || strings.ContainsAny(search, "\r\n\x00") {
		return page, fmt.Errorf("invalid corpus profile page")
	}
	tx, err := db.Begin()
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	const activeRevisions = `WITH active_profile_revision AS (
		SELECT pr.* FROM device_corpus_profile_revisions pr
		WHERE pr.profile_revision_id = (
			SELECT candidate.profile_revision_id
			FROM device_corpus_profile_revisions candidate
			WHERE candidate.profile_id = pr.profile_id
			ORDER BY CASE candidate.status
				WHEN 'draft' THEN 0 WHEN 'published' THEN 1 ELSE 2 END,
				candidate.revision DESC
			LIMIT 1
		)
	)`
	filter := `instr(lower(apr.manufacturer || ' ' || apr.model || ' ' ||
		apr.product_family || ' ' || apr.device_type || ' ' || apr.os_family), ?) > 0`
	if err = tx.QueryRow(activeRevisions+`
		SELECT COUNT(*) FROM active_profile_revision apr WHERE `+filter, search).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := tx.Query(activeRevisions+`
		SELECT apr.profile_id
		FROM active_profile_revision apr
		LEFT JOIN device_corpus_variants v ON v.profile_id = apr.profile_id
		LEFT JOIN device_corpus_variant_revisions vr ON vr.variant_id = v.variant_id
		WHERE `+filter+`
		GROUP BY apr.profile_id, apr.created_at
		ORDER BY CASE
			WHEN COALESCE(MAX(vr.created_at), '') > apr.created_at THEN MAX(vr.created_at)
			ELSE apr.created_at
		END DESC, apr.profile_id ASC
		LIMIT ? OFFSET ?`, search, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return page, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	if err = rows.Close(); err != nil {
		return page, err
	}
	page.Items = make([]corpus.ProfileSummary, 0, len(ids))
	for _, id := range ids {
		profile, getErr := getCorpusProfile(tx, id)
		if getErr != nil {
			return page, getErr
		}
		var active *corpus.ProfileRevision
		status := "retired"
		if profile.Draft != nil {
			active = profile.Draft
			status = "draft"
		} else if profile.Published != nil {
			active = profile.Published
			status = "published"
		} else if len(profile.History) > 0 {
			active = &profile.History[0]
			status = profile.History[0].Status
		}
		if active == nil {
			continue
		}
		summary := corpus.ProfileSummary{ProfileID: id, Labels: active.Labels, Status: status,
			HasDraftChanges: profile.Draft != nil, UpdatedAt: active.CreatedAt, ETag: profile.ETag}
		for _, variant := range profile.Variants {
			if variant.Published != nil {
				summary.PublishedVariants++
			}
			if variant.Draft != nil {
				summary.DraftVariants++
			}
			if len(variant.History) > 0 && variant.History[0].CreatedAt.After(summary.UpdatedAt) {
				summary.UpdatedAt = variant.History[0].CreatedAt
			}
		}
		page.Items = append(page.Items, summary)
	}
	return page, nil
}

// ListCorpusProfiles is retained for callers that do not need paging.
func (db *DB) ListCorpusProfiles(search string, limit int) ([]corpus.ProfileSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	page, err := db.PageCorpusProfiles(search, limit, 0)
	return page.Items, err
}

func (db *DB) PageCorpusAudit(limit, offset int) (CorpusAuditPage, error) {
	page := CorpusAuditPage{Items: []corpus.AuditEntry{}, Limit: limit, Offset: offset}
	if limit < 1 || limit > 100 || offset < 0 {
		return page, fmt.Errorf("invalid corpus audit page")
	}
	tx, err := db.Begin()
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_audit`).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := tx.Query(`SELECT audit_id, actor, entity_type, entity_id, action,
        reason_code, before_hash, after_hash, request_id, corpus_revision, created_at
        FROM device_corpus_audit ORDER BY created_at DESC, audit_id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry corpus.AuditEntry
		var revision sql.NullInt64
		var created string
		if err = rows.Scan(&entry.AuditID, &entry.Actor, &entry.EntityType, &entry.EntityID,
			&entry.Action, &entry.ReasonCode, &entry.BeforeHash, &entry.AfterHash,
			&entry.RequestID, &revision, &created); err != nil {
			rows.Close()
			return page, err
		}
		if revision.Valid {
			r := int(revision.Int64)
			entry.CorpusRevision = &r
		}
		if entry.CreatedAt, err = parseCorpusTime(created); err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, entry)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	if err = rows.Close(); err != nil {
		return page, err
	}
	return page, nil
}

func (db *DB) ListCorpusAudit(limit int) ([]corpus.AuditEntry, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	page, err := db.PageCorpusAudit(limit, 0)
	return page.Items, err
}

func (db *DB) PageCorpusReleases(limit, offset int) (CorpusReleasePage, error) {
	page := CorpusReleasePage{Items: []CorpusReleaseSummary{}, Limit: limit, Offset: offset}
	if limit < 1 || limit > 100 || offset < 0 {
		return page, fmt.Errorf("invalid corpus release page")
	}
	tx, err := db.Begin()
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err = tx.QueryRow(`SELECT COUNT(*) FROM device_corpus_releases`).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := tx.Query(`SELECT corpus_revision, schema_version, snapshot_sha256,
        profile_count, variant_count, created_at FROM device_corpus_releases
        ORDER BY corpus_revision DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var release CorpusReleaseSummary
		var created string
		if err = rows.Scan(&release.CorpusRevision, &release.SchemaVersion,
			&release.SnapshotSHA256, &release.ProfileCount, &release.VariantCount,
			&created); err != nil {
			rows.Close()
			return page, err
		}
		if release.CreatedAt, err = parseCorpusTime(created); err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, release)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	if err = rows.Close(); err != nil {
		return page, err
	}
	return page, nil
}

func (db *DB) ListCorpusReleases(limit int) ([]CorpusReleaseSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	page, err := db.PageCorpusReleases(limit, 0)
	return page.Items, err
}

func (db *DB) GetCorpusRelease(revision int) ([]byte, CorpusReleaseSummary, error) {
	var summary CorpusReleaseSummary
	var raw sql.NullString
	var storedBytes int64
	var created string
	err := db.QueryRow(`SELECT corpus_revision, schema_version, snapshot_sha256, `+
		boundedCorpusSnapshotColumns+`,
		profile_count, variant_count, created_at
		FROM device_corpus_releases WHERE corpus_revision = ?`, maxCorpusSnapshotBytes, revision).Scan(
		&summary.CorpusRevision, &summary.SchemaVersion, &summary.SnapshotSHA256,
		&storedBytes, &raw, &summary.ProfileCount, &summary.VariantCount, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, summary, ErrCorpusNotFound
	}
	if err != nil {
		return nil, summary, err
	}
	if summary.CreatedAt, err = parseCorpusTime(created); err != nil {
		return nil, summary, err
	}
	if storedBytes > maxCorpusSnapshotBytes || !raw.Valid {
		return nil, summary, fmt.Errorf("device corpus snapshot exceeds 16 MiB publication limit")
	}
	manifest := corpus.Manifest{
		SchemaVersion:  summary.SchemaVersion,
		CorpusRevision: summary.CorpusRevision,
		SnapshotSHA256: summary.SnapshotSHA256,
		ProfileCount:   summary.ProfileCount,
		VariantCount:   summary.VariantCount,
		GeneratedAt:    summary.CreatedAt,
		SnapshotPath:   corpusSnapshotPath,
	}
	if _, err = validateStoredCorpusReleaseSnapshot([]byte(raw.String), manifest); err != nil {
		return nil, summary, err
	}
	return []byte(raw.String), summary, nil
}
