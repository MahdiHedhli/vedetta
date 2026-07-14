package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

type countingCorpusQuerier struct {
	corpusQuerier
	queryCount int
}

func (q *countingCorpusQuerier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	q.queryCount++
	return q.corpusQuerier.QueryContext(ctx, query, args...)
}

func TestCorpusSnapshotEvidenceLoadsAreBatched(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	wantEvidence := map[string]struct{ title, version string }{}
	for i, key := range []string{"batch-a", "batch-b", "batch-c"} {
		req := corpusVariantRequest(key)
		req.Sources[0].Title = "Evidence " + key
		req.VersionFacts[0].Value = fmt.Sprintf("3.0.%d", i)
		wantEvidence[key] = struct{ title, version string }{req.Sources[0].Title, req.VersionFacts[0].Value}
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req,
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
	}

	assertEvidence := func(variants []corpus.PublicVariant) {
		t.Helper()
		if len(variants) != len(wantEvidence) {
			t.Fatalf("variant count = %d, want %d", len(variants), len(wantEvidence))
		}
		for _, variant := range variants {
			want, ok := wantEvidence[variant.VariantKey]
			if !ok || len(variant.Sources) != 1 || len(variant.VersionFacts) != 1 ||
				variant.Sources[0].Title != want.title || variant.VersionFacts[0].Value != want.version {
				t.Fatalf("evidence attached to wrong variant: %+v", variant)
			}
		}
	}

	previewProfile := corpus.PublicProfile{ProfileID: profile.ProfileID, Variants: []corpus.PublicVariant{}}
	previewQueries := &countingCorpusQuerier{corpusQuerier: db}
	if err = loadCorpusPreviewVariants(context.Background(), previewQueries, &previewProfile, true); err != nil {
		t.Fatal(err)
	}
	if previewQueries.queryCount != 3 {
		t.Fatalf("preview variant/evidence queries = %d, want 3", previewQueries.queryCount)
	}
	assertEvidence(previewProfile.Variants)

	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	publicProfile := corpus.PublicProfile{ProfileID: profile.ProfileID, Variants: []corpus.PublicVariant{}}
	publicQueries := &countingCorpusQuerier{corpusQuerier: db}
	if err = loadPublicCorpusVariants(context.Background(), publicQueries, &publicProfile); err != nil {
		t.Fatal(err)
	}
	if publicQueries.queryCount != 3 {
		t.Fatalf("public variant/evidence queries = %d, want 3", publicQueries.queryCount)
	}
	assertEvidence(publicProfile.Variants)
	if !reflect.DeepEqual(publicProfile.Variants, previewProfile.Variants) {
		t.Fatal("batched preview and published evidence differ")
	}
}

func TestCorpusEvidenceBatchBoundsSQLiteParameters(t *testing.T) {
	db := newTestDB(t)
	revisionIDs := make([]string, corpusEvidenceBatchSize+1)
	for i := range revisionIDs {
		revisionIDs[i] = fmt.Sprintf("missing-revision-%04d", i)
	}
	queries := &countingCorpusQuerier{corpusQuerier: db}
	evidence, err := loadCorpusEvidenceBatch(context.Background(), queries, revisionIDs)
	if err != nil {
		t.Fatal(err)
	}
	if queries.queryCount != 4 {
		t.Fatalf("chunked evidence queries = %d, want 4", queries.queryCount)
	}
	if len(evidence) != len(revisionIDs) {
		t.Fatalf("evidence entries = %d, want %d", len(evidence), len(revisionIDs))
	}
	for _, revisionID := range revisionIDs {
		loaded := evidence[revisionID]
		if loaded.Sources == nil || loaded.VersionFacts == nil {
			t.Fatalf("missing revision %q did not retain non-nil empty evidence", revisionID)
		}
	}
}

func TestCorpusProfilePagingSearchesBeforeOffset(t *testing.T) {
	db := newTestDB(t)
	for _, model := range []string{"Paging Alpha", "Paging Beta", "Paging Gamma"} {
		req := corpusProfileRequest()
		req.Labels.Model = model
		if _, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{}); err != nil {
			t.Fatal(err)
		}
	}

	page, err := db.PageCorpusProfiles(context.Background(), "paging", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Limit != 1 || page.Offset != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	filtered, err := db.PageCorpusProfiles(context.Background(), "Paging Beta", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].Labels.Model != "Paging Beta" {
		t.Fatalf("search was not applied before pagination: %+v", filtered)
	}

	audit, err := db.PageCorpusAudit(context.Background(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Total != 3 || len(audit.Items) != 2 || audit.Limit != 2 || audit.Offset != 1 {
		t.Fatalf("unexpected audit page: %+v", audit)
	}
	releases, err := db.PageCorpusReleases(context.Background(), 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if releases.Total != 0 || releases.Items == nil {
		t.Fatalf("unexpected empty release page: %+v", releases)
	}
}

func TestCorpusProfilePagingCountsActiveVariantsButOrdersByLatestHistory(t *testing.T) {
	db := newTestDB(t)
	requestA := corpusProfileRequest()
	requestA.Labels.Model = "Ordering Camera A"
	profileA, err := db.CreateCorpusProfile(context.Background(), requestA, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profileA, err = db.CreateCorpusVariant(context.Background(), profileA.ProfileID,
		corpusVariantRequest("ordering-a"), CorpusMutation{ExpectedETag: profileA.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profileA, err = db.PublishCorpusProfile(context.Background(), profileA.ProfileID,
		corpusPublishRequest(0), CorpusMutation{ExpectedETag: profileA.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variant := profileA.Variants[0]
	clean := corpusVariantRequest("unused")
	profileA, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, corpus.ReviseVariantRequest{
		ConfidenceBP: variant.Published.ConfidenceBP,
		Shape:        variant.Published.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "signal_correction",
	}, CorpusMutation{ExpectedETag: profileA.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profileA, err = db.DiscardCorpusVariantDraft(context.Background(), variant.VariantID,
		corpus.LifecycleRequest{ReasonCode: "signal_correction"},
		CorpusMutation{ExpectedETag: profileA.ETag})
	if err != nil {
		t.Fatal(err)
	}

	requestB := corpusProfileRequest()
	requestB.Labels.Model = "Ordering Camera B"
	profileB, err := db.CreateCorpusProfile(context.Background(), requestB, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}

	// Make the lifecycle chronology deterministic: B's active profile revision
	// is newer than A's active content, while A's discarded correction is the
	// newest historical change. List counts must ignore the withdrawn revision,
	// but UpdatedAt and ordering must retain it for curator/audit visibility.
	if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_profile_content_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_variant_content_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_profile_revisions SET created_at = ? WHERE profile_id = ?`,
		"2000-01-01T00:00:00Z", profileA.ProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_profile_revisions SET created_at = ? WHERE profile_id = ?`,
		"2050-01-01T00:00:00Z", profileB.ProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_variant_revisions
		SET created_at = CASE WHEN status = 'withdrawn' THEN ? ELSE ? END WHERE variant_id = ?`,
		"2099-01-01T00:00:00Z", "2001-01-01T00:00:00Z", variant.VariantID); err != nil {
		t.Fatal(err)
	}

	page, err := db.PageCorpusProfiles(context.Background(), "ordering camera", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("unexpected page: %+v", page)
	}
	first := page.Items[0]
	if first.ProfileID != profileA.ProfileID || first.PublishedVariants != 1 || first.DraftVariants != 0 ||
		first.UpdatedAt.Format("2006-01-02T15:04:05Z") != "2099-01-01T00:00:00Z" {
		t.Fatalf("latest historical change did not drive ordering without affecting active counts: %+v", first)
	}
	if page.Items[1].ProfileID != profileB.ProfileID {
		t.Fatalf("profile ordered ahead of newer historical change: %+v", page.Items)
	}
}

func TestCorpusProfilePagingBuildsExactSummariesWithoutHydratingEvidence(t *testing.T) {
	db := newTestDB(t)
	req := corpusProfileRequest()
	req.Labels.Model = "Summary Camera"
	profile, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"summary-v1", "summary-v2"} {
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest(key),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	labels := req.Labels
	labels.Model = "Summary Camera Revised"
	profile, err = db.ReviseCorpusProfile(context.Background(), profile.ProfileID, corpus.ReviseProfileRequest{
		Labels: labels, ReasonCode: "label_correction",
	}, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variant := profile.Variants[0]
	clean := corpusVariantRequest("unused")
	profile, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, corpus.ReviseVariantRequest{
		ConfidenceBP: variant.Published.ConfidenceBP,
		Shape:        variant.Published.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "signal_correction",
	}, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	page, err := db.PageCorpusProfiles(context.Background(), "summary camera revised", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected profile page: %+v", page)
	}
	summary := page.Items[0]
	if summary.ProfileID != profile.ProfileID || !reflect.DeepEqual(summary.Labels, profile.Draft.Labels) {
		t.Fatalf("summary identity/labels = %+v, want profile %+v", summary, profile)
	}
	if summary.Status != "draft" || !summary.HasDraftChanges ||
		summary.PublishedVariants != 2 || summary.DraftVariants != 1 {
		t.Fatalf("summary lifecycle/counts = %+v", summary)
	}
	if summary.ETag != profile.ETag {
		t.Fatalf("summary ETag = %q, want %q", summary.ETag, profile.ETag)
	}
	wantUpdated := profile.Draft.CreatedAt
	for _, item := range profile.Variants {
		if len(item.History) > 0 && item.History[0].CreatedAt.After(wantUpdated) {
			wantUpdated = item.History[0].CreatedAt
		}
	}
	if !summary.UpdatedAt.Equal(wantUpdated) {
		t.Fatalf("summary updated_at = %s, want %s", summary.UpdatedAt, wantUpdated)
	}

	// A list request must not decode or otherwise hydrate the deeply nested
	// shape/evidence graph. Corrupting shape JSON simulates a damaged detail row:
	// the detail endpoint detects it, while the independent summary ledger still
	// returns the exact labels, counts, lifecycle state, and ETag.
	if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_shapes_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_shapes SET canonical_json = 'not-json'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetCorpusProfile(context.Background(), profile.ProfileID); err == nil {
		t.Fatal("corrupt shape unexpectedly hydrated as a valid profile detail")
	}
	lightweight, err := db.PageCorpusProfiles(context.Background(), "summary camera revised", 50, 0)
	if err != nil {
		t.Fatalf("lightweight summary loaded nested evidence: %v", err)
	}
	if len(lightweight.Items) != 1 || !reflect.DeepEqual(lightweight.Items[0], summary) {
		t.Fatalf("lightweight summary changed after unrelated evidence corruption: %+v", lightweight)
	}
}

func TestCorpusProfileBatchedETagsAndSummariesCoverLifecycleHistories(t *testing.T) {
	db := newTestDB(t)
	create := func(model string) *corpus.Profile {
		t.Helper()
		req := corpusProfileRequest()
		req.Labels.Model = model
		profile, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	addVariant := func(profile *corpus.Profile, key string) *corpus.Profile {
		t.Helper()
		updated, err := db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest(key),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}
	publish := func(profile *corpus.Profile) *corpus.Profile {
		t.Helper()
		manifest, err := db.CorpusManifest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		updated, err := db.PublishCorpusProfile(context.Background(), profile.ProfileID,
			corpusPublishRequest(manifest.CorpusRevision), CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}

	draft := create("ETag Draft")

	published := publish(addVariant(create("ETag Published"), "published-v1"))
	publishedVariant := published.Variants[0]
	clean := corpusVariantRequest("unused")
	var err error
	variantDraft := publish(addVariant(create("ETag Variant Draft"), "variant-draft-v1"))
	variantDraftSeries := variantDraft.Variants[0]
	variantDraft, err = db.ReviseCorpusVariant(context.Background(), variantDraftSeries.VariantID, corpus.ReviseVariantRequest{
		ConfidenceBP: variantDraftSeries.Published.ConfidenceBP,
		Shape:        variantDraftSeries.Published.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "signal_correction",
	}, CorpusMutation{ExpectedETag: variantDraft.ETag})
	if err != nil {
		t.Fatal(err)
	}
	published, err = db.ReviseCorpusVariant(context.Background(), publishedVariant.VariantID, corpus.ReviseVariantRequest{
		ConfidenceBP: publishedVariant.Published.ConfidenceBP,
		Shape:        publishedVariant.Published.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "signal_correction",
	}, CorpusMutation{ExpectedETag: published.ETag})
	if err != nil {
		t.Fatal(err)
	}
	published, err = db.DiscardCorpusVariantDraft(context.Background(), publishedVariant.VariantID,
		corpus.LifecycleRequest{ReasonCode: "signal_correction"},
		CorpusMutation{ExpectedETag: published.ETag})
	if err != nil {
		t.Fatal(err)
	}

	withdrawn := publish(addVariant(create("ETag Withdrawn"), "withdrawn-v1"))
	manifest, err := db.CorpusManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	withdrawn, err = db.WithdrawCorpusVariant(context.Background(), withdrawn.Variants[0].VariantID,
		corpusLifecycleRequest("privacy_withdrawal", manifest.CorpusRevision),
		CorpusMutation{ExpectedETag: withdrawn.ETag})
	if err != nil {
		t.Fatal(err)
	}

	retired := publish(addVariant(create("ETag Retired"), "retired-v1"))
	manifest, err = db.CorpusManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	retired, err = db.RetireCorpusProfile(context.Background(), retired.ProfileID,
		corpusLifecycleRequest("obsolete_product", manifest.CorpusRevision),
		CorpusMutation{ExpectedETag: retired.ETag})
	if err != nil {
		t.Fatal(err)
	}

	profiles := []*corpus.Profile{draft, published, variantDraft, withdrawn, retired}
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ProfileID)
	}
	batched, err := corpusProfileETags(context.Background(), db, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range profiles {
		individual, etagErr := corpusProfileETag(context.Background(), db, profile.ProfileID)
		if etagErr != nil {
			t.Fatal(etagErr)
		}
		if batched[profile.ProfileID] != individual || individual != profile.ETag {
			t.Fatalf("profile %s batched ETag=%q individual=%q detail=%q",
				profile.ProfileID, batched[profile.ProfileID], individual, profile.ETag)
		}
	}

	page, err := db.PageCorpusProfiles(context.Background(), "etag", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != len(profiles) || len(page.Items) != len(profiles) {
		t.Fatalf("lifecycle page = %+v", page)
	}
	type wantSummary struct {
		status                  string
		published, draft, dirty int
		profile                 *corpus.Profile
	}
	want := map[string]wantSummary{
		draft.ProfileID:        {status: "draft", draft: 0, dirty: 1, profile: draft},
		published.ProfileID:    {status: "published", published: 1, profile: published},
		variantDraft.ProfileID: {status: "published", published: 1, draft: 1, dirty: 1, profile: variantDraft},
		withdrawn.ProfileID:    {status: "published", profile: withdrawn},
		retired.ProfileID:      {status: "retired", profile: retired},
	}
	for _, summary := range page.Items {
		expected, ok := want[summary.ProfileID]
		if !ok {
			t.Fatalf("unexpected summary: %+v", summary)
		}
		if summary.Status != expected.status || summary.PublishedVariants != expected.published ||
			summary.DraftVariants != expected.draft || summary.HasDraftChanges != (expected.dirty == 1) {
			t.Fatalf("profile %s lifecycle summary = %+v, want %+v", summary.ProfileID, summary, expected)
		}
		activeUpdated := expected.profile.History[0].CreatedAt
		if expected.profile.Draft != nil {
			activeUpdated = expected.profile.Draft.CreatedAt
		} else if expected.profile.Published != nil {
			activeUpdated = expected.profile.Published.CreatedAt
		}
		for _, variant := range expected.profile.Variants {
			if len(variant.History) > 0 && variant.History[0].CreatedAt.After(activeUpdated) {
				activeUpdated = variant.History[0].CreatedAt
			}
		}
		if !summary.UpdatedAt.Equal(activeUpdated) || summary.ETag != expected.profile.ETag {
			t.Fatalf("profile %s timestamp/ETag summary = %+v, want updated=%s etag=%s",
				summary.ProfileID, summary, activeUpdated, expected.profile.ETag)
		}
	}
}

func TestCorpusPreviewUsesDraftsWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	req := corpusProfileRequest()
	req.Labels.Model = "Preview Camera"
	profile, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	variantReq := corpusVariantRequest("preview-v1")
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, variantReq, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
		corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	reviseProfile := corpus.ReviseProfileRequest{Labels: req.Labels, ReasonCode: "label_correction"}
	reviseProfile.Labels.Model = "Preview Camera Revised"
	profile, err = db.ReviseCorpusProfile(context.Background(), profile.ProfileID, reviseProfile, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variant := profile.Variants[0]
	reviseVariant := corpus.ReviseVariantRequest{
		ConfidenceBP: 9300,
		Shape: corpus.CanonicalShapeV1{
			DHCPOption55: []uint16{1, 3, 6, 15, 119},
			MDNSModels:   []string{"Preview Camera Model Two"},
		},
		Sources: []corpus.Source{{SourceRef: "vendor", Kind: "vendor_doc",
			Title: "Preview Camera Support", PublicURL: "https://docs.example.com/preview-camera"}},
		VersionFacts: []corpus.VersionFact{{Attribute: "firmware_version", Relation: "exact",
			Value: "3.0.0", ConfidenceBP: 9000, SourceRef: "vendor"}},
		ReasonCode: "signal_correction",
	}
	profile, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, reviseVariant, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = db.PreviewCorpusProfile(context.Background(), profile.ProfileID, CorpusMutation{}); !errors.Is(err, ErrCorpusPrecondition) {
		t.Fatalf("missing preview precondition returned %v", err)
	}
	if _, err = db.PreviewCorpusProfile(context.Background(), profile.ProfileID, CorpusMutation{ExpectedETag: "stale"}); !errors.Is(err, ErrCorpusConflict) {
		t.Fatalf("stale preview precondition returned %v", err)
	}
	auditBefore, err := db.PageCorpusAudit(context.Background(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := db.PreviewCorpusProfile(context.Background(), profile.ProfileID, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if preview.ETag != profile.ETag || preview.CurrentCorpusRevision != 1 || preview.ProposedCorpusRevision != 2 {
		t.Fatalf("unexpected preview metadata: %+v", preview)
	}
	if len(preview.Snapshot.Profiles) != 1 || preview.Snapshot.Profiles[0].Labels.Model != "Preview Camera Revised" {
		t.Fatalf("preview did not select profile draft: %+v", preview.Snapshot)
	}
	if got := preview.Snapshot.Profiles[0].Variants[0].Shape.MDNSModels; !reflect.DeepEqual(got, []string{"preview camera model two"}) {
		t.Fatalf("preview did not select variant draft: %v", got)
	}

	currentBytes, manifest, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CorpusRevision != 1 || len(currentBytes) == 0 {
		t.Fatalf("preview advanced current release: %+v", manifest)
	}
	unchanged, err := db.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag || unchanged.Draft == nil || unchanged.Variants[0].Draft == nil {
		t.Fatalf("preview mutated draft lifecycle: %+v", unchanged)
	}
	auditAfter, err := db.PageCorpusAudit(context.Background(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if auditAfter.Total != auditBefore.Total {
		t.Fatalf("preview wrote an audit record: before=%d after=%d", auditBefore.Total, auditAfter.Total)
	}

	if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
		corpusPublishRequest(preview.CurrentCorpusRevision),
		CorpusMutation{ExpectedETag: preview.ETag}); err != nil {
		t.Fatalf("publish rejected the ETag returned by preview: %v", err)
	}
	releasedBytes, releasedManifest, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var released corpus.PublicSnapshot
	if err = json.Unmarshal(releasedBytes, &released); err != nil {
		t.Fatal(err)
	}
	if releasedManifest.CorpusRevision != preview.ProposedCorpusRevision ||
		!reflect.DeepEqual(released.Profiles, preview.Snapshot.Profiles) {
		t.Fatalf("published content differs from preview: preview=%+v released=%+v", preview.Snapshot, released)
	}
}

func TestCorpusPublishRejectsInterveningReleaseFromAnotherProfile(t *testing.T) {
	db := newTestDB(t)
	makeDraft := func(model string) *corpus.Profile {
		req := corpusProfileRequest()
		req.Labels.Model = model
		profile, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		variant := corpusVariantRequest("initial")
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, variant,
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	first := makeDraft("Concurrent Camera A")
	second := makeDraft("Concurrent Camera B")

	preview, err := db.PreviewCorpusProfile(context.Background(), first.ProfileID,
		CorpusMutation{ExpectedETag: first.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.PublishCorpusProfile(context.Background(), second.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: second.ETag}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.PublishCorpusProfile(context.Background(), first.ProfileID,
		corpusPublishRequest(preview.CurrentCorpusRevision),
		CorpusMutation{ExpectedETag: preview.ETag}); !errors.Is(err, ErrCorpusRevisionConflict) {
		t.Fatalf("intervening release returned %v, want ErrCorpusRevisionConflict", err)
	}
	unchanged, err := db.GetCorpusProfile(context.Background(), first.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Draft == nil || unchanged.Published != nil || unchanged.ETag != preview.ETag {
		t.Fatalf("failed publish mutated reviewed draft: %+v", unchanged)
	}
}
