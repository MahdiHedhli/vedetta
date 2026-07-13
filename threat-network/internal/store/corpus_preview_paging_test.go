package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func TestCorpusProfilePagingSearchesBeforeOffset(t *testing.T) {
	db := newTestDB(t)
	for _, model := range []string{"Paging Alpha", "Paging Beta", "Paging Gamma"} {
		req := corpusProfileRequest()
		req.Labels.Model = model
		if _, err := db.CreateCorpusProfile(req, CorpusMutation{}); err != nil {
			t.Fatal(err)
		}
	}

	page, err := db.PageCorpusProfiles("paging", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Limit != 1 || page.Offset != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	filtered, err := db.PageCorpusProfiles("Paging Beta", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].Labels.Model != "Paging Beta" {
		t.Fatalf("search was not applied before pagination: %+v", filtered)
	}

	audit, err := db.PageCorpusAudit(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Total != 3 || len(audit.Items) != 2 || audit.Limit != 2 || audit.Offset != 1 {
		t.Fatalf("unexpected audit page: %+v", audit)
	}
	releases, err := db.PageCorpusReleases(5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if releases.Total != 0 || releases.Items == nil {
		t.Fatalf("unexpected empty release page: %+v", releases)
	}
}

func TestCorpusPreviewUsesDraftsWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	req := corpusProfileRequest()
	req.Labels.Model = "Preview Camera"
	profile, err := db.CreateCorpusProfile(req, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	variantReq := corpusVariantRequest("preview-v1")
	profile, err = db.CreateCorpusVariant(profile.ProfileID, variantReq, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.PublishCorpusProfile(profile.ProfileID,
		corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	reviseProfile := corpus.ReviseProfileRequest{Labels: req.Labels, ReasonCode: "label_correction"}
	reviseProfile.Labels.Model = "Preview Camera Revised"
	profile, err = db.ReviseCorpusProfile(profile.ProfileID, reviseProfile, CorpusMutation{ExpectedETag: profile.ETag})
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
	profile, err = db.ReviseCorpusVariant(variant.VariantID, reviseVariant, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = db.PreviewCorpusProfile(profile.ProfileID, CorpusMutation{}); !errors.Is(err, ErrCorpusPrecondition) {
		t.Fatalf("missing preview precondition returned %v", err)
	}
	if _, err = db.PreviewCorpusProfile(profile.ProfileID, CorpusMutation{ExpectedETag: "stale"}); !errors.Is(err, ErrCorpusConflict) {
		t.Fatalf("stale preview precondition returned %v", err)
	}
	auditBefore, err := db.PageCorpusAudit(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := db.PreviewCorpusProfile(profile.ProfileID, CorpusMutation{ExpectedETag: profile.ETag})
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

	currentBytes, manifest, err := db.CurrentCorpusSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CorpusRevision != 1 || len(currentBytes) == 0 {
		t.Fatalf("preview advanced current release: %+v", manifest)
	}
	unchanged, err := db.GetCorpusProfile(profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag || unchanged.Draft == nil || unchanged.Variants[0].Draft == nil {
		t.Fatalf("preview mutated draft lifecycle: %+v", unchanged)
	}
	auditAfter, err := db.PageCorpusAudit(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if auditAfter.Total != auditBefore.Total {
		t.Fatalf("preview wrote an audit record: before=%d after=%d", auditBefore.Total, auditAfter.Total)
	}

	if _, err = db.PublishCorpusProfile(profile.ProfileID,
		corpusPublishRequest(preview.CurrentCorpusRevision),
		CorpusMutation{ExpectedETag: preview.ETag}); err != nil {
		t.Fatalf("publish rejected the ETag returned by preview: %v", err)
	}
	releasedBytes, releasedManifest, err := db.CurrentCorpusSnapshot()
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
		profile, err := db.CreateCorpusProfile(req, CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		variant := corpusVariantRequest("initial")
		profile, err = db.CreateCorpusVariant(profile.ProfileID, variant,
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	first := makeDraft("Concurrent Camera A")
	second := makeDraft("Concurrent Camera B")

	preview, err := db.PreviewCorpusProfile(first.ProfileID,
		CorpusMutation{ExpectedETag: first.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.PublishCorpusProfile(second.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: second.ETag}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.PublishCorpusProfile(first.ProfileID,
		corpusPublishRequest(preview.CurrentCorpusRevision),
		CorpusMutation{ExpectedETag: preview.ETag}); !errors.Is(err, ErrCorpusRevisionConflict) {
		t.Fatalf("intervening release returned %v, want ErrCorpusRevisionConflict", err)
	}
	unchanged, err := db.GetCorpusProfile(first.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Draft == nil || unchanged.Published != nil || unchanged.ETag != preview.ETag {
		t.Fatalf("failed publish mutated reviewed draft: %+v", unchanged)
	}
}
