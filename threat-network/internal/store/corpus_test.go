package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func corpusProfileRequest() corpus.CreateProfileRequest {
	return corpus.CreateProfileRequest{Labels: corpus.ProfileLabels{
		Manufacturer: "Example Devices", Model: "Camera Two", ProductFamily: "Vision",
		DeviceType: "camera", OSFamily: "embedded",
	}, ReasonCode: "new_profile"}
}

func TestCorpusOptimisticConcurrencySerializesWriters(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, key := range []string{"writer-a", "writer-b"} {
		key := key
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, writeErr := db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest(key), CorpusMutation{ExpectedETag: profile.ETag})
			errs <- writeErr
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for writeErr := range errs {
		switch {
		case writeErr == nil:
			successes++
		case errors.Is(writeErr, ErrCorpusConflict):
			conflicts++
		default:
			t.Fatalf("unexpected writer error: %v", writeErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("writers successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func TestCorpusProfileIdentityIsUniqueUnderConcurrentCreate(t *testing.T) {
	db := newTestDB(t)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrCorpusConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("profile creates successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
	var profiles int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_profiles`).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if profiles != 1 {
		t.Fatalf("duplicate product identity created %d stable profiles", profiles)
	}
}

func corpusVariantRequest(key string) corpus.CreateVariantRequest {
	return corpus.CreateVariantRequest{
		VariantKey: key, ConfidenceBP: 9200, ReasonCode: "new_variant",
		Shape: corpus.CanonicalShapeV1{
			DHCPOption55: []uint16{1, 3, 6, 15, 119},
			OUIPrefixes:  []string{"00:00:5e"},
			MDNSServices: []string{"_rtsp._tcp"},
			MDNSModels:   []string{"Example Camera Two"},
			TCPPorts:     []uint16{80, 443, 554},
		},
		Sources: []corpus.Source{{SourceRef: "vendor", Kind: "vendor_doc",
			Title: "Example Camera Support", PublicURL: "https://docs.example.com/camera-two"}},
		VersionFacts: []corpus.VersionFact{{Attribute: "firmware_version", Relation: "exact",
			Value: "2.4.1", ConfidenceBP: 9000, SourceRef: "vendor"}},
	}
}

func corpusPublishRequest(expectedRevision int) corpus.PublishRequest {
	return corpus.PublishRequest{ReasonCode: "publish_reviewed", ExpectedCorpusRevision: &expectedRevision}
}

func corpusLifecycleRequest(reasonCode string, expectedRevision int) corpus.LifecycleRequest {
	return corpus.LifecycleRequest{ReasonCode: reasonCode, ExpectedCorpusRevision: &expectedRevision}
}

func TestCorpusActiveRevisionPointersReferenceHistory(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("pointer-v1"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	labels := profile.Published.Labels
	labels.Model = "Camera Two Revised"
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

	assertProfileRevisionPointer := func(status string, active *corpus.ProfileRevision) {
		t.Helper()
		if active == nil {
			t.Fatalf("active profile %s revision is nil", status)
		}
		for i := range profile.History {
			if profile.History[i].Status == status {
				if active != &profile.History[i] {
					t.Fatalf("profile %s pointer does not reference History element", status)
				}
				return
			}
		}
		t.Fatalf("profile History has no %s revision", status)
	}
	assertProfileRevisionPointer("draft", profile.Draft)
	assertProfileRevisionPointer("published", profile.Published)

	variant = profile.Variants[0]
	assertVariantRevisionPointer := func(status string, active *corpus.VariantRevision) {
		t.Helper()
		if active == nil {
			t.Fatalf("active variant %s revision is nil", status)
		}
		for i := range variant.History {
			if variant.History[i].Status == status {
				if active != &variant.History[i] {
					t.Fatalf("variant %s pointer does not reference History element", status)
				}
				return
			}
		}
		t.Fatalf("variant History has no %s revision", status)
	}
	assertVariantRevisionPointer("draft", variant.Draft)
	assertVariantRevisionPointer("published", variant.Published)
}

func TestCorpusVariantReasonsDistinguishEvolutionFromCorrection(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	base := corpusVariantRequest("base")
	base.ReasonCode = "firmware_evolution"
	if _, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, base, CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
		t.Fatal("new root variant accepted firmware_evolution reason")
	}
	base.ReasonCode = "new_variant"
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, base, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variant := profile.Variants[0]
	clean := corpusVariantRequest("unused")
	revise := corpus.ReviseVariantRequest{
		ConfidenceBP: variant.Draft.ConfidenceBP,
		Shape:        variant.Draft.Shape,
		Sources:      clean.Sources,
		VersionFacts: clean.VersionFacts,
		ReasonCode:   "firmware_evolution",
	}
	if _, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, revise, CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
		t.Fatal("curator correction accepted firmware_evolution reason")
	}
	revise.ReasonCode = "signal_correction"
	if _, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, revise, CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
		t.Fatalf("signal correction rejected: %v", err)
	}
}

func assertPredecessorRejectionLeavesCorpusUnchanged(t *testing.T, db *DB, profile *corpus.Profile,
	req corpus.CreateVariantRequest, checkErr func(error) bool) {
	t.Helper()
	var variantsBefore, revisionsBefore, auditsBefore int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_variants`).Scan(&variantsBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_variant_revisions`).Scan(&revisionsBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_audit`).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := db.CorpusManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req,
		CorpusMutation{ExpectedETag: profile.ETag}); err == nil || !checkErr(err) {
		t.Fatalf("predecessor rejection error = %v", err)
	}
	unchanged, err := db.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag {
		t.Fatalf("rejected predecessor changed ETag: before=%s after=%s", profile.ETag, unchanged.ETag)
	}
	var variantsAfter, revisionsAfter, auditsAfter int
	if err = db.QueryRow(`SELECT COUNT(*) FROM device_corpus_variants`).Scan(&variantsAfter); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM device_corpus_variant_revisions`).Scan(&revisionsAfter); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM device_corpus_audit`).Scan(&auditsAfter); err != nil {
		t.Fatal(err)
	}
	manifestAfter, err := db.CorpusManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if variantsAfter != variantsBefore || revisionsAfter != revisionsBefore || auditsAfter != auditsBefore {
		t.Fatalf("rejected predecessor mutated state: variants %d->%d revisions %d->%d audits %d->%d",
			variantsBefore, variantsAfter, revisionsBefore, revisionsAfter, auditsBefore, auditsAfter)
	}
	if manifestAfter.CorpusRevision != manifestBefore.CorpusRevision {
		t.Fatalf("rejected predecessor advanced corpus revision: %d->%d",
			manifestBefore.CorpusRevision, manifestAfter.CorpusRevision)
	}

	// The same ETag must remain usable after the rejected request; an optimistic
	// concurrency token is not consumed by a failed predecessor validation.
	if _, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("etag-reuse"),
		CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
		t.Fatalf("rejected predecessor spent current ETag: %v", err)
	}
}

func TestCorpusVariantPredecessorMustBeActiveAndSameProfile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("child")
		req.PredecessorVariantID = "missing-predecessor"
		req.ReasonCode = "firmware_evolution"
		assertPredecessorRejectionLeavesCorpusUnchanged(t, db, profile, req,
			func(err error) bool { return errors.Is(err, ErrCorpusNotFound) })
	})

	t.Run("another profile", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		otherReq := corpusProfileRequest()
		otherReq.Labels.Model = "Other Camera"
		other, err := db.CreateCorpusProfile(context.Background(), otherReq, CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		other, err = db.CreateCorpusVariant(context.Background(), other.ProfileID, corpusVariantRequest("other-base"),
			CorpusMutation{ExpectedETag: other.ETag})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("child")
		req.PredecessorVariantID = other.Variants[0].VariantID
		req.ReasonCode = "firmware_evolution"
		assertPredecessorRejectionLeavesCorpusUnchanged(t, db, profile, req,
			func(err error) bool { return strings.Contains(err.Error(), "belongs to another profile") })
	})

	t.Run("abandoned draft", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("abandoned"),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		predecessorID := profile.Variants[0].VariantID
		profile, err = db.DiscardCorpusVariantDraft(context.Background(), predecessorID,
			corpus.LifecycleRequest{ReasonCode: "signal_correction"},
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("child")
		req.PredecessorVariantID = predecessorID
		req.ReasonCode = "firmware_evolution"
		assertPredecessorRejectionLeavesCorpusUnchanged(t, db, profile, req,
			func(err error) bool { return strings.Contains(err.Error(), "must have an active") })
	})

	t.Run("withdrawn published revision", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("withdrawn"),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		predecessorID := profile.Variants[0].VariantID
		profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		profile, err = db.WithdrawCorpusVariant(context.Background(), predecessorID,
			corpusLifecycleRequest("obsolete_product", 1),
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("child")
		req.PredecessorVariantID = predecessorID
		req.ReasonCode = "firmware_evolution"
		assertPredecessorRejectionLeavesCorpusUnchanged(t, db, profile, req,
			func(err error) bool { return strings.Contains(err.Error(), "must have an active") })
	})
}

func TestCorpusVariantAcceptsPublishedPredecessor(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("base"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	predecessorID := profile.Variants[0].VariantID
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	child := corpusVariantRequest("child")
	child.PredecessorVariantID = predecessorID
	child.ReasonCode = "firmware_evolution"
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, child,
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatalf("valid firmware evolution from published predecessor: %v", err)
	}
	var found bool
	for _, variant := range profile.Variants {
		if variant.VariantKey == "child" {
			found = true
			if variant.PredecessorVariantID != predecessorID || variant.Draft == nil {
				t.Fatalf("invalid child lineage: %+v", variant)
			}
		}
	}
	if !found {
		t.Fatal("created child variant missing")
	}
}

func TestWithdrawCorpusVariantWithoutRevisionReturnsNotFound(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	// Model a partially restored database containing a stable identity without
	// revision history. Aggregate status queries must fail closed rather than
	// attempting to scan SQL NULL into an integer.
	if _, err = db.Exec(`INSERT INTO device_corpus_variants
		(variant_id, profile_id, variant_key, created_at) VALUES (?, ?, ?, ?)`,
		"orphan-variant", profile.ProfileID, "orphan", "2026-07-13T16:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.WithdrawCorpusVariant(context.Background(), "orphan-variant",
		corpusLifecycleRequest("obsolete_product", 0),
		CorpusMutation{ExpectedETag: profile.ETag}); !errors.Is(err, ErrCorpusNotFound) {
		t.Fatalf("withdraw orphan error = %v, want ErrCorpusNotFound", err)
	}
}

func TestCorpusDraftPublishRevisionAndImmutableRelease(t *testing.T) {
	db := newTestDB(t)
	initialBytes, initial, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if initial.CorpusRevision != 0 || initial.ProfileCount != 0 || len(initialBytes) == 0 {
		t.Fatalf("unexpected bootstrap snapshot: %+v", initial)
	}

	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Draft == nil || profile.Published != nil || profile.ETag == "" {
		t.Fatalf("unexpected created profile: %+v", profile)
	}
	staleETag := profile.ETag
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("firmware-2"), CorpusMutation{
		Actor: "admin", ExpectedETag: profile.ETag,
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.ETag == staleETag || len(profile.Variants) != 1 || profile.Variants[0].Draft == nil {
		t.Fatalf("variant did not update profile state: %+v", profile)
	}
	if _, err = db.ReviseCorpusProfile(context.Background(), profile.ProfileID, corpus.ReviseProfileRequest{
		Labels: corpusProfileRequest().Labels, ReasonCode: "label_correction",
	}, CorpusMutation{ExpectedETag: staleETag}); !errors.Is(err, ErrCorpusConflict) {
		t.Fatalf("stale ETag error = %v, want conflict", err)
	}
	canonicalDraft, canonicalBytes, _, _, canonicalErr := corpus.CanonicalizeShape(profile.Variants[0].Draft.Shape)
	if canonicalErr != nil {
		t.Fatalf("stored draft shape invalid: %v", canonicalErr)
	}
	storedBytes, _ := json.Marshal(profile.Variants[0].Draft.Shape)
	canonicalStructBytes, _ := json.Marshal(canonicalDraft)
	if string(storedBytes) != string(canonicalStructBytes) {
		t.Fatalf("stored draft shape is not canonical: stored=%s canonical=%s raw=%s", storedBytes, canonicalStructBytes, canonicalBytes)
	}

	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0), CorpusMutation{
		ExpectedETag: profile.ETag,
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Published == nil || profile.Draft != nil || profile.Variants[0].Published == nil {
		t.Fatalf("profile was not atomically published: %+v", profile)
	}
	releaseOneBytes, releaseOne, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if releaseOne.CorpusRevision != 1 || releaseOne.ProfileCount != 1 || releaseOne.VariantCount != 1 {
		t.Fatalf("unexpected release one: %+v", releaseOne)
	}
	var snapshot corpus.PublicSnapshot
	if err = json.Unmarshal(releaseOneBytes, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Labels.Model != "Camera Two" {
		t.Fatalf("unexpected published snapshot: %+v", snapshot)
	}

	variant := profile.Variants[0]
	revise := corpus.ReviseVariantRequest{ConfidenceBP: 9500, Shape: variant.Published.Shape,
		Sources:      corpusVariantRequest("ignored").Sources,
		VersionFacts: corpusVariantRequest("ignored").VersionFacts, ReasonCode: "signal_correction"}
	revise.Shape.TCPPorts = append(revise.Shape.TCPPorts, 8443)
	profile, err = db.ReviseCorpusVariant(context.Background(), variant.VariantID, revise, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	// Draft corrections must not alter current release bytes.
	stillOne, manifest, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CorpusRevision != 1 || string(stillOne) != string(releaseOneBytes) {
		t.Fatal("draft revision changed the public release")
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(1), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	_, releaseTwo, err := db.CurrentCorpusSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if releaseTwo.CorpusRevision != 2 || releaseTwo.SnapshotSHA256 == releaseOne.SnapshotSHA256 {
		t.Fatalf("correction did not create release two: %+v", releaseTwo)
	}
	var persistedOne string
	if err = db.QueryRow(`SELECT snapshot_json FROM device_corpus_releases WHERE corpus_revision = 1`).Scan(&persistedOne); err != nil {
		t.Fatal(err)
	}
	if persistedOne != string(releaseOneBytes) {
		t.Fatal("immutable release one bytes changed")
	}
	if _, err = db.Exec(`UPDATE device_corpus_shapes SET canonical_json = '{}'`); err == nil {
		t.Fatal("shape immutability trigger allowed an update")
	}
}

func TestCorpusPublishRequiresReviewedReasonWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("publish-reason"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	auditBefore, releasesBefore := corpusMutationCounts(t, db)
	for _, reason := range []string{
		"new_profile", "new_variant", "label_correction", "signal_correction", "firmware_evolution",
		"source_update", "privacy_withdrawal", "obsolete_product", "restore_reviewed",
	} {
		request := corpusPublishRequest(0)
		request.ReasonCode = reason
		if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, request,
			CorpusMutation{ExpectedETag: profile.ETag}); !errors.Is(err, ErrCorpusValidation) {
			t.Fatalf("publish reason %q error = %v, want ErrCorpusValidation", reason, err)
		}
	}
	unchanged, err := db.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ETag != profile.ETag || unchanged.Published != nil || unchanged.Draft == nil ||
		len(unchanged.Variants) != 1 || unchanged.Variants[0].Published != nil || unchanged.Variants[0].Draft == nil {
		t.Fatalf("rejected publish reason mutated profile: %+v", unchanged)
	}
	assertCorpusReleaseState(t, db, 0, auditBefore, releasesBefore)
}

func TestCorpusPublicationFailureRollsBackLifecycle(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	req := corpusVariantRequest("unsourced")
	req.Sources = nil
	req.VersionFacts = nil
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID, corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag})
	if err == nil {
		t.Fatal("unsourced corpus unexpectedly published")
	}
	after, getErr := db.GetCorpusProfile(context.Background(), profile.ProfileID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if after.Draft == nil || after.Published != nil || after.Variants[0].Draft == nil {
		t.Fatalf("failed publication partially changed lifecycle: %+v", after)
	}
	manifest, err := db.CorpusManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CorpusRevision != 0 {
		t.Fatalf("failed publication advanced revision to %d", manifest.CorpusRevision)
	}
}

func TestCorpusPublicationQualityGate(t *testing.T) {
	t.Run("generic OUI and ports claim rejected", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("weak")
		req.Shape = corpus.CanonicalShapeV1{OUIPrefixes: []string{"00:00:5e"}, TCPPorts: []uint16{80, 443}}
		req.Sources = []corpus.Source{{Kind: "lab_observation"}}
		req.VersionFacts = nil
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req, CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
			corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
			t.Fatal("generic OUI/ports lab claim unexpectedly published")
		}
	})
	t.Run("correlated DHCP fields count as one family", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("dhcp-correlated")
		req.Shape = corpus.CanonicalShapeV1{
			DHCPOption55:      []uint16{1, 3, 6, 15, 119},
			DHCPVendorClasses: []string{"example-camera-two"},
		}
		req.Sources = []corpus.Source{{Kind: "lab_observation"}}
		req.VersionFacts = nil
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req, CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
			corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
			t.Fatal("correlated DHCP fields bypassed the single-family citation gate")
		}
	})
	t.Run("single exact signature with authoritative citation accepted", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		req := corpusVariantRequest("exact")
		req.Shape = corpus.CanonicalShapeV1{MDNSModels: []string{"Example Camera Two"}}
		req.VersionFacts = nil
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, req, CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
			corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
			t.Fatalf("authoritative exact signature rejected: %v", err)
		}
	})
	t.Run("authoritative citation count is isolated per revision", func(t *testing.T) {
		db := newTestDB(t)
		profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		cited := corpusVariantRequest("cited-exact")
		cited.Shape = corpus.CanonicalShapeV1{MDNSModels: []string{"Example Camera Two"}}
		cited.VersionFacts = nil
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, cited,
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		uncited := corpusVariantRequest("uncited-exact")
		uncited.Shape = corpus.CanonicalShapeV1{MDNSModels: []string{"Example Camera Three"}}
		uncited.Sources = []corpus.Source{{Kind: "lab_observation"}}
		uncited.VersionFacts = nil
		profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, uncited,
			CorpusMutation{ExpectedETag: profile.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
			corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag}); err == nil {
			t.Fatal("authoritative citation from another revision satisfied uncited signature")
		}
	})
}

func TestCorpusStoredSnapshotIsRevalidatedBeforeServing(t *testing.T) {
	db := newTestDB(t)
	raw := []byte(`{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[],"source_ip":"192.0.2.8"}`)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	if _, err := db.Exec(`INSERT INTO device_corpus_releases
		(corpus_revision, schema_version, snapshot_sha256, snapshot_json, profile_count, variant_count, created_at)
		VALUES (1, 1, ?, ?, 0, 0, '2026-07-13T16:00:00Z')`, hash, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_corpus_state SET current_revision = 1,
		current_snapshot_sha256 = ?, updated_at = '2026-07-13T16:00:00Z' WHERE singleton = 1`, hash); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err == nil {
		t.Fatal("stored snapshot with an unreviewed field was served")
	}
}

func TestCorpusAllowsAmbiguousShapeAcrossProfiles(t *testing.T) {
	db := newTestDB(t)
	for i, model := range []string{"Camera Two", "Shared Chipset Camera"} {
		req := corpusProfileRequest()
		req.Labels.Model = model
		profile, err := db.CreateCorpusProfile(context.Background(), req, CorpusMutation{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("shared"), CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
			t.Fatalf("profile %d shared shape: %v", i, err)
		}
	}
	var shapes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_shapes`).Scan(&shapes); err != nil {
		t.Fatal(err)
	}
	if shapes != 1 {
		t.Fatalf("shared canonical shape should deduplicate once, got %d", shapes)
	}
}

func TestCorpusAbandonedUnpublishedVariantCanRestartIdentity(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("base"), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	baseID := profile.Variants[0].VariantID
	childReq := corpusVariantRequest("child")
	childReq.PredecessorVariantID = baseID
	childReq.ReasonCode = "firmware_evolution"
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, childReq, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	var childID string
	for _, variant := range profile.Variants {
		if variant.VariantKey == "child" {
			childID = variant.VariantID
		}
	}
	profile, err = db.DiscardCorpusVariantDraft(context.Background(), childID,
		corpus.LifecycleRequest{ReasonCode: "signal_correction"},
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	restarted := corpusVariantRequest("child")
	restarted.ReasonCode = "restore_reviewed"
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, restarted, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatalf("restart abandoned variant: %v", err)
	}
	var got *corpus.Variant
	for i := range profile.Variants {
		if profile.Variants[i].VariantKey == "child" {
			got = &profile.Variants[i]
		}
	}
	if got == nil || got.VariantID != childID || got.PredecessorVariantID != "" || got.Draft == nil || got.Draft.Revision != 2 {
		t.Fatalf("abandoned identity was not safely restarted: %+v", got)
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
		corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_variants SET predecessor_variant_id = ? WHERE variant_id = ?`, baseID, childID); err == nil {
		t.Fatal("published variant predecessor was mutable")
	}
}

func TestCorpusCannotWithdrawPublishedPredecessorBeforeDescendant(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, corpusVariantRequest("base"), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	baseID := profile.Variants[0].VariantID
	childReq := corpusVariantRequest("child")
	childReq.PredecessorVariantID = baseID
	childReq.ReasonCode = "firmware_evolution"
	profile, err = db.CreateCorpusVariant(context.Background(), profile.ProfileID, childReq, CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.PublishCorpusProfile(context.Background(), profile.ProfileID,
		corpusPublishRequest(0), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	var childID string
	for _, variant := range profile.Variants {
		if variant.VariantKey == "child" {
			childID = variant.VariantID
		}
	}
	if _, err = db.WithdrawCorpusVariant(context.Background(), baseID,
		corpusLifecycleRequest("obsolete_product", 1), CorpusMutation{ExpectedETag: profile.ETag}); !errors.Is(err, ErrCorpusHasDependents) {
		t.Fatalf("predecessor withdrawal error=%v, want active descendants", err)
	}
	profile, err = db.WithdrawCorpusVariant(context.Background(), childID,
		corpusLifecycleRequest("obsolete_product", 1), CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.WithdrawCorpusVariant(context.Background(), baseID,
		corpusLifecycleRequest("obsolete_product", 2), CorpusMutation{ExpectedETag: profile.ETag}); err != nil {
		t.Fatalf("base withdrawal after child: %v", err)
	}
}

func TestMigration004UpgradesExistingFeedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	raw, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001_init.sql", "002_receipts_per_reporter.sql", "003_signals_first_received.sql"} {
		body, readErr := migrationsFS.ReadFile("migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = raw.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		version := int(name[2] - '0')
		if _, err = raw.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, '2026-01-01T00:00:00Z')`, version); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = raw.Exec(`INSERT INTO reporters
		(reporter_id, secret_hash, status, capabilities, vedetta_version, created_at)
		VALUES ('existing', 'hash', 'active', '[]', '0.1.0', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var reporter string
	if err = db.QueryRow(`SELECT reporter_id FROM reporters WHERE reporter_id = 'existing'`).Scan(&reporter); err != nil {
		t.Fatalf("existing feed data lost: %v", err)
	}
	var state int
	if err = db.QueryRow(`SELECT schema_version FROM device_corpus_state WHERE singleton = 1`).Scan(&state); err != nil || state != 1 {
		t.Fatalf("corpus migration missing: state=%d err=%v", state, err)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported a violation after upgrade")
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}
