package store

import (
	"strings"
	"testing"
)

func TestCorpusPublishReconstructsStoredSignalFamilyCount(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(profile.ProfileID, corpusVariantRequest("corrupt-count"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an out-of-band restore/import corrupting immutable shape metadata.
	// Normal application writes cannot do this because the migration installs an
	// immutability trigger; publication must nevertheless distrust stored counts.
	if _, err = db.Exec(`DROP TRIGGER trg_device_corpus_shapes_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE device_corpus_shapes
		SET signal_family_count = signal_family_count + 1`); err != nil {
		t.Fatal(err)
	}

	_, err = db.PublishCorpusProfile(profile.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err == nil {
		t.Fatal("shape with a corrupt stored signal family count unexpectedly published")
	}
	if !strings.Contains(err.Error(), "signal family count") {
		t.Fatalf("corrupt family count error = %v", err)
	}
	manifest, manifestErr := db.CorpusManifest()
	if manifestErr != nil {
		t.Fatal(manifestErr)
	}
	if manifest.CorpusRevision != 0 {
		t.Fatalf("failed publication advanced corpus revision to %d", manifest.CorpusRevision)
	}
}

func TestCorpusPublishRejectsStoredCrossProfilePredecessor(t *testing.T) {
	db := newTestDB(t)

	baseRequest := corpusProfileRequest()
	baseRequest.Labels.Model = "Lineage Base Camera"
	base, err := db.CreateCorpusProfile(baseRequest, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	base, err = db.CreateCorpusVariant(base.ProfileID, corpusVariantRequest("base"),
		CorpusMutation{ExpectedETag: base.ETag})
	if err != nil {
		t.Fatal(err)
	}
	baseVariantID := base.Variants[0].VariantID
	base, err = db.PublishCorpusProfile(base.ProfileID, corpusPublishRequest(0),
		CorpusMutation{ExpectedETag: base.ETag})
	if err != nil {
		t.Fatal(err)
	}

	childRequest := corpusProfileRequest()
	childRequest.Labels.Model = "Lineage Child Camera"
	child, err := db.CreateCorpusProfile(childRequest, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	child, err = db.CreateCorpusVariant(child.ProfileID, corpusVariantRequest("child"),
		CorpusMutation{ExpectedETag: child.ETag})
	if err != nil {
		t.Fatal(err)
	}
	childVariantID := child.Variants[0].VariantID

	// The foreign key proves only global existence. Model a malformed import by
	// linking an unpublished stable identity to a variant owned by another profile.
	if _, err = db.Exec(`UPDATE device_corpus_variants SET predecessor_variant_id = ?
		WHERE variant_id = ?`, baseVariantID, childVariantID); err != nil {
		t.Fatal(err)
	}
	child, err = db.GetCorpusProfile(child.ProfileID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.PublishCorpusProfile(child.ProfileID, corpusPublishRequest(1),
		CorpusMutation{ExpectedETag: child.ETag})
	if err == nil {
		t.Fatal("stored cross-profile predecessor unexpectedly published")
	}
	if !strings.Contains(err.Error(), "predecessor belongs to another profile") {
		t.Fatalf("cross-profile predecessor error = %v", err)
	}
	manifest, manifestErr := db.CorpusManifest()
	if manifestErr != nil {
		t.Fatal(manifestErr)
	}
	if manifest.CorpusRevision != 1 {
		t.Fatalf("failed publication advanced corpus revision to %d", manifest.CorpusRevision)
	}
	unchanged, getErr := db.GetCorpusProfile(child.ProfileID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if unchanged.Draft == nil || unchanged.Published != nil || unchanged.Variants[0].Draft == nil {
		t.Fatalf("failed publication partially promoted child profile: %+v", unchanged)
	}
}
