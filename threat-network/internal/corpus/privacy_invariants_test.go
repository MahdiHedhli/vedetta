package corpus

import (
	"strings"
	"testing"
)

func TestValidatePublicSnapshotRejectsCrossProfilePredecessor(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	second := snapshot.Profiles[0]
	second.ProfileID = testProfileID2
	second.Labels.Model = "Camera Three"
	second.Variants = append([]PublicVariant(nil), second.Variants...)
	second.Variants[0].VariantID = testVariantID2
	second.Variants[0].VariantKey = "firmware-3"
	second.Variants[0].PredecessorVariantID = testVariantID
	second.Variants[0].Sources = append([]Source(nil), second.Variants[0].Sources...)
	second.Variants[0].Sources[0].SourceID = testSourceID2
	second.Variants[0].VersionFacts = append([]VersionFact(nil), second.Variants[0].VersionFacts...)
	second.Variants[0].VersionFacts[0].FactID = testFactID2
	second.Variants[0].VersionFacts[0].SourceID = testSourceID2
	snapshot.Profiles = append(snapshot.Profiles, second)

	err := ValidatePublicSnapshot(snapshot)
	if err == nil {
		t.Fatal("cross-profile predecessor unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "predecessor belongs to another profile") {
		t.Fatalf("cross-profile predecessor error = %v", err)
	}
}

func TestValidatePublicSnapshotRejectsVersionFactWithoutProvenance(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	snapshot.Profiles[0].Variants[0].VersionFacts[0].SourceID = ""
	err := ValidatePublicSnapshot(snapshot)
	if err == nil {
		t.Fatal("unprovenanced public version fact unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "source_id") || strings.Contains(err.Error(), snapshot.Profiles[0].Variants[0].VersionFacts[0].Value) {
		t.Fatalf("unexpected non-reflective provenance error: %v", err)
	}
}
