package export

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The ExportCandidate JSON keys must be a SUBSET of the contract's signal field
// set, and source_hash must never serialize. This is the structural guarantee.
func TestExportCandidateJSONKeysAreContractSubset(t *testing.T) {
	c := ExportCandidate{
		Kind: KindKnownBadDomainHit, Domain: "d.badzone.example", ETLDPlusOne: "badzone.example",
		Behavior: BehaviorBeaconing, TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.5,
		LocalReasons: []string{"known_bad"}, Blocked: true, SourceHash: "should-not-appear",
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Allowed candidate keys (subset of contract signal keys, plus "blocked"
	// which folds into blocked_count during aggregation and is not a wire key).
	allowed := map[string]bool{
		"kind": true, "domain": true, "etld_plus_one": true, "behavior": true,
		"time_bucket": true, "local_confidence": true, "local_reasons": true, "blocked": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("ExportCandidate serialized unexpected key %q", k)
		}
	}
	if _, ok := m["source_hash"]; ok {
		t.Errorf("source_hash must be json:\"-\"")
	}
}

// Guard against a future edit adding a PII-capable field to ExportCandidate.
func TestExportCandidateFieldSetFrozen(t *testing.T) {
	want := map[string]bool{
		"Kind": true, "Domain": true, "ETLDPlusOne": true, "Behavior": true,
		"TimeBucket": true, "LocalConfidence": true, "LocalReasons": true,
		"Blocked": true, "SourceHash": true,
	}
	tp := reflect.TypeOf(ExportCandidate{})
	if tp.NumField() != len(want) {
		t.Fatalf("ExportCandidate has %d fields, expected %d — new field added? Audit for PII.", tp.NumField(), len(want))
	}
	for i := 0; i < tp.NumField(); i++ {
		if !want[tp.Field(i).Name] {
			t.Errorf("unexpected field %q on ExportCandidate — must be reviewed against allowlist", tp.Field(i).Name)
		}
	}
}
