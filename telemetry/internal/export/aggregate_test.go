package export

import (
	"encoding/json"
	"strings"
	"testing"
)

func idGen() func() string {
	n := 0
	return func() string {
		n++
		return "sig-" + string(rune('0'+n))
	}
}

func TestAggregateCollapsesAndCounts(t *testing.T) {
	cands := []ExportCandidate{
		{Kind: KindKnownBadDomainHit, Domain: "bad.badzone.example", ETLDPlusOne: "badzone.example",
			TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.9, LocalReasons: []string{"known_bad"},
			Blocked: true, SourceHash: "hashA"},
		{Kind: KindKnownBadDomainHit, Domain: "bad.badzone.example", ETLDPlusOne: "badzone.example",
			TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.99, LocalReasons: []string{"threat_feed_match"},
			Blocked: false, SourceHash: "hashB"},
		{Kind: KindKnownBadDomainHit, Domain: "bad.badzone.example", ETLDPlusOne: "badzone.example",
			TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.5, LocalReasons: []string{"known_bad"},
			Blocked: true, SourceHash: "hashA"}, // duplicate asset
	}
	sigs := Aggregate(cands, idGen())
	if len(sigs) != 1 {
		t.Fatalf("expected 1 group, got %d", len(sigs))
	}
	s := sigs[0]
	if s.ObservationCount != 3 {
		t.Errorf("observation_count = %d, want 3", s.ObservationCount)
	}
	if s.DistinctAssetCount != 2 {
		t.Errorf("distinct_asset_count = %d, want 2 (hashA,hashB)", s.DistinctAssetCount)
	}
	if s.BlockedCount == nil || *s.BlockedCount != 2 {
		t.Errorf("blocked_count = %v, want 2", s.BlockedCount)
	}
	if s.LocalConfidence != 0.99 {
		t.Errorf("confidence = %v, want max 0.99", s.LocalConfidence)
	}
	if len(s.LocalReasons) != 2 {
		t.Errorf("reasons union = %v", s.LocalReasons)
	}
}

func TestAggregateNoSourceHashInJSON(t *testing.T) {
	cands := []ExportCandidate{
		{Kind: KindBehaviorSummary, Behavior: BehaviorBeaconing, TimeBucket: "2026-07-03T14:00:00Z",
			LocalConfidence: 0.8, LocalReasons: []string{"beaconing_candidate"}, SourceHash: "secret-hash"},
	}
	sigs := Aggregate(cands, idGen())
	data, _ := json.Marshal(sigs)
	if strings.Contains(string(data), "source_hash") || strings.Contains(string(data), "secret-hash") {
		t.Errorf("source_hash leaked: %s", data)
	}
	if v := LeakScan([]byte(`{"schema_version":1,"batch_id":"b","generated_at":"t","window_start":"a","window_end":"b","signals":` + string(data) + `}`)); len(v) > 0 {
		t.Errorf("leak scan: %v", v)
	}
}

func TestAggregateBehaviorNoBlockedCount(t *testing.T) {
	cands := []ExportCandidate{
		{Kind: KindHighConfCandidate, ETLDPlusOne: "qxv-rotator.example", TimeBucket: "2026-07-03T14:00:00Z",
			LocalConfidence: 0.9, LocalReasons: []string{"dga_candidate"}, SourceHash: "h"},
	}
	sigs := Aggregate(cands, idGen())
	if sigs[0].BlockedCount != nil {
		t.Errorf("candidate should not carry blocked_count")
	}
}

func TestAggregateEmptyAssetCountFloor(t *testing.T) {
	cands := []ExportCandidate{
		{Kind: KindBehaviorSummary, Behavior: BehaviorTunneling, TimeBucket: "2026-07-03T14:00:00Z",
			LocalConfidence: 0.8, LocalReasons: []string{"tunneling_candidate"}, SourceHash: ""},
	}
	sigs := Aggregate(cands, idGen())
	if sigs[0].DistinctAssetCount != 1 {
		t.Errorf("distinct_asset_count floor should be 1, got %d", sigs[0].DistinctAssetCount)
	}
}
