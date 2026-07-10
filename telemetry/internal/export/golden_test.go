package export

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

// Golden-file style test: a synthetic Core fixture drives the full
// gate → strip → aggregate chain and the resulting signals are asserted to
// match the contract §7 example SHAPE (deterministic IDs/times injected). Leak
// scan runs over the serialized batch. Fixtures use only synthetic values.
func TestGoldenBatchShapeMatchesContract(t *testing.T) {
	base := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	events := []corereader.Event{
		{EventID: "e1", Timestamp: base.Add(15 * time.Minute), EventType: "dns_query", SourceIP: "192.0.2.55",
			Domain: "c2-payload.badzone.example", Blocked: true, AnomalyScore: 0.99,
			MatchedIndicator: "c2-payload.badzone.example", MatchType: "domain",
			Tags: []string{"known_bad", "threat_feed_match", "c2_candidate"}},
		{EventID: "e1b", Timestamp: base.Add(20 * time.Minute), EventType: "dns_query", SourceIP: "192.0.2.60",
			Domain: "c2-payload.badzone.example", Blocked: true, AnomalyScore: 0.90,
			MatchedIndicator: "c2-payload.badzone.example", MatchType: "domain",
			Tags: []string{"known_bad", "threat_feed_match", "c2_candidate"}},
		{EventID: "e2", Timestamp: base.Add(15 * time.Minute), EventType: "dns_query", SourceIP: "192.0.2.56",
			Domain: "sub.qxv-rotator.example", AnomalyScore: 0.91,
			Tags: []string{"dga_candidate", "newly_registered", "high_entropy"}},
		{EventID: "e3", Timestamp: base.Add(15 * time.Minute), EventType: "dns_query", SourceIP: "192.0.2.57",
			Domain: "beacon.qxv-rotator.example", AnomalyScore: 0.81,
			Tags: []string{"beaconing_candidate"}},
	}

	gate := GateConfig{CandidateMinScore: 0.85, BehaviorMinScore: 0.70}
	var cands []ExportCandidate
	for _, ev := range events {
		if k, ok := Eligible(ev, gate); ok {
			if c, ok := Strip(ev, k, []byte("golden-salt")); ok {
				cands = append(cands, c)
			}
		}
	}

	i := 0
	sigs := Aggregate(cands, func() string {
		i++
		return []string{
			"3c5e7a9b-2d4f-4a6c-8e0b-1f3a5c7e9b0d",
			"8d0f2a4c-6e8b-4c0d-a2e4-3b5d7f9a1c2e",
			"5f7b9d1e-3a5c-4e7f-b1d3-2c4e6a8b0d1f",
		}[i-1]
	})
	SortSignals(sigs)

	// BETA: candidate + behavior export is DISABLED (GHSA-hx86), so only the two
	// known_bad events (e1, e1b — same domain) survive and aggregate to ONE signal;
	// the candidate (e2) and behavior (e3) inputs are withheld.
	if len(sigs) != 1 {
		t.Fatalf("expected 1 aggregated signal (known_bad only; candidate/behavior disabled), got %d", len(sigs))
	}

	batch := Batch{
		SchemaVersion: 1,
		BatchID:       "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
		GeneratedAt:   "2026-07-03T14:15:02Z",
		WindowStart:   "2026-07-03T14:00:00Z",
		WindowEnd:     "2026-07-03T15:00:00Z",
		Signals:       sigs,
	}
	data, _ := json.MarshalIndent(batch, "", "  ")

	// Privacy gate.
	if v := LeakScan(data); len(v) > 0 {
		t.Fatalf("golden batch has leaks: %v\n%s", v, data)
	}

	byKind := map[Kind]Signal{}
	for _, s := range sigs {
		byKind[s.Kind] = s
	}

	kb := byKind[KindKnownBadDomainHit]
	if kb.Domain != "c2-payload.badzone.example" || kb.ETLDPlusOne != "badzone.example" {
		t.Errorf("known_bad domain fields wrong: %+v", kb)
	}
	if kb.ObservationCount != 2 || kb.DistinctAssetCount != 2 {
		t.Errorf("known_bad counts wrong: obs=%d assets=%d", kb.ObservationCount, kb.DistinctAssetCount)
	}
	if kb.BlockedCount == nil || *kb.BlockedCount != 2 {
		t.Errorf("known_bad blocked_count wrong: %v", kb.BlockedCount)
	}

	// Candidate + behavior inputs must produce NO signal while disabled for beta.
	if _, ok := byKind[KindHighConfCandidate]; ok {
		t.Errorf("candidate signal must not be emitted while disabled for beta")
	}
	if _, ok := byKind[KindBehaviorSummary]; ok {
		t.Errorf("behavior signal must not be emitted while disabled for beta")
	}
}
