package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestSerializerMatchesSharedFixtureShape is the PRODUCER side of the
// cross-service contract guard. It builds a batch through the real
// export.Batch/Signal serializer for a synthetic aggregated input and asserts
// its serialized shape (top-level keys, and per-kind signal keys + JSON value
// types) MATCHES the shared golden fixture
// specs/002-telemetry-service/contracts/fixtures/valid-batch.json that the
// threat-network validator pins to. If either side drifts, this fails.
func TestSerializerMatchesSharedFixtureShape(t *testing.T) {
	// Locate + load the shared fixture (repo root is ../../.. from this package).
	dir := filepath.Join("..", "..", "..", "specs", "002-telemetry-service", "contracts", "fixtures")
	fixturePath := filepath.Join(dir, "valid-batch.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("shared fixture not found: %v", err)
	}
	var fixtureBatch map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixtureBatch); err != nil {
		t.Fatalf("fixture is not a JSON object: %v", err)
	}

	// Build the producer's batch from a synthetic aggregated input covering all
	// three kinds — same values as the fixture so the comparison is like-for-like.
	blocked := 4
	sigs := []Signal{
		{
			SignalID:           "3c5e7a9b-2d4f-4a6c-8e0b-1f3a5c7e9b0d",
			Kind:               KindKnownBadDomainHit,
			TimeBucket:         "2026-07-03T14:00:00Z",
			Domain:             "c2-payload.badzone.example",
			ETLDPlusOne:        "badzone.example",
			LocalConfidence:    0.99,
			LocalReasons:       []string{"known_bad", "c2_candidate", "threat_feed_match"},
			ObservationCount:   4,
			DistinctAssetCount: 2,
			BlockedCount:       &blocked,
		},
		{
			SignalID:           "8d0f2a4c-6e8b-4c0d-a2e4-3b5d7f9a1c2e",
			Kind:               KindHighConfCandidate,
			TimeBucket:         "2026-07-03T14:00:00Z",
			ETLDPlusOne:        "qxv-rotator.example",
			LocalConfidence:    0.91,
			LocalReasons:       []string{"dga_candidate", "newly_registered", "high_entropy"},
			ObservationCount:   17,
			DistinctAssetCount: 1,
		},
		{
			SignalID:           "5f7b9d1e-3a5c-4e7f-b1d3-2c4e6a8b0d1f",
			Kind:               KindBehaviorSummary,
			TimeBucket:         "2026-07-03T14:00:00Z",
			Behavior:           BehaviorBeaconing,
			LocalConfidence:    0.81,
			LocalReasons:       []string{"beaconing_candidate"},
			ObservationCount:   6,
			DistinctAssetCount: 2,
		},
	}
	batch := Batch{
		SchemaVersion: SchemaVersion,
		BatchID:       "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
		GeneratedAt:   "2026-07-03T14:15:02Z",
		WindowStart:   "2026-07-03T14:00:00Z",
		WindowEnd:     "2026-07-03T15:00:00Z",
		Signals:       sigs,
	}
	produced, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("serialize batch: %v", err)
	}
	var producedBatch map[string]json.RawMessage
	if err := json.Unmarshal(produced, &producedBatch); err != nil {
		t.Fatalf("re-decode produced batch: %v", err)
	}

	// 1. Top-level keys must match exactly (no extra, no missing).
	if got, want := keysOf(producedBatch), keysOf(fixtureBatch); !reflect.DeepEqual(got, want) {
		t.Fatalf("top-level key set drift:\n producer=%v\n fixture =%v", got, want)
	}

	// 2. Per-signal: for each kind, the serialized key set + JSON value types
	//    must match the fixture signal of the same kind.
	fixtureByKind := signalsByKind(t, fixtureBatch["signals"])
	producedByKind := signalsByKind(t, producedBatch["signals"])

	for kind, fixSig := range fixtureByKind {
		prodSig, ok := producedByKind[kind]
		if !ok {
			t.Fatalf("producer emitted no signal of kind %q present in fixture", kind)
		}
		if got, want := keysOf(fixSig), keysOf(prodSig); !reflect.DeepEqual(got, want) {
			t.Fatalf("kind %q key set drift:\n fixture =%v\n producer=%v", kind, got, want)
		}
		for key, fixVal := range fixSig {
			ft := jsonType(t, fixVal)
			pt := jsonType(t, prodSig[key])
			if ft != pt {
				t.Fatalf("kind %q field %q type drift: fixture=%s producer=%s", kind, key, ft, pt)
			}
		}
	}
	// Symmetric check: producer must not emit an unexpected kind.
	for kind := range producedByKind {
		if _, ok := fixtureByKind[kind]; !ok {
			t.Fatalf("producer emitted unexpected kind %q not in fixture", kind)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// signalsByKind decodes a signals array and indexes each object by its "kind".
func signalsByKind(t *testing.T, arr json.RawMessage) map[string]map[string]json.RawMessage {
	t.Helper()
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(arr, &list); err != nil {
		t.Fatalf("decode signals array: %v", err)
	}
	out := map[string]map[string]json.RawMessage{}
	for _, s := range list {
		var kind string
		if err := json.Unmarshal(s["kind"], &kind); err != nil {
			t.Fatalf("signal missing kind: %v", err)
		}
		out[kind] = s
	}
	return out
}

// jsonType classifies a raw JSON value into a coarse type bucket
// (string/number/bool/array/object/null) for structural comparison.
func jsonType(t *testing.T, rv json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(rv, &v); err != nil {
		t.Fatalf("decode value %s: %v", rv, err)
	}
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}
