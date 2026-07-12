package eventid

import (
	"testing"
	"time"
)

func TestDeterministicStableAcrossMapOrderAndDistinctMaterial(t *testing.T) {
	timestamp := time.Date(2026, time.July, 12, 10, 11, 12, 123, time.UTC)
	first := Deterministic("collector", "192.0.2.10", timestamp, map[string]any{
		"domain": "example.test", "blocked": false,
	})
	reordered := Deterministic("collector", "192.0.2.10", timestamp, map[string]any{
		"blocked": false, "domain": "example.test",
	})
	if first != reordered {
		t.Fatalf("map key order changed deterministic ID: %q != %q", first, reordered)
	}
	if changed := Deterministic("collector", "192.0.2.10", timestamp, map[string]any{
		"domain": "different.test", "blocked": false,
	}); changed == first {
		t.Fatal("distinct normalized material collided")
	}
	if changed := Deterministic("collector", "192.0.2.11", timestamp, map[string]any{
		"domain": "example.test", "blocked": false,
	}); changed == first {
		t.Fatal("distinct source identity collided")
	}
}

func TestDeterministicZeroTimestampIsReplayStable(t *testing.T) {
	first := Deterministic("collector", "unknown", time.Time{}, map[string]string{"raw": "same"})
	second := Deterministic("collector", "unknown", time.Time{}, map[string]string{"raw": "same"})
	if first != second {
		t.Fatalf("timestamp-less replay changed ID: %q != %q", first, second)
	}
}
