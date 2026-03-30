package dnsintel

import (
	"testing"
	"time"
)

func TestBeaconDetector_RegularInterval(t *testing.T) {
	bd := NewBeaconDetector()
	bd.MinSamples = 6

	base := time.Now()
	// Simulate beaconing: exactly every 60 seconds
	var result BeaconResult
	for i := 0; i < 10; i++ {
		ts := base.Add(time.Duration(i) * 60 * time.Second)
		result = bd.RecordAndScore("src1", "evil.com", ts)
	}

	if !result.IsBeaconing {
		t.Errorf("expected beaconing detection for regular 60s intervals, CV=%.4f", result.CV)
	}
	if result.Score < 0.5 {
		t.Errorf("expected high score for beaconing, got %.2f", result.Score)
	}
	if result.SampleCount != 10 {
		t.Errorf("expected 10 samples, got %d", result.SampleCount)
	}
}

func TestBeaconDetector_RandomInterval(t *testing.T) {
	bd := NewBeaconDetector()
	bd.MinSamples = 6

	base := time.Now()
	// Simulate random browsing: irregular intervals
	offsets := []int{0, 3, 47, 120, 122, 500, 510, 900, 1800, 1805}
	var result BeaconResult
	for _, offset := range offsets {
		ts := base.Add(time.Duration(offset) * time.Second)
		result = bd.RecordAndScore("src1", "normal.com", ts)
	}

	if result.IsBeaconing {
		t.Errorf("should not flag random intervals as beaconing, CV=%.4f", result.CV)
	}
}

func TestBeaconDetector_InsufficientSamples(t *testing.T) {
	bd := NewBeaconDetector()
	bd.MinSamples = 6

	base := time.Now()
	// Only 3 queries — below MinSamples
	result := bd.RecordAndScore("src1", "test.com", base)
	result = bd.RecordAndScore("src1", "test.com", base.Add(60*time.Second))
	result = bd.RecordAndScore("src1", "test.com", base.Add(120*time.Second))

	if result.IsBeaconing {
		t.Error("should not flag with insufficient samples")
	}
	if result.SampleCount != 3 {
		t.Errorf("expected 3 samples, got %d", result.SampleCount)
	}
}

func TestBeaconDetector_SeparateKeys(t *testing.T) {
	bd := NewBeaconDetector()
	bd.MinSamples = 4

	base := time.Now()

	// Two different (source, domain) pairs should be tracked independently
	for i := 0; i < 6; i++ {
		ts := base.Add(time.Duration(i) * 60 * time.Second)
		bd.RecordAndScore("src1", "evil.com", ts)
		bd.RecordAndScore("src2", "good.com", ts)
	}

	if bd.EntryCount() != 2 {
		t.Errorf("expected 2 entries, got %d", bd.EntryCount())
	}
}

func TestBeaconDetector_EvictStale(t *testing.T) {
	bd := NewBeaconDetector()
	bd.EntryTTL = 1 * time.Hour

	base := time.Now().Add(-2 * time.Hour)
	bd.RecordAndScore("src1", "old.com", base)

	evicted := bd.EvictStale(time.Now())
	if evicted != 1 {
		t.Errorf("expected 1 evicted, got %d", evicted)
	}
	if bd.EntryCount() != 0 {
		t.Errorf("expected 0 entries after eviction, got %d", bd.EntryCount())
	}
}

func TestBeaconDetector_WindowSize(t *testing.T) {
	bd := NewBeaconDetector()
	bd.WindowSize = 5
	bd.MinSamples = 4

	base := time.Now()
	// Insert more than WindowSize entries
	for i := 0; i < 10; i++ {
		bd.RecordAndScore("src1", "test.com", base.Add(time.Duration(i)*time.Minute))
	}

	// Internal window should be capped at WindowSize
	bd.mu.Lock()
	entry := bd.entries[beaconKey{"src1", "test.com"}]
	count := len(entry.timestamps)
	bd.mu.Unlock()

	if count != 5 {
		t.Errorf("expected window size 5, got %d", count)
	}
}
