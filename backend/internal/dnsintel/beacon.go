package dnsintel

import (
	"math"
	"sync"
	"time"
)

// BeaconDetector tracks per-(source, domain) query timestamps and detects
// beaconing behavior — regular, periodic DNS queries that suggest C2 callbacks.
//
// Detection method: coefficient of variation (CV) of inter-query intervals.
// CV = stddev / mean. A CV < 0.15 indicates highly regular timing.
// Normal user browsing has CV > 0.5. Beaconing malware typically CV < 0.1.
//
// Memory budget: ~10MB for 100K active (source, domain) pairs with 32-entry
// rolling windows. Stale entries are evicted after the configured TTL.
type BeaconDetector struct {
	mu      sync.Mutex
	entries map[beaconKey]*beaconEntry

	// MinSamples is the minimum number of queries before scoring (default: 6).
	MinSamples int

	// WindowSize is the rolling window of timestamps to keep (default: 32).
	WindowSize int

	// CVThreshold is the coefficient of variation below which beaconing
	// is flagged (default: 0.15).
	CVThreshold float64

	// EntryTTL is how long to keep an entry without new queries (default: 2h).
	EntryTTL time.Duration
}

type beaconKey struct {
	SourceHash string
	Domain     string
}

type beaconEntry struct {
	timestamps []time.Time
	lastSeen   time.Time
}

// BeaconResult holds the output of the beaconing analysis.
type BeaconResult struct {
	Score         float64       // 0.0 (not beaconing) to 1.0 (definite beacon)
	IsBeaconing   bool          // True if CV < threshold and enough samples
	CV            float64       // Coefficient of variation of intervals
	MeanInterval  time.Duration // Average time between queries
	SampleCount   int           // Number of timestamps in the window
}

// NewBeaconDetector creates a BeaconDetector with sensible defaults.
func NewBeaconDetector() *BeaconDetector {
	return &BeaconDetector{
		entries:     make(map[beaconKey]*beaconEntry),
		MinSamples:  6,
		WindowSize:  32,
		CVThreshold: 0.15,
		EntryTTL:    2 * time.Hour,
	}
}

// RecordAndScore records a DNS query timestamp and returns the current
// beaconing assessment for the (source, domain) pair.
func (bd *BeaconDetector) RecordAndScore(sourceHash, domain string, ts time.Time) BeaconResult {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	key := beaconKey{SourceHash: sourceHash, Domain: domain}
	entry, exists := bd.entries[key]

	if !exists {
		entry = &beaconEntry{
			timestamps: make([]time.Time, 0, bd.WindowSize),
		}
		bd.entries[key] = entry
	}

	// Append timestamp, keeping only the most recent WindowSize entries
	entry.timestamps = append(entry.timestamps, ts)
	if len(entry.timestamps) > bd.WindowSize {
		entry.timestamps = entry.timestamps[len(entry.timestamps)-bd.WindowSize:]
	}
	entry.lastSeen = ts

	// Need minimum samples for meaningful statistics
	if len(entry.timestamps) < bd.MinSamples {
		return BeaconResult{SampleCount: len(entry.timestamps)}
	}

	// Calculate inter-query intervals
	intervals := make([]float64, len(entry.timestamps)-1)
	for i := 1; i < len(entry.timestamps); i++ {
		intervals[i-1] = entry.timestamps[i].Sub(entry.timestamps[i-1]).Seconds()
	}

	// Calculate mean and stddev
	mean := meanFloat(intervals)
	if mean < 1.0 {
		// Sub-second intervals are noise, not beaconing
		return BeaconResult{SampleCount: len(entry.timestamps)}
	}

	stddev := stddevFloat(intervals, mean)
	cv := stddev / mean

	// Score: map CV to 0–1 suspicion scale
	// CV < 0.05 = near-perfect regularity = score 1.0
	// CV 0.05–0.15 = suspicious = score 0.5–1.0
	// CV 0.15–0.30 = mild = score 0.1–0.5
	// CV > 0.30 = normal = score 0
	var score float64
	switch {
	case cv < 0.05:
		score = 1.0
	case cv < bd.CVThreshold:
		score = 0.5 + 0.5*(bd.CVThreshold-cv)/(bd.CVThreshold-0.05)
	case cv < 0.30:
		score = 0.1 + 0.4*(0.30-cv)/(0.30-bd.CVThreshold)
	default:
		score = 0
	}

	return BeaconResult{
		Score:        clamp(score),
		IsBeaconing:  cv < bd.CVThreshold,
		CV:           cv,
		MeanInterval: time.Duration(mean * float64(time.Second)),
		SampleCount:  len(entry.timestamps),
	}
}

// EvictStale removes entries that haven't been seen within the TTL.
// Should be called periodically (e.g. every 15 minutes).
func (bd *BeaconDetector) EvictStale(now time.Time) int {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	evicted := 0
	for key, entry := range bd.entries {
		if now.Sub(entry.lastSeen) > bd.EntryTTL {
			delete(bd.entries, key)
			evicted++
		}
	}
	return evicted
}

// EntryCount returns the number of active (source, domain) pairs tracked.
func (bd *BeaconDetector) EntryCount() int {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	return len(bd.entries)
}

func meanFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddevFloat(vals []float64, mean float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	sumSq := 0.0
	for _, v := range vals {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}
