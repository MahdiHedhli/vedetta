package api

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiterSweepEvictsStaleBuckets is the finding #1 regression: the
// per-IP token-bucket map must not grow without bound (memory-exhaustion DoS).
// A background sweeper evicts buckets whose last access is older than
// bucketIdleTTL. Here we drive the sweeper's clock deterministically (no real
// sleeps): insert many distinct-IP buckets, keep one recently active, advance
// the clock past the TTL, sweep, and assert the stale buckets are gone while the
// recently-active bucket survives.
func TestRateLimiterSweepEvictsStaleBuckets(t *testing.T) {
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	clock := base
	rl := NewRateLimiter(1.0, 5)
	rl.now = func() time.Time { return clock }

	// Insert 1000 distinct-IP buckets (RFC 5737 TEST-NET-1: 192.0.2.0/24 plus
	// TEST-NET-2/3 to span more than one /24 worth of synthetic addresses).
	const staleCount = 1000
	for i := 0; i < staleCount; i++ {
		rl.Allow(fmt.Sprintf("192.0.2.%d", i%256))
		rl.Allow(fmt.Sprintf("198.51.100.%d", i%256))
		rl.Allow(fmt.Sprintf("203.0.113.%d", i%256))
	}
	stale := rl.size()
	if stale < 256 {
		t.Fatalf("expected many distinct-IP buckets, got %d", stale)
	}

	// Advance almost to the TTL and touch ONE key so it stays fresh.
	clock = base.Add(bucketIdleTTL - time.Minute)
	const freshKey = "192.0.2.42"
	rl.Allow(freshKey)

	// Advance past the TTL relative to the stale buckets (but the fresh key was
	// just touched, so it is still within its TTL) and sweep.
	clock = base.Add(bucketIdleTTL + time.Second)
	rl.sweep(clock)

	after := rl.size()
	if after >= stale {
		t.Fatalf("sweep must shrink the map: before=%d after=%d", stale, after)
	}
	// The fresh key survives; a known stale key is gone.
	rl.mu.Lock()
	_, freshOK := rl.buckets[freshKey]
	_, staleOK := rl.buckets["203.0.113.7"]
	rl.mu.Unlock()
	if !freshOK {
		t.Fatal("recently-active bucket must survive the sweep")
	}
	if staleOK {
		t.Fatal("stale bucket must be evicted by the sweep")
	}

	// Advancing well past the fresh key's TTL and sweeping again evicts it too,
	// so the map fully drains when traffic stops.
	clock = base.Add(3 * bucketIdleTTL)
	rl.sweep(clock)
	if got := rl.size(); got != 0 {
		t.Fatalf("all idle buckets must eventually evict, got %d remaining", got)
	}
}
