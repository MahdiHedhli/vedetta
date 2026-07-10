package api

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClientIPTrustsProxyHeaderOnlyFromTrustedPeer is the GHSA-573f regression:
// behind the co-located cloudflared tunnel every socket peer is the tunnel, so
// the limiter must key on CF-Connecting-IP — but ONLY when the socket peer is a
// trusted proxy. From an untrusted peer the forwarding headers are attacker-
// spoofable and must be ignored in favor of the socket peer.
func TestClientIPTrustsProxyHeaderOnlyFromTrustedPeer(t *testing.T) {
	trusted := buildTrustedProxy("127.0.0.0/8,::1/128")

	// Trusted loopback peer → CF-Connecting-IP is honored as the client key.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := clientIP(r, trusted); got != "203.0.113.9" {
		t.Fatalf("trusted peer: want client 203.0.113.9, got %s", got)
	}

	// Untrusted public peer → forwarding headers ignored, socket peer wins so a
	// direct caller cannot spoof another client's key.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "198.51.100.7:443"
	r2.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r2.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIP(r2, trusted); got != "198.51.100.7" {
		t.Fatalf("untrusted peer: want socket 198.51.100.7, got %s", got)
	}

	// Trusted peer, no CF header → fall back to the right-most X-Forwarded-For hop.
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "127.0.0.1:9"
	r3.Header.Set("X-Forwarded-For", "203.0.113.1, 203.0.113.2")
	if got := clientIP(r3, trusted); got != "203.0.113.2" {
		t.Fatalf("trusted XFF: want right-most 203.0.113.2, got %s", got)
	}

	// Trusted peer but no forwarding headers → socket peer.
	r4 := httptest.NewRequest("GET", "/", nil)
	r4.RemoteAddr = "127.0.0.1:1"
	if got := clientIP(r4, trusted); got != "127.0.0.1" {
		t.Fatalf("trusted peer no headers: want 127.0.0.1, got %s", got)
	}
}

// TestBuildTrustedProxyDefaultLoopback verifies the env default (loopback only)
// and that a custom CIDR/bare-IP list is honored.
func TestBuildTrustedProxyDefaultLoopback(t *testing.T) {
	def := buildTrustedProxy("")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5"
	r.Header.Set("CF-Connecting-IP", "203.0.113.5")
	if got := clientIP(r, def); got != "203.0.113.5" {
		t.Fatalf("default loopback must be trusted, got %s", got)
	}
	// A public peer is NOT trusted by default → header ignored.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "203.0.113.50:5"
	r2.Header.Set("CF-Connecting-IP", "203.0.113.5")
	if got := clientIP(r2, def); got != "203.0.113.50" {
		t.Fatalf("public peer must not be trusted by default, got %s", got)
	}
	// Custom list with a bare IP.
	custom := buildTrustedProxy("203.0.113.50")
	if got := clientIP(r2, custom); got != "203.0.113.5" {
		t.Fatalf("custom trusted proxy must honor CF header, got %s", got)
	}
}

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
