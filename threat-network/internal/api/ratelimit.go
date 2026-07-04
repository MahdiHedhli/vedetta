package api

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// tokenBucket is a simple per-key token bucket. It holds NO IP persistence
// beyond in-memory state that is swept by a background goroutine (see
// RateLimiter.sweep / StartSweeper) — client IPs never reach the store
// (constitution: no PII at rest).
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter is an in-memory per-IP token-bucket limiter. Idle buckets are
// evicted by a background sweeper so the map cannot grow without bound under a
// spray of distinct source IPs (memory-exhaustion DoS). Wire StartSweeper to
// the server/main context so the sweeper stops on shutdown.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64 // tokens per second
	capacity float64
	now      func() time.Time
}

// sweepInterval is how often idle buckets are evicted.
const sweepInterval = 5 * time.Minute

// bucketIdleTTL is how long a bucket may sit untouched before it is evicted. A
// bucket that has not been accessed for this long has, by construction, already
// refilled to full capacity, so evicting it is equivalent to never having seen
// the key — the next request from that IP re-creates a full bucket.
const bucketIdleTTL = 30 * time.Minute

// NewRateLimiter builds a limiter allowing `capacity` burst and `rate` tokens/sec.
func NewRateLimiter(ratePerSec, capacity float64) *RateLimiter {
	return &RateLimiter{
		buckets:  map[string]*tokenBucket{},
		rate:     ratePerSec,
		capacity: capacity,
		now:      time.Now,
	}
}

// StartSweeper launches the background eviction goroutine. It runs until ctx is
// cancelled (server/main shutdown), then returns. Safe to call once per limiter.
func (rl *RateLimiter) StartSweeper(ctx context.Context) {
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rl.sweep(rl.now())
			}
		}
	}()
}

// sweep evicts every bucket whose last access is older than bucketIdleTTL as of
// `now`. It is separated from StartSweeper so tests can drive it deterministically
// with an injected clock instead of real sleeps.
func (rl *RateLimiter) sweep(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-bucketIdleTTL)
	for key, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, key)
		}
	}
}

// size returns the current bucket count (test/observability helper).
func (rl *RateLimiter) size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// Allow consumes one token for the key (client IP). Returns (ok, retryAfterSec).
func (rl *RateLimiter) Allow(key string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	b := rl.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: rl.capacity, last: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}
	// seconds until one token is available
	retry := int((1 - b.tokens) / rl.rate)
	if retry < 1 {
		retry = 1
	}
	return false, retry
}

// clientIP extracts the client IP (limiter key only; never stored). It is
// intentionally simple: the RemoteAddr host portion. Behind a trusted proxy the
// deployment sets X-Forwarded-For handling upstream; for the alpha we key on
// RemoteAddr to avoid trusting spoofable headers.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
