package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
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

// clientIP extracts the client IP used as the rate-limiter key (never stored).
//
// GHSA-573f: this service runs behind a co-located cloudflared tunnel, so the
// socket peer (RemoteAddr) of every request is the tunnel/proxy — keying solely
// on RemoteAddr collapses every distinct client onto one bucket and defeats the
// per-client limits. The real client is carried in CF-Connecting-IP. That header
// is attacker-spoofable, so we honor a forwarding header ONLY when the socket
// peer is itself a trusted proxy; otherwise we use the socket peer. This keeps
// direct (non-proxied) callers un-spoofable while restoring per-client keying
// behind the tunnel.
func clientIP(r *http.Request, trusted func(net.IP) bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || trusted == nil || !trusted(peer) {
		// Not behind a trusted proxy: the socket peer IS the client. Ignore any
		// forwarding headers so a direct caller cannot spoof its key.
		return host
	}
	// Trusted proxy peer: prefer Cloudflare's client IP, then the right-most
	// (proxy-appended, least attacker-controlled) X-Forwarded-For hop.
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return ip.String()
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if ip := net.ParseIP(last); ip != nil {
			return ip.String()
		}
	}
	return host
}

// buildTrustedProxy compiles the THREAT_NETWORK_TRUSTED_PROXIES value into a
// membership predicate over source IPs. The value is a comma-separated list of
// CIDRs or bare IPs; an empty value defaults to loopback only (cloudflared is
// co-located with the service). Unparseable tokens are skipped.
func buildTrustedProxy(env string) func(net.IP) bool {
	var nets []*net.IPNet
	add := func(cidr string) {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	if strings.TrimSpace(env) == "" {
		add("127.0.0.0/8")
		add("::1/128")
	} else {
		for _, tok := range strings.Split(env, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if !strings.Contains(tok, "/") {
				if ip := net.ParseIP(tok); ip != nil {
					bits := 32
					if ip.To4() == nil {
						bits = 128
					}
					tok = fmt.Sprintf("%s/%d", tok, bits)
				}
			}
			add(tok)
		}
	}
	return func(ip net.IP) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
}
