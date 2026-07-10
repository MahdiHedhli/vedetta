package api

// GHSA-wx5m: sensor-registration limiter trusted forwarded headers unconditionally
// and grew its clients map without bound. These tests verify that:
//   - from an UNTRUSTED socket peer, X-Forwarded-For / X-Real-IP are ignored and the
//     limiter keys on the real socket peer (so forged headers can't dodge the limit);
//   - from a TRUSTED proxy peer, X-Forwarded-For is honored, using the right-most
//     untrusted hop;
//   - the clients map is bounded.
//
// Synthetic / documentation-reserved values only.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func reqFrom(remoteAddr, xff, xRealIP string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/sensor/register", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		r.Header.Set("X-Real-IP", xRealIP)
	}
	return r
}

func TestSourceIP_UntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	// No trusted proxies configured (default). Forged XFF/X-Real-IP must be ignored.
	l := &ipRateLimiter{clients: map[string]rateLimitEntry{}, limit: 5, window: time.Minute, maxKeys: defaultMaxRateLimitKeys}

	r := reqFrom("192.0.2.10:5555", "1.1.1.1, 2.2.2.2", "3.3.3.3")
	if got := l.sourceIP(r); got != "192.0.2.10" {
		t.Fatalf("untrusted peer: expected socket peer 192.0.2.10, got %q", got)
	}
}

func TestSourceIP_ForgedXFFCannotEvadeLimit(t *testing.T) {
	// An attacker rotates X-Forwarded-For on every request to try to get a fresh
	// bucket each time. Because the peer is untrusted, all requests key on the same
	// socket peer and the limit still bites.
	l := &ipRateLimiter{clients: map[string]rateLimitEntry{}, limit: 3, window: time.Minute, maxKeys: defaultMaxRateLimitKeys}
	now := time.Now()

	for i := 0; i < 3; i++ {
		r := reqFrom("192.0.2.20:4444", "10.0.0."+itoa(i), "")
		if allowed, _ := l.allow(l.sourceIP(r), now); !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// 4th request with yet another forged XFF must be blocked (same real peer).
	r := reqFrom("192.0.2.20:4444", "10.0.0.99", "")
	if allowed, _ := l.allow(l.sourceIP(r), now); allowed {
		t.Fatal("forged XFF rotation evaded the rate limit")
	}
}

func TestSourceIP_TrustedProxyHonorsRightmostUntrustedHop(t *testing.T) {
	// Peer 192.0.2.30 is a trusted proxy; 192.0.2.31 is a second trusted hop. The
	// right-most UNTRUSTED hop (198.51.100.7) is the real client.
	l := &ipRateLimiter{
		clients: map[string]rateLimitEntry{},
		limit:   5,
		window:  time.Minute,
		maxKeys: defaultMaxRateLimitKeys,
		trusted: parseTrustedProxies("192.0.2.30, 192.0.2.31"),
	}

	r := reqFrom("192.0.2.30:1111", "203.0.113.9, 198.51.100.7, 192.0.2.31", "")
	if got := l.sourceIP(r); got != "198.51.100.7" {
		t.Fatalf("trusted proxy: expected right-most untrusted hop 198.51.100.7, got %q", got)
	}
}

func TestRateLimiterMapIsBounded(t *testing.T) {
	l := &ipRateLimiter{clients: map[string]rateLimitEntry{}, limit: 100, window: time.Minute, maxKeys: 100}
	now := time.Now()

	// Hammer with far more unique keys than the cap; the map must stay bounded.
	for i := 0; i < 5000; i++ {
		l.allow("10.1."+itoa(i/256)+"."+itoa(i%256), now)
	}
	if len(l.clients) > l.maxKeys {
		t.Fatalf("clients map exceeded cap: len=%d maxKeys=%d", len(l.clients), l.maxKeys)
	}
}

func TestRateLimiterLazyExpiryFrees(t *testing.T) {
	l := &ipRateLimiter{clients: map[string]rateLimitEntry{}, limit: 100, window: time.Minute, maxKeys: 100}
	base := time.Now()

	// Fill with entries in an early window.
	for i := 0; i < 100; i++ {
		l.allow("172.16."+itoa(i/256)+"."+itoa(i%256), base)
	}
	// Much later, a new key triggers eviction of the fully-elapsed windows.
	l.allow("172.31.0.1", base.Add(2*time.Minute))
	if len(l.clients) > l.maxKeys {
		t.Fatalf("expected lazy expiry to keep map bounded, len=%d", len(l.clients))
	}
}

// itoa is a tiny int→string helper to avoid importing strconv in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
