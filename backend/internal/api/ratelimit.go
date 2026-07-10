package api

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultMaxRateLimitKeys bounds the per-source tracking map so a spray of unique
// source IPs (e.g. a spoofed-XFF or v6 flood) cannot grow it without limit
// (GHSA-wx5m). Overridable via VEDETTA_RATELIMIT_MAX_KEYS.
const defaultMaxRateLimitKeys = 50000

type ipRateLimiter struct {
	mu      sync.Mutex
	clients map[string]rateLimitEntry
	limit   int
	window  time.Duration

	// trusted is the set of proxy peers (socket RemoteAddr) whose X-Forwarded-For /
	// X-Real-IP headers we are willing to believe. Empty by default: with no trusted
	// proxy configured we always key on the real socket peer and ignore forwarded
	// headers entirely, so a LAN client cannot forge its source to dodge or poison
	// the sensor-registration limiter.
	trusted []*net.IPNet

	// maxKeys caps the clients map; entries are lazily expired and, if still over
	// cap, the oldest windows are evicted.
	maxKeys int
}

type rateLimitEntry struct {
	windowStart time.Time
	count       int
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	maxKeys := defaultMaxRateLimitKeys
	if v := strings.TrimSpace(os.Getenv("VEDETTA_RATELIMIT_MAX_KEYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxKeys = n
		}
	}
	return &ipRateLimiter{
		clients: make(map[string]rateLimitEntry),
		limit:   limit,
		window:  window,
		trusted: parseTrustedProxies(os.Getenv("VEDETTA_TRUSTED_PROXIES")),
		maxKeys: maxKeys,
	}
}

// parseTrustedProxies parses a comma-separated list of trusted-proxy IPs and CIDRs.
// Bare IPs are treated as /32 (v4) or /128 (v6). Unparseable entries are skipped.
func parseTrustedProxies(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, ipNet)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

func (l *ipRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, retryAfter := l.allow(l.sourceIP(r), time.Now())
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "rate limit exceeded",
				"retry_after": retryAfter.Round(time.Second).String(),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *ipRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if key == "" {
		key = "unknown"
	}

	// Bound the map (GHSA-wx5m): only when it grows past the cap, so the common path
	// stays O(1). First drop fully-elapsed windows, then, if still over cap, evict
	// the oldest windows.
	if len(l.clients) >= l.maxKeys {
		l.evictLocked(now)
	}

	entry, ok := l.clients[key]
	if !ok || now.Sub(entry.windowStart) >= l.window {
		l.clients[key] = rateLimitEntry{windowStart: now, count: 1}
		return true, 0
	}

	if entry.count >= l.limit {
		return false, l.window - now.Sub(entry.windowStart)
	}

	entry.count++
	l.clients[key] = entry
	return true, 0
}

// evictLocked bounds the clients map. Caller must hold l.mu.
func (l *ipRateLimiter) evictLocked(now time.Time) {
	// 1. Lazy expiry: drop entries whose window has fully elapsed.
	for k, e := range l.clients {
		if now.Sub(e.windowStart) >= l.window {
			delete(l.clients, k)
		}
	}
	// 2. If still at/over cap, evict the oldest-window entries until under cap.
	for len(l.clients) >= l.maxKeys {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range l.clients {
			if first || e.windowStart.Before(oldest) {
				oldest, oldestKey, first = e.windowStart, k, false
			}
		}
		if first {
			break // map empty
		}
		delete(l.clients, oldestKey)
	}
}

// sourceIP resolves the rate-limit key for a request. It uses the socket peer
// (RemoteAddr) by default and only believes X-Forwarded-For / X-Real-IP when the
// peer is a configured trusted proxy. When honoring X-Forwarded-For it takes the
// right-most hop that is not itself a trusted proxy — the closest attacker-
// controllable address that our own proxies did not append — so a client cannot
// spoof an arbitrary left-most value.
func (l *ipRateLimiter) sourceIP(r *http.Request) string {
	peerHost := hostOnly(r.RemoteAddr)

	if l.isTrusted(peerHost) {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			if ip := l.rightmostUntrusted(forwarded); ip != "" {
				return ip
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return peerHost
}

// rightmostUntrusted returns the right-most X-Forwarded-For entry that is not a
// trusted proxy. Returns "" if the header has no usable untrusted hop.
func (l *ipRateLimiter) rightmostUntrusted(forwarded string) string {
	parts := strings.Split(forwarded, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		if hop == "" {
			continue
		}
		if ip := net.ParseIP(hop); ip != nil && l.isTrustedIP(ip) {
			continue // skip our own proxies, keep walking left
		}
		return hop
	}
	return ""
}

func (l *ipRateLimiter) isTrusted(host string) bool {
	if len(l.trusted) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return l.isTrustedIP(ip)
}

func (l *ipRateLimiter) isTrustedIP(ip net.IP) bool {
	for _, n := range l.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly strips the port from a RemoteAddr, tolerating a bare host.
func hostOnly(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
