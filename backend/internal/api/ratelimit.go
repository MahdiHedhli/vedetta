package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	clients map[string]rateLimitEntry
	limit   int
	window  time.Duration
}

type rateLimitEntry struct {
	windowStart time.Time
	count       int
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		clients: make(map[string]rateLimitEntry),
		limit:   limit,
		window:  window,
	}
}

func (l *ipRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, retryAfter := l.allow(sourceIPFromRequest(r), time.Now())
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

func sourceIPFromRequest(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
