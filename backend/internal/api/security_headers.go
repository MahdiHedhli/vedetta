package api

import "net/http"

// securityHeaders is the outermost middleware on the Core router. It sets
// anti-clickjacking and MIME-sniffing protections on EVERY response — API JSON,
// the served dashboard SPA, health probes, and error pages alike (Sol
// GHSA-69jp). The dashboard was previously frameable, so a malicious page could
// embed it in an <iframe> and drive authenticated actions via clickjacking.
//
//   - X-Frame-Options: DENY — legacy browsers refuse to render any response in a
//     frame/iframe.
//   - Content-Security-Policy: frame-ancestors 'none' — the modern equivalent;
//     no origin (not even same-origin) may frame the response.
//   - X-Content-Type-Options: nosniff — browsers must honor the declared
//     Content-Type instead of guessing, blocking MIME-confusion attacks.
//
// Headers are written before next.ServeHTTP so they are present even if a
// downstream handler writes its status/body immediately (or panics into the
// Recoverer). It deliberately does not touch any header a handler may need to
// control itself.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
