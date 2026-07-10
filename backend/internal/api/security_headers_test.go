package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_PresentOnResponses asserts the anti-clickjacking and
// anti-sniffing headers are stamped on every Core response by the outermost
// middleware (GHSA-69jp), regardless of the route or its status code.
func TestSecurityHeaders_PresentOnResponses(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	want := map[string]string{
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
	}

	// Cover a public route, the health probe, and a not-found path so we prove the
	// headers ride on API JSON, middleware short-circuits, and error responses.
	paths := []string{"/api/v1/version", "/healthz", "/does-not-exist"}

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		for header, expected := range want {
			if got := w.Header().Get(header); got != expected {
				t.Errorf("GET %s: header %q = %q, want %q", path, header, got, expected)
			}
		}
	}
}
