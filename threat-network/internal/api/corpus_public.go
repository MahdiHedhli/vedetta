package api

import (
	"net/http"
	"strings"
)

func (s *Server) handleCorpusManifest(w http.ResponseWriter, r *http.Request) {
	if !s.allowCorpusRead(w, r) {
		return
	}
	manifest, err := s.DB.CorpusManifest()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "device corpus unavailable")
		return
	}
	etag := `"` + manifest.SnapshotSHA256 + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=900")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

func (s *Server) handleCorpusSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.allowCorpusRead(w, r) {
		return
	}
	manifest, err := s.DB.CorpusManifest()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "device corpus unavailable")
		return
	}
	etag := `"` + manifest.SnapshotSHA256 + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=900")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	data, manifest, err := s.DB.CurrentCorpusSnapshot()
	if err != nil {
		w.Header().Del("ETag")
		w.Header().Set("Cache-Control", "no-store")
		writeErr(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "device corpus unavailable")
		return
	}
	// A publication may have committed between the metadata and body reads.
	// Always bind the response headers to the exact immutable body returned.
	w.Header().Set("ETag", `"`+manifest.SnapshotSHA256+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) allowCorpusRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return false
	}
	// The public corpus is immutable and has no query contract. Rejecting every
	// query prevents cache-busting variants from multiplying work upstream.
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "INVALID_QUERY", "query parameters are not supported")
		return false
	}
	if ok, retry := s.corpusLimit.Allow(clientIP(r, s.trustedProxy)); !ok {
		writeRateLimit(w, retry)
		return false
	}
	return true
}

func etagMatches(header, current string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == current || strings.TrimPrefix(candidate, "W/") == current {
			return true
		}
	}
	return false
}
