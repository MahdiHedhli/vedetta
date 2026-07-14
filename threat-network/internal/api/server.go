// Package api wires the threat-network HTTP surface: status, reporter
// registration, signed ingest, and the advisory community feed. Per-IP rate
// limiting is in-memory only; client IPs are never persisted.
package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/auth"
	"github.com/vedetta-network/vedetta/threat-network/internal/feed"
	"github.com/vedetta-network/vedetta/threat-network/internal/ingest"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// maxBodyBytes caps the ingest body to bound memory (250 signals of small JSON).
const maxBodyBytes = 4 << 20 // 4 MiB

// Server holds the service dependencies.
type Server struct {
	DB          *store.DB
	Auth        *auth.Authenticator
	Ingest      *ingest.Processor
	Feed        *feed.Builder
	regLimit    *RateLimiter
	ingLimit    *RateLimiter
	feedLimit   *RateLimiter
	corpusLimit *RateLimiter
	logger      *log.Logger
	// trustedProxy reports whether a socket peer is a trusted forwarding proxy
	// (e.g. the co-located cloudflared tunnel). Only then are forwarding headers
	// consulted for the rate-limit key — see clientIP (GHSA-573f).
	trustedProxy func(net.IP) bool
}

// NewServer builds a Server with sensible per-IP limits.
func NewServer(db *store.DB, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		DB:     db,
		Auth:   auth.New(db),
		Ingest: ingest.NewProcessor(db),
		Feed:   feed.New(db),
		// Registration mints anti-poisoning-relevant identities, so keep this
		// tight: ~1 registration / 5 min sustained, burst 2. This raises the cost
		// of spraying reporter_ids across IPs; the primary Sybil defense is the
		// consensus maturation gate (see consensus.ReporterMaturationDelay).
		regLimit:    NewRateLimiter(1.0/300.0, 2),
		ingLimit:    NewRateLimiter(1.0, 20), // 1 ingest/s sustained, burst 20
		feedLimit:   NewRateLimiter(2.0, 30), // feed reads, burst 30
		corpusLimit: NewRateLimiter(2.0, 30), // immutable corpus reads, burst 30
		logger:      logger,
		// Trusted forwarding proxies for rate-limit keying (GHSA-573f). Default
		// loopback: cloudflared is co-located, so only it may set CF-Connecting-IP.
		trustedProxy: buildTrustedProxy(os.Getenv("THREAT_NETWORK_TRUSTED_PROXIES")),
	}
}

// StartSweepers launches the background idle-bucket sweeper for every per-IP
// rate limiter, tying their lifetime to ctx so they stop on shutdown. Without
// this the per-IP bucket maps grow without bound under a distinct-IP spray
// (memory-exhaustion DoS).
func (s *Server) StartSweepers(ctx context.Context) {
	s.regLimit.StartSweeper(ctx)
	s.ingLimit.StartSweeper(ctx)
	s.feedLimit.StartSweeper(ctx)
	s.corpusLimit.StartSweeper(ctx)
}

// Handler builds the http.Handler (mux) for the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/reporters/register", s.handleRegister)
	mux.HandleFunc("/api/v1/ingest", s.handleIngest)
	mux.HandleFunc("/api/v1/feed/community", s.handleFeed)
	mux.HandleFunc("/api/v1/device-corpus/manifest", s.handleCorpusManifest)
	mux.HandleFunc("/api/v1/device-corpus/snapshot", s.handleCorpusSnapshot)
	// Deprecated stubs kept returning empty for one release (T5.3).
	mux.HandleFunc("/api/v1/feed/top-domains", s.handleDeprecated("domains"))
	mux.HandleFunc("/api/v1/feed/anomalies", s.handleDeprecated("anomalies"))
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet, "GET only")
		return
	}
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "INVALID_QUERY", "query parameters are not supported")
		return
	}
	count, _ := s.DB.CountLiveFeedItems(time.Now())
	status := map[string]any{
		"status":         "ok",
		"service":        "vedetta-threat-network",
		"schema_version": 1,
		"feed_items":     count,
	}
	httpStatus := http.StatusOK
	if manifest, err := s.DB.CorpusManifest(r.Context()); err == nil {
		status["corpus_schema_version"] = manifest.SchemaVersion
		status["corpus_revision"] = manifest.CorpusRevision
		status["corpus_profiles"] = manifest.ProfileCount
		status["corpus_variants"] = manifest.VariantCount
	} else {
		status["status"] = "error"
		status["corpus_status"] = "error"
		httpStatus = http.StatusServiceUnavailable
	}
	writeJSON(w, httpStatus, status)
}

func (s *Server) handleDeprecated(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Deprecation", "true")
		writeJSON(w, http.StatusOK, map[string]any{key: []any{}})
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost, "POST only")
		return
	}
	if ok, retry := s.regLimit.Allow(clientIP(r, s.trustedProxy)); !ok {
		writeRateLimit(w, retry)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_SCHEMA", "unreadable body")
		return
	}
	var req auth.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_SCHEMA", "invalid JSON")
		return
	}
	resp, err := auth.Register(s.DB, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_SCHEMA", err.Error())
		return
	}
	s.logger.Printf("register reporter_id=%s", resp.ReporterID)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost, "POST only")
		return
	}
	if ok, retry := s.ingLimit.Allow(clientIP(r, s.trustedProxy)); !ok {
		writeRateLimit(w, retry)
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_SCHEMA", "unreadable body")
		return
	}

	sr := auth.SignedRequest{
		ReporterID: bearerReporterID(r.Header.Get("Authorization")),
		Timestamp:  r.Header.Get("X-Vedetta-Timestamp"),
		Nonce:      r.Header.Get("X-Vedetta-Nonce"),
		Signature:  r.Header.Get("X-Vedetta-Signature"),
		Body:       body,
	}
	reporter, err := s.Auth.Verify(sr)
	if err != nil {
		var ae *auth.AuthError
		if errors.As(err, &ae) {
			status := http.StatusUnauthorized
			if ae.Code == auth.CodeReporterDenylisted {
				status = http.StatusForbidden
			}
			// sr.ReporterID is untrusted Authorization-header input until Verify
			// succeeds. Never persist it in logs.
			s.logger.Printf("ingest auth reject code=%s", ae.Code)
			writeErr(w, status, ae.Code, ae.Message)
			return
		}
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "auth error")
		return
	}

	res, err := s.Ingest.Process(reporter.ReporterID, body)
	if err != nil {
		// Use the reporter identity loaded from the database after successful
		// signature verification, never the raw Authorization-header value.
		s.writeIngestError(w, reporter.ReporterID, body, err)
		return
	}

	status := http.StatusAccepted
	if res.Duplicate {
		status = http.StatusOK // idempotent replay
	}
	s.logger.Printf("ingest ok reporter_id=%s batch_id=%s accepted=%d rejected=%d duplicate=%t",
		reporter.ReporterID, res.BatchID, res.Accepted, res.Rejected, res.Duplicate)
	writeJSON(w, status, res)
}

// writeIngestError maps ingest pipeline errors to the correct wire response.
func (s *Server) writeIngestError(w http.ResponseWriter, reporterID string, body []byte, err error) {
	var se *ingest.StrictError
	if errors.As(err, &se) {
		// Whole-batch 422 with {error, rule, detail, batch_id} (002 §5).
		batchID, _ := peekBatchIDForError(body)
		s.logger.Printf("ingest reject reporter_id=%s error=%s rule=%s", reporterID, se.ErrorName, se.Rule)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":    se.ErrorName,
			"rule":     se.Rule,
			"detail":   se.Detail,
			"batch_id": batchID,
		})
		return
	}
	var ee *ingest.EnvelopeError
	if errors.As(err, &ee) {
		s.logger.Printf("ingest reject reporter_id=%s code=%s", reporterID, ee.Code)
		writeErr(w, http.StatusBadRequest, ee.Code, ee.Detail)
		return
	}
	var ce *ingest.CapError
	if errors.As(err, &ce) {
		s.logger.Printf("ingest cap reporter_id=%s", reporterID)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               "rate_limit",
			"code":                "RATE_LIMIT_EXCEEDED",
			"retry_after_seconds": ce.RetryAfterSeconds,
		})
		return
	}
	s.logger.Printf("ingest internal error reporter_id=%s", reporterID)
	writeErr(w, http.StatusInternalServerError, "INTERNAL", "ingest failed")
}

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet, "GET only")
		return
	}
	if ok, retry := s.feedLimit.Allow(clientIP(r, s.trustedProxy)); !ok {
		writeFeedRateLimit(w, retry)
		return
	}
	q := r.URL.Query()
	pq, err := feed.ParseQuery(q.Get("cursor"), q.Get("limit"), q.Get("min_confidence"), q.Get("kind"))
	if err != nil {
		var qe *feed.QueryError
		if errors.As(err, &qe) {
			writeFeedError(w, http.StatusBadRequest, qe.Code, qe.Error())
			return
		}
		writeFeedError(w, http.StatusBadRequest, "INVALID_PARAMETER", "bad parameters")
		return
	}
	resp, etag, err := s.Feed.Build(pq)
	if err != nil {
		var qe *feed.QueryError
		if errors.As(err, &qe) {
			writeFeedError(w, http.StatusBadRequest, qe.Code, qe.Error())
			return
		}
		writeFeedError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "temporary")
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "max-age=900")
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- helpers ---

func readBody(r *http.Request) ([]byte, error) {
	var reader io.Reader = io.LimitReader(r.Body, maxBodyBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = io.LimitReader(gz, maxBodyBytes)
	}
	return io.ReadAll(reader)
}

func bearerReporterID(authHeader string) string {
	const prefix = "VedettaReporter "
	if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
		return authHeader[len(prefix):]
	}
	return ""
}

func peekBatchIDForError(body []byte) (string, bool) {
	var m struct {
		BatchID string `json:"batch_id"`
	}
	if json.Unmarshal(body, &m) != nil {
		return "", false
	}
	return m.BatchID, m.BatchID != ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"code": code, "message": msg},
	})
}

func writeMethodNotAllowed(w http.ResponseWriter, allow, msg string) {
	w.Header().Set("Allow", allow)
	writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", msg)
}

func writeRateLimit(w http.ResponseWriter, retryAfter int) {
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error": map[string]any{
			"code":                "RATE_LIMIT_EXCEEDED",
			"message":             "Per-IP request limit exceeded",
			"retry_after_seconds": retryAfter,
		},
	})
}

// writeFeedError / writeFeedRateLimit use the feed contract's error envelope
// shape ({schema_version, error{code,message,...}}).
func writeFeedError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"schema_version": feed.SchemaVersion,
		"error":          map[string]any{"code": code, "message": msg},
	})
}

func writeFeedRateLimit(w http.ResponseWriter, retryAfter int) {
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"schema_version": feed.SchemaVersion,
		"error": map[string]any{
			"code":                "RATE_LIMIT_EXCEEDED",
			"message":             "Per-IP feed request limit exceeded",
			"retry_after_seconds": retryAfter,
		},
	})
}
