package api

import (
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EnrollmentStore holds short-lived, single-use sensor enrollment codes in
// memory. Once an admin exists, registering a BRAND-NEW sensor requires a valid
// code (or an admin bearer) — otherwise any unauthenticated host on the LAN could
// mint a sensor token and push forged data (beta-gate B1a). Codes are ephemeral
// by design and never persisted.
type EnrollmentStore struct {
	mu    sync.Mutex
	codes map[string]time.Time // code -> expiry
	ttl   time.Duration
	now   func() time.Time
}

// NewEnrollmentStore creates a store with a 15-minute code TTL.
func NewEnrollmentStore() *EnrollmentStore {
	return &EnrollmentStore{
		codes: make(map[string]time.Time),
		ttl:   15 * time.Minute,
		now:   time.Now,
	}
}

// Generate mints a new single-use code and returns it with its expiry.
func (s *EnrollmentStore) Generate() (string, time.Time) {
	code := newEnrollmentCode()
	exp := s.now().Add(s.ttl)
	s.mu.Lock()
	s.sweepLocked()
	s.codes[code] = exp
	s.mu.Unlock()
	return code, exp
}

// Consume validates and removes a code (single use). It returns true only if the
// code was present and unexpired.
func (s *EnrollmentStore) Consume(code string) bool {
	code = strings.TrimSpace(strings.ToUpper(code))
	if code == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.codes[code]
	delete(s.codes, code) // single-use: remove whether or not it was valid
	return ok && !s.now().After(exp)
}

func (s *EnrollmentStore) sweepLocked() {
	now := s.now()
	for c, exp := range s.codes {
		if now.After(exp) {
			delete(s.codes, c)
		}
	}
}

// newEnrollmentCode returns an 80-bit code as uppercase base32, grouped for easy
// reading/typing, e.g. "K7Q2-9FJ4-M3XA-BZ10".
func newEnrollmentCode() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	raw := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	var groups []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return strings.Join(groups, "-")
}

// NewSetupCode mints a first-admin bootstrap setup code (GHSA-6cmx), reusing the
// same 80-bit grouped-base32 format as sensor enrollment codes so it is easy to
// read from the boot log and type into the setup wizard.
func NewSetupCode() string {
	return newEnrollmentCode()
}

// handleGenerateEnrollmentCode mints a short-lived, single-use sensor enrollment
// code. Admin only. POST /api/v1/enrollment-codes
func (s *Server) handleGenerateEnrollmentCode(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil {
		s.Enroll = NewEnrollmentStore()
	}
	code, exp := s.Enroll.Generate()
	writeJSON(w, http.StatusCreated, map[string]any{
		"enrollment_code": code,
		"expires_at":      exp.UTC().Format(time.RFC3339),
		"note":            "give this to a new sensor via --enroll-code (or VEDETTA_ENROLL_CODE). Single use; expires soon.",
	})
}
