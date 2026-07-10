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
	// redemptions remembers, for a consumed code, the raw token + sensor_id it minted
	// (Issue #44). This makes first-sensor enrollment idempotent: if the sensor lost
	// the registration response, retrying with the SAME code returns the SAME token
	// instead of a permanent 401. Bound and expired via the code's TTL and a size cap
	// so it cannot grow without limit.
	redemptions map[string]redemption
	ttl         time.Duration
	now         func() time.Time
}

// redemption is the memory of a single consumed enrollment code.
type redemption struct {
	rawToken string
	tokenID  string
	sensorID string
	exp      time.Time
}

// maxRedemptions caps how many consumed-code memories we retain, bounding the
// idempotency map even under a flood of distinct codes. Oldest-expiring entries
// are swept first; a fresh record still evicts when the cap is hit.
const maxRedemptions = 1024

// NewEnrollmentStore creates a store with a 15-minute code TTL.
func NewEnrollmentStore() *EnrollmentStore {
	return &EnrollmentStore{
		codes:       make(map[string]time.Time),
		redemptions: make(map[string]redemption),
		ttl:         15 * time.Minute,
		now:         time.Now,
	}
}

// normalizeCode canonicalizes a presented code the same way Consume does, so the
// redemption map keys line up with what Consume removed.
func normalizeCode(code string) string {
	return strings.TrimSpace(strings.ToUpper(code))
}

// LookupRedemption returns the raw token + token_id previously minted for this
// code, but ONLY when it was redeemed by the SAME sensor_id and has not expired.
// Binding to sensor_id preserves the single-use guarantee against a DIFFERENT
// caller replaying the code while letting the original sensor recover a lost
// response. Returns ok=false when there is no matching, unexpired redemption.
func (s *EnrollmentStore) LookupRedemption(code, sensorID string) (rawToken, tokenID string, ok bool) {
	code = normalizeCode(code)
	if code == "" || sensorID == "" {
		return "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepRedemptionsLocked()
	r, found := s.redemptions[code]
	if !found || r.sensorID != sensorID || s.now().After(r.exp) {
		return "", "", false
	}
	return r.rawToken, r.tokenID, true
}

// RecordRedemption remembers the token minted for a just-consumed code so a
// retry from the same sensor can recover it. The memory expires with the code's
// TTL. No-op for empty inputs.
func (s *EnrollmentStore) RecordRedemption(code, sensorID, rawToken, tokenID string) {
	code = normalizeCode(code)
	if code == "" || sensorID == "" || rawToken == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepRedemptionsLocked()
	s.evictRedemptionsLocked()
	s.redemptions[code] = redemption{
		rawToken: rawToken,
		tokenID:  tokenID,
		sensorID: sensorID,
		exp:      s.now().Add(s.ttl),
	}
}

// sweepRedemptionsLocked drops expired redemption memories. Caller holds s.mu.
func (s *EnrollmentStore) sweepRedemptionsLocked() {
	now := s.now()
	for c, r := range s.redemptions {
		if now.After(r.exp) {
			delete(s.redemptions, c)
		}
	}
}

// evictRedemptionsLocked enforces maxRedemptions by removing the soonest-to-expire
// entry when the map is full. Caller holds s.mu.
func (s *EnrollmentStore) evictRedemptionsLocked() {
	for len(s.redemptions) >= maxRedemptions {
		var oldestCode string
		var oldestExp time.Time
		first := true
		for c, r := range s.redemptions {
			if first || r.exp.Before(oldestExp) {
				oldestCode, oldestExp, first = c, r.exp, false
			}
		}
		if first {
			return
		}
		delete(s.redemptions, oldestCode)
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
