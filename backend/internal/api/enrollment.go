package api

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"io"
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
	codes map[string]codeRecord // code -> record
	// redemptions remembers, for a consumed code, the raw token + sensor_id it minted
	// (Issue #44). This makes first-sensor enrollment idempotent: if the sensor lost
	// the registration response, retrying with the SAME code returns the SAME token
	// instead of a permanent 401. Bound and expired via the code's TTL and a size cap
	// so it cannot grow without limit.
	redemptions map[string]redemption
	ttl         time.Duration
	now         func() time.Time
}

// codeRecord is a minted enrollment code's state: when it expires and, for a
// RESET code, which existing sensor_id it is authorized to reset. An empty
// sensorID marks a generic NEW-sensor code — usable only to enroll a
// not-yet-existing sensor, never to take over an existing (guessable) one.
type codeRecord struct {
	exp      time.Time
	sensorID string // "" = generic new-sensor code; non-empty = reset code bound to this sensor
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
		codes:       make(map[string]codeRecord),
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

// Generate mints a generic single-use NEW-sensor code and returns it with its
// expiry. A generic code can only enroll a not-yet-existing sensor_id; it can
// never reset an existing sensor (see ConsumeReset).
func (s *EnrollmentStore) Generate() (string, time.Time) {
	return s.generate("")
}

// GenerateForSensor mints a single-use RESET code bound to one existing
// sensor_id. Only that sensor can redeem it (ConsumeReset), so possession of an
// enrollment code can never be used to revoke/impersonate a different, guessable
// sensor_id (beta-gate B1a).
func (s *EnrollmentStore) GenerateForSensor(sensorID string) (string, time.Time) {
	return s.generate(strings.TrimSpace(sensorID))
}

func (s *EnrollmentStore) generate(sensorID string) (string, time.Time) {
	code := newEnrollmentCode()
	exp := s.now().Add(s.ttl)
	s.mu.Lock()
	s.sweepLocked()
	s.codes[code] = codeRecord{exp: exp, sensorID: sensorID}
	s.mu.Unlock()
	return code, exp
}

// ConsumeNewSensor validates and spends a code presented to enroll a BRAND-NEW
// sensor_id. A generic code — or a reset code minted for exactly this sensor_id —
// is accepted. Single-use: the code is spent only when accepted.
func (s *EnrollmentStore) ConsumeNewSensor(code, sensorID string) bool {
	return s.consume(code, sensorID, false)
}

// ConsumeReset validates and spends a code presented to RESET an EXISTING
// sensor. ONLY a reset code explicitly minted for this exact sensor_id is
// accepted — a generic new-sensor code is refused, so holding a generic code can
// never revoke or impersonate an existing (guessable) sensor_id. Single-use.
func (s *EnrollmentStore) ConsumeReset(code, sensorID string) bool {
	return s.consume(code, sensorID, true)
}

// consume is the shared validator. requireBound=true demands a reset code bound
// to sensorID; requireBound=false additionally accepts a generic code. A code is
// deleted (spent) ONLY when accepted, so a wrong-type or wrong-sensor
// presentation never burns a still-legitimate code.
func (s *EnrollmentStore) consume(code, sensorID string, requireBound bool) bool {
	code = normalizeCode(code)
	sensorID = strings.TrimSpace(sensorID)
	if code == "" || sensorID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.codes[code]
	if !ok {
		return false
	}
	if s.now().After(rec.exp) {
		delete(s.codes, code) // spent or not, an expired code is dead — clear it
		return false
	}
	switch {
	case rec.sensorID == sensorID:
		// bound to this sensor — valid for both new-enroll and reset
	case rec.sensorID == "" && !requireBound:
		// generic code — valid only for new-sensor enrollment
	default:
		// generic code presented for a reset, or a code bound to a DIFFERENT
		// sensor: refuse WITHOUT spending it, so it remains usable for its
		// intended purpose/sensor.
		return false
	}
	delete(s.codes, code) // single-use: spend only on success
	return true
}

func (s *EnrollmentStore) sweepLocked() {
	now := s.now()
	for c, rec := range s.codes {
		if now.After(rec.exp) {
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
//
// With no body (or an empty sensor_id) it mints a GENERIC new-sensor code. With
// {"sensor_id":"<existing sensor>"} it mints a RESET code BOUND to that sensor —
// the only way to re-enroll a stranded sensor whose Core token is still active,
// and which a generic code deliberately cannot do (beta-gate B1a).
func (s *Server) handleGenerateEnrollmentCode(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil {
		s.Enroll = NewEnrollmentStore()
	}

	type enrollmentCodeRequest struct {
		SensorID string `json:"sensor_id"`
	}
	body := &enrollmentCodeRequest{}
	if r.Body != nil {
		// The body is optional, but a present malformed body must never silently
		// downgrade a requested reset into a generic enrollment code.
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
		var decoded *enrollmentCodeRequest
		if err := decoder.Decode(&decoded); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		} else if err == nil {
			if decoded == nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "request body must be a JSON object"})
				return
			}
			body = decoded
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		} else if err == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "request body must contain one JSON object"})
			return
		}
	}
	sensorID := strings.TrimSpace(body.SensorID)

	if sensorID != "" {
		// Bind to any EXISTING sensor identity — whether its token is currently active
		// (stranded local copy) OR was revoked by an admin (deliberate reactivation).
		// Keying on row existence (not active-token state) is what lets an admin bring
		// a revoked sensor back on purpose, while still refusing generic re-enrollment
		// of that same id (beta-gate B1a). If the id never existed, it is a fresh
		// enrollment: the admin should mint a generic code instead.
		exists, err := s.DB.SensorExists(sensorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check sensor state"})
			return
		}
		if !exists {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "no sensor with that sensor_id exists to reset; omit sensor_id to mint a generic new-sensor code",
			})
			return
		}
		code, exp := s.Enroll.GenerateForSensor(sensorID)
		writeJSON(w, http.StatusCreated, map[string]any{
			"enrollment_code": code,
			"type":            "reset",
			"sensor_id":       sensorID,
			"expires_at":      exp.UTC().Format(time.RFC3339),
			"note":            "reset code BOUND to sensor " + sensorID + " — present it via --enroll-code to re-enroll that specific stranded sensor. Single use; expires soon.",
		})
		return
	}

	code, exp := s.Enroll.Generate()
	writeJSON(w, http.StatusCreated, map[string]any{
		"enrollment_code": code,
		"type":            "new_sensor",
		"expires_at":      exp.UTC().Format(time.RFC3339),
		"note":            "give this to a NEW sensor via --enroll-code (or VEDETTA_ENROLL_CODE). Single use; expires soon.",
	})
}
