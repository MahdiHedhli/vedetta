package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// TokenScope defines what a token can access.
type TokenScope string

const (
	ScopeSensor TokenScope = "sensor"
	ScopeAdmin  TokenScope = "admin"
	// ScopeIngest authorizes pushing events to POST /api/v1/ingest (spec 001,
	// FR-8). /ingest uses the standard bootstrap-bypass auth: open only while NO
	// tokens exist, and requiring a valid ingest (or admin) token as soon as any
	// token exists. The collector's token is provisioned from the shared
	// VEDETTA_INGEST_TOKEN secret (see store.EnsureTokenFromRaw). The old
	// VEDETTA_REQUIRE_INGEST_AUTH toggle was removed.
	ScopeIngest TokenScope = "ingest"
	// ScopeRead authorizes read-only access to the dashboard/query endpoints
	// (GET events, devices, status, and similar) so an operator can mint a
	// least-privilege token for a viewer, a status probe, or a script that must
	// never mutate state or reach admin routes (beta-gate B6). A read token
	// satisfies read-gated routes ONLY; admin implies read (see ScopeSatisfies).
	ScopeRead TokenScope = "read"
)

// ScopeSatisfies reports whether a token carrying scope `have` is permitted to
// access a route that requires scope `need`. It encodes the scope hierarchy in
// one place so middleware stays consistent:
//
//   - ScopeAdmin is a superuser and satisfies EVERY required scope (so the
//     existing dashboard/admin token keeps working on read-gated routes).
//   - Otherwise a scope only satisfies itself (exact match). In particular a
//     ScopeRead token satisfies ScopeRead but never ScopeAdmin, and sensor /
//     ingest machine tokens do not gain read access to the dashboard.
func ScopeSatisfies(have, need TokenScope) bool {
	if have == ScopeAdmin {
		return true
	}
	return have == need
}

// Token represents an API authentication token.
type Token struct {
	TokenID   string     `json:"token_id" db:"token_id"`
	TokenHash string     `json:"-" db:"token_hash"` // SHA-256 of the raw token
	Scope     TokenScope `json:"scope" db:"scope"`
	SensorID  string     `json:"sensor_id,omitempty" db:"sensor_id"`
	Label     string     `json:"label" db:"label"` // human-readable label
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	LastUsed  time.Time  `json:"last_used" db:"last_used"`
	Revoked   bool       `json:"revoked" db:"revoked"`
}

// GenerateToken creates a new random API token and returns the unhashed token string
// and the Token structure with hashed value for storage.
func GenerateToken(scope TokenScope, sensorID, label string) (rawToken string, token Token, err error) {
	// Generate 32 random bytes, hex-encoded = 64 character token string
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", Token{}, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	rawToken = hex.EncodeToString(randomBytes)

	// Generate token ID (also random, shorter)
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", Token{}, fmt.Errorf("failed to generate token ID: %w", err)
	}
	tokenID := hex.EncodeToString(tokenIDBytes)

	now := time.Now().UTC()
	token = Token{
		TokenID:   tokenID,
		TokenHash: HashToken(rawToken),
		Scope:     scope,
		SensorID:  sensorID,
		Label:     label,
		CreatedAt: now,
		LastUsed:  now,
		Revoked:   false,
	}

	return rawToken, token, nil
}

// TokenFromRaw builds a Token for a KNOWN raw token value (rather than a fresh
// random one). Used to provision a credential from an operator-supplied secret,
// e.g. the VEDETTA_INGEST_TOKEN shared between Core and the collector.
func TokenFromRaw(rawToken string, scope TokenScope, sensorID, label string) (Token, error) {
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return Token{}, fmt.Errorf("failed to generate token ID: %w", err)
	}
	now := time.Now().UTC()
	return Token{
		TokenID:   hex.EncodeToString(tokenIDBytes),
		TokenHash: HashToken(rawToken),
		Scope:     scope,
		SensorID:  sensorID,
		Label:     label,
		CreatedAt: now,
		LastUsed:  now,
		Revoked:   false,
	}, nil
}

// HashToken returns the SHA-256 hash of a raw token string in hex format.
func HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}
