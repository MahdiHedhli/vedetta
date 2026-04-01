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
)

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

// HashToken returns the SHA-256 hash of a raw token string in hex format.
func HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}
