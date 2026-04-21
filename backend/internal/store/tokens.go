package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// CreateToken inserts a new API token into the database.
func (db *DB) CreateToken(token auth.Token) error {
	var sensorID any
	if strings.TrimSpace(token.SensorID) != "" {
		sensorID = token.SensorID
	}

	_, err := db.Exec(`
		INSERT INTO api_tokens (token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, token.TokenID, token.TokenHash, token.Scope, sensorID, token.Label, token.CreatedAt, token.LastUsed, false)

	return err
}

// GetTokenByHash retrieves a token by its SHA-256 hash.
func (db *DB) GetTokenByHash(hash string) (*auth.Token, error) {
	token, err := scanAuthToken(db.QueryRow(`
		SELECT token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked
		FROM api_tokens
		WHERE token_hash = ?
	`, hash))
	if err != nil {
		return nil, err
	}

	return token, nil
}

// ValidateToken looks up a raw token, checks it's not revoked, updates last_used, and returns the token.
func (db *DB) ValidateToken(rawToken string) (*auth.Token, error) {
	hash := auth.HashToken(rawToken)

	// Get the token
	token, err := db.GetTokenByHash(hash)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}

	// Check if revoked
	if token.Revoked {
		return nil, fmt.Errorf("token is revoked")
	}

	// Update last_used (async, ignore errors)
	_ = db.TouchToken(token.TokenID)

	return token, nil
}

// TouchToken updates the last_used timestamp for a token.
func (db *DB) TouchToken(tokenID string) error {
	_, err := db.Exec(`UPDATE api_tokens SET last_used = ? WHERE token_id = ?`,
		time.Now().UTC(), tokenID)
	return err
}

// RevokeToken marks a token as revoked.
func (db *DB) RevokeToken(tokenID string) error {
	result, err := db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE token_id = ?`, tokenID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

// ListTokens returns all tokens (without raw token values).
func (db *DB) ListTokens() ([]auth.Token, error) {
	rows, err := db.Query(`
		SELECT token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked
		FROM api_tokens
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []auth.Token
	for rows.Next() {
		token, err := scanAuthToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, *token)
	}

	return tokens, rows.Err()
}

// CountTokens returns the total number of tokens in the database.
func (db *DB) CountTokens() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM api_tokens").Scan(&count)
	return count, err
}

// HasActiveSensorToken returns true when a non-revoked sensor token already exists for the sensor.
func (db *DB) HasActiveSensorToken(sensorID string) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM api_tokens
		WHERE sensor_id = ? AND scope = ? AND revoked = 0
	`, sensorID, auth.ScopeSensor).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeleteTokensBySensor revokes all tokens associated with a sensor.
func (db *DB) DeleteTokensBySensor(sensorID string) error {
	_, err := db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE sensor_id = ?`, sensorID)
	return err
}

type tokenScanner interface {
	Scan(dest ...any) error
}

func scanAuthToken(scanner tokenScanner) (*auth.Token, error) {
	var token auth.Token
	var sensorID sql.NullString
	var createdAtRaw any
	var lastUsedRaw any
	if err := scanner.Scan(&token.TokenID, &token.TokenHash, &token.Scope, &sensorID, &token.Label, &createdAtRaw, &lastUsedRaw, &token.Revoked); err != nil {
		return nil, err
	}
	token.SensorID = sensorID.String

	createdAt, err := parseSQLiteTime(createdAtRaw)
	if err != nil {
		return nil, fmt.Errorf("parse token created_at: %w", err)
	}
	lastUsed, err := parseSQLiteTime(lastUsedRaw)
	if err != nil {
		return nil, fmt.Errorf("parse token last_used: %w", err)
	}
	token.CreatedAt = createdAt
	token.LastUsed = lastUsed

	return &token, nil
}

func parseSQLiteTime(raw any) (time.Time, error) {
	switch value := raw.(type) {
	case time.Time:
		return value.UTC(), nil
	case string:
		return parseSQLiteTimeString(value)
	case []byte:
		return parseSQLiteTimeString(string(value))
	default:
		return time.Time{}, fmt.Errorf("unsupported SQLite time type %T", raw)
	}
}

func parseSQLiteTimeString(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported SQLite time value %q", value)
}
