package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// CreateToken inserts a non-sensor API token into the database. Sensor
// credentials are security state tied to an identity lifecycle and may only be
// installed atomically through ProvisionSensorToken; allowing this generic path
// would let a tombstoned identity authenticate without being reactivated.
func (db *DB) CreateToken(token auth.Token) error {
	if token.Scope == auth.ScopeSensor {
		return fmt.Errorf("sensor-scoped tokens must be issued through sensor enrollment")
	}
	if strings.TrimSpace(token.SensorID) != "" {
		return fmt.Errorf("non-sensor tokens may not carry a sensor_id")
	}
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

// HasActiveIngestToken returns true when at least one non-revoked ingest-scoped
// token exists. Used to decide whether ingest auth enforcement is possible
// (spec 001, FR-8).
func (db *DB) HasActiveIngestToken() (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM api_tokens
		WHERE scope = ? AND revoked = 0
	`, auth.ScopeIngest).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HasActiveReadToken returns true when at least one non-revoked read-scoped
// token exists. Used by the health/status machine-credential surface (issue #34)
// so operators can confirm the telemetry reader's VEDETTA_CORE_TOKEN was
// provisioned and did not collide with the ingest token.
func (db *DB) HasActiveReadToken() (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM api_tokens
		WHERE scope = ? AND revoked = 0
	`, auth.ScopeRead).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HasActiveAdminToken returns true when at least one non-revoked admin-scoped
// token exists. This is the correct signal for "admin enrollment is complete":
// bootstrap gates must key on the existence of an ACTIVE ADMIN, not on the total
// token count — otherwise an auto-issued sensor/ingest token (or a leftover
// revoked row) permanently closes the first-admin creation window and locks the
// operator out (beta-gate B1b).
func (db *DB) HasActiveAdminToken() (bool, error) {
	n, err := db.CountActiveAdminTokens()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountActiveAdminTokens returns the number of non-revoked admin-scoped tokens.
// Used both for the bootstrap gate and to refuse revoking the last admin.
func (db *DB) CountActiveAdminTokens() (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM api_tokens
		WHERE scope = ? AND revoked = 0
	`, auth.ScopeAdmin).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetTokenByID retrieves a single token by its id (without the raw value).
func (db *DB) GetTokenByID(tokenID string) (*auth.Token, error) {
	return scanAuthToken(db.QueryRow(`
		SELECT token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked
		FROM api_tokens
		WHERE token_id = ?
	`, tokenID))
}

// EnsureTokenFromRaw provisions a token for a KNOWN raw value if one is not
// already present (matched by hash). Idempotent — safe to call on every startup.
// Used to register the collector's ingest credential from the shared
// VEDETTA_INGEST_TOKEN secret so /ingest keeps authenticating once auth turns on.
// Returns true when a new token was created.
func (db *DB) EnsureTokenFromRaw(rawToken string, scope auth.TokenScope, label string) (bool, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return false, nil
	}
	if _, err := db.GetTokenByHash(auth.HashToken(rawToken)); err == nil {
		return false, nil // already provisioned
	}
	tok, err := auth.TokenFromRaw(rawToken, scope, "", label)
	if err != nil {
		return false, err
	}
	if err := db.CreateToken(tok); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteTokensBySensor revokes only sensor credentials associated with a
// sensor. Legacy or manually-corrupted non-sensor rows carrying sensor_id must
// never make this helper revoke an admin/read/ingest credential.
func (db *DB) DeleteTokensBySensor(sensorID string) error {
	_, err := db.Exec(`UPDATE api_tokens SET revoked = 1 WHERE sensor_id = ? AND scope = ?`, sensorID, auth.ScopeSensor)
	return err
}

// ErrSensorExists is returned by ProvisionSensorToken for a NEW enrollment whose
// sensor_id identity already exists (active or revoked). A generic new-sensor
// code must not claim or reactivate an existing identity — that would defeat an
// admin revocation (beta-gate B1a).
var ErrSensorExists = errors.New("sensor identity already exists")

// ErrSensorNotFound is returned by ProvisionSensorToken for a RESET whose
// sensor_id identity does not exist. There is nothing to reset/reactivate.
var ErrSensorNotFound = errors.New("sensor identity does not exist")

// ProvisionSensorToken atomically issues a sensor's single active bearer token.
// In ONE transaction it enforces the new-vs-reset precondition on the sensor
// IDENTITY (row existence) and installs exactly one active token:
//   - isReset=false (NEW): the identity MUST NOT already exist (ErrSensorExists
//     otherwise). A plain INSERT is used, so a concurrently-created identity also
//     conflicts — a generic code can never overwrite or reactivate an existing id.
//   - isReset=true (RESET/REACTIVATION): the identity MUST exist (ErrSensorNotFound
//     otherwise). Existing active tokens are revoked and the row is upserted.
//
// The partial unique index ux_api_tokens_active_sensor (migration 024) is the
// backstop guaranteeing at most one active sensor token per sensor_id even under
// racing resets. ANY failure rolls the whole thing back, so a caller that
// receives nil can trust exactly one fresh token is active and no partial state
// leaked.
func (db *DB) ProvisionSensorToken(sensor models.Sensor, token auth.Token, isReset bool) error {
	return db.ProvisionSensorTokenWithActor(sensor, token, isReset, "")
}

// ProvisionSensorTokenWithActor is ProvisionSensorToken plus the authenticated
// actor recorded when a reset deliberately reactivates a removed identity.
func (db *DB) ProvisionSensorTokenWithActor(sensor models.Sensor, token auth.Token, isReset bool, actor string) error {
	if token.Scope != auth.ScopeSensor || strings.TrimSpace(token.SensorID) != sensor.SensorID {
		return fmt.Errorf("provisioned token must be sensor-scoped and bound to sensor_id")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after a successful Commit

	// Enforce the identity precondition INSIDE the tx so it cannot be raced apart
	// from the token install (beta-gate B1a). A reset begins with a no-op UPDATE,
	// making this the transaction's first write and ordering it against removal.
	wasRemoved := false
	if isReset {
		result, err := tx.Exec(`UPDATE sensors SET sensor_id = sensor_id WHERE sensor_id = ?`, sensor.SensorID)
		if err != nil {
			return fmt.Errorf("lock sensor identity for reset: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect reset identity lock: %w", err)
		}
		if rows == 0 {
			return ErrSensorNotFound
		}
		if err := tx.QueryRow(`SELECT removed_at IS NOT NULL FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&wasRemoved); err != nil {
			return fmt.Errorf("check sensor removal state: %w", err)
		}
	} else {
		// Acquire the SQLite writer lock before reading identity state. Without a
		// first write, two distinct enrollments can both consume their single-use
		// codes and one later fail with BUSY_SNAPSHOT when it tries to insert.
		if _, err := tx.Exec(`UPDATE sensors SET sensor_id = sensor_id WHERE 0`); err != nil {
			return fmt.Errorf("lock sensor identities for enrollment: %w", err)
		}
		var rows int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&rows); err != nil {
			return fmt.Errorf("check sensor identity: %w", err)
		}
		if rows > 0 {
			return ErrSensorExists
		}
	}

	if isReset {
		if _, err := tx.Exec(
			`UPDATE api_tokens SET revoked = 1 WHERE sensor_id = ? AND scope = ? AND revoked = 0`,
			sensor.SensorID, auth.ScopeSensor,
		); err != nil {
			return fmt.Errorf("revoke existing sensor tokens: %w", err)
		}
	}

	// upsert only on reset; a NEW enrollment uses a plain INSERT so a racing
	// creation of the same identity conflicts instead of silently overwriting it.
	if err := registerSensorOn(tx, sensor, isReset, isReset); err != nil {
		return fmt.Errorf("write sensor row: %w", err)
	}

	var sensorID any
	if strings.TrimSpace(token.SensorID) != "" {
		sensorID = token.SensorID
	}
	if _, err := tx.Exec(`
		INSERT INTO api_tokens (token_id, token_hash, scope, sensor_id, label, created_at, last_used, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, token.TokenID, token.TokenHash, token.Scope, sensorID, token.Label, token.CreatedAt, token.LastUsed); err != nil {
		return fmt.Errorf("insert sensor token (another active token may already exist for this sensor): %w", err)
	}
	if wasRemoved {
		if strings.TrimSpace(actor) == "" {
			actor = "reset"
		}
		if err := insertSensorLifecycleOn(tx, sensor.SensorID, "reactivated", actor, "", time.Now().UTC()); err != nil {
			return fmt.Errorf("record sensor reactivation: %w", err)
		}
	}

	return tx.Commit()
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
