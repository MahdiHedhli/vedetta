package store

import (
	"database/sql"
	"time"
)

// GetSetting reads a persisted setting by key. The bool return is false (with a
// nil error) when no row exists for the key, so callers can distinguish "not
// set" from a stored empty value — the telemetry effective-value rule (a
// persisted setting wins over env) depends on that distinction.
func (db *DB) GetSetting(key string) (value string, found bool, err error) {
	err = db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting upserts a persisted setting. Idempotent per key: an existing row is
// overwritten and its updated_at bumped.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now().UTC())
	return err
}
