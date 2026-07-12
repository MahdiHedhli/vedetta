package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type CollectionSourceHealth struct {
	SourceID    string     `json:"source_id"`
	SourceType  string     `json:"source_type"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"` // initializing | healthy | stale | error
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	ItemCount   int64      `json:"item_count"`
	Error       string     `json:"error,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// MarkCollectionAttempt records liveness without claiming collection success.
// Fetching adapters should call this before network or file I/O.
func (db *DB) MarkCollectionAttempt(ctx context.Context, sourceID, sourceType, displayName string, at time.Time) error {
	at = healthTime(at)
	_, err := db.ExecContext(ctx, `
		INSERT INTO collection_source_health
			(source_id, source_type, display_name, status, last_attempt, last_success, item_count, error, updated_at)
		VALUES (?, ?, ?, 'initializing', ?, NULL, 0, '', ?)
		ON CONFLICT(source_id) DO UPDATE SET
			source_type = excluded.source_type, display_name = excluded.display_name,
			last_attempt = excluded.last_attempt,
			status = CASE WHEN collection_source_health.last_success IS NULL THEN 'initializing' ELSE collection_source_health.status END,
			updated_at = excluded.updated_at`,
		strings.TrimSpace(sourceID), strings.TrimSpace(sourceType), strings.TrimSpace(displayName), at, at)
	if err != nil {
		return fmt.Errorf("mark collection attempt: %w", err)
	}
	return nil
}

func (db *DB) MarkCollectionSuccess(ctx context.Context, sourceID, sourceType, displayName string, itemCount int64, at time.Time) error {
	at = healthTime(at)
	if itemCount < 0 {
		itemCount = 0
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO collection_source_health
			(source_id, source_type, display_name, status, last_attempt, last_success, item_count, error, updated_at)
		VALUES (?, ?, ?, 'healthy', ?, ?, ?, '', ?)
		ON CONFLICT(source_id) DO UPDATE SET
			source_type = excluded.source_type, display_name = excluded.display_name,
			status = 'healthy', last_attempt = excluded.last_attempt,
			last_success = excluded.last_success, item_count = excluded.item_count,
			error = '', updated_at = excluded.updated_at`,
		strings.TrimSpace(sourceID), strings.TrimSpace(sourceType), strings.TrimSpace(displayName), at, at, itemCount, at)
	if err != nil {
		return fmt.Errorf("mark collection success: %w", err)
	}
	return nil
}

func (db *DB) MarkCollectionError(ctx context.Context, sourceID, sourceType, displayName, errorText string, at time.Time) error {
	at = healthTime(at)
	_, err := db.ExecContext(ctx, `
		INSERT INTO collection_source_health
			(source_id, source_type, display_name, status, last_attempt, last_success, item_count, error, updated_at)
		VALUES (?, ?, ?, 'error', ?, NULL, 0, ?, ?)
		ON CONFLICT(source_id) DO UPDATE SET
			source_type = excluded.source_type, display_name = excluded.display_name,
			status = 'error', last_attempt = excluded.last_attempt,
			error = excluded.error, updated_at = excluded.updated_at`,
		strings.TrimSpace(sourceID), strings.TrimSpace(sourceType), strings.TrimSpace(displayName), at, strings.TrimSpace(errorText), at)
	if err != nil {
		return fmt.Errorf("mark collection error: %w", err)
	}
	return nil
}

// ListCollectionSourceHealth derives stale at read time without erasing the
// last fetch result. A zero staleAfter disables that derived state.
func (db *DB) ListCollectionSourceHealth(ctx context.Context, staleAfter time.Duration) ([]CollectionSourceHealth, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT source_id, source_type, display_name, status, last_attempt,
		       last_success, item_count, error, updated_at
		FROM collection_source_health ORDER BY display_name, source_id`)
	if err != nil {
		return nil, fmt.Errorf("list collection source health: %w", err)
	}
	defer rows.Close()
	now := time.Now().UTC()
	out := []CollectionSourceHealth{}
	for rows.Next() {
		var health CollectionSourceHealth
		var attempt, success sql.NullTime
		if err := rows.Scan(&health.SourceID, &health.SourceType, &health.DisplayName,
			&health.Status, &attempt, &success, &health.ItemCount, &health.Error,
			&health.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan collection source health: %w", err)
		}
		if attempt.Valid {
			t := attempt.Time
			health.LastAttempt = &t
		}
		if success.Valid {
			t := success.Time
			health.LastSuccess = &t
			if staleAfter > 0 && health.Status != "error" && now.Sub(t) > staleAfter {
				health.Status = "stale"
			}
		}
		out = append(out, health)
	}
	return out, rows.Err()
}

func healthTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}
