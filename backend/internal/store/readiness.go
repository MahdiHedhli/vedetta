package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ExpectedSchemaMigration is the id (filename) of the latest migration this binary
// ships. store.Open brings every database to exactly this head: the file-migration
// path records each applied migration in schema_migrations, and the inline fallback
// stamps this same id after building the current schema (see applyInlineFallback).
//
// The readiness probe (GET /readyz) treats any database whose recorded head differs
// from this value as NOT ready — a behind, half-applied, or volume-swapped database
// must never read healthy. Bump this in lockstep whenever a new migration file is
// added AND the inline schema is brought to parity; the guard test
// TestExpectedSchemaMigrationMatchesLatestFile fails loudly if the two drift.
const ExpectedSchemaMigration = "030_arp_cache_states.sql"

// VerifyReadable runs a trivial query on a pooled connection so a database that is
// open but cannot actually serve reads (locked, corrupt header, or vanished under a
// volume swap) surfaces as an error. It is intentionally cheaper than any PRAGMA and
// is safe to run on every readiness probe.
func (db *DB) VerifyReadable(ctx context.Context) error {
	var one int
	return db.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
}

// SchemaHead returns the id of the most recently applied migration recorded in
// schema_migrations — its lexicographic MAX, which is chronological because migration
// ids are zero-padded (001_, 002_, …). It returns "" when nothing has been recorded.
// Cheap enough to run on every readiness probe.
func (db *DB) SchemaHead(ctx context.Context) (string, error) {
	var head sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT MAX(id) FROM schema_migrations`).Scan(&head); err != nil {
		return "", err
	}
	return head.String, nil
}

// ForeignKeyViolations runs PRAGMA foreign_key_check on the pool and returns a short
// description of each orphaned/dangling row. An empty slice means the referential
// graph is intact. Pooled connections carry foreign_keys=ON (set on the DSN), so this
// reports real violations rather than being silently disabled. Moderately expensive
// on a large database — callers must cache it off the probe hot path.
func (db *DB) ForeignKeyViolations(ctx context.Context) (violations []string, retErr error) {
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return nil, fmt.Errorf("foreign_key_check: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close foreign_key_check rows: %w", err))
		}
	}()
	return scanForeignKeyViolations(rows)
}

// IntegrityCheck runs PRAGMA integrity_check and reports whether the database is
// structurally sound. ok is true only when SQLite returns the single row "ok";
// otherwise detail carries the reported problems. This is a full scan and can be slow
// on a large database, so callers MUST run it off the probe hot path (cached) and
// never on every healthcheck.
func (db *DB) IntegrityCheck(ctx context.Context) (ok bool, detail string, retErr error) {
	rows, err := db.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return false, "", fmt.Errorf("integrity_check: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close integrity_check rows: %w", err))
		}
	}()

	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return false, "", fmt.Errorf("scan integrity_check: %w", err)
		}
		problems = append(problems, line)
	}
	if err := rows.Err(); err != nil {
		return false, "", fmt.Errorf("integrity_check rows: %w", err)
	}
	if len(problems) == 1 && problems[0] == "ok" {
		return true, "ok", nil
	}
	return false, strings.Join(problems, "; "), nil
}

// scanForeignKeyViolations reads the rows of a PRAGMA foreign_key_check result set
// (table, rowid, parent, fkid) into human-readable descriptions. Shared by the
// migration-time check (on a reserved connection) and the runtime readiness check
// (on the pool) so both format violations identically.
func scanForeignKeyViolations(rows *sql.Rows) (violations []string, retErr error) {
	for rows.Next() {
		var table, parent sql.NullString
		var rowid, fkID sql.NullInt64
		if err := rows.Scan(&table, &rowid, &parent, &fkID); err != nil {
			return nil, fmt.Errorf("scan foreign_key_check: %w", err)
		}
		violations = append(violations,
			fmt.Sprintf("%s(rowid=%d)->%s", table.String, rowid.Int64, parent.String))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("foreign_key_check rows: %w", err)
	}
	return violations, nil
}
