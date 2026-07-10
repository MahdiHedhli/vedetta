package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/valid"
)

// Reporter is an opted-in deployment credential. No operator identity is ever
// stored: only a random id, a hash of the issued secret, and coarse metadata.
type Reporter struct {
	ReporterID     string
	SecretHash     string
	Capabilities   string // JSON array
	VedettaVersion string
	CreatedAt      string
	LastSeenAt     sql.NullString
	Status         string // "active" | "denylisted"
	DenylistReason sql.NullString
}

// ErrReporterNotFound is returned when a reporter_id is unknown.
var ErrReporterNotFound = errors.New("reporter not found")

// CreateReporter inserts a new reporter row. secretHash is SHA-256(secret); the
// raw secret is never persisted.
func (db *DB) CreateReporter(id, secretHash, capabilitiesJSON, vedettaVersion string) error {
	// Defense in depth for the pinned wire format (GHSA-hx86): reject a
	// non-semver vedetta_version even if a caller bypasses auth.ValidateRegister.
	if !valid.Semver(vedettaVersion) {
		return fmt.Errorf("vedetta_version %q is not strict semver", vedettaVersion)
	}
	_, err := db.Exec(`INSERT INTO reporters
        (reporter_id, secret_hash, capabilities, vedetta_version, created_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')`,
		id, secretHash, capabilitiesJSON, vedettaVersion, nowRFC3339())
	return err
}

// GetReporter looks up a reporter by id.
func (db *DB) GetReporter(id string) (*Reporter, error) {
	row := db.QueryRow(`SELECT reporter_id, secret_hash, capabilities, vedetta_version,
        created_at, last_seen_at, status, denylist_reason FROM reporters WHERE reporter_id = ?`, id)
	var r Reporter
	var version sql.NullString
	if err := row.Scan(&r.ReporterID, &r.SecretHash, &r.Capabilities, &version,
		&r.CreatedAt, &r.LastSeenAt, &r.Status, &r.DenylistReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrReporterNotFound
		}
		return nil, err
	}
	if version.Valid {
		r.VedettaVersion = version.String
	}
	return &r, nil
}

// TouchReporter updates last_seen_at to now.
func (db *DB) TouchReporter(id string) error {
	_, err := db.Exec(`UPDATE reporters SET last_seen_at = ? WHERE reporter_id = ?`,
		nowRFC3339(), id)
	return err
}

// DenylistReporter marks a reporter denylisted with a reason.
func (db *DB) DenylistReporter(id, reason string) error {
	res, err := db.Exec(`UPDATE reporters SET status = 'denylisted', denylist_reason = ?
        WHERE reporter_id = ?`, reason, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrReporterNotFound
	}
	return nil
}

// ReinstateReporter clears a denylist flag.
func (db *DB) ReinstateReporter(id string) error {
	res, err := db.Exec(`UPDATE reporters SET status = 'active', denylist_reason = NULL
        WHERE reporter_id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrReporterNotFound
	}
	return nil
}

// DenylistedReporterIDs returns the set of currently denylisted reporter ids,
// used to exclude their signals from consensus.
func (db *DB) DenylistedReporterIDs() (map[string]bool, error) {
	rows, err := db.Query(`SELECT reporter_id FROM reporters WHERE status = 'denylisted'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// MatureReporterIDs returns the set of reporter ids whose created_at is at or
// before asOf (i.e. registered at least a maturation delay in the past). Consensus
// uses this to exclude freshly-minted reporter_ids from counting toward promotion
// distinctness thresholds — a Sybil defense: an attacker cannot register N
// reporter_ids and immediately promote an indicator, since new ids do not count
// until they have aged. created_at is stored as RFC3339; string comparison is a
// correct ordering for that format.
func (db *DB) MatureReporterIDs(asOf time.Time) (map[string]bool, error) {
	cutoff := asOf.UTC().Format(time.RFC3339)
	rows, err := db.Query(`SELECT reporter_id FROM reporters
        WHERE status = 'active' AND created_at <= ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// InsertNonceIfAbsent records a (reporter_id, nonce) pair. It returns false if
// the nonce was already seen for that reporter (replay), true if newly recorded.
func (db *DB) InsertNonceIfAbsent(reporterID, nonce string) (bool, error) {
	res, err := db.Exec(`INSERT OR IGNORE INTO nonces (reporter_id, nonce, seen_at)
        VALUES (?, ?, ?)`, reporterID, nonce, nowRFC3339())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// PurgeNonces deletes nonces older than the cutoff.
func (db *DB) PurgeNonces(olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM nonces WHERE seen_at < ?`,
		olderThan.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
