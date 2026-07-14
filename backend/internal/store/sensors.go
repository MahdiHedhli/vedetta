package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// execQuerier is satisfied by both *DB (via the embedded *sql.DB) and *sql.Tx,
// so sensor upsert logic can run either standalone or inside a transaction
// (e.g. ProvisionSensorToken's atomic revoke+upsert+mint).
type execQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// RegisterSensor creates or updates a sensor record (upsert).
// If this is the first sensor ever registered, it becomes the primary.
func (db *DB) RegisterSensor(sensor models.Sensor) error {
	return registerSensorOn(db, sensor, true, false)
}

// SensorExists reports whether a sensor row exists for this id, REGARDLESS of
// whether it currently has an active token. This is the identity check that
// governs new-vs-reset enrollment: a generic code may enroll only a never-seen
// id, while any existing id — active OR revoked — requires an admin-minted bound
// reset code, so an admin revocation cannot be silently undone by a generic code
// (beta-gate B1a).
func (db *DB) SensorExists(sensorID string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id = ?`, sensorID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// SensorActive reports whether a retained sensor identity is currently active.
// It deliberately distinguishes a never-seen identity from a tombstone at the
// call sites that need that distinction; both return false here.
func (db *DB) SensorActive(sensorID string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id = ? AND removed_at IS NULL`, sensorID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// registerSensorOn writes the sensor row (and primary-promotion) against any
// execQuerier, so it composes into a larger transaction without duplicating SQL.
// When upsert is true an existing row is updated; when false a plain INSERT is
// used so a pre-existing identity causes a primary-key conflict — that is how a
// NEW enrollment atomically refuses to overwrite/reactivate an existing sensor.
func registerSensorOn(q execQuerier, sensor models.Sensor, upsert, reactivate bool) error {
	now := time.Now().UTC()

	// Auto-promote to primary if: no sensors exist yet, or no primary is set, or flag requested
	var count int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sensors WHERE removed_at IS NULL`).Scan(&count); err != nil {
		return err
	}
	var primaryCount int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sensors WHERE is_primary = TRUE AND removed_at IS NULL`).Scan(&primaryCount); err != nil {
		return err
	}
	makePrimary := count == 0 || primaryCount == 0 || sensor.IsPrimary

	insertSQL := `
		INSERT INTO sensors (sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)`
	if upsert {
		insertSQL += `
		ON CONFLICT(sensor_id) DO UPDATE SET
			hostname = excluded.hostname,
			os = excluded.os,
			arch = excluded.arch,
			cidr = excluded.cidr,
			version = excluded.version,
			last_seen = excluded.last_seen,
			status = 'online',
			interfaces = excluded.interfaces`
		if reactivate {
			insertSQL += `,
			removed_at = NULL,
			removed_by_token_id = NULL,
			removal_reason = ''`
		} else {
			// Ordinary registration may update an active identity, but it may not
			// resurrect a tombstone. Reactivation is reserved for an authenticated
			// reset in ProvisionSensorTokenWithActor.
			insertSQL += ` WHERE sensors.removed_at IS NULL`
		}
	}

	result, err := q.Exec(insertSQL, sensor.SensorID, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version, now, now, makePrimary, sensor.Interfaces)
	if err != nil {
		return err
	}
	if upsert && !reactivate {
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrSensorRemoved
		}
	}

	// If this sensor should be primary, promote it and demote all other active
	// sensors in one statement. The conflict-update path intentionally does not
	// copy excluded.is_primary, so this explicit promotion is required when a
	// reset reactivates an existing non-primary identity with --primary.
	if makePrimary {
		if _, err := q.Exec(`
			UPDATE sensors
			SET is_primary = CASE WHEN sensor_id = ? THEN TRUE ELSE FALSE END
			WHERE removed_at IS NULL
		`, sensor.SensorID); err != nil {
			return err
		}
	}

	return nil
}

// RefreshSensorWithActiveToken updates metadata only when both the sensor row
// and the exact sensor credential are still active. The conditional UPDATE is
// the transaction's first write, so it serializes cleanly against removal: a
// request authenticated just before an admin removal cannot resurrect the row.
func (db *DB) RefreshSensorWithActiveToken(sensor models.Sensor, tokenID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.Exec(`
		UPDATE sensors
		SET hostname = ?, os = ?, arch = ?, cidr = ?, version = ?,
			last_seen = ?, status = 'online', interfaces = ?
		WHERE sensor_id = ? AND removed_at IS NULL
		  AND EXISTS (
			SELECT 1 FROM api_tokens
			WHERE token_id = ? AND sensor_id = ? AND scope = ? AND revoked = 0
		  )
	`, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version,
		now, sensor.Interfaces, sensor.SensorID, tokenID, sensor.SensorID, auth.ScopeSensor)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var removed sql.NullTime
		if err := tx.QueryRow(`SELECT removed_at FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&removed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSensorNotFound
			}
			return err
		}
		if removed.Valid {
			return ErrSensorRemoved
		}
		return ErrSensorTokenInactive
	}

	// Preserve the sensor's --primary contract and repair a legacy/corrupt fleet
	// with no active primary. The credential-checked UPDATE above is the
	// transaction's first write, so no removal or competing promotion can slip
	// between this decision and the single-statement election.
	promote := sensor.IsPrimary
	if !promote {
		var primaryCount int
		if err := tx.QueryRow(`
			SELECT COUNT(*) FROM sensors
			WHERE removed_at IS NULL AND is_primary = TRUE
		`).Scan(&primaryCount); err != nil {
			return err
		}
		promote = primaryCount == 0
	}
	if promote {
		if _, err := tx.Exec(`
			UPDATE sensors
			SET is_primary = CASE WHEN sensor_id = ? THEN TRUE ELSE FALSE END
			WHERE removed_at IS NULL
		`, sensor.SensorID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TouchSensor updates the last_seen timestamp for a sensor.
func (db *DB) TouchSensor(sensorID string) error {
	_, err := db.Exec(`UPDATE sensors SET last_seen = ?, status = 'online' WHERE sensor_id = ? AND removed_at IS NULL`,
		time.Now().UTC(), sensorID)
	return err
}

// ListSensors returns all registered sensors, primary first, then by last_seen.
func (db *DB) ListSensors() ([]models.Sensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE removed_at IS NULL
		ORDER BY is_primary DESC, last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []models.Sensor
	for rows.Next() {
		var s models.Sensor
		if err := rows.Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces); err != nil {
			return nil, err
		}
		sensors = append(sensors, s)
	}

	return sensors, rows.Err()
}

// ListRemovedSensors returns retained sensor tombstones newest-first. It
// intentionally exposes only operator-safe lifecycle state; actor token IDs and
// raw audit details stay in the database.
func (db *DB) ListRemovedSensors() ([]models.RemovedSensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version,
			first_seen, last_seen, status, is_primary, interfaces,
			removed_at, removal_reason
		FROM sensors
		WHERE removed_at IS NOT NULL
		ORDER BY removed_at DESC, sensor_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []models.RemovedSensor
	for rows.Next() {
		var s models.RemovedSensor
		if err := rows.Scan(
			&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version,
			&s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces,
			&s.RemovedAt, &s.RemovalReason,
		); err != nil {
			return nil, err
		}
		sensors = append(sensors, s)
	}
	return sensors, rows.Err()
}

// ListSensorPartitions returns the active and removed dashboard partitions from
// one SQLite statement, so a concurrent removal/reactivation cannot make one
// response contain the same sensor in both arrays (or neither).
func (db *DB) ListSensorPartitions() ([]models.Sensor, []models.RemovedSensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version,
			first_seen, last_seen, status, is_primary, interfaces,
			removed_at, removal_reason
		FROM sensors
		ORDER BY
			CASE WHEN removed_at IS NULL THEN 0 ELSE 1 END,
			is_primary DESC,
			CASE WHEN removed_at IS NULL THEN last_seen END DESC,
			removed_at DESC,
			sensor_id ASC
	`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var active []models.Sensor
	var removed []models.RemovedSensor
	for rows.Next() {
		var sensor models.Sensor
		var removedAt sql.NullTime
		var removalReason string
		if err := rows.Scan(
			&sensor.SensorID, &sensor.Hostname, &sensor.OS, &sensor.Arch, &sensor.CIDR, &sensor.Version,
			&sensor.FirstSeen, &sensor.LastSeen, &sensor.Status, &sensor.IsPrimary, &sensor.Interfaces,
			&removedAt, &removalReason,
		); err != nil {
			return nil, nil, err
		}
		if removedAt.Valid {
			removed = append(removed, models.RemovedSensor{
				Sensor:        sensor,
				RemovedAt:     removedAt.Time.UTC(),
				RemovalReason: removalReason,
			})
		} else {
			active = append(active, sensor)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return active, removed, nil
}

// GetPrimarySensor returns the sensor marked as primary, or nil if none.
func (db *DB) GetPrimarySensor() (*models.Sensor, error) {
	var s models.Sensor
	err := db.QueryRow(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE is_primary = TRUE AND removed_at IS NULL LIMIT 1
	`).Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SetPrimarySensor makes the given sensor primary and demotes all others.
func (db *DB) SetPrimarySensor(sensorID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Promote the active target first. This is the transaction's first write and
	// therefore orders promotion against a concurrent removal.
	result, err := tx.Exec(`UPDATE sensors SET is_primary = TRUE WHERE sensor_id = ? AND removed_at IS NULL`, sensorID)
	if err != nil {
		tx.Rollback()
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		tx.Rollback()
		return ErrSensorNotFound
	}

	// The target is known active and the write lock is held; demote other active
	// sensors without changing retained tombstones.
	if _, err := tx.Exec(`UPDATE sensors SET is_primary = FALSE WHERE sensor_id != ? AND removed_at IS NULL`, sensorID); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// ErrLastPrimarySensor is retained for API compatibility. Any current primary
// must be replaced before removal, which guarantees the active fleet never has
// a zero-primary transition.
var ErrLastPrimarySensor = errors.New("cannot remove the primary sensor")

// ErrSensorRemoved protects the identity tombstone from ordinary registration.
var ErrSensorRemoved = errors.New("sensor identity has been removed")

// ErrSensorTokenInactive means an identity is active but the credential used
// for a metadata refresh no longer is.
var ErrSensorTokenInactive = errors.New("sensor token is no longer active")

// RemoveSensor tombstones a non-primary sensor, revokes only sensor-scoped
// credentials, and records an audit event in one transaction. It never deletes
// the identity row or historical token rows: SensorExists must stay true forever
// so a generic enrollment code cannot reclaim a removed identity. Repeating the
// removal is idempotent and returns the original timestamp.
func (db *DB) RemoveSensor(sensorID, actorTokenID, reason string) (time.Time, error) {
	tx, err := db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.Exec(`
		UPDATE sensors
		SET removed_at = ?, removed_by_token_id = ?, removal_reason = ?, status = 'offline'
		WHERE sensor_id = ? AND removed_at IS NULL AND is_primary = FALSE
	`, now, actorTokenID, reason, sensorID)
	if err != nil {
		return time.Time{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, err
	}
	if rows == 0 {
		var isPrimary bool
		var removed sql.NullTime
		if err := tx.QueryRow(`SELECT is_primary, removed_at FROM sensors WHERE sensor_id = ?`, sensorID).Scan(&isPrimary, &removed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return time.Time{}, ErrSensorNotFound
			}
			return time.Time{}, err
		}
		if removed.Valid {
			return removed.Time.UTC(), nil
		}
		if isPrimary {
			return time.Time{}, ErrLastPrimarySensor
		}
		return time.Time{}, fmt.Errorf("sensor removal made no change")
	}

	if _, err := tx.Exec(`
		UPDATE api_tokens SET revoked = 1
		WHERE sensor_id = ? AND scope = ? AND revoked = 0
	`, sensorID, auth.ScopeSensor); err != nil {
		return time.Time{}, err
	}
	if err := insertSensorLifecycleOn(tx, sensorID, "removed", actorTokenID, reason, now); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

func insertSensorLifecycleOn(q execQuerier, sensorID, eventType, actor, reason string, at time.Time) error {
	_, err := q.Exec(`
		INSERT INTO sensor_lifecycle_events
			(event_id, sensor_id, event_type, actor, reason, details, created_at)
		VALUES (?, ?, ?, ?, ?, '{}', ?)
	`, uuid.NewString(), sensorID, eventType, actor, reason, at.UTC())
	return err
}
