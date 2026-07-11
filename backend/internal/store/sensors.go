package store

import (
	"database/sql"
	"fmt"
	"time"

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
	return registerSensorOn(db, sensor, true)
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

// registerSensorOn writes the sensor row (and primary-promotion) against any
// execQuerier, so it composes into a larger transaction without duplicating SQL.
// When upsert is true an existing row is updated; when false a plain INSERT is
// used so a pre-existing identity causes a primary-key conflict — that is how a
// NEW enrollment atomically refuses to overwrite/reactivate an existing sensor.
func registerSensorOn(q execQuerier, sensor models.Sensor, upsert bool) error {
	now := time.Now()

	// Auto-promote to primary if: no sensors exist yet, or no primary is set, or flag requested
	var count int
	_ = q.QueryRow(`SELECT COUNT(*) FROM sensors`).Scan(&count)
	var primaryCount int
	_ = q.QueryRow(`SELECT COUNT(*) FROM sensors WHERE is_primary = TRUE`).Scan(&primaryCount)
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
	}

	if _, err := q.Exec(insertSQL, sensor.SensorID, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version, now, now, makePrimary, sensor.Interfaces); err != nil {
		return err
	}

	// If this sensor should be primary, demote all others
	if makePrimary {
		if _, err := q.Exec(`UPDATE sensors SET is_primary = FALSE WHERE sensor_id != ?`, sensor.SensorID); err != nil {
			return err
		}
	}

	return nil
}

// TouchSensor updates the last_seen timestamp for a sensor.
func (db *DB) TouchSensor(sensorID string) error {
	_, err := db.Exec(`UPDATE sensors SET last_seen = ?, status = 'online' WHERE sensor_id = ?`,
		time.Now(), sensorID)
	return err
}

// ListSensors returns all registered sensors, primary first, then by last_seen.
func (db *DB) ListSensors() ([]models.Sensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors
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

// GetPrimarySensor returns the sensor marked as primary, or nil if none.
func (db *DB) GetPrimarySensor() (*models.Sensor, error) {
	var s models.Sensor
	err := db.QueryRow(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE is_primary = TRUE LIMIT 1
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

	// Demote all
	if _, err := tx.Exec(`UPDATE sensors SET is_primary = FALSE`); err != nil {
		tx.Rollback()
		return err
	}

	// Promote the target
	result, err := tx.Exec(`UPDATE sensors SET is_primary = TRUE WHERE sensor_id = ?`, sensorID)
	if err != nil {
		tx.Rollback()
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		tx.Rollback()
		return fmt.Errorf("sensor %s not found", sensorID)
	}

	return tx.Commit()
}
