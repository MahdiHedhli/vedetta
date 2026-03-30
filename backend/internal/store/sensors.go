package store

import (
	"fmt"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// RegisterSensor creates or updates a sensor record.
// If this is the first sensor ever registered, it becomes the primary.
func (db *DB) RegisterSensor(sensor models.Sensor) error {
	now := time.Now()

	// Auto-promote to primary if: no sensors exist yet, or no primary is set, or flag requested
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sensors`).Scan(&count)
	var primaryCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE is_primary = TRUE`).Scan(&primaryCount)
	makePrimary := count == 0 || primaryCount == 0 || sensor.IsPrimary

	_, err := db.Exec(`
		INSERT INTO sensors (sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?)
		ON CONFLICT(sensor_id) DO UPDATE SET
			hostname = excluded.hostname,
			os = excluded.os,
			arch = excluded.arch,
			cidr = excluded.cidr,
			version = excluded.version,
			last_seen = excluded.last_seen,
			status = 'online'
	`, sensor.SensorID, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version, now, now, makePrimary)
	if err != nil {
		return err
	}

	// If this sensor should be primary, demote all others
	if makePrimary {
		_, err = db.Exec(`UPDATE sensors SET is_primary = FALSE WHERE sensor_id != ?`, sensor.SensorID)
	}

	return err
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
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary
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
		if err := rows.Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary); err != nil {
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
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary
		FROM sensors WHERE is_primary = TRUE LIMIT 1
	`).Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary)
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
