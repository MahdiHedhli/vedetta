package store

import (
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// RegisterSensor creates or updates a sensor record.
func (db *DB) RegisterSensor(sensor models.Sensor) error {
	now := time.Now()
	_, err := db.Exec(`
		INSERT INTO sensors (sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online')
		ON CONFLICT(sensor_id) DO UPDATE SET
			hostname = excluded.hostname,
			os = excluded.os,
			arch = excluded.arch,
			cidr = excluded.cidr,
			version = excluded.version,
			last_seen = excluded.last_seen,
			status = 'online'
	`, sensor.SensorID, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version, now, now)
	return err
}

// TouchSensor updates the last_seen timestamp for a sensor.
func (db *DB) TouchSensor(sensorID string) error {
	_, err := db.Exec(`UPDATE sensors SET last_seen = ?, status = 'online' WHERE sensor_id = ?`,
		time.Now(), sensorID)
	return err
}

// ListSensors returns all registered sensors.
func (db *DB) ListSensors() ([]models.Sensor, error) {
	rows, err := db.Query(`SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status FROM sensors ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []models.Sensor
	for rows.Next() {
		var s models.Sensor
		if err := rows.Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status); err != nil {
			return nil, err
		}
		sensors = append(sensors, s)
	}
	return sensors, rows.Err()
}
