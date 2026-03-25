package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// UpsertDevice inserts or updates a device by MAC address.
// The segment parameter tags which network the device was found on.
// Returns true if this is a newly discovered device.
func (db *DB) UpsertDevice(host discovery.DiscoveredHost, scanTime time.Time, segment ...string) (bool, error) {
	seg := "default"
	if len(segment) > 0 && segment[0] != "" {
		seg = segment[0]
	}

	// Check if device exists by MAC
	var existingID string
	err := db.QueryRow("SELECT device_id FROM devices WHERE mac_address = ?", host.MACAddress).Scan(&existingID)

	portsJSON, _ := json.Marshal(host.OpenPorts)
	if len(host.OpenPorts) == 0 {
		portsJSON = []byte("[]")
	}

	if err == sql.ErrNoRows {
		// New device
		id := uuid.New().String()
		_, err := db.Exec(`
			INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, open_ports, segment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, scanTime, scanTime, host.IPAddress, host.MACAddress, host.Hostname, host.Vendor, string(portsJSON), seg,
		)
		if err != nil {
			return false, fmt.Errorf("insert device: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("query device: %w", err)
	}

	// Existing device — update last_seen, IP (may change via DHCP), ports, hostname, segment
	_, err = db.Exec(`
		UPDATE devices SET last_seen = ?, ip_address = ?, hostname = COALESCE(NULLIF(?, ''), hostname),
		vendor = COALESCE(NULLIF(?, ''), vendor), open_ports = ?, segment = ?
		WHERE device_id = ?`,
		scanTime, host.IPAddress, host.Hostname, host.Vendor, string(portsJSON), seg, existingID,
	)
	if err != nil {
		return false, fmt.Errorf("update device: %w", err)
	}
	return false, nil
}

// ListDevices returns all devices, ordered by last_seen descending.
func (db *DB) ListDevices() ([]models.Device, error) {
	rows, err := db.Query(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var d models.Device
		var portsJSON string
		err := rows.Scan(&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment)
		if err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// GetNewDevices returns devices first seen within the given duration.
func (db *DB) GetNewDevices(since time.Duration) ([]models.Device, error) {
	cutoff := time.Now().Add(-since)
	rows, err := db.Query(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment
		FROM devices WHERE first_seen > ? ORDER BY first_seen DESC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query new devices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var d models.Device
		var portsJSON string
		err := rows.Scan(&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment)
		if err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// CountDevices returns total device count.
func (db *DB) CountDevices() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&count)
	return count, err
}
