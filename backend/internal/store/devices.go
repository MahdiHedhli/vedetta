package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/fingerprint"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// UpsertDevice inserts or updates a device.
// Identity strategy:
//   - If MAC address is available → match by MAC (handles DHCP IP changes)
//   - If MAC is empty (cross-subnet scan) → match by IP + segment
//
// The segment parameter tags which network the device was found on.
// Runs device fingerprinting to enrich device type, OS, and model information.
// Returns true if this is a newly discovered device.
func (db *DB) UpsertDevice(host discovery.DiscoveredHost, scanTime time.Time, segment ...string) (bool, error) {
	seg := "default"
	if len(segment) > 0 && segment[0] != "" {
		seg = segment[0]
	}

	portsJSON, _ := json.Marshal(host.OpenPorts)
	if len(host.OpenPorts) == 0 {
		portsJSON = []byte("[]")
	}

	// Choose identity key based on whether MAC is available.
	// Local-subnet scans get MAC via ARP; cross-subnet scans don't.
	var existingID string
	var err error
	if host.MACAddress != "" {
		// Primary lookup: by MAC address (stable across DHCP changes)
		err = db.QueryRow("SELECT device_id FROM devices WHERE mac_address = ?", host.MACAddress).Scan(&existingID)
	} else {
		// Fallback: by IP + segment (best we can do without layer-2 data)
		err = db.QueryRow("SELECT device_id FROM devices WHERE ip_address = ? AND segment = ? AND (mac_address = '' OR mac_address IS NULL)",
			host.IPAddress, seg).Scan(&existingID)
	}

	// Run fingerprinting on the new host data
	engine := fingerprint.NewEngine()
	deviceModel := &models.Device{
		IPAddress:  host.IPAddress,
		MACAddress: host.MACAddress,
		Hostname:   host.Hostname,
		Vendor:     host.Vendor,
	}
	fpResult := engine.Fingerprint(deviceModel)

	if err == sql.ErrNoRows {
		// New device
		id := uuid.New().String()
		_, err := db.Exec(`
			INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, open_ports, segment,
			                      device_type, os_family, os_version, model, discovery_method, fingerprint_confidence)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, scanTime, scanTime, host.IPAddress, host.MACAddress, host.Hostname, deviceModel.Vendor, string(portsJSON), seg,
			fpResult.DeviceType, fpResult.OSFamily, fpResult.OSVersion, fpResult.Model, fpResult.DiscoveryMethod, fpResult.FingerprintConfidence,
		)
		if err != nil {
			return false, fmt.Errorf("insert device: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("query device: %w", err)
	}

	// Existing device — fetch current fingerprint confidence
	var currentConfidence float64
	err = db.QueryRow("SELECT COALESCE(fingerprint_confidence, 0.0) FROM devices WHERE device_id = ?", existingID).Scan(&currentConfidence)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("query device confidence: %w", err)
	}

	// Only update fingerprint fields if new confidence >= existing confidence
	// This preserves higher-confidence matches made previously
	updateFP := fpResult.FingerprintConfidence >= currentConfidence

	if updateFP {
		// Update with fingerprinting
		_, err = db.Exec(`
			UPDATE devices SET last_seen = ?, ip_address = ?,
			mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
			hostname = COALESCE(NULLIF(?, ''), hostname),
			vendor = COALESCE(NULLIF(?, ''), vendor), open_ports = ?, segment = ?,
			device_type = ?, os_family = ?, os_version = ?, model = ?,
			discovery_method = ?, fingerprint_confidence = ?
			WHERE device_id = ?`,
			scanTime, host.IPAddress,
			host.MACAddress, host.MACAddress,
			host.Hostname, deviceModel.Vendor, string(portsJSON), seg,
			fpResult.DeviceType, fpResult.OSFamily, fpResult.OSVersion, fpResult.Model,
			fpResult.DiscoveryMethod, fpResult.FingerprintConfidence, existingID,
		)
	} else {
		// Update without fingerprinting (preserve higher confidence match)
		_, err = db.Exec(`
			UPDATE devices SET last_seen = ?, ip_address = ?,
			mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
			hostname = COALESCE(NULLIF(?, ''), hostname),
			vendor = COALESCE(NULLIF(?, ''), vendor), open_ports = ?, segment = ?
			WHERE device_id = ?`,
			scanTime, host.IPAddress,
			host.MACAddress, host.MACAddress,
			host.Hostname, deviceModel.Vendor, string(portsJSON), seg, existingID,
		)
	}

	if err != nil {
		return false, fmt.Errorf("update device: %w", err)
	}
	return false, nil
}

// ListDevices returns all devices, ordered by last_seen descending.
func (db *DB) ListDevices() ([]models.Device, error) {
	rows, err := db.Query(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, '')
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
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
			&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
			&d.DiscoveryMethod, &d.FingerprintConfidence,
			&d.CustomName, &d.Notes)
		if err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// GetDeviceByIP returns a device matching the given IP address.
func (db *DB) GetDeviceByIP(ip string) (*models.Device, error) {
	var d models.Device
	var portsJSON string
	err := db.QueryRow(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, '')
		FROM devices WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1`, ip).Scan(
		&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
		&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
		&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
		&d.DiscoveryMethod, &d.FingerprintConfidence,
		&d.CustomName, &d.Notes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query device by ip: %w", err)
	}
	json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
	return &d, nil
}

// UpdateDeviceMeta updates user-editable fields (custom_name, notes, segment).
func (db *DB) UpdateDeviceMeta(deviceID, customName, notes, segment string) error {
	_, err := db.Exec(`
		UPDATE devices SET custom_name = ?, notes = ?, segment = ? WHERE device_id = ?`,
		customName, notes, segment, deviceID)
	if err != nil {
		return fmt.Errorf("update device meta: %w", err)
	}
	return nil
}

// GetNewDevices returns devices first seen within the given duration.
func (db *DB) GetNewDevices(since time.Duration) ([]models.Device, error) {
	cutoff := time.Now().Add(-since)
	rows, err := db.Query(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, '')
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
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
			&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
			&d.DiscoveryMethod, &d.FingerprintConfidence,
			&d.CustomName, &d.Notes)
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
