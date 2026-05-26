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

	// Choose identity key.
	// Prefer MAC when available (stable across DHCP).
	// Always fall back to IP + segment for local networks, where same IP usually = same device.
	// This deeper merging strategy prevents creating duplicate records when discovery
	// sources provide inconsistent MAC presence (common with mDNS/SSDP vs ARP/nmap).
	var existingID string
	var err error
	if host.MACAddress != "" {
		err = db.QueryRow("SELECT device_id FROM devices WHERE mac_address = ?", host.MACAddress).Scan(&existingID)
	}
	if existingID == "" && host.IPAddress != "" {
		err = db.QueryRow("SELECT device_id FROM devices WHERE ip_address = ? AND segment = ?",
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
			                      device_type, os_family, os_version, model, discovery_method, fingerprint_confidence, eol_risk, eol_model)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, scanTime, scanTime, host.IPAddress, host.MACAddress, host.Hostname, deviceModel.Vendor, string(portsJSON), seg,
			fpResult.DeviceType, fpResult.OSFamily, fpResult.OSVersion, fpResult.Model, fpResult.DiscoveryMethod, fpResult.FingerprintConfidence,
			boolToInt(fpResult.EOLRisk), fpResult.EOLModel,
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
			discovery_method = ?, fingerprint_confidence = ?, eol_risk = ?, eol_model = ?
			WHERE device_id = ?`,
			scanTime, host.IPAddress,
			host.MACAddress, host.MACAddress,
			host.Hostname, deviceModel.Vendor, string(portsJSON), seg,
			fpResult.DeviceType, fpResult.OSFamily, fpResult.OSVersion, fpResult.Model,
			fpResult.DiscoveryMethod, fpResult.FingerprintConfidence, boolToInt(fpResult.EOLRisk), fpResult.EOLModel, existingID,
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
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, '')
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
			&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel)
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
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, '')
		FROM devices WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1`, ip).Scan(
		&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
		&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
		&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
		&d.DiscoveryMethod, &d.FingerprintConfidence,
		&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel)
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

// UpdateDeviceFingerprint updates user-corrected fingerprint fields (device type, OS, model).
// These corrections take priority over auto-detected values.
func (db *DB) UpdateDeviceFingerprint(deviceID, deviceType, osFamily, osVersion, model string) error {
	_, err := db.Exec(`
		UPDATE devices SET device_type = COALESCE(NULLIF(?, ''), device_type),
		                    os_family = COALESCE(NULLIF(?, ''), os_family),
		                    os_version = COALESCE(NULLIF(?, ''), os_version),
		                    model = COALESCE(NULLIF(?, ''), model),
		                    discovery_method = 'user_corrected'
		WHERE device_id = ?`,
		deviceType, osFamily, osVersion, model, deviceID)
	if err != nil {
		return fmt.Errorf("update device fingerprint: %w", err)
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
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, '')
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
			&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel)
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

// CountDevicesNewSince returns count of devices first seen within the given duration.
func (db *DB) CountDevicesNewSince(d time.Duration) (int, error) {
	var count int
	cutoff := time.Now().UTC().Add(-d)
	err := db.QueryRow("SELECT COUNT(*) FROM devices WHERE first_seen > ?", cutoff).Scan(&count)
	return count, err
}

// CountDevicesBySegment returns count of devices in a specific segment (e.g. "iot").
func (db *DB) CountDevicesBySegment(segment string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM devices WHERE segment = ?", segment).Scan(&count)
	return count, err
}

// GetLastDeviceUpdate returns the most recent last_seen timestamp across all devices.
// Used for SNR monitoring to show freshness of the device context baseline
// (e.g. "frozen since end of 10h collection run" vs actively updating during real capture).
func (db *DB) GetLastDeviceUpdate() (time.Time, error) {
	// Prefer TEXT scan + parse (SQLite often surfaces TIMESTAMP as string for aggregates)
	var lastStr string
	err := db.QueryRow("SELECT MAX(last_seen) FROM devices").Scan(&lastStr)
	if err == nil && lastStr != "" {
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, perr := time.Parse(layout, lastStr); perr == nil {
				return t, nil
			}
		}
		// If none matched but we have a value, return zero (caller treats as missing)
		return time.Time{}, nil
	}
	if err == sql.ErrNoRows || lastStr == "" {
		return time.Time{}, nil
	}
	// Try direct time scan as last resort (works if driver parses it)
	var ts time.Time
	if err2 := db.QueryRow("SELECT MAX(last_seen) FROM devices").Scan(&ts); err2 == nil && !ts.IsZero() {
		return ts, nil
	}
	return time.Time{}, err
}

// GetMinFirstSeenForIP returns the earliest first_seen timestamp for any device record
// matching the given IP. This provides an "effective" first-seen age across duplicate
// records for the same IP (common after mixed discovery sources), preventing spurious
// new_device / very_new_device tags on established devices that happen to have multiple
// records with different first_seen values.
func (db *DB) GetMinFirstSeenForIP(ip string) (time.Time, error) {
	if ip == "" {
		return time.Time{}, nil
	}
	var minStr string
	err := db.QueryRow("SELECT MIN(first_seen) FROM devices WHERE ip_address = ?", ip).Scan(&minStr)
	if err == nil && minStr != "" {
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, perr := time.Parse(layout, minStr); perr == nil {
				return t, nil
			}
		}
		return time.Time{}, nil
	}
	if err == sql.ErrNoRows || minStr == "" {
		return time.Time{}, nil
	}
	// Fallback direct scan
	var ts time.Time
	if err2 := db.QueryRow("SELECT MIN(first_seen) FROM devices WHERE ip_address = ?", ip).Scan(&ts); err2 == nil && !ts.IsZero() {
		return ts, nil
	}
	return time.Time{}, err
}

// boolToInt converts bool to 0/1 for SQLite INTEGER columns (no native bool).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
