package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// CreateScanTarget inserts a new scan target.
func (db *DB) CreateScanTarget(name, cidr, segment string, scanPorts, dnsCapture bool, dnsInterface string) (*models.ScanTarget, error) {
	t := &models.ScanTarget{
		TargetID:     uuid.New().String(),
		Name:         name,
		CIDR:         cidr,
		Segment:      segment,
		ScanPorts:    scanPorts,
		Enabled:      true,
		CreatedAt:    time.Now(),
		DNSCapture:   dnsCapture,
		DNSInterface: dnsInterface,
	}

	_, err := db.Exec(`
		INSERT INTO scan_targets (target_id, name, cidr, segment, scan_ports, enabled, created_at, dns_capture, dns_interface)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.TargetID, t.Name, t.CIDR, t.Segment, t.ScanPorts, t.Enabled, t.CreatedAt, t.DNSCapture, t.DNSInterface,
	)
	if err != nil {
		return nil, fmt.Errorf("insert scan target: %w", err)
	}
	return t, nil
}

// ListScanTargets returns all scan targets.
func (db *DB) ListScanTargets() ([]models.ScanTarget, error) {
	rows, err := db.Query(`
		SELECT target_id, name, cidr, segment, scan_ports, enabled, created_at, last_scan, dns_capture, dns_interface
		FROM scan_targets ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query scan targets: %w", err)
	}
	defer rows.Close()

	var targets []models.ScanTarget
	for rows.Next() {
		var t models.ScanTarget
		var lastScan sql.NullTime
		err := rows.Scan(&t.TargetID, &t.Name, &t.CIDR, &t.Segment, &t.ScanPorts, &t.Enabled, &t.CreatedAt, &lastScan, &t.DNSCapture, &t.DNSInterface)
		if err != nil {
			return nil, fmt.Errorf("scan target row: %w", err)
		}
		if lastScan.Valid {
			t.LastScan = &lastScan.Time
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// GetEnabledScanTargets returns only enabled targets.
func (db *DB) GetEnabledScanTargets() ([]models.ScanTarget, error) {
	rows, err := db.Query(`
		SELECT target_id, name, cidr, segment, scan_ports, enabled, created_at, last_scan, dns_capture, dns_interface
		FROM scan_targets WHERE enabled = TRUE ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query enabled scan targets: %w", err)
	}
	defer rows.Close()

	var targets []models.ScanTarget
	for rows.Next() {
		var t models.ScanTarget
		var lastScan sql.NullTime
		err := rows.Scan(&t.TargetID, &t.Name, &t.CIDR, &t.Segment, &t.ScanPorts, &t.Enabled, &t.CreatedAt, &lastScan, &t.DNSCapture, &t.DNSInterface)
		if err != nil {
			return nil, fmt.Errorf("scan target row: %w", err)
		}
		if lastScan.Valid {
			t.LastScan = &lastScan.Time
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// ScrubInvalidScanTargets disables any stored scan target whose CIDR fails
// discovery.ValidateScanTarget. Fresh writes are validated at the API boundary,
// but a database upgraded from an older build (Issue #7) can carry rows that were
// inserted before that validation existed — e.g. a planted 0.0.0.0/0 that would
// otherwise be served to the root-running sensor. Called once at startup. Targets
// are disabled rather than deleted so the operator can see and repair them.
// Returns the number of targets disabled.
func (db *DB) ScrubInvalidScanTargets() (int, error) {
	targets, err := db.ListScanTargets()
	if err != nil {
		return 0, err
	}
	disabled := 0
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		if err := discovery.ValidateScanTarget(t.CIDR); err != nil {
			if derr := db.ToggleScanTarget(t.TargetID, false); derr != nil {
				return disabled, fmt.Errorf("disable invalid scan target %s (%q): %w", t.TargetID, t.CIDR, derr)
			}
			log.Printf("SECURITY: disabled invalid stored scan target %s (%q): %v", t.TargetID, t.CIDR, err)
			disabled++
		}
	}
	return disabled, nil
}

// DeleteScanTarget removes a scan target by ID.
func (db *DB) DeleteScanTarget(targetID string) error {
	result, err := db.Exec("DELETE FROM scan_targets WHERE target_id = ?", targetID)
	if err != nil {
		return fmt.Errorf("delete scan target: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("scan target not found")
	}
	return nil
}

// ToggleScanTarget enables or disables a scan target.
func (db *DB) ToggleScanTarget(targetID string, enabled bool) error {
	_, err := db.Exec("UPDATE scan_targets SET enabled = ? WHERE target_id = ?", enabled, targetID)
	return err
}

// UpdateScanTargetLastScan sets the last_scan timestamp.
func (db *DB) UpdateScanTargetLastScan(targetID string, t time.Time) error {
	_, err := db.Exec("UPDATE scan_targets SET last_scan = ? WHERE target_id = ?", t, targetID)
	return err
}
