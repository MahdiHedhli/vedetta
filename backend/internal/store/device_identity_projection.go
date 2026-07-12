package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

const deviceIdentityReviewThreshold = 0.75

type currentIdentityEvidence struct {
	Type              string
	ValueHMAC         string
	Segment           string
	SensorID          string
	Source            string
	Confidence        float64
	LastSeen          time.Time
	OperatorConfirmed bool
}

// attachIdentitySummary projects the current evidence set for a canonical
// device and every recursively redirected child. It never exposes value_hmac.
func (db *DB) attachIdentitySummary(device *models.Device) error {
	if device == nil || strings.TrimSpace(device.DeviceID) == "" {
		return nil
	}
	device.CanonicalDeviceID = device.DeviceID

	rows, err := db.Query(`
		WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d
			JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT e.evidence_type, e.value_hmac, e.segment, e.sensor_id, e.source,
		       e.confidence, e.last_seen, e.operator_confirmed
		FROM device_identity_evidence e JOIN family f ON f.device_id = e.device_id
		WHERE e.valid_until IS NULL
		ORDER BY e.operator_confirmed DESC, e.confidence DESC, e.last_seen DESC`, device.DeviceID)
	if err != nil {
		return fmt.Errorf("query current identity summary: %w", err)
	}
	defer rows.Close()
	var evidence []currentIdentityEvidence
	for rows.Next() {
		var item currentIdentityEvidence
		if err := rows.Scan(&item.Type, &item.ValueHMAC, &item.Segment, &item.SensorID,
			&item.Source, &item.Confidence, &item.LastSeen, &item.OperatorConfirmed); err != nil {
			return fmt.Errorf("scan current identity summary: %w", err)
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate current identity summary: %w", err)
	}
	if len(evidence) == 0 {
		device.IdentityStatus = "unresolved"
		device.IdentityReason = "no_current_identity_evidence"
		device.NeedsIdentification = true
		return nil
	}

	// Operator confirmation is authoritative unless the same binding was also
	// confirmed to a different canonical asset.
	for _, item := range evidence {
		if !item.OperatorConfirmed {
			continue
		}
		conflict, err := db.identityEvidenceHasOtherCanonicalOwner(item, device.DeviceID, true)
		if err != nil {
			return err
		}
		if conflict {
			device.IdentityStatus = "conflict"
			device.IdentityReason = "conflicting_operator_confirmations"
			device.NeedsIdentification = true
			return nil
		}
		device.IdentityConfidence = 1
		device.IdentityStatus = "confirmed"
		device.IdentityReason = "operator_confirmed_identity"
		device.NeedsIdentification = false
		return nil
	}

	// A strong identifier shared by two active canonical assets is a conflict,
	// not high confidence. Weak aliases remain low-confidence corroboration.
	for _, item := range evidence {
		if !strongIdentityEvidenceType(item.Type) || item.Confidence < 0.70 {
			continue
		}
		conflict, err := db.identityEvidenceHasOtherCanonicalOwner(item, device.DeviceID, false)
		if err != nil {
			return err
		}
		if conflict {
			device.IdentityStatus = "conflict"
			device.IdentityReason = "shared_strong_identity_evidence:" + item.Type
			device.NeedsIdentification = true
			return nil
		}
	}

	best := evidence[0]
	device.IdentityConfidence = clampIdentityConfidence(best.Confidence)
	if !strongIdentityEvidenceType(best.Type) {
		weakTypes := map[string]struct{}{}
		for _, item := range evidence {
			if !strongIdentityEvidenceType(item.Type) {
				weakTypes[item.Type] = struct{}{}
			}
		}
		// A friendly name/fingerprint is not a stable identity by itself even
		// when its source supplied a high nominal confidence.
		if len(weakTypes) < 2 && device.IdentityConfidence >= deviceIdentityReviewThreshold {
			device.IdentityConfidence = 0.65
		}
	}
	switch {
	case device.IdentityConfidence >= deviceIdentityReviewThreshold:
		device.IdentityStatus = "high_confidence"
		device.NeedsIdentification = false
		if best.Type == "mac" {
			device.IdentityReason = "mac_identity_evidence"
		} else if strongIdentityEvidenceType(best.Type) {
			device.IdentityReason = "stable_identity_evidence:" + best.Type
		} else {
			device.IdentityReason = "corroborated_identity_evidence:" + best.Type
		}
	default:
		device.IdentityStatus = "low_confidence"
		device.IdentityReason = "low_confidence_identity_evidence:" + best.Type
		device.NeedsIdentification = true
	}
	return nil
}

func strongIdentityEvidenceType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dhcp_client_id", "ssdp_uuid", "mdns_txt_id", "mac":
		return true
	default:
		return false
	}
}

func globallyScopedIdentityEvidenceType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dhcp_client_id", "ssdp_uuid", "mdns_txt_id":
		return true
	default:
		return false
	}
}

func (db *DB) identityEvidenceHasOtherCanonicalOwner(item currentIdentityEvidence, canonicalID string, operatorOnly bool) (bool, error) {
	query := `SELECT e.device_id FROM device_identity_evidence e
		WHERE e.evidence_type = ? AND e.value_hmac = ? AND e.valid_until IS NULL`
	args := []any{item.Type, item.ValueHMAC}
	if operatorOnly {
		query += ` AND e.operator_confirmed = TRUE`
	}
	if !globallyScopedIdentityEvidenceType(item.Type) {
		query += ` AND e.segment = ?`
		args = append(args, item.Segment)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return false, fmt.Errorf("query identity evidence owners: %w", err)
	}
	defer rows.Close()
	var deviceIDs []string
	for rows.Next() {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			return false, fmt.Errorf("scan identity evidence owner: %w", err)
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate identity evidence owners: %w", err)
	}
	for _, deviceID := range deviceIDs {
		owner, err := db.CanonicalDeviceID(context.Background(), deviceID)
		if err != nil {
			return false, err
		}
		if owner != canonicalID {
			return true, nil
		}
	}
	return false, nil
}

// ListActiveDeviceMerges returns merge actions that still back a live source
// redirect and have not been undone. Labels are safe display projections; no
// HMAC evidence is returned.
func (db *DB) ListActiveDeviceMerges(ctx context.Context) ([]models.ActiveDeviceMerge, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT a.action_id, a.action_type, a.source_device_id, a.target_device_id,
		       COALESCE(NULLIF(s.display_name,''), NULLIF(s.custom_name,''), NULLIF(s.friendly_name,''),
		                NULLIF(s.hostname,''), NULLIF(s.ip_address,''), s.device_id),
		       a.actor, a.reason, a.created_at
		FROM device_identity_actions a
		JOIN devices s ON s.device_id = a.source_device_id AND s.merge_action_id = a.action_id
		WHERE a.action_type = 'merge' AND a.undone_by_action_id IS NULL
		ORDER BY a.created_at DESC, a.action_id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list active device merges: %w", err)
	}
	defer rows.Close()
	var actions []models.ActiveDeviceMerge
	for rows.Next() {
		var action models.ActiveDeviceMerge
		if err := rows.Scan(&action.ActionID, &action.ActionType, &action.SourceDeviceID,
			&action.TargetDeviceID, &action.SourceDisplayName, &action.Actor,
			&action.Reason, &action.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan active device merge: %w", err)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active device merges: %w", err)
	}

	for i := range actions {
		canonical, err := db.CanonicalDeviceID(ctx, actions[i].TargetDeviceID)
		if err != nil {
			return nil, err
		}
		actions[i].CanonicalTargetDeviceID = canonical
		label, err := db.deviceDisplayLabel(ctx, canonical)
		if err != nil {
			return nil, err
		}
		actions[i].TargetDisplayName = label
	}
	if actions == nil {
		actions = []models.ActiveDeviceMerge{}
	}
	return actions, nil
}

func (db *DB) deviceDisplayLabel(ctx context.Context, deviceID string) (string, error) {
	var displayName, customName, friendlyName, hostname, ipAddress string
	err := db.QueryRowContext(ctx, `SELECT COALESCE(display_name,''), COALESCE(custom_name,''),
		COALESCE(friendly_name,''), COALESCE(hostname,''), COALESCE(ip_address,'')
		FROM devices WHERE device_id = ?`, deviceID).
		Scan(&displayName, &customName, &friendlyName, &hostname, &ipAddress)
	if err != nil {
		if err == sql.ErrNoRows {
			return deviceID, nil
		}
		return "", fmt.Errorf("read device display label: %w", err)
	}
	return firstNonEmpty(displayName, customName, friendlyName, hostname, ipAddress, deviceID), nil
}

// GetDeviceByID follows soft-merge redirects and returns the same enriched,
// non-hidden DTO shape as ListDevices for processor/device-context consumers.
func (db *DB) GetDeviceByID(ctx context.Context, deviceID string) (*models.Device, error) {
	canonicalID, err := db.CanonicalDeviceID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	var device models.Device
	var portsJSON, riskReasonsJSON, servicesJSON string
	err = db.QueryRowContext(ctx, `
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, ''),
		       COALESCE(risk_category, ''), COALESCE(risk_model, ''), COALESCE(risk_reasons, '[]'),
		       COALESCE(services, '[]'), COALESCE(display_name, ''), COALESCE(friendly_name, '')
		FROM devices WHERE device_id = ? AND merged_into_device_id IS NULL`, canonicalID).Scan(
		&device.DeviceID, &device.FirstSeen, &device.LastSeen, &device.IPAddress,
		&device.MACAddress, &device.Hostname, &device.Vendor, &portsJSON, &device.Segment,
		&device.DeviceType, &device.OSFamily, &device.OSVersion, &device.Model,
		&device.DiscoveryMethod, &device.FingerprintConfidence,
		&device.CustomName, &device.Notes, &device.EOLRisk, &device.EOLModel,
		&device.RiskCategory, &device.RiskModel, &riskReasonsJSON, &servicesJSON,
		&device.DisplayName, &device.FriendlyName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query canonical device by id: %w", err)
	}
	_ = json.Unmarshal([]byte(portsJSON), &device.OpenPorts)
	_ = json.Unmarshal([]byte(riskReasonsJSON), &device.RiskReasons)
	_ = json.Unmarshal([]byte(servicesJSON), &device.Services)
	db.attachCorrelation(&device)
	return &device, nil
}
