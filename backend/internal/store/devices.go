package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/fingerprint"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// UpsertDevice inserts or updates a device using the spec-004 correlation
// pipeline. It replaces the old MAC-then-IP, last-writer-wins logic with:
//   - an ordered identity resolver (MAC > mDNS name > hostname > IP+segment)
//     that survives DHCP IP churn and never re-assigns across a MAC conflict;
//   - a conservative duplicate merge when a MAC match and an alias/IP match
//     resolve to different records (fold the MAC-less record in);
//   - confidence-weighted per-field merging via device_signals (higher- or
//     equal-confidence sources win; user_corrected locks a field);
//   - multi-network attachment tracking via device_networks;
//   - a derived display_name.
//
// The whole operation runs in one transaction per reported host.
// Returns true if this created a new device record.
func (db *DB) UpsertDevice(host discovery.DiscoveredHost, scanTime time.Time, segment ...string) (bool, error) {
	seg := "default"
	if len(segment) > 0 && segment[0] != "" {
		seg = segment[0]
	}
	return db.ObserveDevice(DeviceObservation{Host: host, Segment: seg, ObservedAt: scanTime})
}

// ObserveDevice is the context-rich inventory entry point. Authenticated sensor
// identity and observation time are retained in temporal address/evidence rows;
// UpsertDevice above remains source compatible for legacy callers.
func (db *DB) ObserveDevice(observation DeviceObservation) (bool, error) {
	host := observation.Host
	scanTime := observation.ObservedAt.UTC()
	if scanTime.IsZero() {
		scanTime = time.Now().UTC()
	}
	seg := normalizeSegment(observation.Segment)
	sensorID := observation.SensorID
	evidence := append([]DeviceIdentityEvidenceInput(nil), observation.Evidence...)
	for _, wire := range host.IdentityEvidence {
		evidence = append(evidence, DeviceIdentityEvidenceInput{
			Type: wire.Type, Value: wire.Value, Source: wire.Source,
			Confidence: wire.Confidence, Sensitive: wire.Sensitive,
		})
	}

	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin upsert tx: %w", err)
	}
	defer tx.Rollback()

	// mDNS instance-name continuity uses the friendly name when the source is mDNS.
	mdnsName := ""
	if host.FriendlyName != "" && (host.DiscoverySource == "passive_mdns" || host.DiscoverySource == "mdns") {
		mdnsName = host.FriendlyName
	}
	in := correlationInput{
		ip:       host.IPAddress,
		mac:      host.MACAddress,
		hostname: host.Hostname,
		mdnsName: mdnsName,
	}

	// Spec 007 precedence: operator/stable typed evidence outranks the legacy
	// MAC/name/IP resolver. A strong conflict vetoes automatic attachment.
	typedResolution, err := db.resolveDeviceAtTx(context.Background(), tx, DeviceIdentityResolutionRequest{
		Timestamp: scanTime, IPAddress: host.IPAddress, MACAddress: host.MACAddress,
		Segment: seg, SensorID: sensorID, Evidence: evidence,
	})
	if err != nil {
		return false, err
	}
	res := resolvedIdentity{}
	if typedResolution.DeviceID != "" {
		res.deviceID = typedResolution.DeviceID
		res.matchRule = typedResolution.Reason
		// Preserve the conservative spec-004 duplicate probe when the typed
		// winner is the exact MAC record. It may find a distinct MAC-less alias
		// row to soft-link without changing the evidence precedence.
		if typedResolution.Reason == "mac_identity_evidence" {
			legacy, legacyErr := db.resolveIdentity(tx, in, seg, scanTime)
			if legacyErr != nil {
				return false, legacyErr
			}
			if legacy.macMatchID == typedResolution.DeviceID && legacy.deviceID != "" && legacy.deviceID != typedResolution.DeviceID {
				res = legacy
			}
		}
	} else if !strings.HasPrefix(typedResolution.Reason, "conflicting_") && typedResolution.Reason != "ambiguous_temporal_address" {
		res, err = db.resolveIdentity(tx, in, seg, scanTime)
		if err != nil {
			return false, err
		}
	}

	isNew := res.deviceID == ""
	deviceID := res.deviceID
	if isNew {
		deviceID = uuid.New().String()
		if _, err := tx.Exec(`
			INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, open_ports, segment,
			                      device_type, os_family, os_version, model, discovery_method, fingerprint_confidence, eol_risk, eol_model,
			                      risk_category, risk_model, risk_reasons, services, display_name, friendly_name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?, 0.0, 0, '', '', '', '[]', '[]', '', '')`,
			deviceID, scanTime, scanTime, host.IPAddress, host.MACAddress, host.Hostname, host.Vendor,
			marshalPorts(host.OpenPorts), seg, firstNonEmpty(host.DiscoverySource, "nmap_active"),
		); err != nil {
			return false, fmt.Errorf("insert device: %w", err)
		}
	}

	// Duplicate merge (T3.3): the MAC matched record A, but the ordered resolver
	// landed on a different record B via an alias/IP rule — fold the MAC-less B
	// into the MAC-bearing A. We only merge when A != B and the resolved record
	// carries no conflicting MAC (the resolver's MAC-conflict veto already
	// prevents landing on a differently-MAC'd record via IP).
	if res.macMatchID != "" && res.matchRule != "mac" && res.deviceID != "" && res.macMatchID != res.deviceID {
		if err := db.mergeDevices(tx, res.macMatchID, res.deviceID, res.matchRule); err != nil {
			return false, err
		}
		deviceID = res.macMatchID
	}
	// Inverse case (incoming MAC matches a MAC-less record B by alias/IP, with no
	// separate MAC record) needs no merge: the MAC is adopted onto B via the
	// mac_address column CASE-write below, and B simply becomes the device.

	// Record identity aliases for this observation (segment-scoped).
	if err := db.upsertIdentityTx(tx, deviceID, "mac", host.MACAddress, seg, scanTime); err != nil {
		return false, err
	}
	if host.Hostname != "" {
		if err := db.upsertIdentityTx(tx, deviceID, "hostname", host.Hostname, seg, scanTime); err != nil {
			return false, err
		}
	}
	if mdnsName != "" {
		if err := db.upsertIdentityTx(tx, deviceID, "mdns_name", mdnsName, seg, scanTime); err != nil {
			return false, err
		}
	}

	// Multi-network attachment (T3.5): device x segment, most-recent wins on the
	// canonical devices.segment/ip_address below.
	if err := db.upsertNetworkTx(tx, deviceID, seg, host.IPAddress, sensorID, scanTime); err != nil {
		return false, err
	}

	// Write raw observation signals at their source confidence (T3.4 write side).
	sigSource := discoverySourceToSignal(host.DiscoverySource)
	var sigs []signalUpsert
	if host.Vendor != "" {
		sigs = append(sigs, signalUpsert{field: "vendor", value: host.Vendor, source: sigSource, confidence: ConfidenceForSource(sigSource)})
	}
	if host.Hostname != "" && !IsGenericHostname(host.Hostname) {
		sigs = append(sigs, signalUpsert{field: "hostname", value: host.Hostname, source: sigSource, confidence: ConfidenceForSource(sigSource)})
	}
	if host.Model != "" {
		// Model from mDNS TXT / SSDP is high-value; key it to the reporting source.
		sigs = append(sigs, signalUpsert{field: "model", value: host.Model, source: sigSource, confidence: ConfidenceForSource(sigSource)})
	}
	if host.FriendlyName != "" {
		fnSource := SourceMDNSTxt
		if host.DiscoverySource == "passive_ssdp" || host.DiscoverySource == "ssdp" {
			fnSource = SourceSSDP
		}
		sigs = append(sigs, signalUpsert{field: "friendly_name", value: host.FriendlyName, source: fnSource, confidence: ConfidenceForSource(fnSource)})
	}
	if err := db.upsertSignalsTx(tx, deviceID, sigs, scanTime); err != nil {
		return false, err
	}

	// Recompute canonical vendor/model/hostname/friendly_name from the signal set
	// (confidence-weighted; user_corrected wins). OUI vendor from OpenPorts/MAC is
	// added as a low-confidence backstop through the fingerprint engine below.
	canonical, err := db.resolveCanonicalFields(tx, deviceID)
	if err != nil {
		return false, err
	}
	canonVendor := canonical["vendor"].value
	canonModel := canonical["model"].value
	canonHostname := canonical["hostname"].value
	canonFriendly := canonical["friendly_name"].value

	// Run the fingerprint engine on the correlated signal set (T3.6): hostname,
	// vendor, model, services, and friendly name all feed device typing / risk.
	engine := fingerprint.NewEngine()
	fpModel := &models.Device{
		IPAddress:    host.IPAddress,
		MACAddress:   host.MACAddress,
		Hostname:     firstNonEmpty(canonHostname, host.Hostname),
		Vendor:       firstNonEmpty(canonVendor, host.Vendor),
		Model:        firstNonEmpty(canonModel, host.Model),
		FriendlyName: firstNonEmpty(canonFriendly, host.FriendlyName),
		Services:     host.Services,
	}
	fpResult := engine.FingerprintSignals(fpModel, host.Services, fpModel.Model, fpModel.FriendlyName)

	// OUI vendor + fingerprint device_type / os feed back as their own signals so
	// they take part in future confidence-weighted resolution (but never beat a
	// higher-confidence passive source on vendor).
	var derived []signalUpsert
	if fpResult.Vendor != "" {
		derived = append(derived, signalUpsert{field: "vendor", value: fpResult.Vendor, source: SourceOUI, confidence: ConfidenceForSource(SourceOUI)})
	}
	if fpResult.DeviceType != "" {
		derived = append(derived, signalUpsert{field: "device_type", value: fpResult.DeviceType, source: SourceHostnamePattern, confidence: fpResult.FingerprintConfidence})
	}
	if fpResult.OSFamily != "" {
		derived = append(derived, signalUpsert{field: "os_family", value: fpResult.OSFamily, source: SourceHostnamePattern, confidence: fpResult.FingerprintConfidence})
	}
	if err := db.upsertSignalsTx(tx, deviceID, derived, scanTime); err != nil {
		return false, err
	}

	// Final canonical read (now includes derived signals) for the device row.
	canonical, err = db.resolveCanonicalFields(tx, deviceID)
	if err != nil {
		return false, err
	}
	finalVendor := firstNonEmpty(canonical["vendor"].value, fpResult.Vendor)
	finalModel := firstNonEmpty(canonical["model"].value, fpResult.Model)
	finalHostname := firstNonEmpty(canonical["hostname"].value, host.Hostname)
	finalFriendly := canonical["friendly_name"].value
	finalDeviceType := firstNonEmpty(canonical["device_type"].value, fpResult.DeviceType)
	finalOSFamily := firstNonEmpty(canonical["os_family"].value, fpResult.OSFamily)

	// Read custom_name so the label deriver honours user overrides.
	var customName string
	_ = tx.QueryRow(`SELECT COALESCE(custom_name, '') FROM devices WHERE device_id = ?`, deviceID).Scan(&customName)
	displayName := deriveDisplayName(customName, finalFriendly, finalModel, finalVendor, finalHostname, host.MACAddress, host.IPAddress)

	riskReasonsJSON, _ := json.Marshal(fpResult.RiskReasons)
	if len(fpResult.RiskReasons) == 0 {
		riskReasonsJSON = []byte("[]")
	}
	servicesJSON, _ := json.Marshal(host.Services)
	if len(host.Services) == 0 {
		servicesJSON = []byte("[]")
	}

	// Canonical devices row: segment/ip_address track the MOST RECENT attachment
	// (this observation). MAC is adopted only when the row had none or matches.
	if _, err := tx.Exec(`
			UPDATE devices SET
				first_seen = CASE WHEN first_seen > ? THEN ? ELSE first_seen END,
				last_seen = CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
				ip_address = CASE WHEN last_seen <= ? THEN ? ELSE ip_address END,
				mac_address = CASE
					WHEN ? != '' AND (mac_address = '' OR last_seen <= ?) THEN ?
					ELSE mac_address END,
				hostname = ?,
				vendor = ?,
				model = ?,
				friendly_name = ?,
				display_name = CASE WHEN last_seen <= ? THEN ? ELSE display_name END,
				device_type = ?,
				os_family = ?,
				os_version = COALESCE(NULLIF(?, ''), os_version),
				segment = CASE WHEN last_seen <= ? THEN ? ELSE segment END,
				open_ports = CASE WHEN last_seen <= ? AND ? != '[]' THEN ? ELSE open_ports END,
				services = CASE WHEN last_seen <= ? AND ? != '[]' THEN ? ELSE services END,
				discovery_method = CASE WHEN last_seen <= ? AND ? != '' THEN ? ELSE discovery_method END,
			fingerprint_confidence = MAX(fingerprint_confidence, ?),
			eol_risk = CASE WHEN ? = 1 THEN 1 ELSE eol_risk END,
			eol_model = CASE WHEN ? != '' THEN ? ELSE eol_model END,
			risk_category = CASE WHEN risk_category = '' AND ? != '' THEN ? ELSE risk_category END,
			risk_model = CASE WHEN risk_model = '' AND ? != '' THEN ? ELSE risk_model END,
			risk_reasons = CASE WHEN risk_reasons IN ('', '[]') AND ? != '[]' THEN ? ELSE risk_reasons END
		WHERE device_id = ?`,
		scanTime, scanTime,
		scanTime, scanTime,
		scanTime, host.IPAddress,
		host.MACAddress, scanTime, host.MACAddress,
		finalHostname,
		finalVendor,
		finalModel,
		finalFriendly,
		scanTime, displayName,
		finalDeviceType,
		finalOSFamily,
		fpResult.OSVersion,
		scanTime, seg,
		scanTime, marshalPorts(host.OpenPorts), marshalPorts(host.OpenPorts),
		scanTime, string(servicesJSON), string(servicesJSON),
		scanTime, firstNonEmpty(host.DiscoverySource, ""), firstNonEmpty(host.DiscoverySource, ""),
		fpResult.FingerprintConfidence,
		boolToInt(fpResult.EOLRisk),
		fpResult.EOLModel, fpResult.EOLModel,
		fpResult.RiskCategory, fpResult.RiskCategory,
		fpResult.RiskModel, fpResult.RiskModel,
		string(riskReasonsJSON), string(riskReasonsJSON),
		deviceID,
	); err != nil {
		return false, fmt.Errorf("update device: %w", err)
	}

	// Temporal address ownership is authoritative for event-time resolution.
	// Current devices.ip_address remains only a compatibility projection.
	addressConfidence := ConfidenceForSource(sigSource)
	if addressConfidence < 0.55 {
		addressConfidence = 0.55
	}
	if sensorID != "" && addressConfidence < 0.75 {
		addressConfidence = 0.75
	}
	if err := db.recordAddressBindingTx(tx, deviceID, "ip", host.IPAddress, seg, sensorID,
		firstNonEmpty(host.DiscoverySource, "device_observation"), addressConfidence, scanTime); err != nil {
		return false, err
	}
	if err := db.recordAddressBindingTx(tx, deviceID, "mac", host.MACAddress, seg, sensorID,
		firstNonEmpty(host.DiscoverySource, "device_observation"), 0.95, scanTime); err != nil {
		return false, err
	}

	if host.MACAddress != "" {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "mac", Value: host.MACAddress,
			Source: firstNonEmpty(host.DiscoverySource, "device_observation"), Confidence: 0.95, Sensitive: true})
		if oui := identityOUI(host.MACAddress); oui != "" {
			evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "oui", Value: oui,
				Source: SourceOUI, Confidence: 0.2})
		}
	}
	if host.Hostname != "" && !IsGenericHostname(host.Hostname) {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "hostname", Value: host.Hostname,
			Source: firstNonEmpty(host.DiscoverySource, "device_observation"), Confidence: 0.65, Sensitive: true})
	}
	if mdnsName != "" {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "mdns_name", Value: mdnsName,
			Source: SourceMDNSTxt, Confidence: 0.75, Sensitive: true})
	}
	for _, service := range host.Services {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "mdns_service", Value: service,
			DisplayValue: service, Source: SourceMDNSPtr, Confidence: 0.45})
	}
	for _, item := range evidence {
		if _, err := db.upsertIdentityEvidenceTx(tx, deviceID, seg, sensorID, item, scanTime, false); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit upsert tx: %w", err)
	}
	return isNew, nil
}

// marshalPorts returns a JSON array string for open ports ("[]" when empty).
func marshalPorts(ports []int) string {
	if len(ports) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(ports)
	return string(b)
}

// firstNonEmpty returns the first non-empty string among its arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ListDevices returns all devices, ordered by last_seen descending. Each device
// is enriched with its multi-segment attachments and per-field provenance
// signals (spec 004).
func (db *DB) ListDevices() ([]models.Device, error) {
	rows, err := db.Query(`
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, ''),
		       COALESCE(risk_category, ''), COALESCE(risk_model, ''), COALESCE(risk_reasons, '[]'),
		       COALESCE(services, '[]'), COALESCE(display_name, ''), COALESCE(friendly_name, '')
		FROM devices WHERE merged_into_device_id IS NULL ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var d models.Device
		var portsJSON, servicesJSON, riskReasonsJSON string
		err := rows.Scan(&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
			&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
			&d.DiscoveryMethod, &d.FingerprintConfidence,
			&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel,
			&d.RiskCategory, &d.RiskModel, &riskReasonsJSON, &servicesJSON,
			&d.DisplayName, &d.FriendlyName)
		if err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
		json.Unmarshal([]byte(riskReasonsJSON), &d.RiskReasons)
		json.Unmarshal([]byte(servicesJSON), &d.Services)
		// Fallback parse from notes if services column not yet populated (from sensor passive data for actionability)
		if len(d.Services) == 0 && d.Notes != "" {
			var n map[string]any
			if json.Unmarshal([]byte(d.Notes), &n) == nil {
				if svcs, ok := n["services"]; ok {
					if s, ok := svcs.([]interface{}); ok {
						for _, v := range s {
							if str, ok := v.(string); ok {
								d.Services = append(d.Services, str)
							}
						}
					}
				}
			}
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range devices {
		db.attachCorrelation(&devices[i])
	}
	return devices, nil
}

// attachCorrelation populates the spec-004 Segments + Signals fields on a device
// (best-effort; errors leave the slices empty rather than failing the read).
func (db *DB) attachCorrelation(d *models.Device) {
	d.CanonicalDeviceID = d.DeviceID
	if segs, err := db.GetDeviceSegments(d.DeviceID); err == nil {
		d.Segments = segs
	}
	if sigs, err := db.GetDeviceSignals(d.DeviceID); err == nil && len(sigs) > 0 {
		out := make([]models.DeviceSignal, 0, len(sigs))
		best := make(map[string]DeviceSignalRow)
		for _, s := range sigs {
			out = append(out, models.DeviceSignal{
				Field: s.Field, Value: s.Value, Source: s.Source,
				Confidence: s.Confidence, LastObserved: s.LastObserved,
			})
			current, ok := best[s.Field]
			if !ok || s.Confidence > current.Confidence ||
				(s.Confidence == current.Confidence && s.LastObserved.After(current.LastObserved)) {
				best[s.Field] = s
			}
		}
		d.Signals = out
		// A soft merge is a pure redirect. Aggregate redirected children's
		// signals at read time so the canonical inventory is useful without
		// irreversibly copying values into the target row.
		if s := best["vendor"]; s.Value != "" {
			d.Vendor = s.Value
		}
		if s := best["model"]; s.Value != "" {
			d.Model = s.Value
		}
		if s := best["hostname"]; s.Value != "" {
			d.Hostname = s.Value
		}
		if s := best["friendly_name"]; s.Value != "" {
			d.FriendlyName = s.Value
		}
		if s := best["device_type"]; s.Value != "" {
			d.DeviceType = s.Value
		}
		if s := best["os_family"]; s.Value != "" {
			d.OSFamily = s.Value
		}
		d.DisplayName = deriveDisplayName(d.CustomName, d.FriendlyName, d.Model, d.Vendor,
			d.Hostname, d.MACAddress, d.IPAddress)
	}
	if err := db.attachIdentitySummary(d); err != nil {
		// Inventory reads should remain available if the identity projection is
		// temporarily unavailable, but must never look confidently identified.
		d.IdentityConfidence = 0
		d.IdentityStatus = "unresolved"
		d.IdentityReason = "identity_summary_unavailable"
		d.NeedsIdentification = true
	}
}

// GetDeviceByIP returns a device matching the given IP address.
func (db *DB) GetDeviceByIP(ip string) (*models.Device, error) {
	var d models.Device
	var portsJSON, riskReasonsJSON, servicesJSON string
	err := db.QueryRow(`
		WITH RECURSIVE redirect(device_id, depth) AS (
			SELECT (SELECT device_id FROM devices WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1), 0
			UNION ALL
			SELECT d.merged_into_device_id, redirect.depth + 1
			FROM devices d JOIN redirect ON d.device_id = redirect.device_id
			WHERE d.merged_into_device_id IS NOT NULL AND redirect.depth < 31
		)
		SELECT device_id, first_seen, last_seen, ip_address, mac_address,
		       COALESCE(hostname, ''), COALESCE(vendor, ''), COALESCE(open_ports, '[]'), segment,
		       COALESCE(device_type, ''), COALESCE(os_family, ''), COALESCE(os_version, ''),
		       COALESCE(model, ''), COALESCE(discovery_method, 'nmap_active'),
		       COALESCE(fingerprint_confidence, 0.0),
		       COALESCE(custom_name, ''), COALESCE(notes, ''),
		       COALESCE(eol_risk, 0), COALESCE(eol_model, ''),
		       COALESCE(risk_category, ''), COALESCE(risk_model, ''), COALESCE(risk_reasons, '[]'),
		       COALESCE(services, '[]'), COALESCE(display_name, ''), COALESCE(friendly_name, '')
		FROM devices WHERE device_id = (
			SELECT device_id FROM redirect WHERE device_id IS NOT NULL ORDER BY depth DESC LIMIT 1
		)`, ip).Scan(
		&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
		&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
		&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
		&d.DiscoveryMethod, &d.FingerprintConfidence,
		&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel,
		&d.RiskCategory, &d.RiskModel, &riskReasonsJSON, &servicesJSON,
		&d.DisplayName, &d.FriendlyName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query device by ip: %w", err)
	}
	json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
	json.Unmarshal([]byte(riskReasonsJSON), &d.RiskReasons)
	json.Unmarshal([]byte(servicesJSON), &d.Services)
	// Fallback from notes
	if len(d.Services) == 0 && d.Notes != "" {
		var n map[string]any
		if json.Unmarshal([]byte(d.Notes), &n) == nil {
			if svcs, ok := n["services"]; ok {
				if s, ok := svcs.([]interface{}); ok {
					for _, v := range s {
						if str, ok := v.(string); ok {
							d.Services = append(d.Services, str)
						}
					}
				}
			}
		}
	}
	db.attachCorrelation(&d)
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
// These corrections take absolute priority: each corrected field is written as a
// user_corrected signal at confidence 1.0, which locks it against automatic
// overwrite in later upserts (spec 004 FR-6, generalizing the old
// discovery_method='user_corrected' behavior to per-field). The canonical
// devices row and display_name are recomputed after the correction.
func (db *DB) UpdateDeviceFingerprint(deviceID, deviceType, osFamily, osVersion, model string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin fingerprint correction tx: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	var sigs []signalUpsert
	if deviceType != "" {
		sigs = append(sigs, signalUpsert{field: "device_type", value: deviceType, source: SourceUserCorrected, confidence: 1.0})
	}
	if osFamily != "" {
		sigs = append(sigs, signalUpsert{field: "os_family", value: osFamily, source: SourceUserCorrected, confidence: 1.0})
	}
	if model != "" {
		sigs = append(sigs, signalUpsert{field: "model", value: model, source: SourceUserCorrected, confidence: 1.0})
	}
	if err := db.upsertSignalsTx(tx, deviceID, sigs, now); err != nil {
		return err
	}

	// Direct column write preserves prior behavior (os_version has no signal field;
	// still COALESCE-updated) and stamps discovery_method for legacy consumers.
	if _, err := tx.Exec(`
		UPDATE devices SET device_type = COALESCE(NULLIF(?, ''), device_type),
		                    os_family = COALESCE(NULLIF(?, ''), os_family),
		                    os_version = COALESCE(NULLIF(?, ''), os_version),
		                    model = COALESCE(NULLIF(?, ''), model),
		                    discovery_method = 'user_corrected'
		WHERE device_id = ?`,
		deviceType, osFamily, osVersion, model, deviceID); err != nil {
		return fmt.Errorf("update device fingerprint: %w", err)
	}

	// Recompute display_name honoring custom_name / corrected model.
	var customName, friendlyName, curModel, curVendor, curHostname, curMAC, curIP string
	if err := tx.QueryRow(`
		SELECT COALESCE(custom_name,''), COALESCE(friendly_name,''), COALESCE(model,''),
		       COALESCE(vendor,''), COALESCE(hostname,''), COALESCE(mac_address,''), COALESCE(ip_address,'')
		FROM devices WHERE device_id = ?`, deviceID).Scan(
		&customName, &friendlyName, &curModel, &curVendor, &curHostname, &curMAC, &curIP); err != nil {
		return fmt.Errorf("read device for display_name recompute: %w", err)
	}
	displayName := deriveDisplayName(customName, friendlyName, curModel, curVendor, curHostname, curMAC, curIP)
	if _, err := tx.Exec(`UPDATE devices SET display_name = ? WHERE device_id = ?`, displayName, deviceID); err != nil {
		return fmt.Errorf("update display_name: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fingerprint correction: %w", err)
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
		       COALESCE(eol_risk, 0), COALESCE(eol_model, ''),
		       COALESCE(risk_category, ''), COALESCE(risk_model, ''), COALESCE(risk_reasons, '[]'),
		       COALESCE(display_name, ''), COALESCE(friendly_name, '')
		FROM devices WHERE merged_into_device_id IS NULL AND first_seen > ? ORDER BY first_seen DESC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query new devices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var d models.Device
		var portsJSON, riskReasonsJSON string
		err := rows.Scan(&d.DeviceID, &d.FirstSeen, &d.LastSeen, &d.IPAddress,
			&d.MACAddress, &d.Hostname, &d.Vendor, &portsJSON, &d.Segment,
			&d.DeviceType, &d.OSFamily, &d.OSVersion, &d.Model,
			&d.DiscoveryMethod, &d.FingerprintConfidence,
			&d.CustomName, &d.Notes, &d.EOLRisk, &d.EOLModel,
			&d.RiskCategory, &d.RiskModel, &riskReasonsJSON,
			&d.DisplayName, &d.FriendlyName)
		if err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		json.Unmarshal([]byte(portsJSON), &d.OpenPorts)
		json.Unmarshal([]byte(riskReasonsJSON), &d.RiskReasons)
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range devices {
		db.attachCorrelation(&devices[i])
	}
	return devices, nil
}

// CountDevices returns total device count.
func (db *DB) CountDevices() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM devices WHERE merged_into_device_id IS NULL").Scan(&count)
	return count, err
}

// CountDevicesNewSince returns count of devices first seen within the given duration.
func (db *DB) CountDevicesNewSince(d time.Duration) (int, error) {
	var count int
	cutoff := time.Now().UTC().Add(-d)
	err := db.QueryRow("SELECT COUNT(*) FROM devices WHERE merged_into_device_id IS NULL AND first_seen > ?", cutoff).Scan(&count)
	return count, err
}

// CountDevicesBySegment returns count of devices in a specific segment (e.g. "iot").
func (db *DB) CountDevicesBySegment(segment string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM devices WHERE merged_into_device_id IS NULL AND segment = ?", segment).Scan(&count)
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
