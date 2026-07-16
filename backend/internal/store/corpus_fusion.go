package store

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

const (
	corpusSignalRecency           = 30 * 24 * time.Hour
	corpusProjectionGenerationKey = "device_corpus_projection_generation"
)

// corpusObservedSignals projects a discovery observation into the corpus shape vocabulary so
// the local matcher can compare it against curated device-class shapes. Hostname templates are
// intentionally not populated here — matching a concrete hostname to a template is pattern
// work, out of scope for this cut; the other signal families carry recognition.
func corpusObservedSignals(host discovery.DiscoveredHost) corpusmatch.ObservedSignals {
	obs := corpusmatch.ObservedSignals{
		TCPPorts: portsToUint16(host.OpenPorts),
	}
	if host.MACAddress != "" {
		obs.OUIPrefixes = []string{host.MACAddress} // the matcher normalizes to a 24-bit prefix
	}
	source := strings.ToLower(strings.TrimSpace(host.DiscoverySource))
	switch source {
	case "passive_mdns", "mdns":
		obs.MDNSServices = append(obs.MDNSServices, host.Services...)
		if host.Model != "" {
			obs.MDNSModels = append(obs.MDNSModels, host.Model)
		}
		if host.Vendor != "" {
			obs.MDNSVendors = append(obs.MDNSVendors, host.Vendor)
		}
	case "passive_ssdp", "ssdp":
		if host.Vendor != "" {
			obs.SSDPServerTokens = append(obs.SSDPServerTokens, host.Vendor)
		}
	case "passive_dhcp", "dhcp":
		if host.Vendor != "" {
			obs.DHCPVendorClasses = append(obs.DHCPVendorClasses, host.Vendor)
		}
	}
	for _, ev := range host.IdentityEvidence {
		switch ev.Type {
		case "mdns_service":
			if source == "passive_mdns" || source == "mdns" {
				obs.MDNSServices = append(obs.MDNSServices, ev.Value)
			}
		case "mdns_txt_model":
			if source == "passive_mdns" || source == "mdns" {
				obs.MDNSModels = append(obs.MDNSModels, ev.Value)
			}
		case "mdns_txt_vendor":
			if source == "passive_mdns" || source == "mdns" {
				obs.MDNSVendors = append(obs.MDNSVendors, ev.Value)
			}
		case "ssdp_device_type":
			if source == "passive_ssdp" || source == "ssdp" {
				obs.SSDPDeviceTypes = append(obs.SSDPDeviceTypes, ev.Value)
			}
		case "ssdp_server_token":
			if source == "passive_ssdp" || source == "ssdp" {
				obs.SSDPServerTokens = append(obs.SSDPServerTokens, ev.Value)
			}
		case "dhcp_vendor_class":
			if source == "passive_dhcp" || source == "dhcp" {
				obs.DHCPVendorClasses = append(obs.DHCPVendorClasses, ev.Value)
			}
		case "dhcp_option_55":
			if source == "passive_dhcp" || source == "dhcp" {
				obs.DHCPOption55 = parseOption55(ev.Value)
			}
		}
	}
	return obs
}

// corpusObservedSignalsTx combines the current report with safe, already-correlated local
// device state. This is what lets a MAC/OUI report and a later mDNS report satisfy the
// two-family rule without recovering HMAC-only identity values. Corpus-derived rows are never
// read back, preventing a prior match from sustaining itself.
func (db *DB) corpusObservedSignalsTx(tx *sql.Tx, deviceID string, host discovery.DiscoveredHost, observedAt time.Time) (corpusmatch.ObservedSignals, error) {
	obs := corpusObservedSignals(host)
	cutoff := observedAt.UTC().Add(-corpusSignalRecency)
	protocolCutoff := observedAt.UTC().Add(-mdnsNameRecencyWindow)

	rows, err := tx.Query(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT DISTINCT h.address_value FROM device_address_history h
		WHERE h.device_id IN (SELECT device_id FROM family) AND h.address_type = 'mac'
		  AND h.valid_from <= ? AND (h.valid_until IS NULL OR ? < h.valid_until)`,
		deviceID, observedAt, observedAt)
	if err != nil {
		return obs, fmt.Errorf("read retained corpus signals: %w", err)
	}
	for rows.Next() {
		var macAddress string
		if err := rows.Scan(&macAddress); err != nil {
			rows.Close()
			return obs, fmt.Errorf("scan retained corpus address: %w", err)
		}
		obs.OUIPrefixes = append(obs.OUIPrefixes, macAddress)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return obs, fmt.Errorf("iterate retained corpus addresses: %w", err)
	}
	rows.Close()

	rows, err = tx.Query(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT field, value, source FROM device_signals
		WHERE device_id IN (SELECT device_id FROM family) AND source != ? AND first_observed <= ?
		  AND last_observed >= ? AND last_observed <= ?`,
		deviceID, SourceCorpus, observedAt, cutoff, observedAt)
	if err != nil {
		return obs, fmt.Errorf("read retained descriptive signals: %w", err)
	}
	for rows.Next() {
		var field, value, source string
		if err := rows.Scan(&field, &value, &source); err != nil {
			rows.Close()
			return obs, fmt.Errorf("scan retained descriptive signal: %w", err)
		}
		switch {
		case source == SourceMDNSTxt && field == "model":
			obs.MDNSModels = append(obs.MDNSModels, value)
		case source == SourceMDNSTxt && field == "vendor":
			obs.MDNSVendors = append(obs.MDNSVendors, value)
		case source == SourceSSDP && field == "vendor":
			obs.SSDPServerTokens = append(obs.SSDPServerTokens, value)
		case source == SourceDHCPHostname && field == "vendor":
			obs.DHCPVendorClasses = append(obs.DHCPVendorClasses, value)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return obs, fmt.Errorf("iterate retained descriptive signals: %w", err)
	}
	rows.Close()

	rows, err = tx.Query(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT evidence_type, value_display FROM device_identity_evidence
		WHERE device_id IN (SELECT device_id FROM family) AND value_display != ''
		  AND first_seen <= ? AND last_seen >= ?
		  AND valid_from <= ? AND (valid_until IS NULL OR ? < valid_until)
		  AND EXISTS (SELECT 1 FROM device_identity_evidence_validity v
		    WHERE v.evidence_id = device_identity_evidence.evidence_id
		      AND v.valid_from <= ? AND ? <= v.valid_until)
		  AND ((evidence_type = 'mdns_service' AND EXISTS
		    (SELECT 1 FROM device_identity_evidence_strength s
		      WHERE s.evidence_id = device_identity_evidence.evidence_id
		        AND s.source = 'passive_mdns' AND s.observed_at >= ? AND s.observed_at <= ?))
		    OR (evidence_type = 'ssdp_device_type' AND EXISTS
		    (SELECT 1 FROM device_identity_evidence_strength s
		      WHERE s.evidence_id = device_identity_evidence.evidence_id
		        AND s.source = 'passive_ssdp' AND s.observed_at >= ? AND s.observed_at <= ?)))`,
		deviceID, observedAt, cutoff, observedAt, observedAt, observedAt, observedAt,
		protocolCutoff, observedAt, protocolCutoff, observedAt)
	if err != nil {
		return obs, fmt.Errorf("read retained typed signals: %w", err)
	}
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			rows.Close()
			return obs, fmt.Errorf("scan retained typed signal: %w", err)
		}
		switch kind {
		case "mdns_service":
			obs.MDNSServices = append(obs.MDNSServices, value)
		case "ssdp_device_type":
			obs.SSDPDeviceTypes = append(obs.SSDPDeviceTypes, value)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return obs, fmt.Errorf("iterate retained typed signals: %w", err)
	}
	rows.Close()
	return obs, nil
}

// corpusDerivedSignals runs the active corpus matcher over an observation and returns the
// descriptive signal upserts for a class match. Confidence is capped by both SourceCorpus
// (below a device's own mDNS TXT and user_corrected) and the curated variant's confidence, so
// it cannot inflate a weak corpus claim. Returns nil when no corpus is loaded or nothing matches.
func corpusDerivedSignalsForObserved(obs corpusmatch.ObservedSignals) []signalUpsert {
	res, ok := corpusmatch.Active().Match(obs)
	if !ok {
		return nil
	}
	// Source trust is a ceiling, not a replacement for the curator's variant
	// confidence. A low-confidence corpus record must not become a 0.85 signal.
	conf := min(ConfidenceForSource(SourceCorpus), float64(res.ConfidenceBP)/10000)
	if conf <= 0 {
		return nil
	}
	var out []signalUpsert
	add := func(field, value string) {
		if value != "" {
			out = append(out, signalUpsert{field: field, value: value, source: SourceCorpus, confidence: conf})
		}
	}
	add("vendor", res.Manufacturer)
	add("model", res.Model)
	add("device_type", res.DeviceType)
	add("os_family", res.OSFamily)
	return out
}

func deleteCorpusSignalsTx(tx *sql.Tx, deviceID string) error {
	if _, err := tx.Exec(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		DELETE FROM device_signals WHERE source = ?
		  AND device_id IN (SELECT device_id FROM family)`, deviceID, SourceCorpus); err != nil {
		return fmt.Errorf("delete stale corpus signals: %w", err)
	}
	return nil
}

// ClearCorpusSignals removes every persisted corpus projection, records the unmanaged state,
// and recomputes affected device rows from non-corpus sources. Core calls this when no managed
// corpus can be activated, so disabling/removing the updater cannot leave quiet devices stale.
func (db *DB) ClearCorpusSignals() error {
	db.corpusProjectionMu.Lock()
	defer db.corpusProjectionMu.Unlock()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin corpus signal clear: %w", err)
	}
	defer tx.Rollback()
	if err := db.clearCorpusSignalsTx(tx); err != nil {
		return err
	}
	if err := setCorpusProjectionGenerationTx(tx, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit corpus signal clear: %w", err)
	}
	return nil
}

// ActivateCorpusGeneration reconciles persisted labels with the exact validated corpus bytes,
// then invokes an infallible process-state activation while device observations are excluded.
// An unchanged generation preserves quiet-device labels across restart; a changed/removed
// generation clears them. If reconciliation fails, activate is not called.
func (db *DB) ActivateCorpusGeneration(generation string, activate func()) error {
	if activate == nil {
		return fmt.Errorf("activate corpus generation: activation callback is required")
	}
	generation = strings.TrimSpace(generation)
	if generation == "" {
		return fmt.Errorf("activate corpus generation: generation ID is required")
	}
	db.corpusProjectionMu.Lock()
	defer db.corpusProjectionMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin corpus generation activation: %w", err)
	}
	defer tx.Rollback()
	var prior string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, corpusProjectionGenerationKey).Scan(&prior)
	switch err {
	case nil:
		if prior != generation {
			if err := db.clearCorpusSignalsTx(tx); err != nil {
				return err
			}
		}
	case sql.ErrNoRows:
		// First generation-aware startup: fail closed and discard any unversioned
		// projections left by an older binary before recording the active bytes.
		if err := db.clearCorpusSignalsTx(tx); err != nil {
			return err
		}
	default:
		return fmt.Errorf("read corpus projection generation: %w", err)
	}
	if err := setCorpusProjectionGenerationTx(tx, generation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit corpus generation activation: %w", err)
	}
	activate()
	return nil
}

func (db *DB) clearCorpusSignalsTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT DISTINCT device_id FROM device_signals WHERE source = ?`, SourceCorpus)
	if err != nil {
		return fmt.Errorf("list corpus signal devices: %w", err)
	}
	var deviceIDs []string
	for rows.Next() {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			rows.Close()
			return fmt.Errorf("scan corpus signal device: %w", err)
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate corpus signal devices: %w", err)
	}
	rows.Close()
	if _, err := tx.Exec(`DELETE FROM device_signals WHERE source = ?`, SourceCorpus); err != nil {
		return fmt.Errorf("clear corpus signals: %w", err)
	}

	affected := make(map[string]struct{}, len(deviceIDs)*2)
	for _, deviceID := range deviceIDs {
		affected[deviceID] = struct{}{}
		canonicalID, err := db.canonicalDeviceIDTx(tx, deviceID)
		if err != nil {
			return fmt.Errorf("resolve corpus projection owner: %w", err)
		}
		affected[canonicalID] = struct{}{}
	}
	for deviceID := range affected {
		canonical, err := db.resolveCanonicalFields(tx, deviceID)
		if err != nil {
			return err
		}
		var customName, friendlyName, hostname, macAddress, ipAddress string
		if err := tx.QueryRow(`SELECT COALESCE(custom_name, ''), COALESCE(friendly_name, ''),
			COALESCE(hostname, ''), COALESCE(mac_address, ''), COALESCE(ip_address, '')
			FROM devices WHERE device_id = ?`, deviceID).
			Scan(&customName, &friendlyName, &hostname, &macAddress, &ipAddress); err != nil {
			return fmt.Errorf("read device for corpus projection clear: %w", err)
		}
		vendor := canonical["vendor"].value
		model := canonical["model"].value
		deviceType := canonical["device_type"].value
		osFamily := canonical["os_family"].value
		displayName := deriveDisplayName(customName, friendlyName, model, vendor, hostname, macAddress, ipAddress)
		if _, err := tx.Exec(`UPDATE devices SET vendor = ?, model = ?, device_type = ?,
			os_family = ?, display_name = ? WHERE device_id = ?`,
			vendor, model, deviceType, osFamily, displayName, deviceID); err != nil {
			return fmt.Errorf("clear device corpus projection: %w", err)
		}
	}
	return nil
}

func setCorpusProjectionGenerationTx(tx *sql.Tx, generation string) error {
	if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		corpusProjectionGenerationKey, generation); err != nil {
		return fmt.Errorf("write corpus projection generation: %w", err)
	}
	return nil
}

func portsToUint16(ports []int) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			out = append(out, uint16(p))
		}
	}
	return out
}

// parseOption55 extracts the DHCP option-55 parameter-request codes from an evidence value,
// preserving order (the sequence is the fingerprint). Any non-digit separates codes.
func parseOption55(v string) []uint16 {
	var out []uint16
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' }) {
		if n, err := strconv.Atoi(tok); err == nil && n >= 1 && n <= 254 {
			out = append(out, uint16(n))
		}
	}
	return out
}
