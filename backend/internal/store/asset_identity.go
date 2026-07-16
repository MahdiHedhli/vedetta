package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

const identityHMACSetting = "asset_identity_hmac_key_v1"

const temporalAddressResolutionWindow = 24 * time.Hour

var maxSQLiteIdentityTime = time.Date(9999, 12, 31, 23, 59, 59, 999*int(time.Millisecond), time.UTC)

// DeviceIdentityEvidenceInput is a raw, in-memory observation. Value is HMACed
// inside the Core transaction before persistence. Callers must never place it
// in event metadata or logs.
type DeviceIdentityEvidenceInput struct {
	Type         string         `json:"type"`
	Value        string         `json:"value"`
	Source       string         `json:"source,omitempty"`
	Confidence   float64        `json:"confidence,omitempty"`
	Sensitive    bool           `json:"sensitive,omitempty"`
	DisplayValue string         `json:"display_value,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// DeviceObservation threads the authenticated sensor and temporal network
// context through inventory correlation. UpsertDevice remains as a legacy
// wrapper for older callers.
type DeviceObservation struct {
	Host             discovery.DiscoveredHost
	Segment          string
	SensorID         string
	ObservedAt       time.Time
	Evidence         []DeviceIdentityEvidenceInput
	DeliveryEpoch    string
	DeliverySequence uint64

	// expectedARPCache is an internal compare-and-set guard used only when Core
	// turns a separate cache row into native_icmp_arp evidence. It prevents a
	// newer ambiguity transition from racing into the transaction split between
	// the cache-state write and the normal identity pipeline. Direct sensor-side
	// native_icmp_arp observations do not use or need this guard.
	expectedARPCache *arpCacheExpectation
}

// DeviceIdentityResolutionRequest contains only evidence valid for one event.
// Resolution never consults devices.ip_address as historical truth.
type DeviceIdentityResolutionRequest struct {
	Timestamp  time.Time
	IPAddress  string
	MACAddress string
	Segment    string
	SensorID   string
	Evidence   []DeviceIdentityEvidenceInput
}

// DeviceIdentityResolution is safe to attach to an event. Evidence contains
// reason/type summaries, never raw sensitive identity values.
type DeviceIdentityResolution struct {
	DeviceID   string  `json:"device_id,omitempty"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Evidence   string  `json:"evidence"`
}

// DeviceIdentityAction is the durable audit record returned by confirm/merge/split.
type DeviceIdentityAction struct {
	ActionID         string    `json:"action_id"`
	ActionType       string    `json:"action_type"`
	SourceDeviceID   string    `json:"source_device_id,omitempty"`
	TargetDeviceID   string    `json:"target_device_id,omitempty"`
	EvidenceID       string    `json:"evidence_id,omitempty"`
	Actor            string    `json:"actor"`
	Reason           string    `json:"reason"`
	CreatedAt        time.Time `json:"created_at"`
	UndoneByActionID string    `json:"undone_by_action_id,omitempty"`
}

func normalizeIdentityValue(kind, value string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	switch kind {
	case "mac":
		if mac, err := net.ParseMAC(value); err == nil {
			return strings.ToUpper(mac.String())
		}
	case "ip", "ipv4", "ipv6":
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	case "hostname", "mdns_name":
		return strings.ToLower(strings.TrimSuffix(value, "."))
	}
	return value
}

func normalizeSegment(segment string) string {
	if segment = strings.TrimSpace(segment); segment != "" {
		return segment
	}
	return "default"
}

func clampIdentityConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func (db *DB) identityHMACKeyTx(tx *sql.Tx) ([]byte, error) {
	var encoded string
	err := tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, identityHMACSetting).Scan(&encoded)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read identity HMAC key: %w", err)
	}
	if err == sql.ErrNoRows {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate identity HMAC key: %w", err)
		}
		encoded = hex.EncodeToString(key)
		if _, err := tx.Exec(`INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES (?, ?, ?)`,
			identityHMACSetting, encoded, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("persist identity HMAC key: %w", err)
		}
		// Another writer may have won INSERT OR IGNORE. Always use the stored key.
		if err := tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, identityHMACSetting).Scan(&encoded); err != nil {
			return nil, fmt.Errorf("reload identity HMAC key: %w", err)
		}
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("identity HMAC key is invalid")
	}
	return key, nil
}

func (db *DB) ensureIdentityHMACKey() error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin identity HMAC key ensure: %w", err)
	}
	defer tx.Rollback()
	if _, err := db.identityHMACKeyTx(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit identity HMAC key ensure: %w", err)
	}
	_, err = db.identityHMACKeyCached()
	return err
}

// identityHMACKeyCached serves the hot event-source hashing path without a
// SQLite transaction per event. The key is generated/persisted during Open;
// only an in-memory copy is cached and it never leaves Core.
func (db *DB) identityHMACKeyCached() ([]byte, error) {
	db.identityKeyMu.RLock()
	if len(db.identityKey) == 32 {
		key := append([]byte(nil), db.identityKey...)
		db.identityKeyMu.RUnlock()
		return key, nil
	}
	db.identityKeyMu.RUnlock()

	var encoded string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, identityHMACSetting).Scan(&encoded); err != nil {
		return nil, fmt.Errorf("read cached identity HMAC key: %w", err)
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("identity HMAC key is invalid")
	}
	db.identityKeyMu.Lock()
	if len(db.identityKey) != 32 {
		db.identityKey = append([]byte(nil), key...)
	}
	cached := append([]byte(nil), db.identityKey...)
	db.identityKeyMu.Unlock()
	return cached, nil
}

func identityValueHMAC(key []byte, kind, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(kind))))
	mac.Write([]byte{0})
	mac.Write([]byte(normalizeIdentityValue(kind, value)))
	return hex.EncodeToString(mac.Sum(nil))
}

// identityDisplayValue is intentionally a narrow allowlist. Stable identifiers,
// hostnames, DHCP fingerprints/client IDs, MACs, and UUIDs stay HMAC-only.
func identityDisplayValue(in DeviceIdentityEvidenceInput) string {
	switch strings.ToLower(strings.TrimSpace(in.Type)) {
	case "mdns_service", "ssdp_device_type":
		return strings.TrimSpace(firstNonEmpty(in.DisplayValue, in.Value))
	default:
		return ""
	}
}

// recordIdentityEvidenceStrengthTx appends only changes to the strength known at
// observedAt. The parent evidence row remains the best/current aggregate for
// inventory compatibility; event-time resolution reads this history instead.
func recordIdentityEvidenceStrengthTx(tx *sql.Tx, evidenceID, source string, confidence float64,
	operatorConfirmed bool, observedAt time.Time) error {
	observedAt = observedAt.UTC()
	confidence = clampIdentityConfidence(confidence)
	source = strings.TrimSpace(source)

	var priorConfidence sql.NullFloat64
	var priorConfirmed int
	if err := tx.QueryRow(`SELECT MAX(confidence),
		COALESCE(MAX(CASE WHEN operator_confirmed THEN 1 ELSE 0 END), 0)
		FROM device_identity_evidence_strength
		WHERE evidence_id = ? AND observed_at <= ?`, evidenceID, observedAt).
		Scan(&priorConfidence, &priorConfirmed); err != nil {
		return fmt.Errorf("read identity evidence strength history: %w", err)
	}
	if priorConfidence.Valid && confidence <= priorConfidence.Float64 && (!operatorConfirmed || priorConfirmed != 0) {
		return nil
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO device_identity_evidence_strength
		(evidence_id, observed_at, source, confidence, operator_confirmed, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, evidenceID, observedAt, source, confidence,
		operatorConfirmed, time.Now().UTC()); err != nil {
		return fmt.Errorf("record identity evidence strength: %w", err)
	}
	return nil
}

// recordAddressBindingStrengthTx is the address-binding counterpart to
// recordIdentityEvidenceStrengthTx. Repeated scans at the same or lower
// effective confidence do not grow the history.
func recordAddressBindingStrengthTx(tx *sql.Tx, bindingID, source string, confidence float64,
	observedAt time.Time) error {
	observedAt = observedAt.UTC()
	confidence = clampIdentityConfidence(confidence)
	source = strings.TrimSpace(source)

	var priorConfidence sql.NullFloat64
	if err := tx.QueryRow(`SELECT MAX(confidence)
		FROM device_address_binding_strength
		WHERE binding_id = ? AND observed_at <= ?`, bindingID, observedAt).
		Scan(&priorConfidence); err != nil {
		return fmt.Errorf("read address binding strength history: %w", err)
	}
	if priorConfidence.Valid && confidence <= priorConfidence.Float64 {
		return nil
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO device_address_binding_strength
		(binding_id, observed_at, source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?)`, bindingID, observedAt, source, confidence, time.Now().UTC()); err != nil {
		return fmt.Errorf("record address binding strength: %w", err)
	}
	return nil
}

// mergeValidityWindowTx stores the exact union of observation-freshness
// windows without writing one row per poll. Repeated observations inside a
// continuous interval extend/merge that interval; observations separated by a
// real stale gap remain separate so historical resolution cannot be changed by
// a later refresh.
func mergeValidityWindowTx(tx *sql.Tx, table, parentColumn, parentID string,
	validFrom, validUntil time.Time) error {
	if (table != "device_address_binding_validity" || parentColumn != "binding_id") &&
		(table != "device_identity_evidence_validity" || parentColumn != "evidence_id") {
		return fmt.Errorf("invalid identity validity table %q", table)
	}
	validFrom = validFrom.UTC()
	validUntil = validUntil.UTC()
	if validUntil.Before(validFrom) {
		return fmt.Errorf("invalid identity validity window: %s before %s", validUntil, validFrom)
	}

	mergedFrom, mergedUntil := validFrom, validUntil
	query := fmt.Sprintf(`SELECT valid_from, valid_until FROM %s
		WHERE %s = ? AND valid_from <= ? AND valid_until >= ?`, table, parentColumn)
	// Query only the connected component that can overlap this observation. A
	// parent can legitimately accumulate many disjoint historical windows, so
	// loading every row on every poll would make the hot path O(total history).
	// Runtime writes keep components compact; another pass is needed only to
	// self-heal a legacy/corrupt chain whose next edge becomes reachable after
	// expanding the current bounds.
	firstPass := true
	for {
		rows, err := tx.Query(query, parentID, mergedUntil, mergedFrom)
		if err != nil {
			return fmt.Errorf("read %s windows: %w", table, err)
		}
		expanded := false
		rowCount := 0
		contained := false
		for rows.Next() {
			rowCount++
			var fromRaw, untilRaw any
			if err := rows.Scan(&fromRaw, &untilRaw); err != nil {
				rows.Close()
				return fmt.Errorf("scan %s window: %w", table, err)
			}
			from, err := parseSQLiteTime(fromRaw)
			if err != nil {
				rows.Close()
				return fmt.Errorf("parse %s valid_from: %w", table, err)
			}
			until, err := parseSQLiteTime(untilRaw)
			if err != nil {
				rows.Close()
				return fmt.Errorf("parse %s valid_until: %w", table, err)
			}
			if from.Before(mergedFrom) {
				mergedFrom = from.UTC()
				expanded = true
			}
			if until.After(mergedUntil) {
				mergedUntil = until.UTC()
				expanded = true
			}
			if !from.After(validFrom) && !until.Before(validUntil) {
				contained = true
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate %s window rows: %w", table, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close %s window rows: %w", table, err)
		}
		if firstPass && rowCount == 1 && contained {
			return nil
		}
		firstPass = false
		if !expanded {
			break
		}
	}

	deleteSQL := fmt.Sprintf(`DELETE FROM %s
		WHERE %s = ? AND valid_from <= ? AND valid_until >= ?`, table, parentColumn)
	if _, err := tx.Exec(deleteSQL, parentID, mergedUntil, mergedFrom); err != nil {
		return fmt.Errorf("merge %s windows: %w", table, err)
	}
	insertSQL := fmt.Sprintf(`INSERT INTO %s
		(%s, valid_from, valid_until, created_at) VALUES (?, ?, ?, ?)`, table, parentColumn)
	if _, err := tx.Exec(insertSQL, parentID, mergedFrom, mergedUntil, time.Now().UTC()); err != nil {
		return fmt.Errorf("record %s window: %w", table, err)
	}
	return nil
}

func recordIdentityEvidenceValidityTx(tx *sql.Tx, evidenceID string, observedAt time.Time) error {
	validUntil, err := identityFreshnessEnd(observedAt, mdnsNameRecencyWindow)
	if err != nil {
		return err
	}
	return mergeValidityWindowTx(tx, "device_identity_evidence_validity", "evidence_id", evidenceID,
		observedAt, validUntil)
}

func recordAddressBindingValidityTx(tx *sql.Tx, bindingID string, observedAt time.Time) error {
	validUntil, err := identityFreshnessEnd(observedAt, temporalAddressResolutionWindow)
	if err != nil {
		return err
	}
	return mergeValidityWindowTx(tx, "device_address_binding_validity", "binding_id", bindingID,
		observedAt, validUntil)
}

func identityFreshnessEnd(observedAt time.Time, window time.Duration) (time.Time, error) {
	observedAt = observedAt.UTC()
	if observedAt.After(maxSQLiteIdentityTime) {
		return time.Time{}, fmt.Errorf("identity observation time %s exceeds SQLite timestamp limit", observedAt)
	}
	if observedAt.After(maxSQLiteIdentityTime.Add(-window)) {
		return maxSQLiteIdentityTime, nil
	}
	return observedAt.Add(window), nil
}

func (db *DB) upsertIdentityEvidenceTx(tx *sql.Tx, deviceID, segment, sensorID string,
	in DeviceIdentityEvidenceInput, observedAt time.Time, operatorConfirmed bool) (string, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Type))
	value := normalizeIdentityValue(kind, in.Value)
	if !supportedIdentityEvidenceType(kind) || value == "" {
		return "", nil
	}
	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return "", err
	}
	valueHash := identityValueHMAC(key, kind, value)
	segment = normalizeSegment(segment)
	sensorID = strings.TrimSpace(sensorID)
	confidence := clampIdentityConfidence(in.Confidence)
	if operatorConfirmed {
		confidence = 1
	}
	// Do not persist caller-supplied identity metadata in v1. It is not needed
	// for resolution and could otherwise become a side channel that bypasses the
	// HMAC-only value column. Add future metadata keys through an explicit local
	// allowlist rather than accepting an arbitrary map.
	meta := []byte("{}")

	var evidenceID string
	err = tx.QueryRow(`SELECT evidence_id FROM device_identity_evidence
		WHERE device_id = ? AND evidence_type = ? AND value_hmac = ? AND segment = ? AND sensor_id = ?`,
		deviceID, kind, valueHash, segment, sensorID).Scan(&evidenceID)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("find identity evidence: %w", err)
	}
	if err == sql.ErrNoRows {
		evidenceID = uuid.New().String()
		_, err = tx.Exec(`INSERT INTO device_identity_evidence
			(evidence_id, device_id, evidence_type, value_hmac, value_display, segment, sensor_id,
			 source, confidence, first_seen, last_seen, valid_from, valid_until,
			 operator_confirmed, metadata, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
			evidenceID, deviceID, kind, valueHash, identityDisplayValue(in), segment, sensorID,
			strings.TrimSpace(in.Source), confidence, observedAt, observedAt, observedAt,
			operatorConfirmed, string(meta), time.Now().UTC())
		if err != nil {
			return "", fmt.Errorf("insert identity evidence: %w", err)
		}
		if err := recordIdentityEvidenceStrengthTx(tx, evidenceID, in.Source, confidence,
			operatorConfirmed, observedAt); err != nil {
			return "", err
		}
		if err := recordIdentityEvidenceValidityTx(tx, evidenceID, observedAt); err != nil {
			return "", err
		}
		return evidenceID, nil
	}
	if err := recordIdentityEvidenceStrengthTx(tx, evidenceID, in.Source, confidence,
		operatorConfirmed, observedAt); err != nil {
		return "", err
	}
	if err := recordIdentityEvidenceValidityTx(tx, evidenceID, observedAt); err != nil {
		return "", err
	}

	_, err = tx.Exec(`UPDATE device_identity_evidence SET
		last_seen = CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
		first_seen = CASE WHEN first_seen > ? THEN ? ELSE first_seen END,
		valid_from = CASE WHEN valid_from > ? THEN ? ELSE valid_from END,
		source = CASE WHEN ? > confidence AND TRIM(?) != '' THEN ? ELSE source END,
		confidence = MAX(confidence, ?),
		operator_confirmed = CASE WHEN ? THEN TRUE ELSE operator_confirmed END,
		metadata = CASE WHEN ? != '{}' THEN ? ELSE metadata END,
		value_display = CASE WHEN value_display = '' THEN ? ELSE value_display END
		WHERE evidence_id = ?`,
		observedAt, observedAt, observedAt, observedAt,
		observedAt, observedAt,
		confidence, strings.TrimSpace(in.Source), strings.TrimSpace(in.Source),
		confidence, operatorConfirmed,
		string(meta), string(meta), identityDisplayValue(in), evidenceID)
	if err != nil {
		return "", fmt.Errorf("refresh identity evidence: %w", err)
	}
	return evidenceID, nil
}

func supportedIdentityEvidenceType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "mac", "hostname", "oui", "dhcp_client_id", "dhcp_option_55", "dhcp_vendor_class",
		"ssdp_uuid", "ssdp_device_type", "mdns_name", "mdns_service",
		"mdns_txt_model", "mdns_txt_vendor", "mdns_txt_id":
		return true
	default:
		return false
	}
}

func normalizeAddress(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "ip":
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	case "mac":
		if mac, err := net.ParseMAC(value); err == nil {
			return strings.ToUpper(mac.String())
		}
	}
	return value
}

func normalizeObservedIPv4(value string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(value)).To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return "", false
	}
	allBroadcast := true
	for _, octet := range ip {
		if octet != 0xff {
			allBroadcast = false
			break
		}
	}
	if allBroadcast {
		return "", false
	}
	return ip.String(), true
}

func normalizeObservedEthernetMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return "", false
	}
	allZero, allBroadcast := true, true
	for _, octet := range mac {
		allZero = allZero && octet == 0
		allBroadcast = allBroadcast && octet == 0xff
	}
	if allZero || allBroadcast {
		return "", false
	}
	return strings.ToUpper(mac.String()), true
}

func (db *DB) recordAddressBindingTx(tx *sql.Tx, deviceID, addressType, addressValue,
	segment, sensorID, source string, confidence float64, observedAt time.Time) error {
	addressType = strings.ToLower(strings.TrimSpace(addressType))
	addressValue = normalizeAddress(addressType, addressValue)
	if deviceID == "" || addressValue == "" {
		return nil
	}
	segment = normalizeSegment(segment)
	sensorID = strings.TrimSpace(sensorID)
	confidence = clampIdentityConfidence(confidence)
	canonicalID, err := db.canonicalDeviceIDTx(tx, deviceID)
	if err != nil {
		return err
	}
	deviceID = canonicalID

	var bindingID, ownerID string
	var from, priorLastSeen time.Time
	var until sql.NullTime
	var priorSource string
	var priorConfidence float64
	err = tx.QueryRow(`SELECT binding_id, device_id, valid_from, valid_until,
		last_seen, evidence_source, confidence
		FROM device_address_history
		WHERE address_type = ? AND address_value = ? AND segment = ? AND sensor_id = ?
		  AND valid_from <= ? AND (valid_until IS NULL OR ? < valid_until)
		ORDER BY valid_from DESC LIMIT 1`,
		addressType, addressValue, segment, sensorID, observedAt, observedAt).
		Scan(&bindingID, &ownerID, &from, &until, &priorLastSeen, &priorSource, &priorConfidence)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("find address interval: %w", err)
	}
	if err == nil {
		ownerID, err = db.canonicalDeviceIDTx(tx, ownerID)
		if err != nil {
			return err
		}
		if ownerID == canonicalID {
			if err := recordAddressBindingStrengthTx(tx, bindingID, source, confidence, observedAt); err != nil {
				return err
			}
			if err := recordAddressBindingValidityTx(tx, bindingID, observedAt); err != nil {
				return err
			}
			_, err := tx.Exec(`UPDATE device_address_history SET
				first_seen = CASE WHEN first_seen > ? THEN ? ELSE first_seen END,
				last_seen = CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
				confidence = MAX(confidence, ?)
				WHERE binding_id = ?`, observedAt, observedAt, observedAt, observedAt, confidence, bindingID)
			return err
		}
		// A different owner observed at this timestamp closes the prior interval.
		if _, err := tx.Exec(`UPDATE device_address_history SET valid_until = ?,
			last_seen = CASE WHEN last_seen > ? THEN ? ELSE last_seen END WHERE binding_id = ?`,
			observedAt, observedAt, observedAt, bindingID); err != nil {
			return fmt.Errorf("close previous address interval: %w", err)
		}
		// A delayed conflicting observation must not erase a later explicit
		// observation of the prior owner. Re-open that owner at its known later
		// observation, preserving the original interval end. The delayed owner is
		// then bounded by this tail instead of becoming incorrectly open-ended.
		if priorLastSeen.After(observedAt) && (!until.Valid || priorLastSeen.Before(until.Time)) {
			var tailUntil any
			if until.Valid {
				tailUntil = until.Time
			}
			tailBindingID := uuid.New().String()
			if _, err := tx.Exec(`INSERT INTO device_address_history
				(binding_id, device_id, address_type, address_value, segment, sensor_id,
				 first_seen, last_seen, valid_from, valid_until, evidence_source, confidence, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				tailBindingID, ownerID, addressType, addressValue, segment, sensorID,
				priorLastSeen, priorLastSeen, priorLastSeen, tailUntil, priorSource,
				priorConfidence, time.Now().UTC()); err != nil {
				return fmt.Errorf("restore later address owner: %w", err)
			}
			if err := recordAddressBindingStrengthTx(tx, tailBindingID, priorSource,
				priorConfidence, priorLastSeen); err != nil {
				return err
			}
			if err := recordAddressBindingValidityTx(tx, tailBindingID, priorLastSeen); err != nil {
				return err
			}
		}
	}

	// For an out-of-order observation, stop at the next known owner rather than
	// manufacturing an overlapping interval.
	// SQLite loses the declared TIMESTAMP type through MIN(), so the driver may
	// return a string rather than time.Time. Scan generically and normalize it.
	var nextRaw any
	if err := tx.QueryRow(`SELECT MIN(valid_from) FROM device_address_history
		WHERE address_type = ? AND address_value = ? AND segment = ? AND sensor_id = ? AND valid_from > ?`,
		addressType, addressValue, segment, sensorID, observedAt).Scan(&nextRaw); err != nil {
		return fmt.Errorf("find next address interval: %w", err)
	}
	var validUntil any
	if nextRaw != nil {
		next, err := parseSQLiteTime(nextRaw)
		if err != nil {
			return fmt.Errorf("parse next address interval: %w", err)
		}
		validUntil = next
	}
	bindingID = uuid.New().String()
	_, err = tx.Exec(`INSERT INTO device_address_history
		(binding_id, device_id, address_type, address_value, segment, sensor_id,
		 first_seen, last_seen, valid_from, valid_until, evidence_source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		bindingID, deviceID, addressType, addressValue, segment, sensorID,
		observedAt, observedAt, observedAt, validUntil, source, confidence, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("insert address interval: %w", err)
	}
	if err := recordAddressBindingStrengthTx(tx, bindingID, source, confidence, observedAt); err != nil {
		return err
	}
	if err := recordAddressBindingValidityTx(tx, bindingID, observedAt); err != nil {
		return err
	}
	return nil
}

// ResolveDeviceAt resolves evidence valid at the event timestamp. It is a read
// transaction so the selected address/evidence intervals form one snapshot.
func (db *DB) ResolveDeviceAt(ctx context.Context, req DeviceIdentityResolutionRequest) (DeviceIdentityResolution, error) {
	// The key is normally initialized by Open. A write-capable transaction also
	// makes resolution recover safely if an operator removed that setting.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceIdentityResolution{}, fmt.Errorf("begin identity resolution: %w", err)
	}
	defer tx.Rollback()
	result, err := db.resolveDeviceAtTx(ctx, tx, req)
	if err != nil {
		return DeviceIdentityResolution{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceIdentityResolution{}, fmt.Errorf("commit identity resolution: %w", err)
	}
	return result, nil
}

func (db *DB) resolveDeviceAtTx(ctx context.Context, tx *sql.Tx, req DeviceIdentityResolutionRequest) (DeviceIdentityResolution, error) {
	if err := ctx.Err(); err != nil {
		return DeviceIdentityResolution{}, err
	}
	at := req.Timestamp.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	segment := normalizeSegment(req.Segment)

	// Add an explicit MAC as typed evidence; raw values are HMACed in-memory.
	evidence := append([]DeviceIdentityEvidenceInput(nil), req.Evidence...)
	if strings.TrimSpace(req.MACAddress) != "" {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "mac", Value: req.MACAddress, Source: "event", Confidence: 0.95, Sensitive: true})
	}

	type rank struct {
		name             string
		types            map[string]bool
		confidence       float64
		minimumEvidence  float64
		reason           string
		requireConfirmed bool
	}
	ranks := []rank{
		{"operator", map[string]bool{}, 1.0, 1.0, "operator_confirmed_identity", true},
		{"stable", map[string]bool{"dhcp_client_id": true, "ssdp_uuid": true}, 0.95, 0.80, "stable_identity_evidence", false},
		{"mac", map[string]bool{"mac": true}, 0.90, 0.70, "mac_identity_evidence", false},
		{"alias", map[string]bool{"hostname": true, "mdns_name": true, "mdns_service": true, "dhcp_option_55": true}, 0.65, 0.30, "corroborated_identity_evidence", false},
	}

	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return DeviceIdentityResolution{}, err
	}
	// Resolve every strong rank before accepting a winner. Stable evidence has
	// precedence for confidence, but a different device's MAC is a contradiction,
	// not something precedence may silently discard.
	strongID := ""
	strongConfidence := 0.0
	strongReason := ""
	var strongTypes []string
	for _, r := range ranks[:3] {
		candidates := map[string]struct{}{}
		var matchedTypes []string
		for _, in := range evidence {
			kind := strings.ToLower(strings.TrimSpace(in.Type))
			if !r.requireConfirmed && !r.types[kind] {
				continue
			}
			if normalizeIdentityValue(kind, in.Value) == "" {
				continue
			}
			valueHash := identityValueHMAC(key, kind, in.Value)
			query := `SELECT e.device_id FROM device_identity_evidence e
				JOIN device_identity_evidence_strength s
				  ON s.evidence_id = e.evidence_id AND s.observed_at <= ?
				WHERE e.evidence_type = ? AND e.value_hmac = ? AND e.valid_from <= ?
				  AND (e.valid_until IS NULL OR ? < e.valid_until)`
			args := []any{at, kind, valueHash, at, at}
			if r.requireConfirmed {
				// Friendly aliases and MACs are local observations even when an
				// operator confirms them. Do not let a common name cross a VLAN.
				if !globallyScopedIdentityEvidenceType(kind) {
					query += ` AND e.segment = ?`
					args = append(args, segment)
					if strings.TrimSpace(req.SensorID) != "" {
						query += ` AND (e.sensor_id = ? OR e.sensor_id = '')`
						args = append(args, strings.TrimSpace(req.SensorID))
					}
				}
			} else if r.name == "alias" || (r.name == "mac" && isLocallyAdministeredMAC(in.Value)) {
				query += ` AND e.segment = ?`
				args = append(args, segment)
				if strings.TrimSpace(req.SensorID) != "" {
					query += ` AND (e.sensor_id = ? OR e.sensor_id = '')`
					args = append(args, strings.TrimSpace(req.SensorID))
				}
			}
			// Stable IDs and MACs are durable keys: the incoming event freshly
			// presents the exact value being looked up. Seven-day validity unions
			// apply only to weak aliases below; expiring a physical/stable key here
			// would split a quiet device when it returns to the network.
			query += ` GROUP BY e.evidence_id, e.device_id`
			if r.requireConfirmed {
				query += ` HAVING MAX(CASE WHEN s.operator_confirmed THEN 1 ELSE 0 END) = 1`
			} else {
				query += ` HAVING MAX(s.confidence) >= ?`
				args = append(args, r.minimumEvidence)
			}
			rows, err := tx.QueryContext(ctx, query, args...)
			if err != nil {
				return DeviceIdentityResolution{}, fmt.Errorf("query identity candidates: %w", err)
			}
			matchedThisType := false
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				id, err = db.canonicalDeviceIDTx(tx, id)
				if err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				candidates[id] = struct{}{}
				matchedThisType = true
			}
			if err := rows.Close(); err != nil {
				return DeviceIdentityResolution{}, err
			}
			if matchedThisType && !identitySliceContains(matchedTypes, kind) {
				matchedTypes = append(matchedTypes, kind)
			}
		}
		if len(candidates) > 1 {
			return identityResolution("", 0, "conflicting_identity_evidence", matchedTypes, len(candidates)), nil
		}
		for id := range candidates {
			if strongID != "" && strongID != id {
				return identityResolution("", 0, "conflicting_identity_evidence",
					append(strongTypes, matchedTypes...), 2), nil
			}
			if strongID == "" {
				strongID, strongConfidence, strongReason = id, r.confidence, r.reason
				strongTypes = append([]string(nil), matchedTypes...)
			}
		}
	}
	if strongID != "" {
		// A weak operator-confirmed alias must still respect a conflicting
		// physical MAC. Stable IDs may legitimately survive a new/randomized MAC,
		// but a hostname confirmation must not collapse a second printer/camera.
		weakConfirmation := strongReason == "operator_confirmed_identity"
		for _, kind := range strongTypes {
			if globallyScopedIdentityEvidenceType(kind) || kind == "mac" {
				weakConfirmation = false
				break
			}
		}
		if weakConfirmation {
			if conflict, err := db.macConflictsAt(tx, strongID, req.MACAddress, at); err != nil {
				return DeviceIdentityResolution{}, err
			} else if conflict {
				return identityResolution("", 0, "conflicting_identity_evidence",
					append(strongTypes, "mac"), 2), nil
			}
		}
		return identityResolution(strongID, strongConfidence, strongReason, strongTypes, 1), nil
	}

	// Weak aliases are considered only when no operator/stable/MAC evidence won,
	// and require at least two corroborating evidence types.
	for _, r := range ranks[3:] {
		candidates := map[string]struct{}{}
		var matchedTypes []string
		for _, in := range evidence {
			kind := strings.ToLower(strings.TrimSpace(in.Type))
			if !r.types[kind] || normalizeIdentityValue(kind, in.Value) == "" {
				continue
			}
			valueHash := identityValueHMAC(key, kind, in.Value)
			query := `SELECT e.device_id FROM device_identity_evidence e
				JOIN device_identity_evidence_strength s
				  ON s.evidence_id = e.evidence_id AND s.observed_at <= ?
				WHERE e.evidence_type = ? AND e.value_hmac = ? AND e.valid_from <= ?
				  AND (e.valid_until IS NULL OR ? < e.valid_until)
				  AND e.segment = ?`
			args := []any{at, kind, valueHash, at, at, segment}
			if strings.TrimSpace(req.SensorID) != "" {
				query += ` AND (e.sensor_id = ? OR e.sensor_id = '')`
				args = append(args, strings.TrimSpace(req.SensorID))
			}
			query += ` AND EXISTS (
					SELECT 1 FROM device_identity_evidence_validity v
					WHERE v.evidence_id = e.evidence_id
					  AND v.valid_from <= ? AND ? <= v.valid_until)
				GROUP BY e.evidence_id, e.device_id HAVING MAX(s.confidence) >= ?`
			args = append(args, at, at, r.minimumEvidence)
			rows, err := tx.QueryContext(ctx, query, args...)
			if err != nil {
				return DeviceIdentityResolution{}, fmt.Errorf("query alias identity candidates: %w", err)
			}
			matchedThisType := false
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				id, err = db.canonicalDeviceIDTx(tx, id)
				if err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				candidates[id] = struct{}{}
				matchedThisType = true
			}
			if err := rows.Close(); err != nil {
				return DeviceIdentityResolution{}, err
			}
			if matchedThisType && !identitySliceContains(matchedTypes, kind) {
				matchedTypes = append(matchedTypes, kind)
			}
		}
		if len(candidates) > 1 {
			return identityResolution("", 0, "conflicting_identity_evidence", matchedTypes, len(candidates)), nil
		}
		if len(candidates) == 1 && len(matchedTypes) >= 2 {
			for id := range candidates {
				if conflict, err := db.macConflictsAt(tx, id, req.MACAddress, at); err != nil {
					return DeviceIdentityResolution{}, err
				} else if conflict {
					return identityResolution("", 0, "conflicting_identity_evidence", append(matchedTypes, "mac"), 2), nil
				}
				return identityResolution(id, r.confidence, r.reason, matchedTypes, 1), nil
			}
		}
	}

	// Final fallback: an address interval valid at the event timestamp. Prefer
	// the authenticated sensor's view, then accept an all-sensor unique result.
	// `default` is also the wire fallback used by sources that cannot observe a
	// VLAN. If no exact-default binding exists, a unique cross-segment address may
	// associate the event at reduced confidence; overlapping addresses stay
	// unresolved.
	if ip := normalizeAddress("ip", req.IPAddress); ip != "" {
		type addressScope struct {
			segment bool
			sensor  bool
			reason  string
		}
		scopes := []addressScope{}
		if strings.TrimSpace(req.SensorID) != "" {
			scopes = append(scopes, addressScope{segment: true, sensor: true, reason: "temporal_address_binding"})
		}
		scopes = append(scopes, addressScope{segment: true, reason: "temporal_address_binding"})
		if segment == "default" {
			if strings.TrimSpace(req.SensorID) != "" {
				scopes = append(scopes, addressScope{sensor: true, reason: "unique_unscoped_address_binding"})
			}
			scopes = append(scopes, addressScope{reason: "unique_unscoped_address_binding"})
		}
		for _, scope := range scopes {
			query := `SELECT h.device_id, MAX(s.confidence)
				FROM device_address_history h
				JOIN device_address_binding_strength s
				  ON s.binding_id = h.binding_id AND s.observed_at <= ?
				WHERE h.address_type = 'ip' AND h.address_value = ?
				  AND h.valid_from <= ? AND (h.valid_until IS NULL OR ? < h.valid_until)
				  AND EXISTS (
					SELECT 1 FROM device_address_binding_validity v
					WHERE v.binding_id = h.binding_id
					  AND v.valid_from <= ? AND ? <= v.valid_until)`
			args := []any{at, ip, at, at, at, at}
			if scope.segment {
				query += ` AND h.segment = ?`
				args = append(args, segment)
			}
			if scope.sensor {
				query += ` AND h.sensor_id = ?`
				args = append(args, strings.TrimSpace(req.SensorID))
			}
			query += ` GROUP BY h.binding_id, h.device_id`
			rows, err := tx.QueryContext(ctx, query, args...)
			if err != nil {
				return DeviceIdentityResolution{}, fmt.Errorf("query temporal address: %w", err)
			}
			candidates := map[string]float64{}
			for rows.Next() {
				var id string
				var confidence float64
				if err := rows.Scan(&id, &confidence); err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				id, err = db.canonicalDeviceIDTx(tx, id)
				if err != nil {
					rows.Close()
					return DeviceIdentityResolution{}, err
				}
				if confidence > candidates[id] {
					candidates[id] = confidence
				}
			}
			rows.Close()
			if len(candidates) == 1 {
				for id, confidence := range candidates {
					if conflict, err := db.macConflictsAt(tx, id, req.MACAddress, at); err != nil {
						return DeviceIdentityResolution{}, err
					} else if conflict {
						return identityResolution("", 0, "conflicting_address_mac", []string{"ip", "mac"}, 2), nil
					}
					if !scope.segment && confidence > 0.60 {
						confidence = 0.60
					}
					return identityResolution(id, confidence, scope.reason, []string{"ip"}, 1), nil
				}
			}
			if len(candidates) > 1 {
				return identityResolution("", 0, "ambiguous_temporal_address", []string{"ip"}, len(candidates)), nil
			}
		}
	}
	return identityResolution("", 0, "unresolved", nil, 0), nil
}

// macConflictsAt is the event-time counterpart to the live-correlation
// macConflicts helper. It intentionally ignores the current devices projection
// and considers only HMAC-only MAC evidence that existed at at, so learning a
// MAC later cannot retroactively veto an older address or alias attribution.
func (db *DB) macConflictsAt(tx *sql.Tx, candidateID, incomingMAC string, at time.Time) (bool, error) {
	incomingMAC = normalizeAddress("mac", incomingMAC)
	if incomingMAC == "" {
		return false, nil
	}
	canonicalID, err := db.canonicalDeviceIDTx(tx, candidateID)
	if err != nil {
		return false, err
	}
	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return false, err
	}
	incomingHash := identityValueHMAC(key, "mac", incomingMAC)
	var known, matching int
	if err := tx.QueryRow(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d
			JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT COUNT(DISTINCT e.value_hmac),
			COUNT(DISTINCT CASE WHEN e.value_hmac = ? THEN e.value_hmac END)
		FROM device_identity_evidence e
		JOIN family f ON f.device_id = e.device_id
		WHERE e.evidence_type = 'mac'
		  AND e.valid_from <= ? AND (e.valid_until IS NULL OR ? < e.valid_until)
		  AND EXISTS (SELECT 1 FROM device_identity_evidence_strength s
			WHERE s.evidence_id = e.evidence_id AND s.observed_at <= ?)`,
		canonicalID, incomingHash, at, at, at).Scan(&known, &matching); err != nil {
		return false, fmt.Errorf("read candidate MAC evidence at event time: %w", err)
	}
	return known > matching, nil
}

func isLocallyAdministeredMAC(value string) bool {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	return err == nil && len(mac) > 0 && mac[0]&0x02 != 0
}

func identityOUI(value string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) < 3 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2]))
}

func identitySliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func identityResolution(deviceID string, confidence float64, reason string, types []string, candidates int) DeviceIdentityResolution {
	data, _ := json.Marshal(map[string]any{
		"reason": reason, "evidence_types": types, "candidate_count": candidates,
	})
	return DeviceIdentityResolution{DeviceID: deviceID, Confidence: clampIdentityConfidence(confidence), Reason: reason, Evidence: string(data)}
}

func (db *DB) canonicalDeviceIDTx(tx *sql.Tx, deviceID string) (string, error) {
	deviceID = strings.TrimSpace(deviceID)
	seen := map[string]bool{}
	for hops := 0; deviceID != "" && hops < 32; hops++ {
		if seen[deviceID] {
			return "", fmt.Errorf("device merge redirect cycle at %s", deviceID)
		}
		seen[deviceID] = true
		var next sql.NullString
		err := tx.QueryRow(`SELECT merged_into_device_id FROM devices WHERE device_id = ?`, deviceID).Scan(&next)
		if err != nil {
			if err == sql.ErrNoRows {
				return "", fmt.Errorf("device %s not found", deviceID)
			}
			return "", fmt.Errorf("follow device redirect: %w", err)
		}
		if !next.Valid || strings.TrimSpace(next.String) == "" {
			return deviceID, nil
		}
		deviceID = next.String
	}
	return "", fmt.Errorf("device merge redirect depth exceeded")
}

// CanonicalDeviceID follows audited soft-merge redirects.
func (db *DB) CanonicalDeviceID(ctx context.Context, deviceID string) (string, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	id, err := db.canonicalDeviceIDTx(tx, deviceID)
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// ConfirmDeviceIdentity records operator-confirmed evidence without overwriting
// or deleting prior observations.
func (db *DB) ConfirmDeviceIdentity(ctx context.Context, deviceID string, evidence DeviceIdentityEvidenceInput,
	segment, sensorID, actor, reason string, observedAt time.Time) (*DeviceIdentityAction, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("confirmation reason is required")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	deviceID, err = db.canonicalDeviceIDTx(tx, deviceID)
	if err != nil {
		return nil, err
	}
	evidence.Source = firstNonEmpty(evidence.Source, "operator")
	evidenceID, err := db.upsertIdentityEvidenceTx(tx, deviceID, segment, sensorID, evidence, observedAt, true)
	if err != nil {
		return nil, err
	}
	if evidenceID == "" {
		return nil, fmt.Errorf("identity evidence type and value are required")
	}
	action := &DeviceIdentityAction{ActionID: uuid.New().String(), ActionType: "confirm", TargetDeviceID: deviceID,
		EvidenceID: evidenceID, Actor: firstNonEmpty(strings.TrimSpace(actor), "operator"), Reason: strings.TrimSpace(reason), CreatedAt: time.Now().UTC()}
	if _, err := tx.Exec(`INSERT INTO device_identity_actions
		(action_id, action_type, target_device_id, evidence_id, actor, reason, metadata, created_at)
		VALUES (?, 'confirm', ?, ?, ?, ?, '{}', ?)`, action.ActionID, deviceID, evidenceID, action.Actor, action.Reason, action.CreatedAt); err != nil {
		return nil, fmt.Errorf("record identity confirmation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return action, nil
}

// MergeDevices creates a reversible source -> target redirect.
func (db *DB) MergeDevices(ctx context.Context, sourceDeviceID, targetDeviceID, reason, actor string) (*DeviceIdentityAction, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("merge reason is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	action, err := db.softMergeDevicesTx(tx, sourceDeviceID, targetDeviceID, reason, firstNonEmpty(strings.TrimSpace(actor), "operator"))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return action, nil
}

func (db *DB) softMergeDevicesTx(tx *sql.Tx, sourceDeviceID, targetDeviceID, reason, actor string) (*DeviceIdentityAction, error) {
	sourceDeviceID = strings.TrimSpace(sourceDeviceID)
	targetDeviceID = strings.TrimSpace(targetDeviceID)
	if sourceDeviceID == "" || targetDeviceID == "" || sourceDeviceID == targetDeviceID {
		return nil, fmt.Errorf("source and target devices must be distinct")
	}
	var existingRedirect sql.NullString
	if err := tx.QueryRow(`SELECT merged_into_device_id FROM devices WHERE device_id = ?`, sourceDeviceID).Scan(&existingRedirect); err != nil {
		return nil, fmt.Errorf("read merge source: %w", err)
	}
	if existingRedirect.Valid && existingRedirect.String != "" {
		return nil, fmt.Errorf("source device is already merged")
	}
	canonicalTarget, err := db.canonicalDeviceIDTx(tx, targetDeviceID)
	if err != nil {
		return nil, err
	}
	if canonicalTarget == sourceDeviceID {
		return nil, fmt.Errorf("merge would create a redirect cycle")
	}

	action := &DeviceIdentityAction{ActionID: uuid.New().String(), ActionType: "merge", SourceDeviceID: sourceDeviceID,
		TargetDeviceID: canonicalTarget, Actor: firstNonEmpty(actor, "system"), Reason: reason, CreatedAt: time.Now().UTC()}
	if _, err := tx.Exec(`INSERT INTO device_identity_actions
		(action_id, action_type, source_device_id, target_device_id, actor, reason, metadata, created_at)
		VALUES (?, 'merge', ?, ?, ?, ?, '{}', ?)`, action.ActionID, sourceDeviceID, canonicalTarget, action.Actor, action.Reason, action.CreatedAt); err != nil {
		return nil, fmt.Errorf("record device merge: %w", err)
	}

	// Pure redirect: never mutate the target or move/delete source evidence.
	// Canonical reads aggregate redirected children. This makes split an exact
	// undo instead of attempting to reconstruct overwritten target projections.
	if _, err := tx.Exec(`UPDATE devices SET merged_into_device_id = ?, merge_action_id = ?, merged_at = ? WHERE device_id = ?`,
		canonicalTarget, action.ActionID, action.CreatedAt, sourceDeviceID); err != nil {
		return nil, fmt.Errorf("set device merge redirect: %w", err)
	}
	return action, nil
}

// UndoDeviceMerge implements the beta "split": undo one audited merge without
// arbitrarily repartitioning historical evidence.
func (db *DB) UndoDeviceMerge(ctx context.Context, mergeActionID, reason, actor string) (*DeviceIdentityAction, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("split reason is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var sourceID, targetID string
	var undone sql.NullString
	err = tx.QueryRow(`SELECT source_device_id, target_device_id, undone_by_action_id
		FROM device_identity_actions WHERE action_id = ? AND action_type = 'merge'`, mergeActionID).
		Scan(&sourceID, &targetID, &undone)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("merge action not found")
		}
		return nil, err
	}
	if undone.Valid && undone.String != "" {
		return nil, fmt.Errorf("merge action has already been undone")
	}
	res, err := tx.Exec(`UPDATE devices SET merged_into_device_id = NULL, merge_action_id = NULL, merged_at = NULL
		WHERE device_id = ? AND merge_action_id = ?`, sourceID, mergeActionID)
	if err != nil {
		return nil, fmt.Errorf("clear device merge redirect: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("merge redirect is no longer current")
	}
	action := &DeviceIdentityAction{ActionID: uuid.New().String(), ActionType: "split", SourceDeviceID: sourceID,
		TargetDeviceID: targetID, Actor: firstNonEmpty(strings.TrimSpace(actor), "operator"), Reason: strings.TrimSpace(reason), CreatedAt: time.Now().UTC()}
	metadata, _ := json.Marshal(map[string]string{"merge_action_id": mergeActionID})
	if _, err := tx.Exec(`INSERT INTO device_identity_actions
		(action_id, action_type, source_device_id, target_device_id, actor, reason, metadata, created_at)
		VALUES (?, 'split', ?, ?, ?, ?, ?, ?)`, action.ActionID, sourceID, targetID, action.Actor, action.Reason, string(metadata), action.CreatedAt); err != nil {
		return nil, fmt.Errorf("record device split: %w", err)
	}
	if _, err := tx.Exec(`UPDATE device_identity_actions SET undone_by_action_id = ? WHERE action_id = ?`, action.ActionID, mergeActionID); err != nil {
		return nil, fmt.Errorf("link split audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return action, nil
}
