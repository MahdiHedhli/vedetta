package store

// Spec 004: Passive Discovery Correlation, Labeling & Multi-Network Handling.
//
// This file holds the correlation substrate that replaces the old MAC-then-IP,
// last-writer-wins UpsertDevice logic:
//   - reviewable constants: generic-hostname stoplist + source->confidence table
//   - store accessors for device_signals / device_identities / device_networks
//   - an ORDERED identity resolver (MAC > mDNS name > hostname > IP, with vetoes)
//   - a conservative duplicate merge (fold a MAC-less record into a MAC-bearing one)
//   - confidence-weighted per-field merging (canonical fields recomputed from signals)
//   - a deterministic display_name deriver
//
// Wrong merges corrupt the device inventory, so every rule here is deliberately
// conservative: prefer a duplicate row over a wrong merge (spec NFR-4).

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// --- T3.1: reviewable constants ---------------------------------------------

// Source identifiers used in device_signals.source and mapped to a confidence
// weight. These are the canonical string values written by the merger; the
// sensor's discovery_source values map onto them via discoverySourceToSignal.
const (
	SourceUserCorrected   = "user_corrected"
	SourceMDNSTxt         = "mdns_txt"
	SourceCorpus          = "corpus" // community device-corpus class match (spec 008)
	SourceSSDP            = "ssdp"
	SourceDHCPHostname    = "dhcp_hostname"
	SourceMDNSPtr         = "mdns_ptr"
	SourceDHCPVendorClass = "dhcp_vendor_class"
	SourceHostnamePattern = "hostname_pattern"
	SourceOUI             = "oui"
	SourceNmap            = "nmap"
)

// sourceConfidence is the baseline trust order from FR-6. A field is only
// overwritten by an equal-or-higher-confidence source (same source may refresh
// its own value). user_corrected is 1.0 and locks a field against automatic
// overwrite.
var sourceConfidence = map[string]float64{
	SourceUserCorrected:   1.0,
	SourceMDNSTxt:         0.9,
	SourceCorpus:          0.85, // ceiling for a corpus match; effective confidence is also capped by the curated variant
	SourceSSDP:            0.75,
	SourceDHCPHostname:    0.7,
	SourceMDNSPtr:         0.65, // PTR service type: weaker than TXT model, stronger than vendor class
	SourceDHCPVendorClass: 0.6,
	SourceHostnamePattern: 0.5, // engine hostname patterns span 0.5-0.8; use the floor as the signal weight
	SourceOUI:             0.2,
	SourceNmap:            0.1,
}

// ConfidenceForSource returns the baseline confidence for a signal source,
// defaulting to the nmap floor (0.1) for unknown sources so a stray source can
// never outrank a real signal.
func ConfidenceForSource(source string) float64 {
	if c, ok := sourceConfidence[source]; ok {
		return c
	}
	return sourceConfidence[SourceNmap]
}

// discoverySourceToSignal maps a sensor discovery_source (as carried on the
// wire and stored in devices.discovery_method) to the signal source that best
// describes the vendor/hostname evidence it provides. This decides the
// confidence at which a report's hostname/vendor is recorded.
func discoverySourceToSignal(discoverySource string) string {
	switch discoverySource {
	case "passive_mdns", "mdns":
		return SourceMDNSTxt
	case "passive_ssdp", "ssdp":
		return SourceSSDP
	case "passive_dhcp", "dhcp":
		return SourceDHCPHostname
	case "passive_arp", "arp", "arp_cache":
		return SourceOUI // ARP gives MAC->vendor (OUI) and no reliable hostname
	case "nmap_active", "active_nmap", "nmap", "native_icmp", nativeICMPBoundSource, arpLiveFusionSource:
		return SourceNmap
	default:
		return SourceNmap
	}
}

// genericHostnameExact is the seed stoplist of bare generic hostnames that must
// never participate in identity matching or non-last-resort labeling (SNR plan
// item 1). Compared case-insensitively against the cleaned hostname.
var genericHostnameExact = map[string]bool{
	"localhost":   true,
	"unknown":     true,
	"android":     true,
	"espressif":   true,
	"wlan0":       true,
	"raspberrypi": true,
	"ubuntu":      true,
	"pc":          true,
	"desktop":     true,
	"laptop":      true,
	"printer":     true,
	"nas":         true,
	"camera":      true,
	"iphone":      true,
	"ipad":        true,
}

// genericHostnamePrefixes matches hostnames of the form "<prefix>-<random>"
// (e.g. android-a1b2c3, esp-1234, esp32-abcd) that are effectively generic.
var genericHostnamePrefixes = []string{
	"android-",
	"esp-",
	"esp32-",
	"espressif-",
}

// IsGenericHostname reports whether a hostname is too generic to be a reliable
// identity or label signal. The comparison is on the leftmost DNS label,
// lower-cased and trimmed of the trailing dot / .local suffix.
func IsGenericHostname(hostname string) bool {
	h := cleanHostnameLabel(hostname)
	if h == "" {
		return true
	}
	if genericHostnameExact[h] {
		return true
	}
	for _, p := range genericHostnamePrefixes {
		if strings.HasPrefix(h, p) {
			return true
		}
	}
	return false
}

// cleanHostnameLabel lowercases a hostname and reduces it to its leftmost label
// with the trailing dot and a .local mDNS suffix removed.
func cleanHostnameLabel(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(h, ".local")
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
}

// --- recency windows --------------------------------------------------------

const (
	// mdnsNameRecencyWindow bounds hostname / mDNS-name identity matches.
	mdnsNameRecencyWindow = 7 * 24 * time.Hour
	// maclessIPRecencyWindow bounds the IP+segment fallback when BOTH sides
	// lack a MAC (more aggressive than the 7-day name window).
	maclessIPRecencyWindow = 24 * time.Hour
)

// --- T2.3: store accessors for the new tables -------------------------------

// signalUpsert is one row destined for device_signals.
type signalUpsert struct {
	field      string
	value      string
	source     string
	confidence float64
}

// upsertSignalsTx writes a batch of signals for a device in a single
// transaction (one tx per report host). Same (device_id, field, source)
// refreshes value + last_observed; first_observed is preserved.
func (db *DB) upsertSignalsTx(tx *sql.Tx, deviceID string, sigs []signalUpsert, now time.Time) error {
	for _, s := range sigs {
		if s.field == "" || s.value == "" {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO device_signals (device_id, field, value, source, confidence, first_observed, last_observed)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(device_id, field, source) DO UPDATE SET
			    value = CASE WHEN excluded.last_observed >= device_signals.last_observed THEN excluded.value ELSE device_signals.value END,
			    confidence = CASE WHEN excluded.last_observed >= device_signals.last_observed THEN excluded.confidence ELSE device_signals.confidence END,
			    first_observed = MIN(device_signals.first_observed, excluded.first_observed),
			    last_observed = MAX(device_signals.last_observed, excluded.last_observed)`,
			deviceID, s.field, s.value, s.source, s.confidence, now, now)
		if err != nil {
			return fmt.Errorf("upsert signal %s/%s: %w", s.field, s.source, err)
		}
	}
	return nil
}

// upsertIdentityTx records an identity alias (mac|hostname|mdns_name) for a
// device within a segment. Refreshes last_seen; keeps the earliest first_seen.
func (db *DB) upsertIdentityTx(tx *sql.Tx, deviceID, idType, idValue, segment string, now time.Time) error {
	if idValue == "" {
		return nil
	}
	if segment == "" {
		segment = "default"
	}
	_, err := tx.Exec(`
		INSERT INTO device_identities (device_id, id_type, id_value, segment, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(id_type, id_value, segment) DO UPDATE SET
			    first_seen = MIN(device_identities.first_seen, excluded.first_seen),
			    last_seen = MAX(device_identities.last_seen, excluded.last_seen)`,
		deviceID, idType, idValue, segment, now, now)
	if err != nil {
		return fmt.Errorf("upsert identity %s=%s: %w", idType, idValue, err)
	}
	return nil
}

// upsertNetworkTx records/refreshes a device's attachment to a segment. Keeps
// the earliest first_seen; updates ip_address, sensor_id, and last_seen.
func (db *DB) upsertNetworkTx(tx *sql.Tx, deviceID, segment, ip, sensorID string, now time.Time) error {
	if segment == "" {
		segment = "default"
	}
	_, err := tx.Exec(`
		INSERT INTO device_networks (device_id, segment, ip_address, sensor_id, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(device_id, segment) DO UPDATE SET
			    ip_address = CASE WHEN excluded.last_seen >= device_networks.last_seen THEN excluded.ip_address ELSE device_networks.ip_address END,
			    sensor_id = CASE WHEN excluded.last_seen >= device_networks.last_seen THEN excluded.sensor_id ELSE device_networks.sensor_id END,
			    first_seen = MIN(device_networks.first_seen, excluded.first_seen),
			    last_seen = MAX(device_networks.last_seen, excluded.last_seen)`,
		deviceID, segment, ip, sensorID, now, now)
	if err != nil {
		return fmt.Errorf("upsert network %s/%s: %w", deviceID, segment, err)
	}
	return nil
}

// GetDeviceSignals returns the per-field provenance for a device (API read).
func (db *DB) GetDeviceSignals(deviceID string) ([]DeviceSignalRow, error) {
	rows, err := db.Query(`
		WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT field, value, source, confidence, last_observed
		FROM device_signals WHERE device_id IN (SELECT device_id FROM family)
		ORDER BY field, confidence DESC`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query device signals: %w", err)
	}
	defer rows.Close()
	var out []DeviceSignalRow
	for rows.Next() {
		var s DeviceSignalRow
		if err := rows.Scan(&s.Field, &s.Value, &s.Source, &s.Confidence, &s.LastObserved); err != nil {
			return nil, fmt.Errorf("scan signal: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeviceSignalRow mirrors a device_signals row for API/provenance reads.
type DeviceSignalRow struct {
	Field        string
	Value        string
	Source       string
	Confidence   float64
	LastObserved time.Time
}

// GetDeviceSegments returns the segments a device is attached to, most-recent
// attachment first.
func (db *DB) GetDeviceSegments(deviceID string) ([]string, error) {
	rows, err := db.Query(`
		WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT segment FROM device_networks
		WHERE device_id IN (SELECT device_id FROM family)
		GROUP BY segment ORDER BY MAX(last_seen) DESC`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query device segments: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var seg string
		if err := rows.Scan(&seg); err != nil {
			return nil, fmt.Errorf("scan segment: %w", err)
		}
		out = append(out, seg)
	}
	return out, rows.Err()
}

// canonicalField holds the winning value + confidence for a device field after
// confidence-weighted resolution across all its signals.
type canonicalField struct {
	value      string
	source     string
	confidence float64
}

// resolveCanonicalFields reads device_signals for a device and returns, per
// field, the highest-confidence value. This is the read side of FR-6: canonical
// devices columns are recomputed from the signal set rather than mutated in place.
//
// The ORDER BY makes the winner DETERMINISTIC: without it, two equal-confidence
// signals for the same field (e.g. two 0.9 mdns_txt values) resolved to whichever
// row SQLite happened to return first, so the canonical value could flip between
// upserts with no new evidence. Ties break on most-recent observation, then
// source, then value, so a given signal set always yields the same canonical row.
func (db *DB) resolveCanonicalFields(tx *sql.Tx, deviceID string) (map[string]canonicalField, error) {
	rows, err := tx.Query(`
		WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT field, value, source, confidence FROM device_signals
		WHERE device_id IN (SELECT device_id FROM family)
		ORDER BY field, confidence DESC, last_observed DESC, source ASC, value ASC`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query signals for canonical resolve: %w", err)
	}
	defer rows.Close()
	best := map[string]canonicalField{}
	for rows.Next() {
		var field, value, source string
		var conf float64
		if err := rows.Scan(&field, &value, &source, &conf); err != nil {
			return nil, fmt.Errorf("scan canonical signal: %w", err)
		}
		cur, ok := best[field]
		if !ok || conf > cur.confidence {
			best[field] = canonicalField{value: value, source: source, confidence: conf}
		}
	}
	return best, rows.Err()
}

// --- T3.2: ordered identity resolver ----------------------------------------

// resolvedIdentity is the outcome of the ordered resolver.
type resolvedIdentity struct {
	deviceID   string // "" when no existing record matched (new device)
	matchRule  string // "mac" | "mdns_name" | "hostname" | "ip_segment" | "" (none)
	macMatchID string // device matched by MAC exact (for merge detection); "" if none
}

// resolveIdentity implements the ORDERED resolver from FR-4:
//  1. MAC exact match.
//  2. mDNS instance-name + segment, within the 7-day recency window.
//  3. unique, non-stoplisted hostname + segment, within the 7-day window.
//  4. IP + segment, with the MAC-conflict veto: never re-assign a record whose
//     stored MAC differs from the incoming MAC; when both sides are MAC-less the
//     match additionally requires 24h recency.
//
// When a MAC match (rule 1) succeeds, the resolver ALSO probes rules 2-4 for a
// DIFFERENT (MAC-less) record. If one is found it is reported as macMatchID !=
// deviceID so the caller folds that duplicate into the MAC-bearing survivor
// (T3.3 duplicate merge). The winning deviceID is always the MAC record.
func (db *DB) resolveIdentity(tx *sql.Tx, host correlationInput, seg string, now time.Time) (resolvedIdentity, error) {
	res := resolvedIdentity{}

	// Rule 1: MAC exact.
	if host.mac != "" {
		var id string
		var err error
		if isLocallyAdministeredMAC(host.mac) {
			err = tx.QueryRow(`SELECT device_id FROM device_identities
				WHERE id_type='mac' AND id_value=? AND segment=? ORDER BY last_seen DESC LIMIT 1`, host.mac, seg).Scan(&id)
		} else {
			err = tx.QueryRow(`SELECT device_id FROM devices WHERE mac_address = ? LIMIT 1`, host.mac).Scan(&id)
		}
		if err != nil && err != sql.ErrNoRows {
			return res, fmt.Errorf("resolve by mac: %w", err)
		}
		if err == nil {
			id, err = db.canonicalDeviceIDTx(tx, id)
			if err != nil {
				return res, err
			}
			res.deviceID = id
			res.matchRule = "mac"
			res.macMatchID = id

			// Duplicate-merge probe: does an alias/IP rule point at a DIFFERENT
			// record? That record is a MAC-less duplicate to fold into this one.
			alias, err := db.matchByAlias(tx, host, seg, now)
			if err != nil {
				return res, err
			}
			if alias.deviceID != "" && alias.deviceID != id {
				alias.deviceID, err = db.canonicalDeviceIDTx(tx, alias.deviceID)
				if err != nil {
					return res, err
				}
			}
			if alias.deviceID != "" && alias.deviceID != id {
				// Only merge when the duplicate has no conflicting MAC. matchByAlias's
				// IP rule already vetoes MAC conflicts; an alias (name/hostname) hit
				// could still be a differently-MAC'd device, so re-check its MAC.
				var otherMAC string
				_ = tx.QueryRow(`SELECT COALESCE(mac_address, '') FROM devices WHERE device_id = ?`, alias.deviceID).Scan(&otherMAC)
				if otherMAC == "" || otherMAC == host.mac {
					res.deviceID = alias.deviceID // caller merges alias(B) into macMatchID(A)
					res.matchRule = alias.matchRule
				}
			}
			return res, nil
		}
	}

	// No MAC match (or MAC-less observation): run the alias/IP rules directly.
	alias, err := db.matchByAlias(tx, host, seg, now)
	if err != nil {
		return res, err
	}
	if alias.deviceID != "" {
		alias.deviceID, err = db.canonicalDeviceIDTx(tx, alias.deviceID)
		if err != nil {
			return res, err
		}
	}
	return alias, nil
}

// matchByAlias runs resolver rules 2-4 (mDNS name, unique hostname, IP+segment)
// and returns the first match. Used both as the primary path for MAC-less
// observations and as the duplicate-detection probe after a MAC match.
func (db *DB) matchByAlias(tx *sql.Tx, host correlationInput, seg string, now time.Time) (resolvedIdentity, error) {
	res := resolvedIdentity{}

	// Rule 2: mDNS instance-name + segment within recency window, with two
	// wrong-merge guards. mDNS friendly names are NOT unique — two "Office Printer"
	// units on the same segment is routine — so a name match alone can fold two
	// physically distinct devices into one (spec NFR-4 prefers a duplicate row over
	// a wrong merge). Guards:
	//   (a) Ambiguity: if MORE THAN ONE distinct device carries the name, skip
	//       (can't pick one safely). This catches a third device joining a name
	//       already shared by two.
	//   (b) Hostname conflict: the ambiguity count is 1 for the SECOND device to
	//       join a name (only the first holds the alias yet), so also veto when the
	//       incoming observation carries a specific hostname that CONFLICTS with the
	//       candidate device's recorded specific hostname. Different hostnames under
	//       a shared friendly name means different devices.
	if host.mdnsName != "" {
		cutoff := now.Add(-mdnsNameRecencyWindow)
		var count int
		err := tx.QueryRow(`
			SELECT COUNT(DISTINCT device_id) FROM device_identities
			WHERE id_type = 'mdns_name' AND id_value = ? AND segment = ? AND last_seen >= ?`,
			host.mdnsName, seg, cutoff).Scan(&count)
		if err != nil {
			return res, fmt.Errorf("count mdns name candidates: %w", err)
		}
		if count == 1 {
			var id string
			err := tx.QueryRow(`
				SELECT device_id FROM device_identities
				WHERE id_type = 'mdns_name' AND id_value = ? AND segment = ? AND last_seen >= ?
				LIMIT 1`, host.mdnsName, seg, cutoff).Scan(&id)
			if err != nil && err != sql.ErrNoRows {
				return res, fmt.Errorf("resolve by mdns name: %w", err)
			}
			if err == nil {
				// MAC-conflict veto (spec FR-4 / NFR-4): never re-assign a record whose
				// stored MAC differs from the incoming MAC. Reached DIRECTLY when the
				// incoming MAC is brand-new (no rule-1 match) but shares an mDNS name with
				// a differently-MAC'd device — that is a distinct physical device, not an
				// update. Without this the mac_address CASE-write in UpsertDevice would
				// silently overwrite the stored MAC and collapse two devices into one.
				macConflict, err := db.macConflictsForAlias(tx, id, host.mac)
				if err != nil {
					return res, err
				}
				conflict, err := db.hostnameConflicts(tx, id, host.hostname)
				if err != nil {
					return res, err
				}
				if !macConflict && !conflict {
					res.deviceID = id
					res.matchRule = "mdns_name"
					return res, nil
				}
			}
		}
	}

	// Rule 3: unique, non-stoplisted hostname + segment within recency window.
	if host.hostname != "" && !IsGenericHostname(host.hostname) {
		cutoff := now.Add(-mdnsNameRecencyWindow)
		var id string
		var count int
		// Uniqueness within segment: more than one candidate device => ambiguous, skip.
		err := tx.QueryRow(`
			SELECT COUNT(DISTINCT device_id) FROM device_identities
			WHERE id_type = 'hostname' AND id_value = ? AND segment = ? AND last_seen >= ?`,
			host.hostname, seg, cutoff).Scan(&count)
		if err != nil {
			return res, fmt.Errorf("count hostname candidates: %w", err)
		}
		if count == 1 {
			err := tx.QueryRow(`
				SELECT device_id FROM device_identities
				WHERE id_type = 'hostname' AND id_value = ? AND segment = ? AND last_seen >= ?
				LIMIT 1`, host.hostname, seg, cutoff).Scan(&id)
			if err != nil && err != sql.ErrNoRows {
				return res, fmt.Errorf("resolve by hostname: %w", err)
			}
			if err == nil {
				// MAC-conflict veto (spec FR-4 / NFR-4): a brand-new MAC that happens to
				// share a specific hostname with a differently-MAC'd stored record (e.g.
				// replacement hardware reusing a DHCP hostname, or two IoT units) is a
				// distinct device. Skip so the caller creates a new record instead of
				// stealing this one and overwriting its MAC.
				macConflict, err := db.macConflictsForAlias(tx, id, host.mac)
				if err != nil {
					return res, err
				}
				if !macConflict {
					res.deviceID = id
					res.matchRule = "hostname"
					return res, nil
				}
			}
		}
	}

	// Rule 4: IP + segment, with MAC-conflict veto.
	if host.ip != "" {
		var id, storedMAC string
		err := tx.QueryRow(`
			SELECT device_id, COALESCE(mac_address, '') FROM devices
			WHERE ip_address = ? AND segment = ? ORDER BY last_seen DESC LIMIT 1`,
			host.ip, seg).Scan(&id, &storedMAC)
		if err != nil && err != sql.ErrNoRows {
			return res, fmt.Errorf("resolve by ip+segment: %w", err)
		}
		if err == nil {
			// MAC-conflict veto includes HMAC-only cache evidence. Cache provisional
			// rows intentionally keep the canonical MAC blank, so comparing only
			// devices.mac_address would let a strong observation for MAC B promote a
			// provisional that actually represents MAC A after IP reuse.
			macConflict, err := db.macConflicts(tx, id, host.mac)
			if err != nil {
				return res, err
			}
			if macConflict {
				return res, nil // no match; caller creates a new device
			}
			// When both sides are MAC-less, require 24h recency on the attachment.
			if host.mac == "" && storedMAC == "" {
				var lastSeen time.Time
				err := tx.QueryRow(`
					SELECT last_seen FROM device_networks WHERE device_id = ? AND segment = ?`,
					id, seg).Scan(&lastSeen)
				if err == sql.ErrNoRows {
					// No attachment row (pre-018 fixture edge); fall back to devices.last_seen.
					_ = tx.QueryRow(`SELECT last_seen FROM devices WHERE device_id = ?`, id).Scan(&lastSeen)
				} else if err != nil {
					return res, fmt.Errorf("resolve ip recency: %w", err)
				}
				if lastSeen.IsZero() || now.Sub(lastSeen) > maclessIPRecencyWindow {
					return res, nil // stale MAC-less match; treat as new device
				}
			}
			res.deviceID = id
			res.matchRule = "ip_segment"
			return res, nil
		}
	}

	return res, nil
}

// macConflicts reports whether the candidate device carries a non-empty canonical
// MAC, or active HMAC-only MAC evidence, that differs from the incoming
// observation's non-empty MAC. It is the MAC-conflict
// veto for the alias rules (mDNS name, hostname): two records with different known
// MACs are, by definition, different physical devices and must never be folded
// together (spec FR-4 "MUST NOT re-assign a record whose stored MAC differs",
// NFR-4 "prefer a duplicate row over a wrong merge"). It is conservative — if
// either side lacks a MAC there is no conflict, so MAC-less continuity matching
// (mDNS/hostname link-up before ARP supplies a MAC) still works.
func (db *DB) macConflicts(tx *sql.Tx, candidateID, incomingMAC string) (bool, error) {
	incomingMAC = normalizeAddress("mac", incomingMAC)
	if incomingMAC == "" {
		return false, nil
	}
	canonicalID, err := db.canonicalDeviceIDTx(tx, candidateID)
	if err != nil {
		return false, err
	}
	var candMAC string
	err = tx.QueryRow(`SELECT COALESCE(mac_address, '') FROM devices WHERE device_id = ?`, canonicalID).Scan(&candMAC)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("read candidate mac for conflict check: %w", err)
	}
	if candMAC != "" {
		if normalizeAddress("mac", candMAC) != incomingMAC {
			return true, nil
		}
	}

	// Cache-only MAC evidence is intentionally too weak to resolve a device, but
	// it is still strong enough to veto a contradictory IP/alias merge. Prefer a
	// duplicate over promoting the wrong provisional identity.
	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return false, err
	}
	incomingHash := identityValueHMAC(key, "mac", incomingMAC)
	var active, matching int
	// Merge redirects preserve the source row and its evidence for auditability.
	// Treat that complete recursive family as the candidate identity: checking only
	// the canonical row lets a weak HMAC-only cache MAC on a merged child disappear
	// from this veto and allows a contradictory legacy IP/alias fallback to overwrite
	// the family. UNION also protects the walk from malformed historical cycles.
	if err := tx.QueryRow(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d
			JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN e.value_hmac = ? THEN 1 ELSE 0 END), 0)
		FROM device_identity_evidence e
		JOIN family f ON f.device_id = e.device_id
		WHERE e.evidence_type = 'mac' AND e.valid_until IS NULL`,
		canonicalID, incomingHash).Scan(&active, &matching); err != nil {
		return false, fmt.Errorf("read candidate MAC evidence for conflict check: %w", err)
	}
	// More than one active MAC value is ambiguous even when one happens to
	// match the incoming value. Never let a matching weak edge mask another
	// contradictory edge on the same provisional.
	return active > matching, nil
}

// macConflictsForAlias is the MAC-conflict veto used by the ALIAS rules (mDNS
// name, hostname). It relaxes the strict macConflicts check for RANDOMIZED
// (locally administered) incoming MACs.
//
// A locally administered MAC is ephemeral: phones and laptops rotate a private
// Wi-Fi address by design, so a difference from the candidate's stored MAC is not
// evidence of distinct hardware. Left strict, the veto spawns a brand-new device
// row on every rotation — the "MAC sprawl" that dominates the inventory once a
// household runs modern default-randomizing clients. When the incoming MAC is
// randomized we let the alias rule's own continuity guards decide instead (a
// UNIQUE mDNS instance name / specific non-generic hostname within segment +
// 7-day recency, plus the hostname-conflict veto on the mDNS rule).
//
// The relaxation is bounded: a randomized observation may fold only into a
// candidate that is NOT pinned to a stable, globally administered MAC. Folding
// into burned-in hardware would both risk a wrong merge (two distinct devices
// that happen to share an alias) and clobber a durable hardware key with an
// ephemeral one, so a stable-MAC candidate keeps the strict veto and the caller
// creates a duplicate row instead (spec NFR-4: prefer a duplicate over a wrong
// merge). Globally administered incoming MACs are stable keys and always use the
// strict check.
func (db *DB) macConflictsForAlias(tx *sql.Tx, candidateID, incomingMAC string) (bool, error) {
	if incomingMAC != "" && isLocallyAdministeredMAC(incomingMAC) {
		return db.candidateHasStableMAC(tx, candidateID)
	}
	return db.macConflicts(tx, candidateID, incomingMAC)
}

// candidateHasStableMAC reports whether the candidate device family (following
// merge redirects and including redirected children) carries a non-empty,
// globally administered canonical MAC — a durable hardware key. Soft merges
// preserve child rows for auditability, and an operator may choose a MAC-less or
// randomized record as the canonical target, so checking only that target would
// discard stable hardware evidence retained on a child.
//
// Used by macConflictsForAlias to keep a randomized observation from folding
// into, and overwriting, real burned-in hardware.
func (db *DB) candidateHasStableMAC(tx *sql.Tx, candidateID string) (bool, error) {
	canonicalID, err := db.canonicalDeviceIDTx(tx, candidateID)
	if err != nil {
		return false, err
	}
	rows, err := tx.Query(`WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d
			JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT COALESCE(d.mac_address, '')
		FROM devices d JOIN family f ON f.device_id = d.device_id`, canonicalID)
	if err != nil {
		return false, fmt.Errorf("read candidate mac family for stability check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var candMAC string
		if err := rows.Scan(&candMAC); err != nil {
			return false, fmt.Errorf("scan candidate mac family for stability check: %w", err)
		}
		if candMAC != "" && !isLocallyAdministeredMAC(candMAC) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate candidate mac family for stability check: %w", err)
	}
	return false, nil
}

// hostnameConflicts reports whether the candidate device carries a specific
// (non-generic) hostname that differs from the incoming observation's specific
// hostname. Used as a wrong-merge veto on the mDNS-name rule: a shared friendly
// name across two DIFFERENT specific hostnames means two distinct devices. It is
// conservative — if either side lacks a specific hostname there is no conflict
// signal, so the match is allowed (the mDNS name is the only continuity we have).
func (db *DB) hostnameConflicts(tx *sql.Tx, candidateID, incomingHostname string) (bool, error) {
	inc := cleanHostnameLabel(incomingHostname)
	if inc == "" || IsGenericHostname(incomingHostname) {
		return false, nil
	}
	var candHost string
	err := tx.QueryRow(`SELECT COALESCE(hostname, '') FROM devices WHERE device_id = ?`, candidateID).Scan(&candHost)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("read candidate hostname for conflict check: %w", err)
	}
	if candHost == "" || IsGenericHostname(candHost) {
		return false, nil
	}
	return cleanHostnameLabel(candHost) != inc, nil
}

// correlationInput is the normalized identity view of a reported host.
type correlationInput struct {
	ip       string
	mac      string
	hostname string
	mdnsName string // friendly / mDNS instance name used for name-continuity matching
}

// --- T3.3: duplicate merge --------------------------------------------------

// mergeDevices is the legacy automatic duplicate-link entry point. Spec 007
// changes it from destructive folding to an audited, reversible soft redirect.
// The source row and all historical evidence remain intact.
func (db *DB) mergeDevices(tx *sql.Tx, survivorID, absorbedID, rule string) error {
	if survivorID == "" || absorbedID == "" || survivorID == absorbedID {
		return nil
	}
	_, err := db.softMergeDevicesTx(tx, absorbedID, survivorID,
		"automatic duplicate link via "+firstNonEmpty(rule, "identity"), "system:auto")
	return err
}

// --- T4.2: label deriver ----------------------------------------------------

var macSuffixRe = regexp.MustCompile(`[:\-]`)

// deriveDisplayName computes the human-readable label per FR-8 precedence:
// custom_name > friendly_name > model(+vendor) > cleaned hostname (unless
// generic) > vendor + last MAC octets > IP address.
func deriveDisplayName(customName, friendlyName, model, vendor, hostname, mac, ip string) string {
	if s := strings.TrimSpace(customName); s != "" {
		return s
	}
	if s := strings.TrimSpace(friendlyName); s != "" {
		return s
	}
	model = strings.TrimSpace(model)
	vendor = strings.TrimSpace(vendor)
	if model != "" {
		if vendor != "" && !strings.Contains(strings.ToLower(model), strings.ToLower(vendor)) {
			return model + " (" + vendor + ")"
		}
		return model
	}
	if h := strings.TrimSpace(hostname); h != "" && !IsGenericHostname(h) {
		return cleanHostnameLabel(h)
	}
	if vendor != "" {
		if suffix := macSuffix(mac); suffix != "" {
			return vendor + " " + suffix
		}
		return vendor
	}
	return strings.TrimSpace(ip)
}

// macSuffix returns the last two octets of a MAC as "AA:BB" (upper-case),
// or "" if the MAC is unusable.
func macSuffix(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	parts := macSuffixRe.Split(mac, -1)
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-2:]
	return strings.ToUpper(last[0] + ":" + last[1])
}
