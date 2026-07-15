package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/fingerprint"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

const (
	arpCacheIdentityConfidence = 0.55
	arpLiveFusionConfidence    = 0.85
	arpLiveFusionWindow        = 5 * time.Minute
	nativeICMPBoundSource      = "native_icmp_bound"
	arpLiveFusionSource        = "native_icmp_arp"
	arpCacheStateUnique        = "unique"
	arpCacheStateAmbiguous     = "ambiguous"
	maxCacheDeliverySequence   = uint64(1<<63 - 1)
)

// ErrARPCacheDeliveryMutation marks a contradictory replay of an already
// accepted, sequenced ARP-cache delivery. The scoped generation key is
// immutable: callers should acknowledge this as a permanently processed no-op
// so the official sensor can discard the batch instead of retrying forever.
var ErrARPCacheDeliveryMutation = errors.New("ARP cache delivery generation is immutable")

// ErrARPCacheDeliveryStale marks a known sequenced delivery that an accepted
// later sequence or activated epoch has superseded. Callers should acknowledge
// it as a permanently processed no-op; stale payloads cannot repair or create
// projections after newer state exists.
var ErrARPCacheDeliveryStale = errors.New("ARP cache delivery generation is stale")

type arpCacheState struct {
	state            string
	macHMAC          string
	observedAt       time.Time
	epochOrder       int64
	deliverySequence int64
}

type arpCacheExpectation struct {
	sensorID         string
	segment          string
	ipAddress        string
	macHMAC          string
	observedAt       time.Time
	epochOrder       int64
	deliverySequence int64
}

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
	host.DiscoverySource = strings.ToLower(strings.TrimSpace(host.DiscoverySource))
	if host.DiscoverySource == "arp" {
		host.DiscoverySource = "arp_cache"
	}
	switch host.DiscoverySource {
	case "arp_cache":
		ip, ok := normalizeObservedIPv4(host.IPAddress)
		if !ok {
			return false, fmt.Errorf("arp_cache observation requires a valid unicast IPv4 address")
		}
		host.IPAddress = ip
		if strings.TrimSpace(host.MACAddress) != "" {
			if mac, ok := normalizeObservedEthernetMAC(host.MACAddress); ok {
				host.MACAddress = mac
			} else {
				// A malformed/non-device cache MAC is negative identity evidence,
				// never a string to HMAC and promote as a unique hardware address.
				host.MACAddress = ""
			}
		}
	case arpLiveFusionSource:
		ip, ipOK := normalizeObservedIPv4(host.IPAddress)
		mac, macOK := normalizeObservedEthernetMAC(host.MACAddress)
		if !ipOK {
			return false, fmt.Errorf("native_icmp_arp observation requires a valid unicast IPv4 address")
		}
		host.IPAddress = ip
		if !macOK {
			// Preserve valid source-bound liveness while withholding the malformed
			// link-layer identity.
			host.DiscoverySource = nativeICMPBoundSource
			host.MACAddress = ""
		} else {
			host.MACAddress = mac
		}
	}
	// Discovery-source labels are a trust contract, not merely provenance text.
	// Keep each native/cache source inside the evidence it can actually prove:
	//
	//   - old Windows sensors reported kernel-neighbor-cache rows as `arp`; treat
	//     that exact legacy label as the current cache-only `arp_cache` source;
	//   - native_icmp/native_icmp_bound prove only that an IP answered. A MAC (or
	//     descriptive/typed identity data) spliced into either payload must not
	//     bypass the scoped cache-corroboration rules below;
	//   - native_icmp_arp is the source-bound, same-generation IP/MAC join. It may
	//     carry that pair, but no hostname, service, port, or typed identity claims.
	//
	// This boundary also makes Core-first upgrades safe while an older Windows
	// sensor is still emitting the pre-refactor `native_icmp` + `arp` wire forms.
	switch host.DiscoverySource {
	case "native_icmp", nativeICMPBoundSource:
		host.MACAddress = ""
		clearNonNetworkDiscoveryClaims(&host)
		observation.Evidence = nil
	case arpLiveFusionSource:
		clearNonNetworkDiscoveryClaims(&host)
		observation.Evidence = nil
	}
	scanTime := observation.ObservedAt.UTC()
	if scanTime.IsZero() {
		scanTime = time.Now().UTC()
	}
	seg := normalizeSegment(observation.Segment)
	sensorID := observation.SensorID
	if host.DiscoverySource == "arp_cache" {
		return db.observeARPCacheDevice(host, scanTime, seg, sensorID,
			observation.DeliveryEpoch, observation.DeliverySequence)
	}

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
	if expected := observation.expectedARPCache; expected != nil {
		// The cache-state transaction committed before entering this normal
		// identity transaction. Acquire the writer lock first, then compare the
		// exact state and retain the lock through every fusion write. Without this
		// CAS, a newer blank/proxy transition can commit in between and stale MAC
		// evidence can still become canonical.
		if _, err := tx.Exec(`UPDATE settings SET value = value WHERE key = ?`, identityHMACSetting); err != nil {
			return false, fmt.Errorf("serialize expected ARP cache fusion: %w", err)
		}
		matches, err := db.matchesARPCacheExpectationTx(tx, expected)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}

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
	// A cache-only row deliberately sits below the normal MAC resolution
	// threshold. When a later non-cache observation corroborates its exact scoped
	// IP/MAC tuple, prefer that provisional over a conflicting weak IP fallback.
	// Strong operator/stable/MAC/alias evidence still wins over this local bridge.
	provisionalID, err := db.findARPCacheProvisionalTx(tx, host.IPAddress, host.MACAddress, seg, sensorID)
	if err != nil {
		return false, err
	}
	useProvisional := provisionalID != ""
	switch typedResolution.Reason {
	case "operator_confirmed_identity", "stable_identity_evidence", "mac_identity_evidence", "corroborated_identity_evidence", "conflicting_identity_evidence":
		useProvisional = false
	}
	res := resolvedIdentity{}
	if useProvisional {
		res.deviceID = provisionalID
		res.matchRule = "arp_cache_corroboration"
	} else if typedResolution.DeviceID != "" {
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
	// The driver-free Windows scanner proves IP liveness with a native ICMP probe
	// bound to the selected source address while the separately scoped cache
	// reader supplies the selected-link MAC. When the cache arrived first, fuse
	// one unique, same-sensor MAC only inside a tight time window. This is stronger
	// than cache evidence alone, but still below a directly captured DHCP/packet
	// MAC. Unbound native_icmp is intentionally ineligible.
	if host.DiscoverySource == nativeICMPBoundSource && host.MACAddress == "" {
		cacheMAC, err := db.recentARPCacheMACForLiveDeviceTx(tx, deviceID, host.IPAddress, seg, sensorID, scanTime)
		if err != nil {
			return false, err
		}
		if cacheMAC != "" {
			host.MACAddress = cacheMAC
			host.DiscoverySource = arpLiveFusionSource
		}
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

	// Canonical devices row: segment/ip_address track the MOST RECENT attachment.
	// A delayed strong observation may still promote an ARP-cache provisional's
	// provenance and previously-empty descriptive fields, but it must not regress
	// the newer location projection.
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
				display_name = CASE
					WHEN discovery_method = 'arp_cache' AND ? != '' THEN ?
					WHEN last_seen <= ? THEN ? ELSE display_name END,
				device_type = ?,
				os_family = ?,
				os_version = COALESCE(NULLIF(?, ''), os_version),
				segment = CASE WHEN last_seen <= ? THEN ? ELSE segment END,
				open_ports = CASE WHEN ? != '[]' AND (open_ports IN ('', '[]') OR last_seen <= ?) THEN ? ELSE open_ports END,
				services = CASE WHEN ? != '[]' AND (services IN ('', '[]') OR last_seen <= ?) THEN ? ELSE services END,
				discovery_method = CASE
					WHEN ? != '' AND (discovery_method = 'arp_cache' OR last_seen <= ?) THEN ?
					ELSE discovery_method END,
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
		firstNonEmpty(host.DiscoverySource, "nmap_active"), displayName,
		scanTime, displayName,
		finalDeviceType,
		finalOSFamily,
		fpResult.OSVersion,
		scanTime, seg,
		marshalPorts(host.OpenPorts), scanTime, marshalPorts(host.OpenPorts),
		string(servicesJSON), scanTime, string(servicesJSON),
		firstNonEmpty(host.DiscoverySource, "nmap_active"), scanTime, firstNonEmpty(host.DiscoverySource, "nmap_active"),
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
	macIdentityConfidence := 0.95
	if host.DiscoverySource == arpLiveFusionSource {
		macIdentityConfidence = arpLiveFusionConfidence
	}
	if err := db.recordAddressBindingTx(tx, deviceID, "mac", host.MACAddress, seg, sensorID,
		firstNonEmpty(host.DiscoverySource, "device_observation"), macIdentityConfidence, scanTime); err != nil {
		return false, err
	}

	if host.MACAddress != "" {
		evidence = append(evidence, DeviceIdentityEvidenceInput{Type: "mac", Value: host.MACAddress,
			Source: firstNonEmpty(host.DiscoverySource, "device_observation"), Confidence: macIdentityConfidence, Sensitive: true})
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

// clearNonNetworkDiscoveryClaims retains only the IP/status/source/timestamp and,
// for callers that do not clear it separately, the MAC. Native liveness and
// cache-join sources cannot substantiate descriptive inventory or stable typed
// identity claims.
func clearNonNetworkDiscoveryClaims(host *discovery.DiscoveredHost) {
	host.Hostname = ""
	host.Vendor = ""
	host.OpenPorts = nil
	host.Model = ""
	host.FriendlyName = ""
	host.Services = nil
	host.IdentityEvidence = nil
}

// observeARPCacheDevice keeps kernel-neighbor-cache observations out of the
// normal identity pipeline. A cache row is useful evidence that an IP/MAC edge
// existed, but is too weak to resolve a device, replace a live address owner, or
// feed canonical fields/fingerprinting. Ambiguous rows therefore remain as
// durable, deduplicated provisional devices until a stronger source observes
// them.
func (db *DB) observeARPCacheDevice(host discovery.DiscoveredHost, observedAt time.Time,
	segment, sensorID, deliveryEpoch string, deliverySequence uint64) (bool, error) {
	host.IPAddress = normalizeAddress("ip", host.IPAddress)
	host.MACAddress = normalizeAddress("mac", host.MACAddress)
	sensorID = strings.TrimSpace(sensorID)
	if host.IPAddress == "" {
		return false, nil
	}
	// Do not allow fields spliced into a cache payload to become inventory or
	// fingerprint input. Only the local IP/MAC edge survives this boundary.
	host.Hostname = ""
	host.Vendor = ""
	host.OpenPorts = nil
	host.Model = ""
	host.FriendlyName = ""
	host.Services = nil
	host.IdentityEvidence = nil

	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin ARP cache observation: %w", err)
	}
	defer tx.Rollback()
	// Acquire SQLite's writer lock before the dedupe read. Without this first
	// write, two concurrent sensor reports can both observe "no provisional row"
	// in deferred transactions and race to create duplicates. The identity key is
	// guaranteed by Open; assigning it to itself is deliberately state-neutral.
	if _, err := tx.Exec(`UPDATE settings SET value = value WHERE key = ?`, identityHMACSetting); err != nil {
		return false, fmt.Errorf("serialize ARP cache observation: %w", err)
	}
	if err := db.recordARPCacheStateTx(tx, host.IPAddress, host.MACAddress, segment, sensorID,
		observedAt, deliveryEpoch, deliverySequence); err != nil {
		return false, err
	}
	// Active-first Windows flow: ICMP already proved this exact IP live on the
	// same authenticated sensor/segment. Convert the scoped cache edge into a
	// normal corroborated observation so the canonical MAC and OUI fingerprint
	// are useful without trusting cache evidence by itself.
	if host.MACAddress != "" {
		liveID, err := db.recentIPOnlyNativeDeviceTx(tx, host.IPAddress, host.MACAddress, segment, sensorID, observedAt)
		if err != nil {
			return false, err
		}
		if liveID != "" {
			state, err := db.scopedARPCacheStateTx(tx, host.IPAddress, segment, sensorID)
			if err != nil {
				return false, err
			}
			expected := &arpCacheExpectation{
				sensorID: strings.TrimSpace(sensorID), segment: normalizeSegment(segment),
				ipAddress: host.IPAddress, macHMAC: state.macHMAC,
				observedAt: state.observedAt, epochOrder: state.epochOrder,
				deliverySequence: state.deliverySequence,
			}
			// Keep the ordering ledger durable before crossing into ObserveDevice's
			// separate transaction. A rollback here would erase the unique state and
			// let a delayed pre-ambiguity cache report win later.
			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("commit ARP cache state before live fusion: %w", err)
			}
			host.DiscoverySource = arpLiveFusionSource
			host.Status = "up"
			return db.ObserveDevice(DeviceObservation{
				Host: host, Segment: segment, SensorID: sensorID, ObservedAt: observedAt,
				expectedARPCache: expected,
			})
		}
	}

	// Replays after a sensor/process restart must refresh, not multiply, the
	// exact provisional edge. Sensor scope prevents overlapping LANs with the
	// same RFC1918 address and locally administered MAC from collapsing.
	deviceID, err := db.findARPCacheProvisionalTx(tx, host.IPAddress, host.MACAddress, segment, sensorID)
	if err != nil {
		return false, err
	}
	created := deviceID == ""
	if !created {
		if err := db.refreshARPCacheProvisionalTx(tx, deviceID, host, segment, sensorID, observedAt); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit repeated ARP cache observation: %w", err)
		}
		return false, nil
	}

	// An exact match against the current canonical tuple may refresh presence,
	// but never address history or identity evidence. Requiring the current IP and
	// segment is what prevents a stale same-MAC cache row for an old IP from
	// dragging a live device backwards.
	deviceID, err = db.currentDeviceForARPCacheTx(tx, host.IPAddress, host.MACAddress,
		segment, sensorID, observedAt)
	if err != nil {
		return false, err
	}
	if deviceID != "" {
		if err := db.refreshCurrentDeviceFromARPCacheTx(tx, deviceID, host.IPAddress, segment, observedAt); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit corroborating ARP cache observation: %w", err)
		}
		return false, nil
	}

	deviceID = uuid.New().String()
	if _, err := tx.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, open_ports, segment,
		 device_type, os_family, os_version, model, discovery_method, fingerprint_confidence, eol_risk, eol_model,
		 risk_category, risk_model, risk_reasons, services, display_name, friendly_name)
		VALUES (?, ?, ?, ?, '', '', '', '[]', ?, '', '', '', '', 'arp_cache', 0.0, 0, '', '', '', '[]', '[]', ?, '')`,
		deviceID, observedAt, observedAt, host.IPAddress, segment, host.IPAddress); err != nil {
		return false, fmt.Errorf("insert provisional ARP cache device: %w", err)
	}
	if err := db.refreshARPCacheProvisionalTx(tx, deviceID, host, segment, sensorID, observedAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit provisional ARP cache observation: %w", err)
	}
	return true, nil
}

func reportTimesWithin(a, b time.Time, window time.Duration) bool {
	a = a.UTC()
	b = b.UTC()
	if a.Before(b) {
		return b.Sub(a) <= window
	}
	return a.Sub(b) <= window
}

func normalizeCacheDelivery(epoch string, sequence uint64) (string, int64) {
	epoch = strings.TrimSpace(epoch)
	if epoch == "" || len(epoch) > 64 || sequence == 0 || sequence > maxCacheDeliverySequence {
		return "", 0
	}
	for _, r := range epoch {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", 0
	}
	return epoch, int64(sequence)
}

// IssueARPCacheDeliveryEpoch creates an inactive, one-time delivery-session
// candidate for an authenticated registration. The candidate is activated only
// when a device report proves the sensor received it. This two-phase boundary is
// deliberate: a stale registration handler may finish after a newer process has
// already registered, but its dead/timed-out caller can never send the candidate
// it did not receive and therefore cannot invalidate the live process.
func (db *DB) IssueARPCacheDeliveryEpoch(sensorID string) (string, error) {
	sensorID = strings.TrimSpace(sensorID)
	if sensorID == "" {
		return "", fmt.Errorf("issue ARP cache delivery epoch: sensor ID required")
	}
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("begin ARP cache delivery epoch: %w", err)
	}
	defer tx.Rollback()

	epoch := uuid.NewString()
	if _, err := tx.Exec(`INSERT INTO arp_cache_delivery_epochs
		(sensor_id, delivery_epoch, issued_at) VALUES (?, ?, ?)`,
		sensorID, epoch, time.Now().UTC()); err != nil {
		return "", fmt.Errorf("issue ARP cache delivery epoch: %w", err)
	}
	// Bound never-activated candidates generated by lost/timed-out registration
	// responses. Ever-activated epochs remain durable after retirement so a
	// delayed payload can always be classified as stale; retain the active row
	// independently as well.
	if _, err := tx.Exec(`DELETE FROM arp_cache_delivery_epochs
		WHERE sensor_id = ? AND activated_at IS NULL AND ever_activated_at IS NULL
		AND epoch_order NOT IN (
			SELECT epoch_order FROM arp_cache_delivery_epochs
			WHERE sensor_id = ? AND activated_at IS NULL AND ever_activated_at IS NULL
			ORDER BY epoch_order DESC LIMIT 8
		)`, sensorID, sensorID); err != nil {
		return "", fmt.Errorf("prune ARP cache delivery candidates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit ARP cache delivery epoch: %w", err)
	}
	return epoch, nil
}

func (db *DB) cacheDeliveryEpochOrderTx(tx *sql.Tx, sensorID, epoch string) (int64, error) {
	if sensorID == "" || epoch == "" {
		return 0, nil
	}
	var order int64
	var activatedAt, everActivatedAt sql.NullTime
	err := tx.QueryRow(`SELECT epoch_order, activated_at, ever_activated_at
		FROM arp_cache_delivery_epochs WHERE sensor_id=? AND delivery_epoch=?`, sensorID, epoch).
		Scan(&order, &activatedAt, &everActivatedAt)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read ARP cache delivery epoch: %w", err)
	}
	if activatedAt.Valid {
		return order, nil
	}
	if everActivatedAt.Valid {
		return 0, ErrARPCacheDeliveryStale
	}

	var activeOrder int64
	err = tx.QueryRow(`SELECT epoch_order FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND activated_at IS NOT NULL`, sensorID).Scan(&activeOrder)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("read active ARP cache delivery epoch: %w", err)
	}
	if activeOrder >= order {
		// This is a real Core-issued epoch, not unsequenced legacy input, but
		// another process has already activated a later one. Stop the entire
		// projection path instead of downgrading a delayed retry to cache-only
		// evidence.
		return 0, ErrARPCacheDeliveryStale
	}
	if _, err := tx.Exec(`UPDATE arp_cache_delivery_epochs SET activated_at=NULL
		WHERE sensor_id=? AND activated_at IS NOT NULL`, sensorID); err != nil {
		return 0, fmt.Errorf("retire active ARP cache delivery epoch: %w", err)
	}
	activatedAtTime := time.Now().UTC()
	result, err := tx.Exec(`UPDATE arp_cache_delivery_epochs
		SET activated_at=?, ever_activated_at=COALESCE(ever_activated_at, ?)
		WHERE sensor_id=? AND delivery_epoch=? AND activated_at IS NULL`,
		activatedAtTime, activatedAtTime, sensorID, epoch)
	if err != nil {
		return 0, fmt.Errorf("activate ARP cache delivery epoch: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return 0, fmt.Errorf("confirm ARP cache delivery epoch activation: %w", err)
		}
		return 0, fmt.Errorf("confirm ARP cache delivery epoch activation: updated %d rows", changed)
	}
	return order, nil
}

// recordARPCacheStateTx linearizes the latest cache transition for one
// authenticated sensor/segment/IP. Raw MACs stay in the ordinary local address
// history; this ordering ledger stores only their node-local HMAC. Current
// sensors use a Core-issued process epoch and sequence so an NTP step cannot
// reverse local observation order and exact retries remain idempotent. Once a
// scoped sequenced generation is accepted, its state, MAC HMAC, and observation
// time are immutable; a changed replay returns ErrARPCacheDeliveryMutation
// before any projection can change. A known older sequence/epoch returns
// ErrARPCacheDeliveryStale at the same boundary. Unsequenced legacy input retains
// event-time ordering but is never eligible for Core-side MAC fusion.
func (db *DB) recordARPCacheStateTx(tx *sql.Tx, ip, mac, segment, sensorID string,
	observedAt time.Time, deliveryEpoch string, deliverySequence uint64) error {
	var ok bool
	ip, ok = normalizeObservedIPv4(ip)
	if !ok {
		return fmt.Errorf("ARP cache state requires a valid unicast IPv4 address")
	}
	if strings.TrimSpace(mac) != "" {
		if normalized, valid := normalizeObservedEthernetMAC(mac); valid {
			mac = normalized
		} else {
			mac = ""
		}
	}
	segment = normalizeSegment(segment)
	sensorID = strings.TrimSpace(sensorID)
	observedAt = observedAt.UTC()
	if observedAt.IsZero() {
		return fmt.Errorf("ARP cache state requires an IP and observation time")
	}

	deliveryEpoch, sequence := normalizeCacheDelivery(deliveryEpoch, deliverySequence)
	if sensorID == "" {
		deliveryEpoch, sequence = "", 0
	}
	epochOrder, err := db.cacheDeliveryEpochOrderTx(tx, sensorID, deliveryEpoch)
	if err != nil {
		return err
	}
	if epochOrder == 0 {
		// Only a session issued during authenticated registration can establish
		// ordering. Unknown/random epochs are legacy-strength observations and can
		// never promote a cache MAC in Core.
		deliveryEpoch, sequence = "", 0
	}
	incoming := arpCacheState{
		state: arpCacheStateAmbiguous, observedAt: observedAt,
		epochOrder: epochOrder, deliverySequence: sequence,
	}
	if mac != "" {
		key, err := db.identityHMACKeyTx(tx)
		if err != nil {
			return err
		}
		incoming.state = arpCacheStateUnique
		incoming.macHMAC = identityValueHMAC(key, "mac", mac)
	}

	var current arpCacheState
	err = tx.QueryRow(`SELECT state, mac_hmac, observed_at,
			delivery_epoch_order, delivery_sequence FROM arp_cache_states
		WHERE sensor_id = ? AND segment = ? AND ip_address = ?`, sensorID, segment, ip).
		Scan(&current.state, &current.macHMAC, &current.observedAt,
			&current.epochOrder, &current.deliverySequence)
	switch {
	case err == sql.ErrNoRows:
		if _, err := tx.Exec(`INSERT INTO arp_cache_states
			(sensor_id, segment, ip_address, state, mac_hmac, observed_at,
			 delivery_epoch_order, delivery_sequence, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, sensorID, segment, ip, incoming.state,
			incoming.macHMAC, incoming.observedAt, incoming.epochOrder,
			incoming.deliverySequence, time.Now().UTC()); err != nil {
			return fmt.Errorf("insert ARP cache state: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("read ARP cache state: %w", err)
	}

	sameGeneration := false
	switch {
	case current.epochOrder > 0 || incoming.epochOrder > 0:
		switch {
		case incoming.epochOrder == 0:
			return nil // unsequenced legacy input cannot reclaim sequenced state
		case current.epochOrder == 0:
			// First sequenced observation after upgrade supersedes legacy ordering.
		case current.epochOrder > incoming.epochOrder:
			return ErrARPCacheDeliveryStale
		case current.epochOrder < incoming.epochOrder:
			// A newly observed sensor-process epoch supersedes older epoch retries.
		case current.deliverySequence > incoming.deliverySequence:
			return ErrARPCacheDeliveryStale
		case current.deliverySequence == incoming.deliverySequence:
			sameGeneration = true
		}
	default:
		switch {
		case current.observedAt.After(incoming.observedAt):
			return nil
		case current.observedAt.Equal(incoming.observedAt):
			sameGeneration = true
		}
	}
	if sameGeneration {
		if current.epochOrder > 0 {
			if current.state != incoming.state || current.macHMAC != incoming.macHMAC ||
				!current.observedAt.Equal(incoming.observedAt) {
				return ErrARPCacheDeliveryMutation
			}
			// An exact replay is already durable. Leave updated_at and the ordering
			// ledger untouched, then let the idempotent projection path confirm any
			// work whose response may have been lost.
			return nil
		}
		if current.state == arpCacheStateAmbiguous || incoming.state == arpCacheStateAmbiguous ||
			current.macHMAC != incoming.macHMAC {
			incoming.state = arpCacheStateAmbiguous
			incoming.macHMAC = ""
		}
		if current.observedAt.After(incoming.observedAt) {
			incoming.observedAt = current.observedAt
		}
	}

	if _, err := tx.Exec(`UPDATE arp_cache_states SET
		state = ?, mac_hmac = ?, observed_at = ?, delivery_epoch_order = ?,
		delivery_sequence = ?, updated_at = ?
		WHERE sensor_id = ? AND segment = ? AND ip_address = ?`,
		incoming.state, incoming.macHMAC, incoming.observedAt, incoming.epochOrder,
		incoming.deliverySequence, time.Now().UTC(),
		sensorID, segment, ip); err != nil {
		return fmt.Errorf("update ARP cache state: %w", err)
	}
	return nil
}

func (db *DB) scopedARPCacheStateTx(tx *sql.Tx, ip, segment, sensorID string) (arpCacheState, error) {
	var state arpCacheState
	err := tx.QueryRow(`SELECT state, mac_hmac, observed_at,
			delivery_epoch_order, delivery_sequence FROM arp_cache_states
		WHERE sensor_id = ? AND segment = ? AND ip_address = ?`,
		strings.TrimSpace(sensorID), normalizeSegment(segment), normalizeAddress("ip", ip)).
		Scan(&state.state, &state.macHMAC, &state.observedAt,
			&state.epochOrder, &state.deliverySequence)
	if err == sql.ErrNoRows {
		return arpCacheState{}, nil
	}
	if err != nil {
		return arpCacheState{}, fmt.Errorf("read scoped ARP cache state: %w", err)
	}
	state.observedAt = state.observedAt.UTC()
	return state, nil
}

func (db *DB) matchesARPCacheExpectationTx(tx *sql.Tx, expected *arpCacheExpectation) (bool, error) {
	if expected == nil {
		return true, nil
	}
	state, err := db.scopedARPCacheStateTx(tx, expected.ipAddress, expected.segment, expected.sensorID)
	if err != nil {
		return false, err
	}
	return state.state == arpCacheStateUnique && state.macHMAC == expected.macHMAC &&
		state.observedAt.Equal(expected.observedAt.UTC()) &&
		state.epochOrder == expected.epochOrder &&
		state.deliverySequence == expected.deliverySequence, nil
}

// recentIPOnlyNativeDeviceTx finds the unique active-first side of the Windows
// ICMP+ARP fusion. Only a liveness probe explicitly bound to the selected
// interface/source address is eligible: plain native_icmp may have escaped a
// different route and must never corroborate this link's cache. The current IP
// interval, sensor, segment, source, empty MAC, and time window must all agree;
// ambiguity fails closed.
func (db *DB) recentIPOnlyNativeDeviceTx(tx *sql.Tx, ip, incomingMAC, segment, sensorID string,
	observedAt time.Time) (string, error) {
	rows, err := tx.Query(`SELECT DISTINCT d.device_id, h.last_seen
		FROM devices d JOIN device_address_history h ON h.device_id = d.device_id
		WHERE d.merged_into_device_id IS NULL AND d.discovery_method = ?
		  AND COALESCE(d.mac_address, '') = '' AND d.ip_address = ? AND d.segment = ?
		  AND h.address_type = 'ip' AND h.address_value = ? AND h.segment = ? AND h.sensor_id = ?
		  AND h.evidence_source = ?
		  AND h.valid_from <= ? AND (h.valid_until IS NULL OR ? < h.valid_until)`,
		nativeICMPBoundSource, ip, segment, ip, segment, strings.TrimSpace(sensorID),
		nativeICMPBoundSource, observedAt, observedAt)
	if err != nil {
		return "", fmt.Errorf("query recent native ICMP device for ARP fusion: %w", err)
	}
	defer rows.Close()
	match := ""
	for rows.Next() {
		var deviceID string
		var seen time.Time
		if err := rows.Scan(&deviceID, &seen); err != nil {
			return "", fmt.Errorf("scan recent native ICMP device for ARP fusion: %w", err)
		}
		if !reportTimesWithin(seen, observedAt, arpLiveFusionWindow) {
			continue
		}
		if match != "" && match != deviceID {
			return "", nil
		}
		match = deviceID
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate recent native ICMP devices for ARP fusion: %w", err)
	}
	if err := rows.Close(); err != nil {
		return "", fmt.Errorf("close recent native ICMP devices for ARP fusion: %w", err)
	}
	if match == "" {
		return "", nil
	}
	state, err := db.scopedARPCacheStateTx(tx, ip, segment, sensorID)
	if err != nil {
		return "", err
	}
	// This call is processing the current nonblank cache transition. It may fuse
	// only when that exact event-time transition is still the latest scoped state;
	// a newer out-of-order state or an equal-time conflict fails closed.
	if state.state != arpCacheStateUnique || state.epochOrder <= 0 ||
		state.deliverySequence <= 0 || !state.observedAt.Equal(observedAt.UTC()) {
		return "", nil
	}
	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return "", err
	}
	if state.macHMAC != identityValueHMAC(key, "mac", incomingMAC) {
		return "", nil
	}
	return match, nil
}

// recentARPCacheMACForLiveDeviceTx is the cache-first side of the same fusion.
// Raw MACs remain local in temporal address history; only one recent, scoped MAC
// across every cache provisional for the IP may corroborate the IP-only live
// observation. Looking only at the provisional chosen by the legacy IP fallback
// would make the result depend on row ordering when a recycled IP has competing
// cache MACs.
func (db *DB) recentARPCacheMACForLiveDeviceTx(tx *sql.Tx, deviceID, ip, segment, sensorID string,
	observedAt time.Time) (string, error) {
	var method, currentIP string
	if err := tx.QueryRow(`SELECT discovery_method, ip_address FROM devices WHERE device_id = ?`, deviceID).
		Scan(&method, &currentIP); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("read cache-first device for ARP fusion: %w", err)
	}
	if method != "arp_cache" || normalizeAddress("ip", currentIP) != normalizeAddress("ip", ip) {
		return "", nil
	}
	state, err := db.scopedARPCacheStateTx(tx, ip, segment, sensorID)
	if err != nil {
		return "", err
	}
	// Cache-first fusion requires a unique transition at or before the live
	// generation. Future/out-of-order cache state cannot retroactively enrich it.
	if state.state != arpCacheStateUnique || state.epochOrder <= 0 || state.deliverySequence <= 0 ||
		state.observedAt.After(observedAt.UTC()) ||
		!reportTimesWithin(state.observedAt, observedAt, arpLiveFusionWindow) {
		return "", nil
	}
	return db.rawARPCacheMACForStateTx(tx, ip, segment, sensorID, state)
}

// rawARPCacheMACForStateTx recovers the local raw MAC that corresponds to the
// HMAC-only latest-state ledger. The transition timestamp must match the cache
// history row, so an older candidate cannot be resurrected after ambiguity.
func (db *DB) rawARPCacheMACForStateTx(tx *sql.Tx, ip, segment, sensorID string,
	state arpCacheState) (string, error) {
	rows, err := tx.Query(`SELECT DISTINCT h.address_value, h.last_seen
		FROM devices d
		JOIN device_networks n ON n.device_id = d.device_id
		JOIN device_address_history h ON h.device_id = d.device_id
		WHERE d.merged_into_device_id IS NULL
		  AND n.segment = ? AND n.ip_address = ? AND n.sensor_id = ?
		  AND h.address_type = 'mac' AND h.segment = ? AND h.sensor_id = ?
		  AND h.evidence_source = 'arp_cache' AND h.valid_until IS NULL`,
		segment, ip, strings.TrimSpace(sensorID), segment, strings.TrimSpace(sensorID))
	if err != nil {
		return "", fmt.Errorf("query cache MAC for latest ARP state: %w", err)
	}
	defer rows.Close()
	unique := make(map[string]struct{})
	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var mac string
		var seen time.Time
		if err := rows.Scan(&mac, &seen); err != nil {
			return "", fmt.Errorf("scan cache MAC for latest ARP state: %w", err)
		}
		mac = normalizeAddress("mac", mac)
		if mac == "" || !seen.UTC().Equal(state.observedAt) ||
			identityValueHMAC(key, "mac", mac) != state.macHMAC {
			continue
		}
		unique[mac] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate cache MACs for latest ARP state: %w", err)
	}
	if len(unique) != 1 {
		return "", nil
	}
	for mac := range unique {
		return mac, nil
	}
	return "", nil
}

func (db *DB) findARPCacheProvisionalTx(tx *sql.Tx, ip, mac, segment, sensorID string) (string, error) {
	base := `SELECT d.device_id FROM devices d
		JOIN device_networks n ON n.device_id = d.device_id AND n.segment = ?
		WHERE d.merged_into_device_id IS NULL AND d.discovery_method = 'arp_cache'
		  AND d.ip_address = ? AND d.segment = ? AND n.ip_address = ? AND n.sensor_id = ?`
	args := []any{segment, ip, segment, ip, strings.TrimSpace(sensorID)}
	if mac == "" {
		base += ` AND NOT EXISTS (SELECT 1 FROM device_identity_evidence e
			WHERE e.device_id = d.device_id AND e.evidence_type = 'mac'
			  AND e.segment = ? AND e.sensor_id = ? AND e.valid_until IS NULL)`
		args = append(args, segment, strings.TrimSpace(sensorID))
	} else {
		key, err := db.identityHMACKeyTx(tx)
		if err != nil {
			return "", err
		}
		base += ` AND EXISTS (SELECT 1 FROM device_identity_evidence e
			WHERE e.device_id = d.device_id AND e.evidence_type = 'mac' AND e.value_hmac = ?
			  AND e.segment = ? AND e.sensor_id = ? AND e.source = 'arp_cache'
			  AND e.valid_until IS NULL)`
		args = append(args, identityValueHMAC(key, "mac", mac), segment, strings.TrimSpace(sensorID))
	}
	base += ` ORDER BY d.last_seen DESC, d.device_id LIMIT 1`
	var deviceID string
	if err := tx.QueryRow(base, args...).Scan(&deviceID); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("find provisional ARP cache device: %w", err)
	}
	return deviceID, nil
}

func (db *DB) currentDeviceForARPCacheTx(tx *sql.Tx, ip, mac, segment, sensorID string,
	observedAt time.Time) (string, error) {
	if mac == "" {
		return "", nil
	}
	rows, err := tx.Query(`SELECT DISTINCT d.device_id, COALESCE(d.mac_address, '') FROM devices d
		JOIN device_address_history h ON h.device_id = d.device_id
		WHERE d.merged_into_device_id IS NULL AND d.discovery_method != 'arp_cache'
		  AND d.ip_address = ? AND d.segment = ?
		  AND h.address_type = 'ip' AND h.address_value = ? AND h.segment = ? AND h.sensor_id = ?
		  AND h.valid_from <= ? AND (h.valid_until IS NULL OR ? < h.valid_until)
		  AND h.last_seen >= ? AND h.confidence > ?`,
		ip, segment, ip, segment, strings.TrimSpace(sensorID), observedAt, observedAt,
		observedAt.Add(-temporalAddressResolutionWindow), arpCacheIdentityConfidence)
	if err != nil {
		return "", fmt.Errorf("query current device for ARP cache: %w", err)
	}
	defer rows.Close()
	match := ""
	for rows.Next() {
		var deviceID, storedMAC string
		if err := rows.Scan(&deviceID, &storedMAC); err != nil {
			return "", fmt.Errorf("scan current device for ARP cache: %w", err)
		}
		if normalizeAddress("mac", storedMAC) != mac {
			continue
		}
		if match != "" && match != deviceID {
			return "", nil // duplicate canonical rows are ambiguous; preserve a provisional edge
		}
		match = deviceID
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate current device for ARP cache: %w", err)
	}
	return match, nil
}

func (db *DB) refreshCurrentDeviceFromARPCacheTx(tx *sql.Tx, deviceID, ip, segment string, observedAt time.Time) error {
	if _, err := tx.Exec(`UPDATE devices SET
		first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
		WHERE device_id = ? AND ip_address = ? AND segment = ?`,
		observedAt, observedAt, deviceID, ip, segment); err != nil {
		return fmt.Errorf("refresh current device from ARP cache: %w", err)
	}
	// Refresh only an already-current attachment. An INSERT/UPSERT here could
	// manufacture a weak attachment or replace a newer live IP.
	if _, err := tx.Exec(`UPDATE device_networks SET
		first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
		WHERE device_id = ? AND segment = ? AND ip_address = ?`,
		observedAt, observedAt, deviceID, segment, ip); err != nil {
		return fmt.Errorf("refresh current network from ARP cache: %w", err)
	}
	return nil
}

func (db *DB) refreshARPCacheProvisionalTx(tx *sql.Tx, deviceID string, host discovery.DiscoveredHost,
	segment, sensorID string, observedAt time.Time) error {
	if _, err := tx.Exec(`UPDATE devices SET
		first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
		WHERE device_id = ? AND discovery_method = 'arp_cache'`, observedAt, observedAt, deviceID); err != nil {
		return fmt.Errorf("refresh provisional ARP cache device: %w", err)
	}
	if err := db.upsertNetworkTx(tx, deviceID, segment, host.IPAddress, sensorID, observedAt); err != nil {
		return err
	}
	if err := db.recordARPCacheBindingIfSafeTx(tx, deviceID, "ip", host.IPAddress,
		segment, sensorID, observedAt); err != nil {
		return err
	}
	if err := db.recordARPCacheBindingIfSafeTx(tx, deviceID, "mac", host.MACAddress,
		segment, sensorID, observedAt); err != nil {
		return err
	}
	if host.MACAddress != "" {
		_, err := db.upsertIdentityEvidenceTx(tx, deviceID, segment, sensorID, DeviceIdentityEvidenceInput{
			Type: "mac", Value: host.MACAddress, Source: "arp_cache",
			Confidence: arpCacheIdentityConfidence, Sensitive: true,
		}, observedAt, false)
		if err != nil {
			return err
		}
	}
	return nil
}

// recordARPCacheBindingIfSafeTx can create or refresh a weak cache interval,
// but it never closes, extends, or replaces any other current interval. That
// one-way rule is the store-level backstop protecting live DHCP/passive history.
func (db *DB) recordARPCacheBindingIfSafeTx(tx *sql.Tx, deviceID, addressType, addressValue,
	segment, sensorID string, observedAt time.Time) error {
	addressValue = normalizeAddress(addressType, addressValue)
	if addressValue == "" {
		return nil
	}
	var bindingID, ownerID, source string
	var confidence float64
	err := tx.QueryRow(`SELECT binding_id, device_id, evidence_source, confidence
		FROM device_address_history
		WHERE address_type = ? AND address_value = ? AND segment = ? AND sensor_id = ?
		  AND valid_from <= ? AND (valid_until IS NULL OR ? < valid_until)
		ORDER BY valid_from DESC LIMIT 1`,
		addressType, addressValue, segment, strings.TrimSpace(sensorID), observedAt, observedAt).
		Scan(&bindingID, &ownerID, &source, &confidence)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("inspect current address owner before ARP cache write: %w", err)
	}
	if err == nil {
		canonicalOwner, err := db.canonicalDeviceIDTx(tx, ownerID)
		if err != nil {
			return err
		}
		canonicalDevice, err := db.canonicalDeviceIDTx(tx, deviceID)
		if err != nil {
			return err
		}
		if canonicalOwner != canonicalDevice || source != "arp_cache" || confidence > arpCacheIdentityConfidence {
			return nil
		}
		if _, err := tx.Exec(`UPDATE device_address_history SET
			first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
			WHERE binding_id = ?`, observedAt, observedAt, bindingID); err != nil {
			return fmt.Errorf("refresh ARP cache address interval: %w", err)
		}
		if err := recordAddressBindingValidityTx(tx, bindingID, observedAt); err != nil {
			return err
		}
		return nil
	}
	return db.recordAddressBindingTx(tx, deviceID, addressType, addressValue, segment,
		sensorID, "arp_cache", arpCacheIdentityConfidence, observedAt)
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
// (for example, a stale inventory snapshot versus actively updating discovery data).
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
