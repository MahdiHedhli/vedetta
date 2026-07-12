package models

import "time"

// Event represents the core event schema for all Vedetta events.
// Every field must earn its place — lean and meaningful.
type Event struct {
	EventID    string    `json:"event_id" db:"event_id"`               // Caller ID or Core-derived replay-stable UUIDv8
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`             // ISO8601
	EventType  string    `json:"event_type" db:"event_type"`           // dns_query | nmap_discovery | firewall_log | anomaly
	SourceHash string    `json:"source_hash" db:"source_hash"`         // Core-owned HMAC of local IP with a private per-install key
	SourceIP   string    `json:"source_ip,omitempty" db:"source_ip"`   // Raw client IP (local network only)
	ServerIP   string    `json:"server_ip,omitempty" db:"server_ip"`   // DNS server queried (for actionability)
	Domain     string    `json:"domain,omitempty" db:"domain"`         // queried domain (DNS events)
	QueryType  string    `json:"query_type,omitempty" db:"query_type"` // A | AAAA | MX | TXT
	ResolvedIP string    `json:"resolved_ip,omitempty" db:"resolved_ip"`
	Blocked    bool      `json:"blocked" db:"blocked"`
	// Outcome is Core-derived processing context: blocked | allowed | observed.
	// It is not trusted from ingest callers and is persisted with the raw event.
	Outcome        string   `json:"outcome,omitempty" db:"outcome"`
	AnomalyScore   float64  `json:"anomaly_score" db:"anomaly_score"`
	Tags           []string `json:"tags" db:"-"`            // c2_candidate, dga_candidate, new_device, etc.
	Geo            string   `json:"geo,omitempty" db:"geo"` // Country code (ISO 3166-1 alpha-2)
	DeviceVendor   string   `json:"device_vendor,omitempty" db:"device_vendor"`
	NetworkSegment string   `json:"network_segment,omitempty" db:"network_segment"` // default | iot | guest
	DNSSource      string   `json:"dns_source,omitempty" db:"dns_source"`           // passive_capture | pihole | adguard | embedded_resolver | iptables_intercept
	ThreatDesc     string   `json:"threat_desc,omitempty" db:"threat_desc"`         // Human-readable threat explanation
	Metadata       string   `json:"metadata,omitempty" db:"metadata"`               // JSON: detection details (entropy, signals, CV, etc.)
	Acknowledged   bool     `json:"acknowledged" db:"acknowledged"`                 // User reviewed this event
	AckReason      string   `json:"ack_reason,omitempty" db:"ack_reason"`           // Why the user dismissed it

	// Spec 007: stable asset identity and ingestion/disposition provenance. An
	// empty DeviceID is explicitly unresolved; existing rows are not backfilled
	// from a device's current IP. IdentityEvidence is bounded structured JSON
	// explaining the deterministic resolution result.
	DeviceID           string  `json:"device_id,omitempty" db:"device_id"`
	CanonicalDeviceID  string  `json:"canonical_device_id,omitempty" db:"-"`
	IdentityConfidence float64 `json:"identity_confidence" db:"identity_confidence"`
	IdentityReason     string  `json:"identity_reason,omitempty" db:"identity_reason"`
	IdentityEvidence   string  `json:"identity_evidence,omitempty" db:"identity_evidence"`
	Origin             string  `json:"origin,omitempty" db:"origin"`
	SensorID           string  `json:"sensor_id,omitempty" db:"sensor_id"`
	Disposition        string  `json:"disposition,omitempty" db:"disposition"`
	SuppressionRuleID  string  `json:"suppression_rule_id,omitempty" db:"suppression_rule_id"`

	// Match provenance (GHSA-hx86): when an event is tagged known_bad, record WHICH
	// indicator matched and via which path so downstream readers can tell a domain
	// match from a resolved-IP match. MatchType is "" (no match), "domain", or
	// "resolved_ip". For a domain match MatchedIndicator is the matched list entry
	// (== the observed FQDN today); for a resolved_ip match it is the matched IP.
	MatchedIndicator string `json:"matched_indicator,omitempty" db:"matched_indicator"`
	MatchType        string `json:"match_type,omitempty" db:"match_type"`
}

// Device represents a discovered network device.
type Device struct {
	DeviceID              string    `json:"device_id" db:"device_id"`
	FirstSeen             time.Time `json:"first_seen" db:"first_seen"`
	LastSeen              time.Time `json:"last_seen" db:"last_seen"`
	IPAddress             string    `json:"ip_address" db:"ip_address"`
	MACAddress            string    `json:"mac_address" db:"mac_address"`
	Hostname              string    `json:"hostname,omitempty" db:"hostname"`
	Vendor                string    `json:"vendor,omitempty" db:"vendor"`
	OpenPorts             []int     `json:"open_ports,omitempty" db:"-"`
	Segment               string    `json:"segment" db:"segment"` // default | iot | guest
	DeviceType            string    `json:"device_type,omitempty" db:"device_type"`
	OSFamily              string    `json:"os_family,omitempty" db:"os_family"`
	OSVersion             string    `json:"os_version,omitempty" db:"os_version"`
	Model                 string    `json:"model,omitempty" db:"model"`
	DiscoveryMethod       string    `json:"discovery_source,omitempty" db:"discovery_method"`
	FingerprintConfidence float64   `json:"fingerprint_confidence" db:"fingerprint_confidence"`
	Services              []string  `json:"services,omitempty" db:"-"` // from sensor passive discovery for actionability

	CustomName string `json:"custom_name,omitempty" db:"custom_name"`
	Notes      string `json:"notes,omitempty" db:"notes"`
	// EOLRisk and EOLModel are retained for backward compatibility with the original
	// IC3 AVrecon work. New code should prefer the generalized risk fields below.
	EOLRisk  bool   `json:"eol_risk" db:"eol_risk"`
	EOLModel string `json:"eol_model,omitempty" db:"eol_model"`

	// Generalized risk categories (see migration 016).
	// Primary category: "known_exploited", "eol_eos", or "high_risk_iot".
	RiskCategory string   `json:"risk_category,omitempty" db:"risk_category"`
	RiskModel    string   `json:"risk_model,omitempty" db:"risk_model"`
	RiskReasons  []string `json:"risk_reasons,omitempty" db:"-"` // populated from risk_reasons JSON TEXT

	// Spec 004: correlation, labeling & multi-network fields.
	// DisplayName is the derived human-readable label (custom_name > friendly_name >
	// model+vendor > cleaned hostname > vendor+MAC-suffix > IP), recomputed on upsert.
	DisplayName  string         `json:"display_name,omitempty" db:"display_name"`
	FriendlyName string         `json:"friendly_name,omitempty" db:"friendly_name"`
	Segments     []string       `json:"segments,omitempty" db:"-"` // from device_networks attachments
	Signals      []DeviceSignal `json:"signals,omitempty" db:"-"`  // per-field provenance from device_signals

	// Spec 007: read-time identity summary. These are projections of current
	// HMAC evidence (including redirected children), not mutable device columns.
	IdentityConfidence  float64 `json:"identity_confidence" db:"-"`
	IdentityStatus      string  `json:"identity_status" db:"-"`
	IdentityReason      string  `json:"identity_reason,omitempty" db:"-"`
	NeedsIdentification bool    `json:"needs_identification" db:"-"`
	CanonicalDeviceID   string  `json:"canonical_device_id" db:"-"`
}

// ActiveDeviceMerge is an undoable soft-merge audit projection. TargetDeviceID
// is the target recorded by the original action; CanonicalTargetDeviceID follows
// any later redirect chain so clients navigate to the currently visible asset.
type ActiveDeviceMerge struct {
	ActionID                string    `json:"action_id"`
	ActionType              string    `json:"action_type"`
	SourceDeviceID          string    `json:"source_device_id"`
	TargetDeviceID          string    `json:"target_device_id"`
	CanonicalTargetDeviceID string    `json:"canonical_target_device_id"`
	SourceDisplayName       string    `json:"source_display_name"`
	TargetDisplayName       string    `json:"target_display_name"`
	Actor                   string    `json:"actor"`
	Reason                  string    `json:"reason"`
	CreatedAt               time.Time `json:"created_at"`
}

// DeviceSignal is one per-field provenance record: which source last set a
// canonical device field, at what confidence, and when (spec 004, FR-6/FR-9).
type DeviceSignal struct {
	Field        string    `json:"field"`
	Value        string    `json:"value"`
	Source       string    `json:"source"`
	Confidence   float64   `json:"confidence"`
	LastObserved time.Time `json:"last_observed"`
}

// SuppressionRule defines a user-created filter to auto-hide matching events.
type SuppressionRule struct {
	RuleID    string    `json:"rule_id" db:"rule_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Domain    string    `json:"domain,omitempty" db:"domain"`
	SourceIP  string    `json:"source_ip,omitempty" db:"source_ip"`
	Tags      []string  `json:"tags" db:"-"`
	Reason    string    `json:"reason,omitempty" db:"reason"`
	Active    bool      `json:"active" db:"active"`
}

// Sensor represents a registered sensor that reports to Core.
type Sensor struct {
	SensorID   string    `json:"sensor_id" db:"sensor_id"`
	Hostname   string    `json:"hostname" db:"hostname"`
	OS         string    `json:"os" db:"os"`
	Arch       string    `json:"arch" db:"arch"`
	CIDR       string    `json:"cidr" db:"cidr"`
	Version    string    `json:"version" db:"version"`
	FirstSeen  time.Time `json:"first_seen" db:"first_seen"`
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	Status     string    `json:"status" db:"status"`                   // online | offline
	IsPrimary  bool      `json:"is_primary" db:"is_primary"`           // only one sensor should be primary
	Interfaces string    `json:"interfaces,omitempty" db:"interfaces"` // JSON-encoded []NetworkInterface
}

// ScanTarget represents a named subnet to scan (e.g., IoT VLAN, Guest network).
type ScanTarget struct {
	TargetID     string     `json:"target_id" db:"target_id"`
	Name         string     `json:"name" db:"name"`
	CIDR         string     `json:"cidr" db:"cidr"`
	Segment      string     `json:"segment" db:"segment"` // default | iot | guest
	ScanPorts    bool       `json:"scan_ports" db:"scan_ports"`
	Enabled      bool       `json:"enabled" db:"enabled"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	LastScan     *time.Time `json:"last_scan,omitempty" db:"last_scan"`
	DNSCapture   bool       `json:"dns_capture" db:"dns_capture"`
	DNSInterface string     `json:"dns_interface,omitempty" db:"dns_interface"` // which NIC to capture DNS on
}

// WhitelistRule defines a known-traffic pattern to filter expected home network noise.
type WhitelistRule struct {
	RuleID          string    `json:"rule_id" db:"rule_id"`
	Name            string    `json:"name" db:"name"`
	Description     string    `json:"description,omitempty" db:"description"`
	DomainPattern   string    `json:"domain_pattern,omitempty" db:"domain_pattern"`
	SourceIPPattern string    `json:"source_ip_pattern,omitempty" db:"source_ip_pattern"`
	TagMatch        string    `json:"tag_match,omitempty" db:"tag_match"`
	Category        string    `json:"category" db:"category"`
	IsDefault       bool      `json:"is_default" db:"is_default"`
	Enabled         bool      `json:"enabled" db:"enabled"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}
