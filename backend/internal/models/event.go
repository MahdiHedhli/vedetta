package models

import "time"

// Event represents the core event schema for all Vedetta events.
// Every field must earn its place — lean and meaningful.
type Event struct {
	EventID         string    `json:"event_id" db:"event_id"`               // UUID v4
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`             // ISO8601
	EventType       string    `json:"event_type" db:"event_type"`           // dns_query | nmap_discovery | firewall_log | anomaly
	SourceHash      string    `json:"source_hash" db:"source_hash"`         // SHA-256 of local IP + per-install salt
	SourceIP        string    `json:"source_ip,omitempty" db:"source_ip"`   // Raw client IP (local network only)
	Domain          string    `json:"domain,omitempty" db:"domain"`         // queried domain (DNS events)
	QueryType       string    `json:"query_type,omitempty" db:"query_type"` // A | AAAA | MX | TXT
	ResolvedIP      string    `json:"resolved_ip,omitempty" db:"resolved_ip"`
	Blocked         bool      `json:"blocked" db:"blocked"`
	AnomalyScore    float64   `json:"anomaly_score" db:"anomaly_score"`
	Tags            []string  `json:"tags" db:"-"`                                            // c2_candidate, dga_candidate, new_device, etc.
	Geo             string    `json:"geo,omitempty" db:"geo"`                                 // Country code (ISO 3166-1 alpha-2)
	DeviceVendor    string    `json:"device_vendor,omitempty" db:"device_vendor"`
	NetworkSegment  string    `json:"network_segment,omitempty" db:"network_segment"`         // default | iot | guest
	DNSSource       string    `json:"dns_source,omitempty" db:"dns_source"`                   // passive_capture | pihole | adguard | embedded_resolver | iptables_intercept
	ThreatDesc      string    `json:"threat_desc,omitempty" db:"threat_desc"`                 // Human-readable threat explanation
	Metadata        string    `json:"metadata,omitempty" db:"metadata"`                       // JSON: detection details (entropy, signals, CV, etc.)
	Acknowledged    bool      `json:"acknowledged" db:"acknowledged"`                         // User reviewed this event
	AckReason       string    `json:"ack_reason,omitempty" db:"ack_reason"`                   // Why the user dismissed it
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
	DiscoveryMethod       string    `json:"discovery_method,omitempty" db:"discovery_method"`
	FingerprintConfidence float64   `json:"fingerprint_confidence" db:"fingerprint_confidence"`
	CustomName            string    `json:"custom_name,omitempty" db:"custom_name"`
	Notes                 string    `json:"notes,omitempty" db:"notes"`
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
	Status     string    `json:"status" db:"status"`       // online | offline
	IsPrimary  bool      `json:"is_primary" db:"is_primary"` // only one sensor should be primary
	Interfaces string    `json:"interfaces,omitempty" db:"interfaces"` // JSON-encoded []NetworkInterface
}

// ScanTarget represents a named subnet to scan (e.g., IoT VLAN, Guest network).
type ScanTarget struct {
	TargetID      string     `json:"target_id" db:"target_id"`
	Name          string     `json:"name" db:"name"`
	CIDR          string     `json:"cidr" db:"cidr"`
	Segment       string     `json:"segment" db:"segment"`     // default | iot | guest
	ScanPorts     bool       `json:"scan_ports" db:"scan_ports"`
	Enabled       bool       `json:"enabled" db:"enabled"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	LastScan      *time.Time `json:"last_scan,omitempty" db:"last_scan"`
	DNSCapture    bool       `json:"dns_capture" db:"dns_capture"`
	DNSInterface  string     `json:"dns_interface,omitempty" db:"dns_interface"` // which NIC to capture DNS on
}
