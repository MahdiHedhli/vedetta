package models

import "time"

// Event represents the core event schema for all Vedetta events.
// Every field must earn its place — lean and meaningful.
type Event struct {
	EventID        string    `json:"event_id" db:"event_id"`               // UUID v4
	Timestamp      time.Time `json:"timestamp" db:"timestamp"`             // ISO8601
	EventType      string    `json:"event_type" db:"event_type"`           // dns_query | nmap_discovery | firewall_log | anomaly
	SourceHash     string    `json:"source_hash" db:"source_hash"`         // SHA-256 of local IP + per-install salt
	Domain         string    `json:"domain,omitempty" db:"domain"`         // queried domain (DNS events)
	QueryType      string    `json:"query_type,omitempty" db:"query_type"` // A | AAAA | MX | TXT
	ResolvedIP     string    `json:"resolved_ip,omitempty" db:"resolved_ip"`
	Blocked        bool      `json:"blocked" db:"blocked"`
	AnomalyScore   float64   `json:"anomaly_score" db:"anomaly_score"`
	Tags           []string  `json:"tags" db:"-"`                                            // c2_candidate, dga_candidate, new_device, etc.
	Geo            string    `json:"geo,omitempty" db:"geo"`                                 // Country code (ISO 3166-1 alpha-2)
	DeviceVendor   string    `json:"device_vendor,omitempty" db:"device_vendor"`
	NetworkSegment string    `json:"network_segment,omitempty" db:"network_segment"`         // default | iot | guest
}

// Device represents a discovered network device.
type Device struct {
	DeviceID    string    `json:"device_id" db:"device_id"`
	FirstSeen   time.Time `json:"first_seen" db:"first_seen"`
	LastSeen    time.Time `json:"last_seen" db:"last_seen"`
	IPAddress   string    `json:"ip_address" db:"ip_address"`
	MACAddress  string    `json:"mac_address" db:"mac_address"`
	Hostname    string    `json:"hostname,omitempty" db:"hostname"`
	Vendor      string    `json:"vendor,omitempty" db:"vendor"`
	OpenPorts   []int     `json:"open_ports,omitempty" db:"-"`
	Segment     string    `json:"segment" db:"segment"` // default | iot | guest
}

// Sensor represents a registered sensor that reports to Core.
type Sensor struct {
	SensorID  string    `json:"sensor_id" db:"sensor_id"`
	Hostname  string    `json:"hostname" db:"hostname"`
	OS        string    `json:"os" db:"os"`
	Arch      string    `json:"arch" db:"arch"`
	CIDR      string    `json:"cidr" db:"cidr"`
	Version   string    `json:"version" db:"version"`
	FirstSeen time.Time `json:"first_seen" db:"first_seen"`
	LastSeen  time.Time `json:"last_seen" db:"last_seen"`
	Status    string    `json:"status" db:"status"`       // online | offline
	IsPrimary bool      `json:"is_primary" db:"is_primary"` // only one sensor should be primary
}

// ScanTarget represents a named subnet to scan (e.g., IoT VLAN, Guest network).
type ScanTarget struct {
	TargetID  string     `json:"target_id" db:"target_id"`
	Name      string     `json:"name" db:"name"`
	CIDR      string     `json:"cidr" db:"cidr"`
	Segment   string     `json:"segment" db:"segment"`     // default | iot | guest
	ScanPorts bool       `json:"scan_ports" db:"scan_ports"`
	Enabled   bool       `json:"enabled" db:"enabled"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	LastScan  *time.Time `json:"last_scan,omitempty" db:"last_scan"`
}
