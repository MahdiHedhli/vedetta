package netscan

import "time"

// ScanResult is the outcome of one discovery pass, shared across backends (nmap on
// Unix, native ICMP/ARP on Windows) so it lives in an untagged file.
type ScanResult struct {
	Hosts    []DiscoveredHost `json:"hosts"`
	ScanTime time.Time        `json:"scan_time"`
	Duration time.Duration    `json:"duration"`
}

// DiscoveredHost is a single discovered device.
type DiscoveredHost struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	OpenPorts  []int  `json:"open_ports,omitempty"`
	Status     string `json:"status"` // up | down

	// Actionability fields from passive discovery (mDNS/DHCP/SSDP etc).
	Model            string             `json:"model,omitempty"`
	FriendlyName     string             `json:"friendly_name,omitempty"` // human-readable label derived from mDNS instance / TXT fn=/n= / SSDP (spec 004)
	Services         []string           `json:"services,omitempty"`
	DiscoverySource  string             `json:"discovery_source,omitempty"`
	IdentityEvidence []IdentityEvidence `json:"identity_evidence,omitempty"`
}

// IdentityEvidence carries optional passive identity observations to Core.
// Core applies its per-install keyed HMAC before persistence; the sensor does
// not log or retain Value.
type IdentityEvidence struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Source     string  `json:"source,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Sensitive  bool    `json:"sensitive,omitempty"`
}
