// Package corereader reads events from Core's HTTP events API and persists a
// poll cursor. It never opens Core's SQLite file directly — the API is the
// supported boundary.
package corereader

import "time"

// Event mirrors the JSON shape of backend models.Event over the wire. Telemetry
// is a separate Go module, so this is kept in sync BY CONTRACT, not by import.
// Only the fields the telemetry pipeline reads are declared; unknown JSON keys
// are ignored on decode. Note: every field here that carries PII (SourceIP,
// ServerIP, ResolvedIP, Geo, DeviceVendor, NetworkSegment, ThreatDesc,
// Metadata, DNSSource) exists ONLY so the export gate/stripper can deliberately
// refuse to forward it — none of it is allowed onto the wire.
type Event struct {
	EventID      string    `json:"event_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"`
	SourceHash   string    `json:"source_hash"`
	SourceIP     string    `json:"source_ip,omitempty"`
	ServerIP     string    `json:"server_ip,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	QueryType    string    `json:"query_type,omitempty"`
	ResolvedIP   string    `json:"resolved_ip,omitempty"`
	Blocked      bool      `json:"blocked"`
	AnomalyScore float64   `json:"anomaly_score"`
	Tags         []string  `json:"tags"`
	// MatchedIndicator/MatchType carry Core's known-bad match provenance
	// (contract-synced with Core). MatchType is "domain" for a known-bad
	// DOMAIN-list match or "resolved_ip" for a known-bad RESOLVED-IP match.
	// MatchedIndicator is the matched list entry (the FQDN for a domain match,
	// the IP for a resolved_ip match). The export stripper forwards the matched
	// DOMAIN indicator instead of the observed QNAME (GHSA-hx86).
	MatchedIndicator string `json:"matched_indicator,omitempty"`
	MatchType        string `json:"match_type,omitempty"`
	Geo              string `json:"geo,omitempty"`
	DeviceVendor     string `json:"device_vendor,omitempty"`
	NetworkSegment   string `json:"network_segment,omitempty"`
	DNSSource        string `json:"dns_source,omitempty"`
	ThreatDesc       string `json:"threat_desc,omitempty"`
	Metadata         string `json:"metadata,omitempty"`
	Acknowledged     bool   `json:"acknowledged"`
	AckReason        string `json:"ack_reason,omitempty"`
}

// EventPage mirrors backend store.EventQueryResult JSON.
type EventPage struct {
	Events []Event `json:"events"`
	Total  int     `json:"total"`
	Page   int     `json:"page"`
	Limit  int     `json:"limit"`
}
