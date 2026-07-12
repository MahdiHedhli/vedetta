package dnscap

import "time"

// Query represents a captured DNS query (or resolution from a response). It is the
// common currency between every capture backend — libpcap on Unix, ETW on Windows —
// and the push pipeline, so it lives in an untagged file.
type Query struct {
	ObservationID string // generated once before pairing/buffering; stable across delivery retries
	Timestamp     time.Time
	Domain        string
	QueryType     string
	ClientIP      string
	ServerIP      string
	Direction     string // "query" or "response" when the capture backend can tell
	RCode         string // DNS response code (for example NXDOMAIN), response-only
	Blocked       bool
	Source        string   // e.g., "passive_capture", "etw_dns_client"
	Answers       []string // resolved destinations from answer records (populated for responses)
	Process       string   // originating process (populated by host-local sensor modes)
}

// Config contains settings for DNS capture. Not every field applies to every
// backend — the ETW backend is host-scoped and ignores Interface/Filter/CIDR.
type Config struct {
	Interface    string        // Network interface to capture on (or "auto" for best match)
	CoreURL      string        // Vedetta Core URL used as a route hint
	CIDR         string        // Scan CIDR used to prefer the local LAN interface
	Filter       string        // BPF filter string (optional, overrides default)
	BatchSize    int           // Number of queries to batch before sending
	BatchTimeout time.Duration // Max time to wait before sending a batch
	OnQuery      func(Query)   // Callback for each captured query
}
