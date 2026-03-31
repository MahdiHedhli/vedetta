package dnsingest

// DNSQuery represents a single DNS query that can be ingested from any source.
type DNSQuery struct {
	Timestamp  int64  `json:"timestamp"`  // Unix timestamp
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"` // A, AAAA, MX, etc.
	ClientIP   string `json:"client_ip"`
	ResponseIP string `json:"response_ip,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"` // which DNS server was queried
	Blocked    bool   `json:"blocked"`
	Source     string `json:"source"` // "passive_capture", "pihole", "embedded_resolver", etc.
}
