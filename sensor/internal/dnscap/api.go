package dnscap

// DNSPushRequest is the request body for POST /api/v1/sensor/dns
type DNSPushRequest struct {
	SensorID string     `json:"sensor_id"`
	Queries  []DNSQuery `json:"queries"`
}

// DNSQuery represents a DNS query being pushed from sensor to core.
type DNSQuery struct {
	Timestamp  int64    `json:"timestamp"`  // Unix timestamp in milliseconds (for sub-second precision)
	Domain     string   `json:"domain"`
	QueryType  string   `json:"query_type"` // A, AAAA, MX, etc.
	ClientIP   string   `json:"client_ip"`
	ResponseIP string   `json:"response_ip,omitempty"`
	ServerIP   string   `json:"server_ip,omitempty"` // which DNS server was queried
	Blocked    bool     `json:"blocked"`
	Source     string   `json:"source"` // "passive_capture", "embedded_resolver", etc.
	Answers    []string `json:"answers,omitempty"` // resolved IPs or names from answers (for actionability / destination info)
	Process    string   `json:"process,omitempty"` // originating process hint (empty for network capture; populated by host-local sensor modes)
}

// DNSPushResponse is the response from POST /api/v1/sensor/dns
type DNSPushResponse struct {
	Accepted int `json:"accepted"`
}
