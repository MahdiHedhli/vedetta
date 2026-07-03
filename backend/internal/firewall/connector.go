package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// FirewallEvent represents a normalized firewall log entry.
type FirewallEvent struct {
	Timestamp   time.Time
	Action      string // allow | block | drop | reject
	Protocol    string // tcp | udp | icmp
	SrcIP       string
	SrcPort     int
	DstIP       string
	DstPort     int
	Interface   string // wan | lan | iot | guest
	Direction   string // in | out
	Rule        string // firewall rule name/ID that matched
	BytesSent   int64
	BytesRecv   int64
	Application string // DPI app name if available
	RawLog      string // original log line for debugging

	// IPS marks an intrusion-prevention/detection event from the REST connector
	// (dialect "rest"); Severity is the UniFi 1/2/3 severity used for scoring.
	IPS      bool
	Severity int
}

// ConnectorConfig holds common configuration for all firewall connectors.
type ConnectorConfig struct {
	Name          string        // human-readable name (e.g. "My UniFi Gateway")
	Type          string        // unifi | openwrt | pfsense | mikrotik
	Host          string        // hostname or IP of the firewall
	Port          int           // API/management port
	Username      string        // API username
	Password      string        // API password
	APIKey        string        // API key (alternative to username/password)
	TLSSkipVerify bool          // skip TLS cert verification (self-signed certs)
	PollInterval  time.Duration // how often to poll for new events
	Enabled       bool
}

// Connector is the interface all firewall integrations implement.
// Community contributors add new connectors by implementing this interface.
type Connector interface {
	// Name returns the connector type identifier (e.g. "unifi", "openwrt").
	Name() string

	// Discover attempts to auto-detect the firewall and return its info.
	// Returns nil if the firewall is not reachable or not the expected type.
	Discover(ctx context.Context) (*FirewallInfo, error)

	// Connect establishes a session with the firewall.
	Connect(ctx context.Context) error

	// Disconnect gracefully closes the session.
	Disconnect() error

	// Poll fetches new firewall events since the last poll.
	// Returns events normalized to the Vedetta schema.
	Poll(ctx context.Context) ([]FirewallEvent, error)

	// Health returns the current health status of the connector.
	Health() ConnectorHealth
}

// FirewallInfo describes a discovered firewall.
type FirewallInfo struct {
	Model      string
	Firmware   string
	Hostname   string
	WanIP      string
	LanSubnets []string
	Features   []string // ips, dpi, vpn, etc.
}

// ConnectorHealth reports the health of a firewall connector.
type ConnectorHealth struct {
	Connected  bool          `json:"connected"`
	LastPoll   time.Time     `json:"last_poll"`
	LastError  string        `json:"last_error"`
	EventCount int64         `json:"event_count"` // total events received since connect
	Uptime     time.Duration `json:"uptime"`
}

// mustJSON is a helper that marshals a value to JSON string.
// Panics on error (use sparingly, mainly for metadata serialization).
func mustJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error": "marshal failed: %v"}`, err)
	}
	return string(data)
}

// ToEvent converts a FirewallEvent (from the optional REST connector poll) to a
// normalized Vedetta firewall_log Event matching the spec 001 contract: tags
// source:unifi / fw:<action> / dir:<dir>, and structured firewall fields in the
// metadata JSON. IPS events additionally carry the "ips" tag, ips_severity, and
// dialect "rest" so the enricher scores them by severity.
func (fe *FirewallEvent) ToEvent(sourceHash string) models.Event {
	blocked := fe.Action == "block" || fe.Action == "drop" || fe.Action == "reject"

	tags := []string{"source:unifi"}
	if fe.Action != "" {
		tags = append(tags, "fw:"+fe.Action)
	}
	if fe.Direction != "" {
		tags = append(tags, "dir:"+fe.Direction)
	}
	if fe.IPS {
		tags = append(tags, "ips")
	}
	if blocked {
		tags = append(tags, "blocked")
	}

	desc := fe.Action + " " + fe.Protocol
	if fe.DstPort > 0 {
		desc += fmt.Sprintf(" :%d", fe.DstPort)
	}
	if fe.Rule != "" {
		desc += " (rule: " + fe.Rule + ")"
	}

	meta := map[string]any{
		"action":    fe.Action,
		"protocol":  fe.Protocol,
		"src_ip":    fe.SrcIP,
		"src_port":  fe.SrcPort,
		"dst_ip":    fe.DstIP,
		"dst_port":  fe.DstPort,
		"interface": fe.Interface,
		"direction": fe.Direction,
		"rule":      fe.Rule,
		"dialect":   "rest",
		"raw_log":   fe.RawLog,
	}
	if fe.Application != "" {
		meta["application"] = fe.Application
	}
	if fe.IPS {
		meta["ips_severity"] = fe.Severity
	}

	return models.Event{
		EventID:    uuid.New().String(),
		Timestamp:  fe.Timestamp,
		EventType:  "firewall_log",
		SourceHash: sourceHash,
		SourceIP:   fe.SrcIP,
		Blocked:    blocked,
		Tags:       tags,
		ThreatDesc: desc,
		Metadata:   mustJSON(meta),
	}
}
