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
}

// ConnectorConfig holds common configuration for all firewall connectors.
type ConnectorConfig struct {
	Name         string        // human-readable name (e.g. "My UniFi Gateway")
	Type         string        // unifi | openwrt | pfsense | mikrotik
	Host         string        // hostname or IP of the firewall
	Port         int           // API/management port
	Username     string        // API username
	Password     string        // API password
	APIKey       string        // API key (alternative to username/password)
	TLSSkipVerify bool        // skip TLS cert verification (self-signed certs)
	PollInterval time.Duration // how often to poll for new events
	Enabled      bool
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
	Model       string
	Firmware    string
	Hostname    string
	WanIP       string
	LanSubnets  []string
	Features    []string // ips, dpi, vpn, etc.
}

// ConnectorHealth reports the health of a firewall connector.
type ConnectorHealth struct {
	Connected    bool
	LastPoll     time.Time
	LastError    string
	EventCount   int64 // total events received since connect
	Uptime       time.Duration
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

// ToEvent converts a FirewallEvent to a Vedetta Event.
func (fe *FirewallEvent) ToEvent(sourceHash string) models.Event {
	tags := []string{"firewall"}
	if fe.Action == "block" || fe.Action == "drop" || fe.Action == "reject" {
		tags = append(tags, "blocked")
	}

	desc := fe.Action + " " + fe.Protocol
	if fe.DstPort > 0 {
		desc += fmt.Sprintf(" :%d", fe.DstPort)
	}
	if fe.Rule != "" {
		desc += " (rule: " + fe.Rule + ")"
	}

	return models.Event{
		EventID:    uuid.New().String(),
		Timestamp:  fe.Timestamp,
		EventType:  "firewall_log",
		SourceHash: sourceHash,
		SourceIP:   fe.SrcIP,
		Tags:       tags,
		ThreatDesc: desc,
		Metadata:   mustJSON(fe),
	}
}
