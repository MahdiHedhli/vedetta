# Firewall Connector Guide

The Vedetta Firewall Connector framework allows community contributors to add support for any firewall platform. This guide explains how to implement a new connector.

## Overview

Vedetta normalizes firewall events from multiple sources into a unified schema. The connector architecture enables:

- **Multi-platform support**: UniFi, OpenWrt, pfSense, Mikrotik, etc.
- **Pluggable design**: Add a new firewall type without modifying core code
- **Normalized events**: All firewall logs converted to a common schema
- **Automatic polling**: Background task fetches events on a schedule
- **Health monitoring**: Track connector status and event flow

## The Connector Interface

All firewall connectors implement the `firewall.Connector` interface:

```go
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
```

## Core Types

### FirewallEvent

The normalized event representation:

```go
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
```

### ConnectorConfig

Configuration passed to your connector:

```go
type ConnectorConfig struct {
	Name         string        // human-readable name (e.g. "My UniFi Gateway")
	Type         string        // unifi | openwrt | pfsense | mikrotik
	Host         string        // hostname or IP of the firewall
	Port         int           // API/management port
	Username     string        // API username
	Password     string        // API password
	APIKey       string        // API key (alternative to username/password)
	TLSSkipVerify bool        // skip TLS cert verification
	PollInterval time.Duration // polling frequency
	Enabled      bool
}
```

### ConnectorHealth

Status information returned during polling:

```go
type ConnectorHealth struct {
	Connected    bool
	LastPoll     time.Time
	LastError    string
	EventCount   int64
	Uptime       time.Duration
}
```

## Implementing a New Connector

### Step 1: Create Your Connector Type

Create a new file in `backend/internal/firewall/` named after your firewall platform, e.g., `openwrt.go`:

```go
package firewall

import (
	"context"
	"sync"
	"time"
)

type OpenWrtConnector struct {
	cfg           ConnectorConfig
	client        *http.Client
	connected     bool
	lastPoll      time.Time
	lastError     string
	eventCount    int64
	connectTime   time.Time
	mu            sync.RWMutex
}

func NewOpenWrtConnector(cfg ConnectorConfig) *OpenWrtConnector {
	return &OpenWrtConnector{
		cfg: cfg,
		// Initialize HTTP client, etc.
	}
}
```

### Step 2: Implement the Connector Interface

Implement all required methods:

```go
func (oc *OpenWrtConnector) Name() string {
	return "openwrt"
}

func (oc *OpenWrtConnector) Discover(ctx context.Context) (*FirewallInfo, error) {
	// Connect and fetch firewall model, firmware version, etc.
	// Return nil if this isn't an OpenWrt device
}

func (oc *OpenWrtConnector) Connect(ctx context.Context) error {
	// Authenticate and establish a session
	// Set oc.connected = true on success
}

func (oc *OpenWrtConnector) Disconnect() error {
	// Gracefully close the session
	// Set oc.connected = false
}

func (oc *OpenWrtConnector) Poll(ctx context.Context) ([]FirewallEvent, error) {
	// Fetch firewall events and convert to FirewallEvent slice
	// Update oc.lastPoll, oc.eventCount, oc.lastError
}

func (oc *OpenWrtConnector) Health() ConnectorHealth {
	// Return current health status
}
```

### Step 3: API Integration

Depending on your firewall, you may use:

- **REST API**: JSON over HTTP/HTTPS (recommended)
- **SSH**: Execute commands, parse output
- **Log files**: Poll syslog or other logs
- **SNMP**: Query MIBs

Example: Querying a REST API and parsing JSON:

```go
func (oc *OpenWrtConnector) Poll(ctx context.Context) ([]FirewallEvent, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://"+oc.cfg.Host+"/api/firewall/logs", nil)
	req.Header.Set("Authorization", "Bearer "+oc.cfg.APIKey)

	resp, err := oc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var logs []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return nil, err
	}

	var events []FirewallEvent
	for _, log := range logs {
		event := oc.parseLog(log)
		if event != nil {
			events = append(events, *event)
		}
	}

	oc.mu.Lock()
	oc.lastPoll = time.Now()
	oc.eventCount += int64(len(events))
	oc.mu.Unlock()

	return events, nil
}
```

### Step 4: Event Normalization

Convert firewall-specific events to the standard `FirewallEvent` schema:

```go
func (oc *OpenWrtConnector) parseLog(log map[string]interface{}) *FirewallEvent {
	// Extract required fields
	srcIP, ok := log["src_addr"].(string)
	if !ok {
		return nil
	}

	event := &FirewallEvent{
		Timestamp:  parseTime(log["timestamp"].(string)),
		Action:     normalizeAction(log["action"].(string)),
		Protocol:   log["protocol"].(string),
		SrcIP:      srcIP,
		SrcPort:    int(log["src_port"].(float64)),
		DstIP:      log["dst_addr"].(string),
		DstPort:    int(log["dst_port"].(float64)),
		Interface:  log["interface"].(string),
		Direction:  log["direction"].(string),
		Rule:       log["rule_name"].(string),
	}

	return event
}

func normalizeAction(action string) string {
	switch action {
	case "ACCEPT", "allow":
		return "allow"
	case "DROP", "discard":
		return "drop"
	case "REJECT", "deny":
		return "reject"
	default:
		return action
	}
}
```

## Registration and Startup

Register your connector in the main application initialization:

```go
// In main.go or initialization code

import "github.com/vedetta-network/vedetta/backend/internal/firewall"

// Create manager with event sink
manager := firewall.NewManager(func(events []models.Event) error {
	return db.InsertEvents(events)
})

// Register UniFi connector
unifiCfg := firewall.ConnectorConfig{
	Name:         "my_unifi",
	Type:         "unifi",
	Host:         "192.168.1.1",
	Port:         443,
	Username:     "admin",
	Password:     "password",
	TLSSkipVerify: true,
	PollInterval: 60 * time.Second,
	Enabled:      true,
}
unifiConn := firewall.NewUniFiConnector(unifiCfg)
manager.Register(unifiCfg, unifiConn)

// Register your OpenWrt connector
openWrtCfg := firewall.ConnectorConfig{
	Name:         "my_openwrt",
	Type:         "openwrt",
	Host:         "192.168.2.1",
	Port:         8080,
	APIKey:       "your-api-key",
	PollInterval: 30 * time.Second,
	Enabled:      true,
}
openWrtConn := firewall.NewOpenWrtConnector(openWrtCfg)
manager.Register(openWrtCfg, openWrtConn)

// Start all connectors
if err := manager.Start(); err != nil {
	log.Fatal(err)
}

// Graceful shutdown
defer manager.Stop()
```

## Testing Your Connector

### Unit Tests

Create `backend/internal/firewall/openwrt_test.go`:

```go
package firewall

import (
	"context"
	"testing"
)

func TestOpenWrtConnectorName(t *testing.T) {
	cfg := ConnectorConfig{Name: "test"}
	conn := NewOpenWrtConnector(cfg)
	if conn.Name() != "openwrt" {
		t.Errorf("expected 'openwrt', got %q", conn.Name())
	}
}

func TestOpenWrtConnect(t *testing.T) {
	cfg := ConnectorConfig{
		Host:     "192.168.1.1", // Mock or real test device
		Port:     8080,
		APIKey:   "test-key",
	}
	conn := NewOpenWrtConnector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := conn.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect()

	// Verify connection
	health := conn.Health()
	if !health.Connected {
		t.Error("expected connected=true")
	}
}

func TestOpenWrtPoll(t *testing.T) {
	cfg := ConnectorConfig{
		Host:     "192.168.1.1",
		Port:     8080,
		APIKey:   "test-key",
	}
	conn := NewOpenWrtConnector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect()

	events, err := conn.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}

	// Verify event structure
	for _, event := range events {
		if event.Timestamp.IsZero() {
			t.Error("event.Timestamp is zero")
		}
		if event.SrcIP == "" {
			t.Error("event.SrcIP is empty")
		}
	}
}
```

### Integration Testing

Test against a real firewall in your lab environment:

```bash
# Run tests with firewall details
FIREWALL_HOST=192.168.1.1 \
FIREWALL_USER=admin \
FIREWALL_PASS=password \
go test -v ./backend/internal/firewall/
```

## Best Practices

1. **Thread Safety**: Use `sync.RWMutex` to protect shared state (as shown in UniFi connector)
2. **Error Handling**: Track errors in `lastError` and log appropriately
3. **Timeouts**: Always use context timeouts for network calls
4. **TLS Verification**: Respect the `TLSSkipVerify` config flag for self-signed certs
5. **Metadata**: Store raw logs in `FirewallEvent.RawLog` for debugging
6. **Graceful Shutdown**: Implement proper cleanup in `Disconnect()`
7. **Rate Limiting**: Respect the `PollInterval` to avoid overwhelming the firewall
8. **Logging**: Use `log.Printf()` for important events (connect, disconnect, errors)

## Example: Complete MinimalConnector

Here's a minimal but complete connector for a hypothetical firewall:

```go
package firewall

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type MinimalConnector struct {
	cfg         ConnectorConfig
	client      *http.Client
	connected   bool
	lastPoll    time.Time
	lastError   string
	eventCount  int64
	connectTime time.Time
	mu          sync.RWMutex
}

func NewMinimalConnector(cfg ConnectorConfig) *MinimalConnector {
	return &MinimalConnector{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (mc *MinimalConnector) Name() string {
	return "minimal"
}

func (mc *MinimalConnector) Discover(ctx context.Context) (*FirewallInfo, error) {
	return &FirewallInfo{
		Model:    "TestModel",
		Firmware: "1.0",
		Features: []string{"firewall"},
	}, nil
}

func (mc *MinimalConnector) Connect(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.connected = true
	mc.connectTime = time.Now()
	return nil
}

func (mc *MinimalConnector) Disconnect() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.connected = false
	return nil
}

func (mc *MinimalConnector) Poll(ctx context.Context) ([]FirewallEvent, error) {
	// Return empty for now
	return []FirewallEvent{}, nil
}

func (mc *MinimalConnector) Health() ConnectorHealth {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	uptime := time.Duration(0)
	if !mc.connectTime.IsZero() {
		uptime = time.Since(mc.connectTime)
	}
	return ConnectorHealth{
		Connected:  mc.connected,
		LastPoll:   mc.lastPoll,
		LastError:  mc.lastError,
		EventCount: mc.eventCount,
		Uptime:     uptime,
	}
}
```

## API Reference

### Discover()

Purpose: Auto-detect and validate that the connected device is the expected firewall type.

Returns:
- `*FirewallInfo`: Device metadata (model, firmware, IP config)
- `error`: If the firewall is not reachable or not the expected type

Typical implementation checks API endpoints or queries system info.

### Connect()

Purpose: Establish and authenticate a session.

Should:
- Validate credentials
- Establish connection (login, API token, etc.)
- Set `uc.connected = true`
- Set `uc.connectTime = time.Now()`

### Disconnect()

Purpose: Graceful cleanup.

Should:
- Logout or revoke tokens
- Close connections
- Set `uc.connected = false`

### Poll()

Purpose: Fetch new firewall events.

Returns:
- `[]FirewallEvent`: Normalized events
- `error`: If fetch fails

Must update:
- `uc.lastPoll = time.Now()`
- `uc.eventCount += int64(len(events))`
- `uc.lastError` (set to "" on success)

### Health()

Purpose: Return current status for monitoring dashboards.

Returns `ConnectorHealth` with connection state, event count, last error, and uptime.

## Contributing

When submitting a new connector:

1. Place code in `backend/internal/firewall/{type}.go`
2. Add tests in `{type}_test.go`
3. Document the firewall API in code comments
4. Update this guide with platform-specific notes
5. Test with real hardware if possible
6. Submit a pull request with clear commit messages

---

**Questions?** Open an issue on the Vedetta GitHub repository.
