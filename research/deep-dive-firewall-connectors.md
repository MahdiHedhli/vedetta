# Deep Dive: Firewall Connectors for Vedetta (M5)

> **Author:** Automated research task
> **Date:** 2026-03-28
> **Status:** Research complete — ready for implementation
> **Milestone:** M5 — Firewall Connectors

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [UniFi Integration](#1-unifi-integration)
3. [pfSense / OPNsense Integration](#2-pfsense--opnsense-integration)
4. [Generic Connector Interface (Go)](#3-generic-connector-interface-go)
5. [Fluent Bit Parser Design](#4-fluent-bit-parser-design)
6. [Polling Schedule Design](#5-polling-schedule-design)
7. [Event Schema Mapping](#6-event-schema-mapping)
8. [Contributor Guide: Adding a New Connector](#7-contributor-guide-adding-a-new-connector)

---

## Executive Summary

Vedetta M5 targets two firewall integrations for V1: **UniFi** (REST API polling) and **pfSense/OPNsense** (syslog ingestion via Fluent Bit). This document covers the complete design for both, including a generic Go connector interface that community contributors can implement to add support for additional firewall platforms.

**Key findings:**

- UniFi exposes 86 REST API endpoints covering clients, devices, events, firewall policies, DPI stats, IPS/IDS alerts, and network health. Authentication uses cookie-based sessions (local accounts) or API keys via `X-API-KEY` header. Self-signed certs on local controllers require TLS skip-verify or cert pinning.
- UniFi's SIEM integration exports logs in Common Event Format (CEF) via syslog. However, IPS/IDS detections are not forwarded to syslog by default — Vedetta should poll the REST API for these.
- pfSense's `filterlog` format is a well-documented CSV-based syslog format. A Fluent Bit regex parser can extract all fields. The pfSense REST API package (pfrest.org) adds 200+ endpoints for richer data.
- OPNsense shares the `filterlog` format (BSD pf-based) with minor differences. OPNsense has a built-in REST API (no package needed) with endpoints for firewall rules, diagnostics, DHCP, and DNS.
- The connector interface should be a Go interface that abstracts device listing, event polling, and firewall state retrieval. Each connector implements it, and the backend orchestrates polling via a scheduler.

---

## 1. UniFi Integration

### 1.1 API Surface (Validated via Live MCP)

We have a live UniFi MCP connected to Mahdi's network (Gateway Pro, firmware 5.0.12). The following data was confirmed available via the UniFi Network Controller REST API:

#### Available Data Categories (86 tools confirmed)

| Category | Key Endpoints | Vedetta Use Case |
|---|---|---|
| **Clients** | `list_clients`, `get_client_details`, `get_client_stats`, `lookup_by_ip`, `list_blocked_clients` | Device inventory, connection tracking |
| **Devices** | `list_devices`, `get_device_details`, `get_device_stats`, `get_device_radio` | Infrastructure monitoring |
| **Events** | `list_events`, `get_event_types`, `list_alarms` | Security event ingestion |
| **Firewall** | `list_firewall_policies`, `get_firewall_policy_details`, `list_firewall_zones`, `list_ip_groups` | Firewall state awareness |
| **Stats** | `get_alerts`, `get_dpi_stats`, `get_network_stats`, `get_top_clients`, `get_network_health` | Traffic analysis, anomaly detection |
| **Network** | `list_networks`, `get_network_details`, `list_wlans` | VLAN/segment mapping |
| **Port Forwards** | `list_port_forwards` | Attack surface monitoring |
| **VPN** | `list_vpn_clients`, `list_vpn_servers` | Remote access auditing |
| **Routing** | `list_routes`, `list_active_routes`, `list_traffic_routes` | Network topology |
| **QoS** | `list_qos_rules` | Bandwidth policy awareness |

#### Event Type Prefixes (Confirmed Live)

```
EVT_SW_   — Switch events
EVT_AP_   — Access Point events
EVT_GW_   — Gateway events
EVT_LAN_  — LAN events
EVT_WU_   — WLAN User events (connect/disconnect)
EVT_WG_   — WLAN Guest events
EVT_IPS_  — IPS/IDS security events        ← HIGH PRIORITY for Vedetta
EVT_AD_   — Admin events
EVT_DPI_  — Deep Packet Inspection events
```

#### Live Client Response Example (from Mahdi's network)

```json
{
  "mac": "ec:b5:fa:15:37:c3",
  "name": "Philips Hue Controller",
  "hostname": "ecb5fa1537c3",
  "ip": "10.0.0.183",
  "connection_type": "Wired",
  "status": "Online",
  "last_seen": 1774735275,
  "_id": "67822a6b5c10d31c8da31173"
}
```

#### Live Network Health Response (from Mahdi's network)

```json
{
  "subsystem": "wan",
  "status": "ok",
  "wan_ip": "96.235.182.42",
  "nameservers": ["9.9.9.9", "8.8.8.8"],
  "num_sta": 81,
  "tx_bytes-r": 232339,
  "rx_bytes-r": 160646,
  "gw_mac": "74:ac:b9:ed:5c:02",
  "gw_name": "Gateway Pro",
  "gw_system-stats": {
    "cpu": "4.6",
    "mem": "59.7",
    "uptime": "1015169"
  },
  "gw_version": "5.0.12.30269",
  "isp_name": "Verizon Fios",
  "uptime_stats": {
    "WAN": { "availability": 100.0, "latency_average": 6 },
    "WAN2": { "availability": 100.0, "latency_average": 29 }
  }
}
```

### 1.2 Authentication

UniFi supports three authentication methods:

#### Method 1: Cookie-Based Session (Legacy / Self-Hosted Controllers)

```
POST /api/login
Content-Type: application/json

{"username": "vedetta-readonly", "password": "..."}
```

Response sets `unifises` and `csrf_token` cookies. Subsequent requests must include both.

**Important:** Must use a **local account** on the controller. UniFi Cloud/SSO accounts do not work with the local API.

#### Method 2: API Key (UniFi Network 7.x+)

```
GET /api/s/{site}/stat/sta
X-API-KEY: <generated-api-key>
```

API keys are generated in Settings → Control Plane → Integrations. This is the preferred method for Vedetta.

#### Method 3: Cloud API (ui.com)

Not recommended for Vedetta — requires internet, adds latency, and contradicts the local-first design principle.

#### Self-Signed Certificate Handling

Local controllers (Cloud Key, UDM, self-hosted) default to self-signed certs. The Vedetta connector must:

1. **Default:** Skip TLS verification with user acknowledgment during setup wizard
2. **Better:** Certificate pinning — on first connect, store the controller's cert fingerprint and verify on subsequent connections (TOFU model)
3. **Best:** Allow user to provide a custom CA cert path

#### UDM Pro / UCG Max Path Prefix

All API endpoints on UDM-line devices require the prefix `/proxy/network/`. For example:
- Cloud Key: `https://192.168.1.1:8443/api/s/default/stat/sta`
- UDM Pro: `https://192.168.1.1/proxy/network/api/s/default/stat/sta`

The connector must detect which variant is in use (try `/proxy/network/` first, fall back to direct).

### 1.3 UniFi IPS/IDS and Threat Management

UniFi's built-in IPS/IDS (Threat Management) uses Suricata under the hood on UDM-line gateways.

**What's available:**
- IPS/IDS events appear as `EVT_IPS_` event types in the controller API
- Alert severity levels map to Suricata categories
- Blocked vs. detected (IPS vs IDS mode) is indicated in the event data
- Events include: source IP, destination IP, signature ID, category, message

**Key limitation:** UniFi does **not** forward IPS/IDS detections to syslog by default, even when SIEM integration is configured. The only reliable way to consume these is via the REST API (`list_events` with `event_type: "EVT_IPS_"`).

**SIEM Integration (CEF Syslog):**
- Configured in UniFi Network → Settings → System → System Logs
- Exports in Common Event Format (CEF) — an industry-standard structure
- Includes: admin events, client connect/disconnect, device state changes
- Does NOT reliably include IPS/IDS alerts — Vedetta should poll the API directly

**Vedetta strategy:** Poll the REST API for `EVT_IPS_` events every 30 seconds. If the user also configures CEF syslog to Vedetta's Fluent Bit, we can ingest those as supplementary data, but the API is the primary source.

### 1.4 Connector Design: Endpoints to Poll

| Endpoint | Poll Interval | Vedetta Event Type | Notes |
|---|---|---|---|
| `list_clients` | 60s | Device inventory sync | Includes IP, MAC, hostname, SSID, signal |
| `list_events(EVT_IPS_)` | 30s | `firewall_log` (subtype: ips) | IPS/IDS security alerts |
| `list_events(EVT_GW_)` | 60s | `firewall_log` (subtype: gateway) | Gateway connectivity events |
| `list_events(EVT_WU_)` | 60s | `firewall_log` (subtype: client) | Client connect/disconnect |
| `get_dpi_stats` | 300s | `firewall_log` (subtype: dpi) | Application-level traffic classification |
| `get_network_health` | 120s | Internal (not an event) | Health dashboard, WAN status |
| `list_alarms` | 60s | `firewall_log` (subtype: alarm) | Security and connectivity alerts |
| `list_firewall_policies` | 600s | Internal (config sync) | Firewall rule awareness |
| `get_network_stats` | 300s | Internal (metrics) | Bandwidth and latency trends |

### 1.5 UniFi MCP as Development Accelerator

The `unifi-network-mcp` package in the environment wraps all 86 UniFi API endpoints. While Vedetta's Go connector will call the REST API directly, this MCP provides:

- **Schema reference** — each tool's input/output schema documents the API contract
- **Live testing** — we can validate assumptions against Mahdi's actual Gateway Pro
- **Batch operations** — `unifi_batch` enables parallel endpoint queries for performance testing

---

## 2. pfSense / OPNsense Integration

### 2.1 pfSense filterlog Syslog Format

pfSense logs firewall events via the `filterlog` program. The format is CSV-based, transmitted over syslog (RFC 3164 or RFC 5424).

#### Syslog Wrapper

```
<priority>timestamp hostname filterlog[pid]: <CSV fields>
```

Example:
```
<134>Aug  3 08:59:02 pfsense filterlog[12345]: 5,16777216,,1000000103,igb1,match,block,in,4,0x10,,128,0,0,none,17,udp,328,198.51.100.1,198.51.100.2,67,68,308
```

#### CSV Field Specification

**Common Header Fields (all protocols):**

| Position | Field | Description |
|---|---|---|
| 0 | Rule Number | Internal rule tracking number |
| 1 | Sub-rule Number | Sub-rule tracking number |
| 2 | Anchor | Anchor name (empty if none) |
| 3 | Tracker | Rule tracker ID (unique per rule) |
| 4 | Interface | Real interface name (e.g., igb0, em0) |
| 5 | Reason | match, bad-offset, fragment, short, normalize, memory |
| 6 | Action | pass, block, reject |
| 7 | Direction | in, out |
| 8 | IP Version | 4 or 6 |

**IPv4 Fields (after common header):**

| Position | Field | Description |
|---|---|---|
| 9 | TOS | Type of Service (hex) |
| 10 | ECN | Explicit Congestion Notification |
| 11 | TTL | Time To Live |
| 12 | ID | IP identification |
| 13 | Offset | Fragment offset |
| 14 | Flags | IP flags (none, DF, MF, DF+MF) |
| 15 | Protocol ID | 6=TCP, 17=UDP, 1=ICMP |
| 16 | Protocol Text | tcp, udp, icmp |
| 17 | Length | Packet length |
| 18 | Source IP | Source IP address |
| 19 | Destination IP | Destination IP address |

**IPv6 Fields (after common header):**

| Position | Field | Description |
|---|---|---|
| 9 | Class | Traffic class |
| 10 | Flow Label | Flow label |
| 11 | Hop Limit | Hop limit |
| 12 | Protocol Text | tcp, udp, icmp6 |
| 13 | Protocol ID | Numeric protocol |
| 14 | Length | Payload length |
| 15 | Source IP | Source IPv6 address |
| 16 | Destination IP | Destination IPv6 address |

**TCP-Specific Fields (appended after IP fields):**

| Offset | Field | Description |
|---|---|---|
| +0 | Source Port | Source port number |
| +1 | Destination Port | Destination port number |
| +2 | Data Length | TCP data length |
| +3 | TCP Flags | Flags (S, SA, A, PA, FA, R, etc.) |
| +4 | Sequence Number | TCP sequence number |
| +5 | ACK | TCP acknowledgment number |
| +6 | Window | TCP window size |
| +7 | URG | Urgent pointer |
| +8 | Options | TCP options |

**UDP-Specific Fields:**

| Offset | Field | Description |
|---|---|---|
| +0 | Source Port | Source port number |
| +1 | Destination Port | Destination port number |
| +2 | Data Length | UDP data length |

**ICMP-Specific Fields:**

| Offset | Field | Description |
|---|---|---|
| +0 | ICMP Type | ICMP message type |
| +1 | (varies) | Depends on ICMP type |

### 2.2 OPNsense Syslog Format Differences

OPNsense is also pf-based and uses a very similar `filterlog` format. Key differences:

1. **Interface names** — OPNsense may use different interface naming (e.g., `vtnet0` on VM deployments vs `igb0`)
2. **Tracker IDs** — Format is similar but OPNsense generates its own tracker values
3. **Additional log sources** — OPNsense includes Suricata IDS/IPS in its syslog output (unlike pfSense where Suricata logs separately)
4. **Syslog format** — OPNsense defaults to RFC 5424 syslog format (more structured) vs pfSense's RFC 3164 default

The Fluent Bit parser should handle both formats by accepting both RFC 3164 and RFC 5424 syslog inputs.

### 2.3 pfSense REST API (pfrest.org)

The community pfSense REST API package (by Jared Hendrickson / pfrest org) provides **200+ endpoints** for comprehensive programmatic access.

**Key Endpoints for Vedetta:**

| Category | Endpoint | Method | Description |
|---|---|---|---|
| **Firewall Rules** | `/api/v2/firewall/rule` | GET | List all firewall rules |
| **Firewall States** | `/api/v2/diagnostics/state_table` | GET | Current connection states |
| **Firewall Logs** | `/api/v2/diagnostics/system_log/firewall` | GET | Parsed firewall log entries |
| **DHCP Leases** | `/api/v2/services/dhcpd/lease` | GET | Active DHCP leases |
| **DNS Resolver** | `/api/v2/services/unbound` | GET | Unbound DNS resolver config |
| **ARP Table** | `/api/v2/diagnostics/arp_table` | GET | ARP cache (device discovery) |
| **Interfaces** | `/api/v2/interface` | GET | Network interface status |
| **System Status** | `/api/v2/system/status` | GET | System info, uptime, versions |
| **Gateways** | `/api/v2/routing/gateway` | GET | Gateway status and latency |

**Authentication methods:**
1. **Local database** — Username + password in request body or basic auth
2. **API Token** — Client ID + Client Token (preferred) via `Authorization` header
3. **JWT** — OAuth-style JWT tokens for session-based access

**Installation:** The REST API is a pfSense package — not installed by default. Vedetta docs should note this as a prerequisite, or fall back to syslog-only mode.

### 2.4 OPNsense REST API (Built-in)

OPNsense ships with a built-in REST API — no packages needed. API access is configured in System → Access → Users (generate API key + secret).

**Key Endpoints for Vedetta:**

| Category | Endpoint | Method | Description |
|---|---|---|---|
| **Firewall Rules** | `/api/firewall/filter/searchRule` | GET | Search/list firewall rules |
| **Firewall Aliases** | `/api/firewall/alias/searchItem` | GET | IP groups and aliases |
| **Diagnostics** | `/api/diagnostics/interface/getArp` | GET | ARP table |
| **Diagnostics** | `/api/diagnostics/firewall/log` | GET | Firewall log entries |
| **DHCP Leases** | `/api/dhcpv4/leases/searchLease` | GET | DHCPv4 lease table |
| **DNS (Unbound)** | `/api/unbound/diagnostics/stats` | GET | DNS resolver statistics |
| **DNS (Unbound)** | `/api/unbound/settings/get` | GET | Resolver configuration |
| **System** | `/api/core/firmware/status` | GET | System version info |
| **Interfaces** | `/api/interfaces/overview/export` | GET | Interface status |
| **IDS/IPS** | `/api/ids/service/queryAlerts` | GET | Suricata IDS alerts |

**Authentication:** API key + secret, passed as HTTP Basic Auth (`key:secret` base64-encoded).

**OPNsense advantage over pfSense:** Built-in API with no package dependency. OPNsense also exposes IDS/IPS alerts via API, making it a more complete integration target.

---

## 3. Generic Connector Interface (Go)

### 3.1 Interface Definitions

```go
// backend/internal/connector/connector.go

package connector

import (
    "context"
    "time"

    "vedetta/backend/internal/models"
)

// ConnectorType identifies the firewall platform.
type ConnectorType string

const (
    ConnectorUniFi    ConnectorType = "unifi"
    ConnectorPFSense  ConnectorType = "pfsense"
    ConnectorOPNSense ConnectorType = "opnsense"
)

// ConnectorConfig holds the configuration for a firewall connector.
type ConnectorConfig struct {
    Type          ConnectorType     `json:"type"`
    Name          string            `json:"name"`           // User-friendly name
    Host          string            `json:"host"`           // Controller URL or syslog source IP
    Port          int               `json:"port,omitempty"` // Override default port
    APIKey        string            `json:"api_key,omitempty"`
    APISecret     string            `json:"api_secret,omitempty"`
    Username      string            `json:"username,omitempty"`
    Password      string            `json:"password,omitempty"`
    Site          string            `json:"site,omitempty"`          // UniFi site (default: "default")
    TLSSkipVerify bool              `json:"tls_skip_verify"`
    TLSCACert     string            `json:"tls_ca_cert,omitempty"`   // Path to custom CA
    CertFingerprint string          `json:"cert_fingerprint,omitempty"` // TOFU pinned cert
    PollIntervals PollIntervalConfig `json:"poll_intervals,omitempty"`
    Metadata      map[string]string `json:"metadata,omitempty"`      // Platform-specific options
}

// PollIntervalConfig allows per-data-type polling intervals.
type PollIntervalConfig struct {
    Devices   time.Duration `json:"devices"`    // Default: 60s
    Events    time.Duration `json:"events"`     // Default: 30s
    Stats     time.Duration `json:"stats"`      // Default: 300s
    Config    time.Duration `json:"config"`     // Default: 600s
    Health    time.Duration `json:"health"`     // Default: 120s
}

// DefaultPollIntervals returns sensible defaults for a home/SMB environment.
func DefaultPollIntervals() PollIntervalConfig {
    return PollIntervalConfig{
        Devices: 60 * time.Second,
        Events:  30 * time.Second,
        Stats:   5 * time.Minute,
        Config:  10 * time.Minute,
        Health:  2 * time.Minute,
    }
}

// Connector is the core interface that every firewall connector must implement.
// It abstracts the platform-specific details behind a unified contract.
type Connector interface {
    // Type returns the connector type identifier.
    Type() ConnectorType

    // Name returns the user-configured display name.
    Name() string

    // Connect establishes a connection to the firewall controller.
    // Returns an error if authentication fails or the controller is unreachable.
    Connect(ctx context.Context) error

    // Close gracefully shuts down the connector.
    Close() error

    // Healthy returns true if the connector can reach the controller.
    Healthy(ctx context.Context) bool

    // --- Device inventory ---

    // ListDevices returns all devices/clients known to the firewall.
    // These map to Vedetta's Device model for inventory enrichment.
    ListDevices(ctx context.Context) ([]DeviceInfo, error)

    // --- Security events ---

    // PollEvents retrieves security events since the given timestamp.
    // The connector must track its own high-water mark for deduplication.
    // Returns events mapped to Vedetta's Event schema.
    PollEvents(ctx context.Context, since time.Time) ([]models.Event, error)

    // --- Firewall state ---

    // GetFirewallState returns the current firewall configuration state.
    // This is used for situational awareness, not real-time alerting.
    GetFirewallState(ctx context.Context) (*FirewallState, error)

    // --- Network health ---

    // GetHealthStatus returns the overall health of the firewall and network.
    GetHealthStatus(ctx context.Context) (*HealthStatus, error)
}

// DeviceInfo represents a device as reported by the firewall connector.
// This is converted to models.Device by the orchestrator.
type DeviceInfo struct {
    MACAddress     string            `json:"mac_address"`
    IPAddress      string            `json:"ip_address"`
    Hostname       string            `json:"hostname,omitempty"`
    Vendor         string            `json:"vendor,omitempty"`
    ConnectionType string            `json:"connection_type,omitempty"` // wired, wireless
    NetworkSegment string            `json:"network_segment,omitempty"`
    SSID           string            `json:"ssid,omitempty"`
    SignalDBM      int               `json:"signal_dbm,omitempty"`
    LastSeen       time.Time         `json:"last_seen"`
    IsBlocked      bool              `json:"is_blocked"`
    Metadata       map[string]string `json:"metadata,omitempty"`
}

// FirewallState represents a snapshot of the firewall's configuration.
type FirewallState struct {
    Rules       []FirewallRule `json:"rules"`
    PortForwards []PortForward `json:"port_forwards,omitempty"`
    Networks    []NetworkInfo  `json:"networks,omitempty"`
    Timestamp   time.Time      `json:"timestamp"`
}

// FirewallRule is a normalized representation of a firewall rule.
type FirewallRule struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Action      string `json:"action"`      // allow, block, reject
    Direction   string `json:"direction"`   // in, out
    Source      string `json:"source"`
    Destination string `json:"destination"`
    Protocol    string `json:"protocol,omitempty"`
    Port        string `json:"port,omitempty"`
    Enabled     bool   `json:"enabled"`
    Index       int    `json:"index"`
}

// PortForward represents an inbound port forwarding / NAT rule.
type PortForward struct {
    ID            string `json:"id"`
    Name          string `json:"name"`
    ExternalPort  string `json:"external_port"`
    InternalIP    string `json:"internal_ip"`
    InternalPort  string `json:"internal_port"`
    Protocol      string `json:"protocol"`
    Enabled       bool   `json:"enabled"`
}

// NetworkInfo represents a network/VLAN as seen by the firewall.
type NetworkInfo struct {
    ID      string `json:"id"`
    Name    string `json:"name"`
    Subnet  string `json:"subnet"`
    VLAN    int    `json:"vlan,omitempty"`
    Purpose string `json:"purpose,omitempty"` // lan, wan, guest, iot
}

// HealthStatus represents the firewall/network health snapshot.
type HealthStatus struct {
    FirewallOnline bool              `json:"firewall_online"`
    WANStatus      string            `json:"wan_status"`      // ok, warning, error
    CPUPercent     float64           `json:"cpu_percent"`
    MemoryPercent  float64           `json:"memory_percent"`
    Uptime         time.Duration     `json:"uptime"`
    ThroughputIn   int64             `json:"throughput_in"`   // bytes/sec
    ThroughputOut  int64             `json:"throughput_out"`  // bytes/sec
    WANLatencyMS   int               `json:"wan_latency_ms"`
    Metadata       map[string]string `json:"metadata,omitempty"`
}
```

### 3.2 Connector Registry

```go
// backend/internal/connector/registry.go

package connector

import (
    "fmt"
    "sync"
)

// Factory creates a Connector from a config.
type Factory func(cfg ConnectorConfig) (Connector, error)

var (
    registryMu sync.RWMutex
    registry   = make(map[ConnectorType]Factory)
)

// Register adds a connector factory to the registry.
// Called in init() by each connector package.
func Register(ct ConnectorType, factory Factory) {
    registryMu.Lock()
    defer registryMu.Unlock()
    if _, exists := registry[ct]; exists {
        panic(fmt.Sprintf("connector: duplicate registration for %q", ct))
    }
    registry[ct] = factory
}

// New creates a connector instance from config.
func New(cfg ConnectorConfig) (Connector, error) {
    registryMu.RLock()
    factory, ok := registry[cfg.Type]
    registryMu.RUnlock()
    if !ok {
        return nil, fmt.Errorf("connector: unknown type %q", cfg.Type)
    }
    return factory(cfg)
}

// Available returns all registered connector types.
func Available() []ConnectorType {
    registryMu.RLock()
    defer registryMu.RUnlock()
    types := make([]ConnectorType, 0, len(registry))
    for ct := range registry {
        types = append(types, ct)
    }
    return types
}
```

### 3.3 Connector Orchestrator (Polling Scheduler)

```go
// backend/internal/connector/orchestrator.go

package connector

import (
    "context"
    "log/slog"
    "sync"
    "time"

    "vedetta/backend/internal/models"
    "vedetta/backend/internal/store"
)

// EventSink receives events from connectors.
type EventSink interface {
    InsertEvents(ctx context.Context, events []models.Event) error
    UpsertDevices(ctx context.Context, devices []models.Device) error
}

// Orchestrator manages all active connectors and their polling loops.
type Orchestrator struct {
    connectors []Connector
    sink       EventSink
    logger     *slog.Logger
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

// NewOrchestrator creates a new orchestrator.
func NewOrchestrator(sink EventSink, logger *slog.Logger) *Orchestrator {
    return &Orchestrator{
        sink:   sink,
        logger: logger,
    }
}

// Add registers a connector with the orchestrator.
func (o *Orchestrator) Add(c Connector) {
    o.connectors = append(o.connectors, c)
}

// Start begins polling loops for all registered connectors.
func (o *Orchestrator) Start(ctx context.Context) {
    ctx, o.cancel = context.WithCancel(ctx)

    for _, c := range o.connectors {
        o.wg.Add(1)
        go o.runConnector(ctx, c)
    }
}

// Stop gracefully shuts down all connectors.
func (o *Orchestrator) Stop() {
    if o.cancel != nil {
        o.cancel()
    }
    o.wg.Wait()

    for _, c := range o.connectors {
        if err := c.Close(); err != nil {
            o.logger.Error("connector close error",
                "connector", c.Name(), "error", err)
        }
    }
}

func (o *Orchestrator) runConnector(ctx context.Context, c Connector) {
    defer o.wg.Done()

    if err := c.Connect(ctx); err != nil {
        o.logger.Error("connector connect failed",
            "connector", c.Name(), "type", c.Type(), "error", err)
        return
    }

    o.logger.Info("connector started",
        "connector", c.Name(), "type", c.Type())

    // Event polling loop
    eventTicker := time.NewTicker(30 * time.Second)
    defer eventTicker.Stop()

    // Device sync loop
    deviceTicker := time.NewTicker(60 * time.Second)
    defer deviceTicker.Stop()

    // Health check loop
    healthTicker := time.NewTicker(2 * time.Minute)
    defer healthTicker.Stop()

    lastEventTime := time.Now().Add(-24 * time.Hour) // Start with last 24h

    for {
        select {
        case <-ctx.Done():
            return

        case <-eventTicker.C:
            events, err := c.PollEvents(ctx, lastEventTime)
            if err != nil {
                o.logger.Warn("event poll failed",
                    "connector", c.Name(), "error", err)
                continue
            }
            if len(events) > 0 {
                if err := o.sink.InsertEvents(ctx, events); err != nil {
                    o.logger.Error("event insert failed",
                        "connector", c.Name(), "error", err)
                } else {
                    lastEventTime = time.Now()
                    o.logger.Info("events ingested",
                        "connector", c.Name(), "count", len(events))
                }
            }

        case <-deviceTicker.C:
            devices, err := c.ListDevices(ctx)
            if err != nil {
                o.logger.Warn("device list failed",
                    "connector", c.Name(), "error", err)
                continue
            }
            // Convert DeviceInfo → models.Device and upsert
            modelDevices := convertDevices(devices)
            if err := o.sink.UpsertDevices(ctx, modelDevices); err != nil {
                o.logger.Error("device upsert failed",
                    "connector", c.Name(), "error", err)
            }

        case <-healthTicker.C:
            if !c.Healthy(ctx) {
                o.logger.Warn("connector unhealthy, attempting reconnect",
                    "connector", c.Name())
                _ = c.Close()
                if err := c.Connect(ctx); err != nil {
                    o.logger.Error("reconnect failed",
                        "connector", c.Name(), "error", err)
                }
            }
        }
    }
}

func convertDevices(infos []DeviceInfo) []models.Device {
    devices := make([]models.Device, len(infos))
    for i, info := range infos {
        devices[i] = models.Device{
            MACAddress: info.MACAddress,
            IPAddress:  info.IPAddress,
            Hostname:   info.Hostname,
            Vendor:     info.Vendor,
            Segment:    info.NetworkSegment,
            LastSeen:   info.LastSeen,
        }
    }
    return devices
}
```

### 3.4 UniFi Connector Implementation Skeleton

```go
// backend/internal/connector/unifi/unifi.go

package unifi

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/http/cookiejar"
    "time"

    "vedetta/backend/internal/connector"
    "vedetta/backend/internal/models"
)

func init() {
    connector.Register(connector.ConnectorUniFi, func(cfg connector.ConnectorConfig) (connector.Connector, error) {
        return New(cfg)
    })
}

type UniFiConnector struct {
    cfg    connector.ConnectorConfig
    client *http.Client
    site   string
    apiBase string // Includes /proxy/network prefix for UDM-line
}

func New(cfg connector.ConnectorConfig) (*UniFiConnector, error) {
    if cfg.Site == "" {
        cfg.Site = "default"
    }

    jar, _ := cookiejar.New(nil)

    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: cfg.TLSSkipVerify,
        },
    }

    return &UniFiConnector{
        cfg: cfg,
        client: &http.Client{
            Jar:       jar,
            Transport: transport,
            Timeout:   15 * time.Second,
        },
        site: cfg.Site,
    }, nil
}

func (u *UniFiConnector) Type() connector.ConnectorType { return connector.ConnectorUniFi }
func (u *UniFiConnector) Name() string                   { return u.cfg.Name }

func (u *UniFiConnector) Connect(ctx context.Context) error {
    // Detect UDM vs Cloud Key by trying /proxy/network first
    baseURL := fmt.Sprintf("https://%s", u.cfg.Host)
    if u.cfg.Port > 0 {
        baseURL = fmt.Sprintf("https://%s:%d", u.cfg.Host, u.cfg.Port)
    }

    // Try UDM-style first
    u.apiBase = baseURL + "/proxy/network"
    if err := u.authenticate(ctx); err != nil {
        // Fall back to Cloud Key / self-hosted style
        u.apiBase = baseURL
        if u.cfg.Port == 0 {
            u.apiBase = fmt.Sprintf("https://%s:8443", u.cfg.Host)
        }
        if err := u.authenticate(ctx); err != nil {
            return fmt.Errorf("unifi: authentication failed: %w", err)
        }
    }
    return nil
}

func (u *UniFiConnector) authenticate(ctx context.Context) error {
    // If API key is configured, just validate it
    if u.cfg.APIKey != "" {
        req, _ := http.NewRequestWithContext(ctx, "GET",
            u.apiBase+"/api/s/"+u.site+"/self", nil)
        req.Header.Set("X-API-KEY", u.cfg.APIKey)
        resp, err := u.client.Do(req)
        if err != nil {
            return err
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
            return fmt.Errorf("API key validation failed: %d", resp.StatusCode)
        }
        return nil
    }

    // Cookie-based login
    loginURL := u.apiBase + "/api/login"
    body := fmt.Sprintf(`{"username":"%s","password":"%s"}`,
        u.cfg.Username, u.cfg.Password)
    req, _ := http.NewRequestWithContext(ctx, "POST", loginURL,
        io.NopCloser(nil)) // TODO: proper body
    req.Header.Set("Content-Type", "application/json")
    // ... complete implementation
    return nil
}

func (u *UniFiConnector) Close() error {
    // Logout if using cookie-based auth
    return nil
}

func (u *UniFiConnector) Healthy(ctx context.Context) bool {
    req, _ := http.NewRequestWithContext(ctx, "GET",
        u.apiBase+"/api/s/"+u.site+"/stat/health", nil)
    if u.cfg.APIKey != "" {
        req.Header.Set("X-API-KEY", u.cfg.APIKey)
    }
    resp, err := u.client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.StatusCode == 200
}

func (u *UniFiConnector) ListDevices(ctx context.Context) ([]connector.DeviceInfo, error) {
    data, err := u.apiGet(ctx, "/api/s/"+u.site+"/stat/sta")
    if err != nil {
        return nil, err
    }

    var resp struct {
        Data []struct {
            MAC        string `json:"mac"`
            IP         string `json:"ip"`
            Hostname   string `json:"hostname"`
            Name       string `json:"name"`
            OUI        string `json:"oui"`
            IsWired    bool   `json:"is_wired"`
            Network    string `json:"network"`
            ESSID      string `json:"essid"`
            Signal     int    `json:"signal"`
            LastSeen   int64  `json:"last_seen"`
        } `json:"data"`
    }

    if err := json.Unmarshal(data, &resp); err != nil {
        return nil, fmt.Errorf("unifi: parse clients: %w", err)
    }

    devices := make([]connector.DeviceInfo, len(resp.Data))
    for i, c := range resp.Data {
        connType := "wireless"
        if c.IsWired {
            connType = "wired"
        }
        name := c.Name
        if name == "" {
            name = c.Hostname
        }
        devices[i] = connector.DeviceInfo{
            MACAddress:     c.MAC,
            IPAddress:      c.IP,
            Hostname:       name,
            Vendor:         c.OUI,
            ConnectionType: connType,
            NetworkSegment: c.Network,
            SSID:           c.ESSID,
            SignalDBM:      c.Signal,
            LastSeen:       time.Unix(c.LastSeen, 0),
        }
    }
    return devices, nil
}

func (u *UniFiConnector) PollEvents(ctx context.Context, since time.Time) ([]models.Event, error) {
    // Poll IPS events
    withinHours := int(time.Since(since).Hours()) + 1
    if withinHours < 1 {
        withinHours = 1
    }

    data, err := u.apiGet(ctx, fmt.Sprintf(
        "/api/s/%s/stat/event?within=%d&type=EVT_IPS_",
        u.site, withinHours))
    if err != nil {
        return nil, err
    }

    var resp struct {
        Data []struct {
            Key        string `json:"key"`
            Datetime   string `json:"datetime"`
            Msg        string `json:"msg"`
            SrcIP      string `json:"src_ip"`
            DstIP      string `json:"dst_ip"`
            SrcPort    int    `json:"src_port"`
            DstPort    int    `json:"dst_port"`
            Proto      string `json:"proto"`
            Catname    string `json:"catname"`
            InnerAlert struct {
                Signature string `json:"signature"`
                Category  string `json:"category"`
                Severity  int    `json:"severity"`
            } `json:"inner_alert_params"`
        } `json:"data"`
    }

    if err := json.Unmarshal(data, &resp); err != nil {
        return nil, fmt.Errorf("unifi: parse events: %w", err)
    }

    events := make([]models.Event, 0, len(resp.Data))
    for _, e := range resp.Data {
        ts, _ := time.Parse(time.RFC3339, e.Datetime)
        if ts.Before(since) {
            continue
        }
        events = append(events, models.Event{
            Timestamp:      ts,
            EventType:      "firewall_log",
            Domain:         e.DstIP,
            Tags:           []string{"ips", e.Catname},
            AnomalyScore:   float64(e.InnerAlert.Severity) / 3.0, // Normalize 1-3 → 0.33-1.0
            NetworkSegment: "default",
        })
    }
    return events, nil
}

func (u *UniFiConnector) GetFirewallState(ctx context.Context) (*connector.FirewallState, error) {
    // TODO: Implement via /api/s/{site}/rest/firewallrule
    return &connector.FirewallState{Timestamp: time.Now()}, nil
}

func (u *UniFiConnector) GetHealthStatus(ctx context.Context) (*connector.HealthStatus, error) {
    data, err := u.apiGet(ctx, "/api/s/"+u.site+"/stat/health")
    if err != nil {
        return nil, err
    }
    // Parse health response (same structure as live data above)
    _ = data
    return &connector.HealthStatus{FirewallOnline: true}, nil
}

func (u *UniFiConnector) apiGet(ctx context.Context, path string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", u.apiBase+path, nil)
    if err != nil {
        return nil, err
    }
    if u.cfg.APIKey != "" {
        req.Header.Set("X-API-KEY", u.cfg.APIKey)
    }
    resp, err := u.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("unifi: GET %s: %w", path, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("unifi: GET %s returned %d", path, resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}
```

---

## 4. Fluent Bit Parser Design

### 4.1 pfSense/OPNsense filterlog Parser

Add to `collector/config/parsers.conf`:

```ini
# --- pfSense / OPNsense filterlog parser ---
# Matches the CSV portion of filterlog syslog messages.
# The syslog header is already parsed by the syslog input plugin.
# This parser extracts the common fields + IPv4 TCP/UDP fields.
# For the full grammar, nested parsers handle protocol-specific tails.

[PARSER]
    Name         pf_filterlog_ipv4_tcp
    Format       regex
    Regex        ^(?<rule_number>\d+),(?<sub_rule>\d*),(?<anchor>[^,]*),(?<tracker>\d+),(?<iface>[^,]+),(?<reason>[^,]+),(?<action>[^,]+),(?<direction>[^,]+),4,(?<tos>[^,]*),(?<ecn>[^,]*),(?<ttl>\d+),(?<ip_id>\d+),(?<offset>\d+),(?<flags>[^,]*),(?<proto_id>6),(?<proto>tcp),(?<length>\d+),(?<src_ip>[^,]+),(?<dst_ip>[^,]+),(?<src_port>\d+),(?<dst_port>\d+),(?<data_length>\d+),(?<tcp_flags>[^,]*),(?<seq>\d*),(?<ack>\d*),(?<window>\d*),(?<urg>[^,]*),(?<options>.*)$

[PARSER]
    Name         pf_filterlog_ipv4_udp
    Format       regex
    Regex        ^(?<rule_number>\d+),(?<sub_rule>\d*),(?<anchor>[^,]*),(?<tracker>\d+),(?<iface>[^,]+),(?<reason>[^,]+),(?<action>[^,]+),(?<direction>[^,]+),4,(?<tos>[^,]*),(?<ecn>[^,]*),(?<ttl>\d+),(?<ip_id>\d+),(?<offset>\d+),(?<flags>[^,]*),(?<proto_id>17),(?<proto>udp),(?<length>\d+),(?<src_ip>[^,]+),(?<dst_ip>[^,]+),(?<src_port>\d+),(?<dst_port>\d+),(?<data_length>\d+)$

[PARSER]
    Name         pf_filterlog_ipv4_icmp
    Format       regex
    Regex        ^(?<rule_number>\d+),(?<sub_rule>\d*),(?<anchor>[^,]*),(?<tracker>\d+),(?<iface>[^,]+),(?<reason>[^,]+),(?<action>[^,]+),(?<direction>[^,]+),4,(?<tos>[^,]*),(?<ecn>[^,]*),(?<ttl>\d+),(?<ip_id>\d+),(?<offset>\d+),(?<flags>[^,]*),(?<proto_id>1),(?<proto>icmp),(?<length>\d+),(?<src_ip>[^,]+),(?<dst_ip>[^,]+),(?<icmp_type>[^,]+),(?<icmp_data>.*)$

[PARSER]
    Name         pf_filterlog_ipv6_tcp
    Format       regex
    Regex        ^(?<rule_number>\d+),(?<sub_rule>\d*),(?<anchor>[^,]*),(?<tracker>\d+),(?<iface>[^,]+),(?<reason>[^,]+),(?<action>[^,]+),(?<direction>[^,]+),6,(?<class>[^,]*),(?<flow_label>[^,]*),(?<hop_limit>\d+),(?<proto>tcp),(?<proto_id>6),(?<length>\d+),(?<src_ip>[^,]+),(?<dst_ip>[^,]+),(?<src_port>\d+),(?<dst_port>\d+),(?<data_length>\d+),(?<tcp_flags>[^,]*),(?<seq>\d*),(?<ack>\d*),(?<window>\d*),(?<urg>[^,]*),(?<options>.*)$

[PARSER]
    Name         pf_filterlog_ipv6_udp
    Format       regex
    Regex        ^(?<rule_number>\d+),(?<sub_rule>\d*),(?<anchor>[^,]*),(?<tracker>\d+),(?<iface>[^,]+),(?<reason>[^,]+),(?<action>[^,]+),(?<direction>[^,]+),6,(?<class>[^,]*),(?<flow_label>[^,]*),(?<hop_limit>\d+),(?<proto>udp),(?<proto_id>17),(?<length>\d+),(?<src_ip>[^,]+),(?<dst_ip>[^,]+),(?<src_port>\d+),(?<dst_port>\d+),(?<data_length>\d+)$
```

### 4.2 Updated Fluent Bit Configuration

Update `collector/config/fluent-bit.conf` to handle filterlog messages:

```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info
    Parsers_File parsers.conf

# --- Pi-hole DNS logs ---
[INPUT]
    Name         tail
    Path         /var/log/pihole/pihole.log
    Tag          dns.pihole
    Parser       pihole
    Refresh_Interval 10

# --- Firewall syslog (pfSense / OPNsense) ---
[INPUT]
    Name         syslog
    Tag          firewall.syslog
    Listen       0.0.0.0
    Port         5140
    Mode         udp
    Parser       syslog-rfc3164

# Also accept RFC 5424 (OPNsense default)
[INPUT]
    Name         syslog
    Tag          firewall.syslog5424
    Listen       0.0.0.0
    Port         5141
    Mode         udp
    Parser       syslog-rfc5424

# --- Filter: extract filterlog messages and parse CSV ---
[FILTER]
    Name         grep
    Match        firewall.*
    Regex        ident filterlog

# --- Route filterlog to re-parser based on protocol ---
# Lua script handles the protocol-dependent field parsing
[FILTER]
    Name         lua
    Match        firewall.*
    script       scripts/parse_filterlog.lua
    call         parse_filterlog

# --- Normalize and forward to backend ---
[OUTPUT]
    Name         http
    Match        *
    Host         backend
    Port         8080
    URI          /api/v1/ingest
    Format       json
    Json_date_key timestamp
    Json_date_format iso8601
```

### 4.3 Lua Filter Script for Protocol-Dependent Parsing

```lua
-- collector/scripts/parse_filterlog.lua
-- Parses pfSense/OPNsense filterlog CSV into structured fields.

function parse_filterlog(tag, timestamp, record)
    local msg = record["message"]
    if msg == nil then
        return 0, 0, 0 -- keep record unchanged
    end

    local fields = {}
    for field in msg:gmatch("[^,]+") do
        fields[#fields + 1] = field
    end
    -- Allow empty fields
    local idx = 0
    fields = {}
    for field in (msg .. ","):gmatch("([^,]*),") do
        idx = idx + 1
        fields[idx] = field
    end

    if #fields < 9 then
        return 0, 0, 0 -- not a filterlog line
    end

    -- Common header
    record["rule_number"]  = fields[1]
    record["tracker"]      = fields[4]
    record["iface"]        = fields[5]
    record["reason"]       = fields[6]
    record["action"]       = fields[7]
    record["direction"]    = fields[8]
    record["ip_version"]   = fields[9]

    local ip_ver = tonumber(fields[9])

    if ip_ver == 4 and #fields >= 20 then
        record["ttl"]       = fields[12]
        record["proto_id"]  = fields[16]
        record["proto"]     = fields[17]
        record["length"]    = fields[18]
        record["src_ip"]    = fields[19]
        record["dst_ip"]    = fields[20]

        local proto = fields[17]
        if proto == "tcp" and #fields >= 29 then
            record["src_port"]    = fields[21]
            record["dst_port"]    = fields[22]
            record["tcp_flags"]   = fields[24]
        elseif proto == "udp" and #fields >= 23 then
            record["src_port"]    = fields[21]
            record["dst_port"]    = fields[22]
        elseif proto == "icmp" and #fields >= 22 then
            record["icmp_type"]   = fields[21]
        end

    elseif ip_ver == 6 and #fields >= 17 then
        record["hop_limit"] = fields[12]
        record["proto"]     = fields[13]
        record["proto_id"]  = fields[14]
        record["length"]    = fields[15]
        record["src_ip"]    = fields[16]
        record["dst_ip"]    = fields[17]

        local proto = fields[13]
        if proto == "tcp" and #fields >= 26 then
            record["src_port"]    = fields[18]
            record["dst_port"]    = fields[19]
            record["tcp_flags"]   = fields[21]
        elseif proto == "udp" and #fields >= 20 then
            record["src_port"]    = fields[18]
            record["dst_port"]    = fields[19]
        end
    end

    -- Map to Vedetta event schema
    record["event_type"] = "firewall_log"
    if record["action"] == "block" then
        record["blocked"] = true
    else
        record["blocked"] = false
    end

    return 1, timestamp, record -- modified record
end
```

---

## 5. Polling Schedule Design

### 5.1 Priority Tiers

| Tier | Poll Interval | Data Type | Rationale |
|---|---|---|---|
| **Critical** | 30s | IPS/IDS events, security alarms | Near-real-time threat alerting |
| **Standard** | 60s | Client list, gateway events, client connect/disconnect | Device tracking, connection auditing |
| **Background** | 120s | Network health, WAN status | Dashboard metrics |
| **Slow** | 300s | DPI stats, network stats, traffic stats | Trend analysis, bandwidth monitoring |
| **Config** | 600s | Firewall rules, port forwards, networks | Config drift detection |

### 5.2 Rate Limiting Considerations

**UniFi Controller:** No published rate limits, but the controller runs on embedded hardware (UDM Pro, Cloud Key). Recommendations:
- Maximum 1 concurrent request per connector
- Minimum 10s between requests to the same endpoint
- Batch API calls where possible (use the stat endpoints which return bulk data)
- Exponential backoff on 429/5xx responses

**pfSense REST API:** Same hardware constraints. The API runs on the firewall itself:
- Maximum 2 concurrent requests
- 30s minimum between full state-table queries (can be large)
- ARP and DHCP lease queries are lightweight — can poll at 60s

**OPNsense API:** Similar to pfSense:
- Built-in API is lightweight
- IDS alert queries can return large result sets — use pagination
- 60s minimum for firewall log queries

### 5.3 Deduplication Strategy

Each connector maintains a high-water mark (timestamp of the most recent event processed). On startup, it initializes from the last known event timestamp in the Vedetta database. This prevents re-ingesting events after a restart.

For syslog-based connectors (pfSense/OPNsense), Fluent Bit handles deduplication via its built-in offset tracking for file-based inputs. For UDP syslog, events are deduplicated at the ingest endpoint using a hash of (timestamp + source_ip + dest_ip + action + tracker_id).

---

## 6. Event Schema Mapping

### 6.1 UniFi Events → Vedetta Event Schema

| UniFi Field | Vedetta Field | Transformation |
|---|---|---|
| `datetime` | `timestamp` | Parse RFC3339 |
| `"EVT_IPS_*"` | `event_type` = `"firewall_log"` | Static mapping |
| `src_ip` | `source_hash` | SHA-256(ip + install_salt) |
| `dst_ip` | `domain` | Direct (IP as domain for non-DNS events) |
| `catname` | `tags[]` | Append as tag |
| `inner_alert.severity` | `anomaly_score` | Map 1→0.33, 2→0.66, 3→1.0 |
| `key` | `tags[]` | Event subtype tag |
| (inferred from IP) | `network_segment` | Cross-reference with UniFi network list |
| (OUI lookup) | `device_vendor` | From client details |

### 6.2 pfSense/OPNsense filterlog → Vedetta Event Schema

| filterlog Field | Vedetta Field | Transformation |
|---|---|---|
| syslog timestamp | `timestamp` | Parse syslog date format |
| `"firewall_log"` | `event_type` | Static |
| `src_ip` | `source_hash` | SHA-256(ip + install_salt) |
| `dst_ip` | `domain` | Direct (IP) |
| `action` = `"block"` | `blocked` = `true` | Boolean mapping |
| `action` = `"pass"` | `blocked` = `false` | Boolean mapping |
| `iface` | `network_segment` | Map interface → segment via config |
| `proto` + `dst_port` | `tags[]` | e.g., ["tcp", "port:443"] |
| (not available) | `anomaly_score` | Default 0.0; elevated for blocks on unusual ports |
| (not available) | `device_vendor` | Cross-reference with device registry by IP |

---

## 7. Contributor Guide: Adding a New Connector

### Step-by-Step Process

1. **Create a new package** under `backend/internal/connector/<name>/`
2. **Implement the `connector.Connector` interface** — all 7 methods are required
3. **Register in `init()`** — call `connector.Register(ConnectorTypeFoo, factoryFunc)`
4. **Add the ConnectorType constant** to `connector.go`
5. **Add Fluent Bit parser** (if syslog-based) to `collector/config/parsers.conf`
6. **Add setup wizard step** in `frontend/src/components/ConnectorSetup.jsx`
7. **Write tests** using recorded API responses (no live firewall needed)
8. **Document** in `docs/connectors/<name>.md`

### What a Connector Must Provide

| Capability | Required | Notes |
|---|---|---|
| `Connect` / `Close` | Yes | Lifecycle management |
| `Healthy` | Yes | Used by orchestrator for reconnection |
| `ListDevices` | Yes | Device inventory enrichment |
| `PollEvents` | Yes | Security event ingestion — the core value |
| `GetFirewallState` | Yes | May return empty state if not supported |
| `GetHealthStatus` | Yes | May return minimal status if not available |

### Testing Strategy

```go
// backend/internal/connector/unifi/unifi_test.go

func TestUniFiListDevices(t *testing.T) {
    // Use httptest.NewServer with recorded responses
    srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/login":
            w.Write([]byte(`{"meta":{"rc":"ok"}}`))
        case "/api/s/default/stat/sta":
            w.Write(clientsFixture) // Recorded from live controller
        default:
            w.WriteHeader(404)
        }
    }))
    defer srv.Close()

    cfg := connector.ConnectorConfig{
        Type:          connector.ConnectorUniFi,
        Host:          srv.Listener.Addr().String(),
        Username:      "test",
        Password:      "test",
        TLSSkipVerify: true,
    }

    c, err := unifi.New(cfg)
    require.NoError(t, err)
    require.NoError(t, c.Connect(context.Background()))

    devices, err := c.ListDevices(context.Background())
    require.NoError(t, err)
    assert.Greater(t, len(devices), 0)
}
```

### File Structure

```
backend/internal/connector/
├── connector.go         # Interface definitions
├── registry.go          # Factory registry
├── orchestrator.go      # Polling scheduler
├── unifi/
│   ├── unifi.go         # UniFi connector implementation
│   ├── unifi_test.go    # Tests with recorded responses
│   └── fixtures/        # Recorded API responses
├── pfsense/
│   ├── pfsense.go       # pfSense REST API connector
│   ├── syslog.go        # Syslog parsing helpers
│   └── pfsense_test.go
└── opnsense/
    ├── opnsense.go      # OPNsense REST API connector
    ├── syslog.go        # Shared with pfSense (same filterlog)
    └── opnsense_test.go
```

---

## Appendix A: Existing Vedetta Infrastructure

### Current Fluent Bit Config

The existing `collector/config/fluent-bit.conf` already has:
- Syslog input on UDP port 5140 (exposed in `docker-compose.yml`)
- HTTP output to `backend:8080/api/v1/ingest`
- Pi-hole DNS log tail input

The syslog input is ready for pfSense/OPNsense — users just need to configure their firewall to send syslog to Vedetta's IP on port 5140. The filterlog parser and Lua script additions above complete the pipeline.

### Current Event Model

The `models.Event` struct supports `event_type: "firewall_log"` but the schema may need extension for firewall-specific fields (source port, destination port, protocol, action). Options:
1. **Use `Tags` field** — encode as tags like `["tcp", "port:443", "block"]`
2. **Add a `Metadata` JSON column** — flexible key-value store for connector-specific data
3. **Extend the struct** — add `SrcPort`, `DstPort`, `Protocol`, `Action` fields

Recommendation: Option 2 (metadata column) for V1 flexibility, with Option 3 planned for V2 when the schema stabilizes.

### Blockers

M5 depends on:
- **M2/M3:** `POST /api/v1/ingest` endpoint (currently missing — events would be dropped)
- **M3:** `store.InsertEvents()` function (no write path exists)

The connector code can be developed and tested independently, but end-to-end integration requires the ingest endpoint to be implemented first.

---

## Appendix B: Reference Links

- [UniFi Controller API (Community Wiki)](https://ubntwiki.com/products/software/unifi-controller/api)
- [UniFi Official API Getting Started](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- [UniFi SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)
- [UniFi IDS/IPS Documentation](https://help.ui.com/hc/en-us/articles/360006893234-UniFi-Gateway-Intrusion-Detection-and-Prevention-IDS-IPS)
- [pfSense Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html)
- [pfSense REST API (pfrest.org)](https://pfrest.org/)
- [pfSense REST API GitHub](https://github.com/pfrest/pfSense-pkg-RESTAPI)
- [OPNsense API Reference](https://docs.opnsense.org/development/api.html)
- [OPNsense Firewall API](https://docs.opnsense.org/development/api/core/firewall.html)
- [Art-of-WiFi UniFi API Browser](https://github.com/Art-of-WiFi/UniFi-API-browser)

---

*Generated by automated research task — 2026-03-28*
