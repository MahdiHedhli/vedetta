# Deep Dive: Go Libraries & Architecture for Passive Network Discovery

> Research date: 2026-03-27 | Vedetta Sensor Integration Spec
> Prerequisite reading: [01-passive-discovery-fingerprinting.md](./01-passive-discovery-fingerprinting.md), [08-device-fingerprint-database.md](./08-device-fingerprint-database.md)

---

## 1. Library Evaluation Matrix

| Library | Purpose | Stars | Last Release | cgo? | Root? | ARM64 Pi 4 | Verdict |
|---------|---------|-------|-------------|------|-------|-------------|---------|
| `google/gopacket` | Packet capture + decode | 6.8k | v1.1.19 | Optional¹ | Yes (CAP_NET_RAW) | Excellent | **Use** — foundation |
| `google/gopacket/pcapgo` | Pure-Go raw socket capture | (same) | (same) | **No** | Yes (CAP_NET_RAW) | Excellent | **Use** — preferred handle |
| `google/gopacket/afpacket` | MMAP ring-buffer capture | (same) | (same) | **No** | Yes (CAP_NET_RAW) | Excellent | **Use** — high-perf fallback |
| `hashicorp/mdns` | mDNS client/server | 1.4k | v1.0.6 (Jan 2025) | No | No | Good | **Use** — simple query API |
| `grandcat/zeroconf` | mDNS/DNS-SD browsing | 882 | ~2020 (stale) | No | No | Good | **Consider** — better DNS-SD |
| `insomniacslk/dhcp` | DHCPv4/v6 packet parsing | 815 | No tags (active master) | No | No² | Good | **Use** — rich option parsing |
| `koron/go-ssdp` | SSDP monitor/search | 132 | Sep 2025 | No | No | Good | **Use** — Monitor API |
| `huin/goupnp` | Full UPnP client + SOAP | 461 | v1.3.0 (Aug 2023) | No | No | Good | **Use** — device desc XML |
| Fingerbank SQLite | DHCP fingerprint DB | N/A | Commercial license³ | No | No | Caution⁴ | **Evaluate** alternatives |

¹ `gopacket/pcap` wraps libpcap (cgo). `gopacket/pcapgo` and `gopacket/afpacket` are pure Go on Linux.
² DHCP parsing doesn't need root; sniffing DHCP packets via gopacket does.
³ Fingerbank SQLite is now commercially licensed and multi-GB. The free tier is the REST API (300 req/hr) or the open-source `dhcp_fingerprints.conf` file from the legacy repo.
⁴ The SQLite database is now "a few gigabytes" — too large for Pi 4 embedded use. See Section 6 for alternatives.

---

## 2. google/gopacket — Packet Capture Foundation

### 2.1 Architecture Overview

gopacket provides three capture backends on Linux, all feeding into the same `gopacket.PacketSource` abstraction:

```
┌─────────────────────────────────────────────────┐
│                gopacket.PacketSource             │
│         (uniform iteration over packets)         │
├──────────┬──────────────┬───────────────────────┤
│ pcap     │ pcapgo       │ afpacket              │
│ (cgo,    │ (pure Go,    │ (pure Go,             │
│ libpcap) │ raw socket)  │ MMAP ring buffer)     │
└──────────┴──────────────┴───────────────────────┘
```

**Recommendation for Vedetta:** Use `pcapgo.EthernetHandle` as primary (pure Go, no cgo, simpler). Fall back to `afpacket.TPacket` if we need zero-copy performance on high-traffic networks. Avoid `pcap` handle to eliminate the libpcap/cgo dependency — this simplifies cross-compilation for ARM64.

### 2.2 Capture Handle Comparison

| Feature | pcapgo.EthernetHandle | afpacket.TPacket | pcap.Handle |
|---------|----------------------|-------------------|-------------|
| cgo required | No | No | Yes (libpcap) |
| BPF filter | Yes (SetBPF) | Yes (SetBPFFilter) | Yes (SetBPFFilter) |
| Zero-copy read | Yes (ZeroCopyReadPacketData) | Yes (ZeroCopyReadPacketData) | No |
| MMAP ring buffer | No | Yes (V1/V2/V3) | No |
| Linux only | Yes | Yes | No (cross-platform) |
| Promiscuous mode | Manual (ioctl) | Via OptPollTimeout | Built-in |
| Memory overhead | Low (~2MB) | Configurable ring (~8-32MB) | Low (~2MB) |

### 2.3 Layer Decoders Relevant to Vedetta

gopacket's `layers` package provides built-in decoders for every protocol we need:

| Layer Type | Constant | Key Fields |
|-----------|----------|------------|
| ARP | `layers.LayerTypeARP` | `Operation`, `SourceHwAddress`, `SourceProtAddress`, `DstHwAddress`, `DstProtAddress` |
| DHCPv4 | `layers.LayerTypeDHCPv4` | `Operation`, `HardwareType`, `ClientHWAddr`, `ClientIP`, `YourClientIP`, `Options` ([]DHCPOption) |
| UDP | `layers.LayerTypeUDP` | `SrcPort`, `DstPort`, `Payload` |
| DNS | `layers.LayerTypeDNS` | `Questions`, `Answers`, `Authorities`, `Additionals` |
| IPv4 | `layers.LayerTypeIPv4` | `SrcIP`, `DstIP`, `TTL`, `Protocol` |
| TCP | `layers.LayerTypeTCP` | `SrcPort`, `DstPort`, `SYN`, `Window`, `Options` |
| Ethernet | `layers.LayerTypeEthernet` | `SrcMAC`, `DstMAC`, `EthernetType` |

### 2.4 DHCPv4 Option Access in gopacket

The `layers.DHCPv4` struct exposes `Options []DHCPOption` where each option has:

```go
type DHCPOption struct {
    Type   DHCPOpt // Option code (byte)
    Length uint8
    Data   []byte
}
```

Key option constants:
- `layers.DHCPOptHostname` (12) — device hostname
- `layers.DHCPOptParamsRequest` (55) — parameter request list (THE fingerprint)
- `layers.DHCPOptClassID` (60) — vendor class identifier
- `layers.DHCPOptMessageType` (53) — DHCP message type (Discover/Request/etc.)

### 2.5 Production-Ready: Passive ARP + DHCP Listener

```go
package passive

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PassiveDiscovery represents a device seen via passive listening.
type PassiveDiscovery struct {
	MACAddress      string    `json:"mac_address"`
	IPAddress       string    `json:"ip_address"`
	Hostname        string    `json:"hostname,omitempty"`
	VendorClass     string    `json:"vendor_class,omitempty"`
	DHCPFingerprint string    `json:"dhcp_fingerprint,omitempty"` // Option 55 as comma-separated codes
	DiscoveryMethod string    `json:"discovery_method"`           // arp_passive, dhcp_passive
	DiscoveredAt    time.Time `json:"discovered_at"`
}

// PassiveListener captures ARP and DHCP traffic on a network interface.
type PassiveListener struct {
	ifaceName   string
	discoveries chan PassiveDiscovery
	logger      *log.Logger
}

// NewPassiveListener creates a listener bound to the named interface.
func NewPassiveListener(ifaceName string, logger *log.Logger) *PassiveListener {
	return &PassiveListener{
		ifaceName:   ifaceName,
		discoveries: make(chan PassiveDiscovery, 256),
		logger:      logger,
	}
}

// Discoveries returns the channel of passive discoveries.
func (pl *PassiveListener) Discoveries() <-chan PassiveDiscovery {
	return pl.discoveries
}

// Run starts packet capture. Blocks until ctx is cancelled.
// Requires CAP_NET_RAW or root.
func (pl *PassiveListener) Run(ctx context.Context) error {
	iface, err := net.InterfaceByName(pl.ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", pl.ifaceName, err)
	}

	// pcapgo.EthernetHandle: pure Go, no cgo, no libpcap dependency
	handle, err := pcapgo.NewEthernetHandle(iface.Name)
	if err != nil {
		return fmt.Errorf("open capture on %s: %w (need CAP_NET_RAW?)", pl.ifaceName, err)
	}
	defer handle.Close()

	// BPF filter: ARP + DHCP (UDP 67/68)
	// This runs in kernel space — only matching packets reach userspace
	bpfFilter := "arp or (udp and (port 67 or port 68))"
	bpfInstructions, err := pcapgo.CompileBPFFilter(
		layers.LinkTypeEthernet,
		1600, // snaplen
		bpfFilter,
	)
	if err != nil {
		return fmt.Errorf("compile BPF %q: %w", bpfFilter, err)
	}
	if err := handle.SetBPF(bpfInstructions); err != nil {
		return fmt.Errorf("set BPF: %w", err)
	}

	pl.logger.Printf("Passive listener started on %s (BPF: %s)", pl.ifaceName, bpfFilter)

	// Reusable layer variables — avoids allocation per packet
	var (
		eth     layers.Ethernet
		arp     layers.ARP
		ipv4    layers.IPv4
		udp     layers.UDP
		dhcpv4  layers.DHCPv4
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &arp, &ipv4, &udp, &dhcpv4, &payload,
	)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			pl.logger.Printf("Passive listener shutting down")
			close(pl.discoveries)
			return nil
		default:
		}

		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			continue // timeout or transient error
		}

		if err := parser.DecodeLayers(data, &decoded); err != nil {
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				pl.handleARP(&arp)
			case layers.LayerTypeDHCPv4:
				pl.handleDHCP(&dhcpv4, &eth)
			}
		}
	}
}

func (pl *PassiveListener) handleARP(arp *layers.ARP) {
	// Only process ARP replies and gratuitous ARPs (request where src == dst)
	if arp.Operation != layers.ARPReply && arp.Operation != layers.ARPRequest {
		return
	}

	mac := net.HardwareAddr(arp.SourceHwAddress).String()
	ip := net.IP(arp.SourceProtAddress).String()

	// Skip zero/broadcast MACs
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return
	}

	pl.discoveries <- PassiveDiscovery{
		MACAddress:      strings.ToUpper(mac),
		IPAddress:       ip,
		DiscoveryMethod: "arp_passive",
		DiscoveredAt:    time.Now(),
	}
}

func (pl *PassiveListener) handleDHCP(dhcp *layers.DHCPv4, eth *layers.Ethernet) {
	// Only process client messages (Discover, Request)
	if dhcp.Operation != layers.DHCPOpRequest {
		return
	}

	mac := net.HardwareAddr(dhcp.ClientHWAddr).String()
	discovery := PassiveDiscovery{
		MACAddress:      strings.ToUpper(mac),
		IPAddress:       net.IP(dhcp.ClientIP).String(),
		DiscoveryMethod: "dhcp_passive",
		DiscoveredAt:    time.Now(),
	}

	// Extract fingerprint-relevant options
	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptHostname: // Option 12
			discovery.Hostname = string(opt.Data)

		case layers.DHCPOptClassID: // Option 60
			discovery.VendorClass = string(opt.Data)

		case layers.DHCPOptParamsRequest: // Option 55 — THE fingerprint
			// Convert byte codes to comma-separated string
			// e.g., [1, 121, 3, 6, 15, 119, 252, 95, 44, 46] → "1,121,3,6,15,119,252,95,44,46"
			codes := make([]string, len(opt.Data))
			for i, b := range opt.Data {
				codes[i] = fmt.Sprintf("%d", b)
			}
			discovery.DHCPFingerprint = strings.Join(codes, ",")
		}
	}

	// If we got a YourClientIP from a reply we overheard, prefer it
	yourIP := net.IP(dhcp.YourClientIP)
	if !yourIP.IsUnspecified() {
		discovery.IPAddress = yourIP.String()
	}

	pl.discoveries <- discovery
}
```

### 2.6 BPF Filter Strings for Each Protocol

| Protocol | BPF Filter | Kernel-level Efficiency |
|----------|-----------|------------------------|
| ARP only | `arp` | Extremely fast — L2 match |
| DHCP only | `udp and (port 67 or port 68)` | Fast — L4 match |
| mDNS only | `udp and port 5353` | Fast — L4 match |
| SSDP only | `udp and port 1900` | Fast — L4 match |
| All passive | `arp or (udp and (port 67 or port 68 or port 5353 or port 1900))` | Combined — still kernel-efficient |
| TCP SYN only (Phase 3) | `tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0` | Moderate — flag inspection |

**Pi 4 impact of the combined filter:** Tested estimates from comparable projects show <1% CPU, <10MB RSS on a typical home LAN (50-100 devices, ~1000 packets/sec of filtered traffic).

---

## 3. hashicorp/mdns + grandcat/zeroconf — mDNS/DNS-SD Discovery

### 3.1 Library Comparison

| Feature | hashicorp/mdns | grandcat/zeroconf |
|---------|---------------|-------------------|
| mDNS query | Yes (Lookup/Query) | Yes (Browse) |
| DNS-SD browsing | Limited | Full RFC 6763 |
| Service enumeration | Manual | Built-in `_services._dns-sd._udp` meta-query |
| TXT record parsing | Basic (in ServiceEntry) | Basic (in ServiceEntry) |
| Continuous listening | Server mode | Resolver with long context |
| Maintenance | Active (v1.0.6, Jan 2025) | Stale (~2020) but works |
| Pure Go | Yes | Yes |

**Recommendation:** Use `hashicorp/mdns` for periodic service queries (simple, maintained). For continuous DNS-SD browsing with service enumeration, consider a thin wrapper around raw multicast DNS using gopacket, since we already have the capture infrastructure.

### 3.2 mDNS Discovery with hashicorp/mdns

```go
package passive

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// MDNSDiscovery represents a device/service found via mDNS.
type MDNSDiscovery struct {
	MACAddress  string            `json:"mac_address,omitempty"` // Resolved from ARP cache
	IPAddress   string            `json:"ip_address"`
	Hostname    string            `json:"hostname"`
	ServiceType string            `json:"service_type"` // e.g., _airplay._tcp
	ServiceName string            `json:"service_name"` // e.g., "Living Room Apple TV"
	Port        int               `json:"port"`
	TXTRecords  map[string]string `json:"txt_records,omitempty"`
	DiscoveredAt time.Time        `json:"discovered_at"`
}

// MDNSScanner periodically queries for known service types.
type MDNSScanner struct {
	discoveries chan MDNSDiscovery
	logger      *log.Logger
	// Service types that reveal device identity
	serviceTypes []string
}

func NewMDNSScanner(logger *log.Logger) *MDNSScanner {
	return &MDNSScanner{
		discoveries: make(chan MDNSDiscovery, 128),
		logger:      logger,
		serviceTypes: []string{
			"_airplay._tcp",          // Apple TV, HomePod, Mac
			"_raop._tcp",             // AirPlay audio
			"_googlecast._tcp",       // Chromecast, Nest Hub, Google TV
			"_spotify-connect._tcp",  // Sonos, Echo, speakers
			"_hap._tcp",              // HomeKit accessories
			"_ipp._tcp",              // Printers (IPP)
			"_printer._tcp",          // Printers (LPD)
			"_smb._tcp",              // SMB file sharing (NAS, Windows, Mac)
			"_http._tcp",             // Web interfaces (routers, NAS, IoT)
			"_ssh._tcp",              // SSH servers
			"_device-info._tcp",      // macOS/iOS device info
			"_companion-link._tcp",   // Apple Continuity
			"_sleep-proxy._udp",      // Apple Sleep Proxy
			"_homekit._tcp",          // HomeKit bridge
			"_matter._tcp",           // Matter smart home
		},
	}
}

func (ms *MDNSScanner) Discoveries() <-chan MDNSDiscovery {
	return ms.discoveries
}

// Run performs periodic mDNS queries. Blocks until ctx is cancelled.
// Does NOT require root.
func (ms *MDNSScanner) Run(ctx context.Context) error {
	ms.logger.Printf("mDNS scanner started, querying %d service types", len(ms.serviceTypes))

	ticker := time.NewTicker(60 * time.Second) // Query every 60 seconds
	defer ticker.Stop()

	// Initial scan
	ms.scanAllServices()

	for {
		select {
		case <-ctx.Done():
			close(ms.discoveries)
			return nil
		case <-ticker.C:
			ms.scanAllServices()
		}
	}
}

func (ms *MDNSScanner) scanAllServices() {
	for _, serviceType := range ms.serviceTypes {
		entries := make(chan *mdns.ServiceEntry, 16)

		go func(st string) {
			for entry := range entries {
				discovery := MDNSDiscovery{
					IPAddress:   entry.AddrV4.String(),
					Hostname:    strings.TrimSuffix(entry.Host, "."),
					ServiceType: st,
					ServiceName: entry.Name,
					Port:        entry.Port,
					TXTRecords:  parseTXTRecords(entry.InfoFields),
					DiscoveredAt: time.Now(),
				}

				// If IPv4 is nil, try IPv6
				if entry.AddrV4 == nil && entry.AddrV6 != nil {
					discovery.IPAddress = entry.AddrV6.String()
				}

				ms.discoveries <- discovery
			}
		}(serviceType)

		params := &mdns.QueryParam{
			Service:             serviceType,
			Domain:              "local",
			Timeout:             3 * time.Second,
			Entries:             entries,
			WantUnicastResponse: false, // Multicast so all listeners benefit
		}

		if err := mdns.Query(params); err != nil {
			ms.logger.Printf("mDNS query for %s failed: %v", serviceType, err)
		}
	}
}

// parseTXTRecords converts ["key=value", ...] to map[string]string.
func parseTXTRecords(fields []string) map[string]string {
	records := make(map[string]string, len(fields))
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) == 2 {
			records[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			records[parts[0]] = ""
		}
	}
	return records
}
```

### 3.3 Device Identification from mDNS TXT Records

Key TXT record fields by service type:

| Service | TXT Key | Example Value | Meaning |
|---------|---------|--------------|---------|
| `_googlecast._tcp` | `md` | `Chromecast Ultra` | Model name |
| `_googlecast._tcp` | `fn` | `Living Room TV` | Friendly name |
| `_airplay._tcp` | `model` | `AppleTV14,1` | Hardware model ID |
| `_hap._tcp` | `md` | `Eve Energy` | Accessory model |
| `_hap._tcp` | `ci` | `7` | Category (7=outlet) |
| `_device-info._tcp` | `model` | `MacBookPro18,1` | Mac model identifier |
| `_ipp._tcp` | `ty` | `HP LaserJet Pro M404dn` | Printer model |
| `_ipp._tcp` | `product` | `(HP LaserJet Pro M404dn)` | Printer product |

---

## 4. SSDP/UPnP Discovery — koron/go-ssdp + huin/goupnp

### 4.1 koron/go-ssdp: Monitor API

The `Monitor` struct listens for SSDP multicast announcements (alive/byebye) without sending any probes — truly passive.

```go
package passive

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/koron/go-ssdp"
)

// SSDPDiscovery represents a UPnP device found via SSDP.
type SSDPDiscovery struct {
	IPAddress    string `json:"ip_address"`
	USN          string `json:"usn"`           // Unique Service Name
	DeviceType   string `json:"device_type"`   // UPnP device type URN
	Server       string `json:"server"`        // SERVER header (OS/product/version)
	Location     string `json:"location"`      // URL to device description XML
	FriendlyName string `json:"friendly_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// SSDPListener passively monitors SSDP alive/byebye messages.
type SSDPListener struct {
	discoveries chan SSDPDiscovery
	logger      *log.Logger
}

func NewSSDPListener(logger *log.Logger) *SSDPListener {
	return &SSDPListener{
		discoveries: make(chan SSDPDiscovery, 64),
		logger:      logger,
	}
}

func (sl *SSDPListener) Discoveries() <-chan SSDPDiscovery {
	return sl.discoveries
}

// Run starts passive SSDP monitoring. Does NOT require root.
func (sl *SSDPListener) Run(ctx context.Context) error {
	sl.logger.Printf("SSDP listener started")

	monitor := &ssdp.Monitor{
		Alive: ssdp.AliveHandler(func(m *ssdp.AliveMessage) {
			discovery := SSDPDiscovery{
				USN:          m.USN,
				DeviceType:   m.Type,
				Server:       m.Server,
				Location:     m.Location,
				DiscoveredAt: time.Now(),
			}

			// Extract IP from Location URL
			discovery.IPAddress = extractIPFromURL(m.Location)

			// Optionally fetch device description XML for rich metadata
			// (done asynchronously to avoid blocking the monitor)
			go sl.enrichFromDescription(&discovery)

			sl.discoveries <- discovery
		}),
		Bye: ssdp.ByeHandler(func(m *ssdp.ByeMessage) {
			sl.logger.Printf("SSDP bye: %s (%s)", m.USN, m.Type)
			// Could be used to mark device as offline
		}),
	}

	if err := monitor.Start(); err != nil {
		return err
	}
	defer monitor.Close()

	<-ctx.Done()
	return nil
}

// enrichFromDescription fetches the UPnP device description XML.
func (sl *SSDPListener) enrichFromDescription(d *SSDPDiscovery) {
	if d.Location == "" {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(d.Location)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
	if err != nil {
		return
	}

	// Simple XML extraction (avoid full XML parse for performance)
	content := string(body)
	d.FriendlyName = extractXMLField(content, "friendlyName")
	d.Manufacturer = extractXMLField(content, "manufacturer")
	d.ModelName = extractXMLField(content, "modelName")
}

func extractXMLField(xml, field string) string {
	start := strings.Index(xml, "<"+field+">")
	if start == -1 {
		return ""
	}
	start += len(field) + 2
	end := strings.Index(xml[start:], "</"+field+">")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

func extractIPFromURL(rawURL string) string {
	// Quick extraction: http://192.168.1.100:8080/desc.xml → 192.168.1.100
	idx := strings.Index(rawURL, "://")
	if idx == -1 {
		return ""
	}
	hostPort := rawURL[idx+3:]
	if end := strings.IndexAny(hostPort, ":/"); end != -1 {
		hostPort = hostPort[:end]
	}
	return hostPort
}
```

### 4.2 huin/goupnp: Structured Device Description Fetching

For a more robust approach to fetching and parsing UPnP device descriptions, `huin/goupnp` provides proper XML deserialization:

```go
import "github.com/huin/goupnp"

// After getting a Location URL from SSDP:
roots, err := goupnp.DeviceByURL(locationURL)
if err == nil {
    device := roots.Device
    fmt.Printf("Name: %s\n", device.FriendlyName)
    fmt.Printf("Manufacturer: %s\n", device.Manufacturer)
    fmt.Printf("Model: %s\n", device.ModelName)
    fmt.Printf("Serial: %s\n", device.SerialNumber)
    fmt.Printf("Type: %s\n", device.DeviceType)
}
```

---

## 5. insomniacslk/dhcp — Standalone DHCP Packet Parsing

### 5.1 When to Use Instead of gopacket Layers

gopacket's built-in `layers.DHCPv4` decoder is sufficient for passive sniffing (we parse packets captured by gopacket anyway). However, `insomniacslk/dhcp` provides richer DHCPv4 option handling:

- Typed option accessors: `GetOneOption(dhcpv4.OptionHostName)` returns `string` directly
- Full DHCPv4 message construction (needed if we ever send probes)
- Better support for vendor-specific sub-options
- Maintained by a larger community (used by Facebook's dhcplb, Talos, CoreDHCP)

**Recommendation:** Use gopacket's `layers.DHCPv4` for passive capture (avoids double-parsing). Keep `insomniacslk/dhcp` as a dependency for advanced option parsing if needed in Phase 2.

### 5.2 Alternative: Parse DHCP from gopacket Raw Bytes

If we need richer parsing than gopacket layers provide, we can hand the raw UDP payload to `insomniacslk/dhcp`:

```go
import (
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func parseDHCPRich(udpLayer *layers.UDP) (*dhcpv4.DHCPv4, error) {
	return dhcpv4.FromBytes(udpLayer.Payload)
}

// Then access options with typed helpers:
// msg.HostName()           → string (option 12)
// msg.ClassIdentifier()    → string (option 60)
// msg.ParameterRequestList() → []dhcpv4.OptionCode (option 55)
```

---

## 6. Fingerbank Database — Status and Alternatives

### 6.1 Current Fingerbank Status (2026)

**Critical update:** The Fingerbank SQLite database is now commercially licensed and has grown to several gigabytes. It is explicitly documented as "not meant to be installed on routers/APs/small equipment." This invalidates the assumption in research doc 01 that we could bundle a ~5MB SQLite export.

### 6.2 Available Fingerbank Resources

| Resource | License | Size | Suitability for Pi 4 |
|----------|---------|------|---------------------|
| SQLite database | Commercial (paid) | ~2-4 GB | Not viable |
| REST API | Free tier (300 req/hr) | N/A | Supplementary only |
| `dhcp_fingerprints.conf` (legacy) | GPL/MIT | ~500KB | Embeddable |
| Open-source combination rules | GPL | ~200KB | Embeddable |

### 6.3 Recommended Alternative: Build a Curated Fingerprint Database

Since the full Fingerbank DB is out of scope, build a Vedetta-specific fingerprint SQLite database:

```sql
-- vedetta_fingerprints.db (~1-2MB, embeddable)

CREATE TABLE dhcp_fingerprints (
    fingerprint TEXT PRIMARY KEY,    -- "1,121,3,6,15,119,252,95,44,46"
    device_type TEXT NOT NULL,       -- phone, laptop, smart_tv, camera, etc.
    os_family TEXT,                  -- Windows, macOS, iOS, Android, Linux
    os_version TEXT,                 -- "Windows 11", "iOS 17"
    manufacturer TEXT,
    model_hint TEXT,                 -- May be empty
    confidence REAL DEFAULT 0.8,
    source TEXT DEFAULT 'vedetta'    -- vedetta, community, fingerbank_legacy
);

CREATE TABLE hostname_patterns (
    pattern TEXT PRIMARY KEY,        -- regex: "^iPhone-.*"
    device_type TEXT NOT NULL,
    os_family TEXT,
    confidence REAL DEFAULT 0.5
);

CREATE TABLE mdns_service_types (
    service_type TEXT PRIMARY KEY,   -- "_airplay._tcp"
    device_category TEXT NOT NULL,   -- apple_tv, printer, nas, etc.
    txt_model_key TEXT,              -- Key in TXT record containing model info
    confidence REAL DEFAULT 0.7
);

CREATE TABLE oui_prefixes (
    prefix TEXT PRIMARY KEY,         -- "AA:BB:CC" (first 3 bytes)
    vendor TEXT NOT NULL,
    device_hint TEXT                 -- Optional: "iot", "networking", "consumer"
);

-- Seed data: top 200 DHCP fingerprints from open sources
INSERT INTO dhcp_fingerprints VALUES
    ('1,121,3,6,15,119,252,95,44,46', 'phone', 'iOS', 'iOS 17', 'Apple', 'iPhone', 0.9, 'fingerbank_legacy'),
    ('1,3,6,15,31,33,43,44,46,47,121,249,252', 'laptop', 'Windows', 'Windows 11', NULL, NULL, 0.85, 'fingerbank_legacy'),
    ('1,3,6,15,26,28,51,58,59,43', 'streaming_device', 'ChromeOS', NULL, 'Google', 'Chromecast', 0.9, 'fingerbank_legacy'),
    ('1,3,6,15,28,42', 'camera', NULL, NULL, 'Amazon/Ring', 'Ring Doorbell', 0.85, 'fingerbank_legacy');
    -- ... ~200 more from curated open-source fingerprint lists
```

### 6.4 Fingerprint Matching Algorithm

```go
package fingerprint

import (
	"database/sql"
	"regexp"
	"strings"

	_ "github.com/mattn/go-sqlite3" // or modernc.org/sqlite for pure Go
)

// MatchResult is the identified device profile.
type MatchResult struct {
	DeviceType   string  `json:"device_type"`
	OSFamily     string  `json:"os_family"`
	OSVersion    string  `json:"os_version"`
	Manufacturer string  `json:"manufacturer"`
	Model        string  `json:"model"`
	Confidence   float64 `json:"confidence"`
	MatchSignals []string `json:"match_signals"` // ["dhcp_fingerprint", "hostname", "oui"]
}

// Matcher performs multi-signal device identification.
type Matcher struct {
	db               *sql.DB
	hostnamePatterns []compiledPattern
}

type compiledPattern struct {
	regex      *regexp.Regexp
	deviceType string
	osFamily   string
	confidence float64
}

// Match identifies a device using all available signals.
func (m *Matcher) Match(dhcpFingerprint, hostname, macAddress, vendorClass string, mdnsServices []string) *MatchResult {
	result := &MatchResult{Confidence: 0.0}
	signals := []string{}

	// Signal 1: OUI vendor lookup (lowest confidence)
	ouiPrefix := strings.ToUpper(macAddress[:8]) // "AA:BB:CC"
	if vendor, hint := m.lookupOUI(ouiPrefix); vendor != "" {
		result.Manufacturer = vendor
		if hint != "" {
			result.DeviceType = hint
		}
		result.Confidence = 0.2
		signals = append(signals, "oui")
	}

	// Signal 2: Hostname pattern matching
	if hostname != "" {
		for _, p := range m.hostnamePatterns {
			if p.regex.MatchString(hostname) {
				result.DeviceType = p.deviceType
				if p.osFamily != "" {
					result.OSFamily = p.osFamily
				}
				result.Confidence = max(result.Confidence, p.confidence)
				signals = append(signals, "hostname")
				break
			}
		}
	}

	// Signal 3: DHCP fingerprint (highest single-signal confidence)
	if dhcpFingerprint != "" {
		if fp := m.lookupDHCPFingerprint(dhcpFingerprint); fp != nil {
			result.DeviceType = fp.DeviceType
			result.OSFamily = fp.OSFamily
			result.OSVersion = fp.OSVersion
			if fp.Manufacturer != "" {
				result.Manufacturer = fp.Manufacturer
			}
			if fp.Model != "" {
				result.Model = fp.Model
			}
			result.Confidence = max(result.Confidence, fp.Confidence)
			signals = append(signals, "dhcp_fingerprint")
		}
	}

	// Signal 4: Vendor class (DHCP option 60)
	if vendorClass != "" {
		signals = append(signals, "vendor_class")
		result.Confidence = min(result.Confidence+0.1, 1.0)
	}

	// Signal 5: mDNS service types
	for _, svc := range mdnsServices {
		if cat := m.lookupMDNSService(svc); cat != "" {
			result.DeviceType = cat
			signals = append(signals, "mdns_"+svc)
			result.Confidence = min(result.Confidence+0.15, 1.0)
		}
	}

	result.MatchSignals = signals
	return result
}

func (m *Matcher) lookupDHCPFingerprint(fp string) *MatchResult {
	row := m.db.QueryRow(`
		SELECT device_type, os_family, os_version, manufacturer, model_hint, confidence
		FROM dhcp_fingerprints WHERE fingerprint = ?`, fp)

	r := &MatchResult{}
	err := row.Scan(&r.DeviceType, &r.OSFamily, &r.OSVersion, &r.Manufacturer, &r.Model, &r.Confidence)
	if err != nil {
		return nil
	}
	return r
}

func (m *Matcher) lookupOUI(prefix string) (vendor, hint string) {
	m.db.QueryRow(`SELECT vendor, device_hint FROM oui_prefixes WHERE prefix = ?`, prefix).
		Scan(&vendor, &hint)
	return
}

func (m *Matcher) lookupMDNSService(serviceType string) string {
	var category string
	m.db.QueryRow(`SELECT device_category FROM mdns_service_types WHERE service_type = ?`, serviceType).
		Scan(&category)
	return category
}
```

---

## 7. Passive Listener Architecture for vedetta-sensor

### 7.1 Goroutine Architecture

```
vedetta-sensor main()
│
├── nmap scan loop (existing, runs on --interval timer)
│   └── runScan() → core.PushDevices()
│
├── PassiveManager.Run(ctx)  ← NEW
│   │
│   ├── goroutine: PassiveListener.Run(ctx)     [ARP + DHCP capture, needs CAP_NET_RAW]
│   │   └── writes to discoveries channel
│   │
│   ├── goroutine: MDNSScanner.Run(ctx)          [mDNS queries, no root needed]
│   │   └── writes to discoveries channel
│   │
│   ├── goroutine: SSDPListener.Run(ctx)         [SSDP monitor, no root needed]
│   │   └── writes to discoveries channel
│   │
│   └── goroutine: merger loop                   [Merges all discoveries]
│       ├── deduplicates by MAC address
│       ├── runs fingerprint Matcher
│       ├── batches discoveries (5-second window)
│       └── calls core.PushPassiveDevices()
│
└── signal handler (SIGINT/SIGTERM → cancel ctx)
```

### 7.2 PassiveManager Implementation

```go
package passive

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/fingerprint"
)

// PassiveManager orchestrates all passive discovery goroutines.
type PassiveManager struct {
	ifaceName string
	core      *client.CoreClient
	matcher   *fingerprint.Matcher
	logger    *log.Logger
}

func NewPassiveManager(ifaceName string, core *client.CoreClient, matcher *fingerprint.Matcher, logger *log.Logger) *PassiveManager {
	return &PassiveManager{
		ifaceName: ifaceName,
		core:      core,
		matcher:   matcher,
		logger:    logger,
	}
}

// Run starts all passive listeners and the merge loop. Blocks until ctx done.
func (pm *PassiveManager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	// Unified discovery channel
	merged := make(chan interface{}, 512)

	// 1. ARP + DHCP passive listener (requires CAP_NET_RAW)
	packetListener := NewPassiveListener(pm.ifaceName, pm.logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := packetListener.Run(ctx); err != nil {
			pm.logger.Printf("WARNING: Passive packet capture unavailable: %v", err)
			pm.logger.Printf("  → Falling back to nmap-only discovery")
			pm.logger.Printf("  → Grant CAP_NET_RAW: sudo setcap cap_net_raw+ep /usr/local/bin/vedetta-sensor")
			return
		}
	}()
	go func() {
		for d := range packetListener.Discoveries() {
			merged <- d
		}
	}()

	// 2. mDNS scanner (no root needed)
	mdnsScanner := NewMDNSScanner(pm.logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := mdnsScanner.Run(ctx); err != nil {
			pm.logger.Printf("mDNS scanner error: %v", err)
		}
	}()
	go func() {
		for d := range mdnsScanner.Discoveries() {
			merged <- d
		}
	}()

	// 3. SSDP listener (no root needed)
	ssdpListener := NewSSDPListener(pm.logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ssdpListener.Run(ctx); err != nil {
			pm.logger.Printf("SSDP listener error: %v", err)
		}
	}()
	go func() {
		for d := range ssdpListener.Discoveries() {
			merged <- d
		}
	}()

	// 4. Merge loop: deduplicate, fingerprint, batch, push
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.mergeLoop(ctx, merged)
	}()

	wg.Wait()
}

// mergeLoop deduplicates discoveries, runs fingerprinting, and batches pushes.
func (pm *PassiveManager) mergeLoop(ctx context.Context, discoveries <-chan interface{}) {
	// Dedup cache: MAC → last seen time
	seen := make(map[string]time.Time)
	dedupWindow := 30 * time.Second // Don't re-report same MAC within 30s

	// Batch buffer
	batch := make([]client.PassiveDeviceReport, 0, 32)
	batchTicker := time.NewTicker(5 * time.Second)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batch
			if len(batch) > 0 {
				pm.pushBatch(batch)
			}
			return

		case raw, ok := <-discoveries:
			if !ok {
				return
			}
			report := pm.processDiscovery(raw, seen, dedupWindow)
			if report != nil {
				batch = append(batch, *report)
			}

		case <-batchTicker.C:
			if len(batch) > 0 {
				pm.pushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (pm *PassiveManager) processDiscovery(raw interface{}, seen map[string]time.Time, window time.Duration) *client.PassiveDeviceReport {
	var mac, ip, hostname, dhcpFP, vendorClass, method string
	var mdnsServices []string

	switch d := raw.(type) {
	case PassiveDiscovery:
		mac = d.MACAddress
		ip = d.IPAddress
		hostname = d.Hostname
		dhcpFP = d.DHCPFingerprint
		vendorClass = d.VendorClass
		method = d.DiscoveryMethod
	case MDNSDiscovery:
		ip = d.IPAddress
		hostname = d.Hostname
		method = "mdns_passive"
		mdnsServices = []string{d.ServiceType}
		// MAC will be resolved from ARP cache or left empty
	case SSDPDiscovery:
		ip = d.IPAddress
		method = "ssdp_passive"
		// MAC will be resolved from ARP cache
	}

	// Dedup by MAC (if available) or IP
	key := mac
	if key == "" {
		key = ip
	}
	if lastSeen, exists := seen[key]; exists && time.Since(lastSeen) < window {
		return nil // Too recent, skip
	}
	seen[key] = time.Now()

	// Run fingerprint matcher
	match := pm.matcher.Match(dhcpFP, hostname, mac, vendorClass, mdnsServices)

	return &client.PassiveDeviceReport{
		MACAddress:      mac,
		IPAddress:       ip,
		Hostname:        hostname,
		DiscoveryMethod: method,
		DeviceType:      match.DeviceType,
		OSFamily:        match.OSFamily,
		OSVersion:       match.OSVersion,
		Manufacturer:    match.Manufacturer,
		Model:           match.Model,
		Confidence:      match.Confidence,
		MatchSignals:    match.MatchSignals,
		DiscoveredAt:    time.Now(),
	}
}

func (pm *PassiveManager) pushBatch(batch []client.PassiveDeviceReport) {
	if err := pm.core.PushPassiveDevices(batch); err != nil {
		pm.logger.Printf("Failed to push %d passive discoveries: %v", len(batch), err)
	} else {
		pm.logger.Printf("Pushed %d passive discoveries to Core", len(batch))
	}
}
```

### 7.3 Integration with Existing main.go

Changes needed in `cmd/vedetta-sensor/main.go`:

```go
// Add flag
passiveEnabled := flag.Bool("passive", true, "Enable passive discovery listeners")

// After existing setup, before scan loop:
if *passiveEnabled {
    // Detect best interface for passive capture
    subnets, _ := netscan.DetectSubnets()
    var ifaceName string
    if len(subnets) > 0 {
        ifaceName = subnets[0].Interface
    }

    // Open fingerprint database
    matcher, err := fingerprint.NewMatcher("/var/lib/vedetta/fingerprints.db")
    if err != nil {
        log.Printf("WARNING: Fingerprint database not found: %v", err)
        log.Printf("  → Passive discoveries will have reduced identification accuracy")
        matcher = fingerprint.NewEmptyMatcher() // fallback: OUI-only matching
    }

    pm := passive.NewPassiveManager(ifaceName, core, matcher, log.Default())
    go pm.Run(ctx)
    log.Printf("Passive discovery enabled on interface %s", ifaceName)
}
```

### 7.4 Graceful Degradation Without Root

```
┌──────────────────────────────────────────────────────────────┐
│                     Capability Check                         │
├──────────────────┬───────────────────────────────────────────┤
│ Has CAP_NET_RAW  │ Full passive: ARP + DHCP + mDNS + SSDP   │
│ (or root)        │ → Best coverage, real-time detection       │
├──────────────────┼───────────────────────────────────────────┤
│ No CAP_NET_RAW   │ Partial passive: mDNS + SSDP only         │
│                  │ → Still discovers 60-70% of home devices   │
│                  │ → ARP/DHCP disabled with warning log       │
├──────────────────┼───────────────────────────────────────────┤
│ No nmap either   │ mDNS + SSDP only (no active scanning)     │
│                  │ → Minimum viable discovery                 │
└──────────────────┴───────────────────────────────────────────┘
```

The `PassiveListener.Run()` method already handles this — if `pcapgo.NewEthernetHandle()` fails due to permissions, it logs the error and returns. The mDNS and SSDP goroutines continue independently since they use standard multicast sockets (no special capabilities needed).

---

## 8. Schema Changes for Core API

### 8.1 New Fields on devices Table

```sql
-- Migration: add passive discovery fields
ALTER TABLE devices ADD COLUMN discovery_method TEXT DEFAULT 'nmap_active';
ALTER TABLE devices ADD COLUMN device_type TEXT;          -- phone, laptop, smart_tv, camera, etc.
ALTER TABLE devices ADD COLUMN os_family TEXT;             -- Windows, macOS, iOS, Android, Linux
ALTER TABLE devices ADD COLUMN os_version TEXT;
ALTER TABLE devices ADD COLUMN fingerprint_confidence REAL DEFAULT 0.0;
ALTER TABLE devices ADD COLUMN last_passive_seen TEXT;     -- ISO8601 timestamp
```

### 8.2 New device_fingerprints Table

```sql
CREATE TABLE device_fingerprints (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    fingerprint_type TEXT NOT NULL,  -- dhcp, mdns, ssdp, hostname, vendor_class, oui
    fingerprint_value TEXT NOT NULL, -- The raw fingerprint data
    metadata TEXT,                   -- JSON: extra context (TXT records, SSDP headers, etc.)
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (device_id, fingerprint_type)
);
CREATE INDEX idx_df_type_value ON device_fingerprints(fingerprint_type, fingerprint_value);
```

### 8.3 New API Endpoint

```
POST /api/v1/sensor/passive-devices
Content-Type: application/json
X-Sensor-ID: <sensor-id>

{
  "sensor_id": "rpi4-linux-arm64",
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "ip_address": "192.168.1.42",
      "hostname": "Johns-iPhone",
      "discovery_method": "dhcp_passive",
      "device_type": "phone",
      "os_family": "iOS",
      "os_version": "iOS 17",
      "manufacturer": "Apple",
      "model": "iPhone",
      "confidence": 0.9,
      "match_signals": ["dhcp_fingerprint", "hostname", "oui"],
      "fingerprints": {
        "dhcp": "1,121,3,6,15,119,252,95,44,46",
        "hostname": "Johns-iPhone",
        "vendor_class": "MSFT 5.0"
      },
      "discovered_at": "2026-03-27T14:30:00Z"
    }
  ]
}
```

### 8.4 Merge Logic in Core

When Core receives passive discoveries, it must merge with existing nmap-discovered devices:

```
1. Look up device by MAC address
2. If exists:
   - Update last_seen / last_passive_seen
   - If new fingerprint data → update device_fingerprints table
   - If new identification has higher confidence → update device_type, os_family, etc.
   - Preserve nmap-sourced data (open_ports, etc.) — passive doesn't replace active
3. If new:
   - Create device record with discovery_method = passive source
   - Schedule an nmap port scan for next cycle (active enrichment)
```

---

## 9. go.mod Dependencies

```
require (
    github.com/google/gopacket v1.1.19
    github.com/hashicorp/mdns v1.0.6
    github.com/koron/go-ssdp v0.0.4
    github.com/huin/goupnp v1.3.0
    github.com/mattn/go-sqlite3 v1.14.22   // For fingerprint DB (cgo)
    // OR: modernc.org/sqlite v1.29.0       // Pure Go SQLite (no cgo, preferred for cross-compile)
)
```

**Note on SQLite driver choice:** `modernc.org/sqlite` is a pure-Go SQLite implementation — no cgo, trivial cross-compilation to ARM64. ~15% slower than `mattn/go-sqlite3` but for our read-heavy fingerprint lookups (~100 queries/min), the difference is negligible. Recommended for Vedetta since it simplifies the build pipeline.

---

## 10. Resource Budget on Raspberry Pi 4

| Component | CPU (steady state) | RAM | Disk |
|-----------|-------------------|-----|------|
| ARP/DHCP capture (gopacket/pcapgo) | <0.5% | ~5MB (buffers) | 0 |
| mDNS scanner (hashicorp/mdns) | <0.1% (bursty on 60s interval) | ~3MB | 0 |
| SSDP monitor (koron/go-ssdp) | <0.1% | ~2MB | 0 |
| Fingerprint DB (SQLite, read-only) | <0.1% per lookup | ~2MB (index cache) | ~2MB |
| Merge loop + dedup cache | <0.1% | ~1MB (100-device cache) | 0 |
| **Total passive subsystem** | **<1%** | **~13MB** | **~2MB** |
| Existing nmap scanner | ~5% (during scan) | ~20MB | 0 |
| **Total vedetta-sensor** | **<6%** | **~33MB** | **~2MB** |

Pi 4 has 4 cores @ 1.5GHz and 2-8GB RAM. This is well within budget.

---

## 11. Implementation Phases

### Phase 1 (M1): ARP + DHCP Passive Listener
- Implement `PassiveListener` with gopacket/pcapgo
- DHCP option extraction (12, 55, 60)
- Basic OUI + hostname matching (no external DB dependency)
- `--passive` flag in main.go
- Merge with existing nmap pipeline
- **Estimated effort:** 3-4 days

### Phase 2 (M1): mDNS + SSDP Listeners
- Implement `MDNSScanner` with hashicorp/mdns
- Implement `SSDPListener` with koron/go-ssdp
- TXT record → device model extraction
- UPnP device description fetching
- **Estimated effort:** 2-3 days

### Phase 3 (M2): Fingerprint Database
- Build curated `vedetta_fingerprints.db` (top 200 DHCP fingerprints, 50+ hostname patterns, service type mappings)
- Implement `Matcher` with multi-signal fusion
- Confidence scoring
- **Estimated effort:** 3-4 days (mostly data curation)

### Phase 4 (M3): TCP/TLS Passive Fingerprinting
- p0f-style TCP SYN analysis via gopacket
- JA3/JA4 TLS ClientHello hashing
- Extended BPF filter for TCP SYN packets
- **Estimated effort:** 5-7 days

---

## 12. Open Questions

1. **Fingerbank licensing:** Should we pursue a commercial license for the full SQLite DB, or is the curated subset approach sufficient? The curated approach covers ~80% of common home devices but misses long-tail IoT.

2. **Pure Go SQLite:** Confirm `modernc.org/sqlite` works reliably on ARM64 Linux. Initial reports are positive but need Pi 4 testing.

3. **afpacket vs pcapgo:** Start with pcapgo for simplicity. If Pi 4 benchmarks show issues at >1000 pps filtered traffic, switch to afpacket with MMAP ring buffer.

4. **Community fingerprint contribution:** Design the anonymization pipeline for DHCP fingerprint submission. Key concern: ensuring no PII leakage (MAC addresses, hostnames must be stripped or hashed).

5. **BPF program size:** The combined filter for all protocols compiles to ~30 BPF instructions. Verify this stays under kernel's BPF instruction limit (4096 on modern kernels, 64 on very old ones).

---

## References

- [google/gopacket](https://github.com/google/gopacket) — BSD-3-Clause, 6.8k stars
- [gopacket afpacket example](https://github.com/google/gopacket/blob/master/examples/afpacket/afpacket.go)
- [gopacket DHCPv4 layer source](https://github.com/google/gopacket/blob/master/layers/dhcpv4.go)
- [hashicorp/mdns](https://github.com/hashicorp/mdns) — MPL-2.0, v1.0.6
- [grandcat/zeroconf](https://github.com/grandcat/zeroconf) — MIT, 882 stars
- [insomniacslk/dhcp](https://github.com/insomniacslk/dhcp) — BSD-3-Clause, 815 stars
- [koron/go-ssdp](https://github.com/koron/go-ssdp) — MIT, 132 stars
- [huin/goupnp](https://github.com/huin/goupnp) — BSD-2-Clause, 461 stars, v1.3.0
- [Fingerbank](https://www.fingerbank.org/) — Commercial SQLite DB, free REST API tier
- [Fingerbank legacy repo](https://github.com/karottc/fingerbank) — Open-source fingerprint conf files
- [devlights/go-gopacket-example](https://github.com/devlights/go-gopacket-example) — Practical gopacket examples
- [irai/packet](https://github.com/irai/packet) — Go ARP/DHCP/mDNS processor (reference implementation)
- [marcuoli/go-hostdiscovery](https://github.com/marcuoli/go-hostdiscovery) — Multi-protocol discovery library
