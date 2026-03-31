# Passive Network Discovery & Device Fingerprinting

> Priority: P0 — Core differentiator for Vedetta

## Current State in Vedetta

Vedetta currently relies on **active nmap scanning** (`-sn` ping sweep or `-sS` SYN scan) for device discovery. The sensor binary wraps nmap, parses XML output, and pushes results to the Core API. Device identity is keyed on MAC address with vendor lookup via nmap's OUI database.

**Gaps:**
- Active scanning is noisy and can trigger IDS alerts on enterprise-grade routers
- nmap requires `sudo` / root for ARP-based discovery
- No passive discovery — transient devices (phones, laptops) between scan intervals go unnoticed
- OUI vendor lookup is shallow (manufacturer only, not device type or OS)
- No DHCP, mDNS, SSDP, or UPnP listener for zero-probe discovery

## Research Findings

### 1. Passive Protocol Listeners

Devices on any LAN constantly emit discoverable traffic without any probing:

**ARP (Layer 2)**
- Every device must ARP. Listening in promiscuous mode on the bridge interface yields MAC + IP pairs in real time.
- Go libraries: `google/gopacket` with `pcap` or `afpacket` capture handles.
- Extremely lightweight — sub-1% CPU on a Pi 4.

**DHCP (Layer 2/3)**
- DHCP Discover/Request packets contain: MAC, requested IP, hostname (`option 12`), vendor class (`option 60`), parameter request list (`option 55`).
- The **parameter request list order** is a fingerprint — different OSes and device types request DHCP options in different, consistent orders.
- Fingerbank (open-source, MIT) maintains a database of 6M+ DHCP fingerprints mapping to 110K+ device profiles.
- Go: Listen on UDP 67/68 or sniff with gopacket.

**mDNS / DNS-SD (Multicast DNS, port 5353)**
- Apple devices, Chromecasts, printers, and IoT devices announce services via mDNS.
- Service types (`_http._tcp`, `_airplay._tcp`, `_googlecast._tcp`) directly reveal device purpose.
- TXT records often contain model names, firmware versions.
- Go library: `hashicorp/mdns` or raw multicast listener.

**SSDP / UPnP (port 1900 UDP)**
- Smart TVs, gaming consoles, NAS devices, and routers broadcast SSDP NOTIFY and respond to M-SEARCH.
- The `SERVER` header and device description XML contain: manufacturer, model, firmware version, serial number.
- Go: Listen on multicast group `239.255.255.250:1900`.

**LLDP / CDP (Layer 2)**
- Managed switches and enterprise APs emit LLDP frames with hostname, model, VLAN, and capabilities.
- Less common in home networks but valuable in SMB environments.

### 2. Passive OS & Application Fingerprinting

**TCP/IP Stack Fingerprinting (p0f-style)**
- Analyze SYN packets passively: initial TTL, window size, TCP options order, DF bit, MSS.
- Each OS has a unique "signature" in how it constructs TCP packets.
- p0f is the gold standard but hasn't been updated since 2016. The signature database approach is sound but needs modern OS signatures.
- **Recommendation**: Embed a p0f-style engine in Go using gopacket. Maintain our own signature database that Vedetta nodes can contribute to via the threat network.

**TLS Fingerprinting (JA3/JA4)**
- JA3 hashes the TLS ClientHello (cipher suites, extensions, elliptic curves) into a 32-byte MD5.
- JA4 (2023+) improves on JA3 with better normalization and is gaining adoption.
- Different browsers, apps, and malware produce distinct JA3/JA4 fingerprints.
- Use case: Detect IoT devices phoning home to unusual TLS endpoints, identify malware C2 by known-bad JA3 hashes.
- Go: Parse TLS ClientHello from gopacket TCP payload.

**HTTP User-Agent (opportunistic)**
- When HTTP (non-TLS) traffic is visible, User-Agent strings reveal OS, browser, and app versions.
- Declining relevance with HTTPS everywhere, but still valuable for IoT devices using plaintext HTTP.

**DNS Behavioral Fingerprinting**
- Devices have characteristic DNS query patterns: Windows queries `wpad.domain`, Apple queries `_dns-sd._udp.local`, Android queries connectivity check domains.
- Can infer device OS from DNS behavior alone.

### 3. Tool & Library Landscape

| Tool | Type | License | Pi-Friendly | Notes |
|------|------|---------|-------------|-------|
| **p0f** | Passive OS fingerprint | LGPL | Yes | Last updated 2016; signature DB aging |
| **nDPI** (ntop) | Deep packet inspection | LGPL | Yes (C lib) | 250+ app protocols, JA3, risk scoring |
| **Fingerbank** | DHCP fingerprint DB | MIT | Yes (API/DB) | 6M+ fingerprints, REST API |
| **Satori** | Passive OS fingerprint | GPL | Yes | Python, XML signature format |
| **gopacket** | Go packet capture | BSD | Yes | Foundation for all passive capture |
| **NetworkRadar** | Passive L2/L3 scanner | GPL | Yes | ARP/DHCP/mDNS/SSDP listener |

### 4. Competitor Approaches

- **Firewalla**: Combines active nmap with passive ARP/DHCP listening. Runs a modified p0f for OS detection. Proprietary device cloud database for identification.
- **Fingbox**: Uses ARP monitoring + UPnP/SSDP + OUI for continuous device tracking. Proprietary fingerprint database.
- **ntopng**: Uses nDPI for deep packet inspection and passive fingerprinting. Community edition is open source.

## Recommended Approach for Vedetta

### Phase 1: Passive ARP + DHCP Listener (Immediate)

Add a passive listener to the sensor binary alongside the existing nmap scanner:

```
vedetta-sensor
├── nmap scanner (existing, runs on interval)
└── passive listener (NEW, runs continuously)
    ├── ARP watcher → MAC + IP in real-time
    ├── DHCP sniffer → hostname, vendor class, DHCP fingerprint
    └── mDNS listener → service type, model, firmware
```

**Implementation:**
- Use `google/gopacket` with `afpacket` (Linux) for zero-copy packet capture
- BPF filters: `arp or (udp port 67 or udp port 68) or (udp port 5353) or (udp port 1900)`
- Run in a goroutine alongside the nmap scheduler
- Feed discovered devices into the same `POST /api/v1/sensor/devices` pipeline
- New field in Device model: `discovery_method` enum (`nmap_active`, `arp_passive`, `dhcp_passive`, `mdns_passive`, `ssdp_passive`)

**Hardware impact on Pi 4:** Minimal. BPF-filtered passive capture on a home LAN uses <1% CPU, <10MB RAM.

### Phase 2: DHCP Fingerprint Database (Short-term)

- Bundle a subset of the Fingerbank database (SQLite, ~5MB) with the sensor
- Match DHCP option 55 parameter request lists against known fingerprints
- Enrich Device model with: `device_type` (phone, laptop, smart_tv, camera, etc.), `os_family`, `os_version`
- Expose fingerprint confidence score (exact match vs. fuzzy match)

### Phase 3: TCP/TLS Passive Fingerprinting (Medium-term)

- Implement JA3/JA4 hashing from TLS ClientHello packets
- Build a p0f-style TCP SYN analyzer with modern OS signatures
- Correlate: DHCP fingerprint + TCP fingerprint + JA3 + mDNS service type = high-confidence device profile
- Contribute anonymized fingerprint data to the Vedetta threat network for community-built database

### Schema Additions

```sql
-- New columns for devices table
ALTER TABLE devices ADD COLUMN device_type TEXT;        -- phone, laptop, smart_tv, camera, printer, iot_sensor, etc.
ALTER TABLE devices ADD COLUMN os_family TEXT;           -- Windows, macOS, iOS, Android, Linux, ChromeOS
ALTER TABLE devices ADD COLUMN os_version TEXT;          -- e.g., "Windows 11", "iOS 17.2"
ALTER TABLE devices ADD COLUMN discovery_method TEXT;    -- nmap_active, arp_passive, dhcp_passive, mdns_passive
ALTER TABLE devices ADD COLUMN dhcp_fingerprint TEXT;    -- DHCP option 55 fingerprint hash
ALTER TABLE devices ADD COLUMN ja3_fingerprint TEXT;     -- Most recent JA3 hash
ALTER TABLE devices ADD COLUMN services JSON;            -- mDNS/SSDP discovered services
ALTER TABLE devices ADD COLUMN fingerprint_confidence REAL DEFAULT 0.0;  -- 0.0-1.0
```

## References

- Fingerbank: https://www.fingerbank.org/
- gopacket: https://github.com/google/gopacket
- nDPI: https://github.com/ntop/nDPI
- p0f v3: https://lcamtuf.coredump.cx/p0f3/
- JA3 Fingerprinting: https://github.com/salesforce/ja3
- Passive Network Fingerprinting (FOSDEM 2025): https://archive.fosdem.org/2025/events/attachments/fosdem-2025-5461-passive-network-traffic-fingerprinting/
- DHCP Fingerprinting Explained: https://efficientip.com/glossary/dhcp-fingerprinting/
