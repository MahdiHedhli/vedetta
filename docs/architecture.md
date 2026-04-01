# Vedetta — Architecture Reference

> Last updated: 2026-04-01 | Vedetta 0.1.0-dev

---

## Overview

Vedetta is an open-source home SIEM that combines passive DNS threat hunting with active network discovery. It uses a **Core + Sensor** architecture: Docker-based services for storage, API, and UI, paired with native sensor binaries that run on host machines for Layer 2 network access.

**Design principles:** passive-first (never destabilize the host network), DNS-centric threat detection, minimal resource footprint, zero mandatory cloud dependency.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  HOST MACHINE (Mac, Linux, Pi)                              │
│                                                             │
│  ┌──────────────────────┐    ┌───────────────────────────┐  │
│  │  Sensor (native bin) │    │  Docker Compose            │  │
│  │  ────────────────    │    │  ─────────────────────     │  │
│  │  • nmap scanning     │───▶│  backend   :8080  (Go)    │  │
│  │  • DNS capture (pcap)│    │  frontend  :3107  (React) │  │
│  │  • Interface enum    │    │  collector :5140  (Fluent) │  │
│  │  • Encrypted DNS det │    │  telemetry       (Go)     │  │
│  └──────────────────────┘    │  threat-net:9090 (Go)     │  │
│                              └───────────────────────────┘  │
│           ▲                              │                  │
│           │ raw ARP/mDNS/DHCP            │ SQLite           │
│           │ (host NIC required)          ▼                  │
│      ┌────┴────┐                  vedetta-data volume       │
│      │ Network │                                            │
└──────┴─────────┴────────────────────────────────────────────┘
```

**Why the split?** Docker on macOS/Windows runs containers inside a Linux VM — containers cannot see real ARP, DHCP, or Layer 2 broadcast traffic. The native sensor binary runs on the host OS with full NIC access. On Linux with `--network=host`, Core can run a built-in scanner as fallback.

---

## Docker Services

| Service | Port | Runtime | Purpose |
|---------|------|---------|---------|
| **backend** | 8080 | Go 1.22 | Core API, SIEM storage, threat intel, DNS enrichment |
| **frontend** | 3107 | React + Vite + Nginx | Dashboard UI (proxies `/api/` → backend) |
| **collector** | 5140/UDP | Fluent Bit | Syslog ingest from firewalls, Pi-hole logs |
| **telemetry** | internal | Go | Opt-in anonymized event batching to threat network |
| **threat-network** | 9090 | Go | Community threat intelligence backend (stub) |

Volume: `vedetta-data:/data` (shared SQLite database)

---

## Backend Dependencies

### Go Modules — `backend/go.mod`

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/go-chi/chi/v5` | 5.0.12 | HTTP router + middleware |
| `github.com/google/uuid` | 1.6.0 | UUID generation (events, devices, rules) |
| `github.com/mattn/go-sqlite3` | 1.14.22 | SQLite3 driver (CGO) |

### Sensor Modules — `sensor/go.mod`

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/google/uuid` | 1.6.0 | UUID generation (sensor registration) |

**External binaries:** `nmap` (required on sensor host for active scanning)

### Planned Dependencies (Phase 3)

| Library | Purpose |
|---------|---------|
| `google/gopacket` + `pcapgo` | Packet capture (ARP, DHCP, mDNS) — pure Go, no CGO |
| `hashicorp/mdns` | mDNS service discovery |
| `insomniacslk/dhcp` | DHCP option parsing (hostname, vendor class, fingerprint) |
| `koron/go-ssdp` | SSDP multicast announcement capture |
| `huin/goupnp` | UPnP device description XML parsing |

All validated for ARM64 (Raspberry Pi 4).

---

## API Endpoints

### Status & Diagnostics
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/status` | Health, device/event/sensor counts, scan state |
| GET | `/api/v1/version` | Build info + available routes |

### Events
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/events` | Query events (filters: time, type, source, tags, score, limit) |
| GET | `/api/v1/events/stats` | Aggregate counts, top domains, threat summary |
| GET | `/api/v1/events/timeline` | Hourly event histogram (24h) |
| POST | `/api/v1/ingest` | External event ingestion |
| PUT | `/api/v1/events/{id}/ack` | Acknowledge event |
| DELETE | `/api/v1/events/{id}/ack` | Remove acknowledgment |

### Devices
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/devices` | List all discovered devices |
| GET | `/api/v1/devices/new` | Devices discovered in last 24h |
| PUT | `/api/v1/devices/{id}` | Update name, notes, segment |

### Suppression & Whitelist
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/suppression` | List suppression rules |
| POST | `/api/v1/suppression` | Create suppression rule |
| DELETE | `/api/v1/suppression/{id}` | Delete rule |
| GET | `/api/v1/whitelist` | List known-traffic whitelist rules |
| POST | `/api/v1/whitelist` | Create custom whitelist rule |
| PUT | `/api/v1/whitelist/{id}` | Toggle rule enabled/disabled |
| DELETE | `/api/v1/whitelist/{id}` | Delete (non-default only) |
| POST | `/api/v1/whitelist/seed` | Load default rules |

### Scanning
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/scan` | Trigger immediate scan |
| GET | `/api/v1/scan/status` | Scan progress and state |
| GET | `/api/v1/scan/subnets` | Auto-detected LAN subnets |
| PUT | `/api/v1/scan/cidr` | Set default CIDR |
| GET | `/api/v1/scan/targets` | List custom scan targets |
| POST | `/api/v1/scan/targets` | Create target (VLAN/segment) |
| DELETE | `/api/v1/scan/targets/{id}` | Remove target |
| PUT | `/api/v1/scan/targets/{id}/toggle` | Enable/disable target |
| POST | `/api/v1/scan/targets/{id}/scan` | Scan specific target |

### Sensors
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/sensor/register` | Register sensor (hostname, OS, arch) |
| POST | `/api/v1/sensor/devices` | Push discovered devices to Core |
| POST | `/api/v1/sensor/dns` | Push captured DNS queries |
| GET | `/api/v1/sensor/list` | List sensors + status |
| GET | `/api/v1/sensor/work` | Poll for work assignments |
| PUT | `/api/v1/sensor/{id}/primary` | Set primary sensor |

### Activity
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/logs` | Audit trail of user actions |

---

## DNS Intelligence Pipeline

All detection runs in `backend/internal/dnsintel/`. Scored events feed a composite 0.0–1.0 anomaly score.

| Engine | File | Detection Method | Tag |
|--------|------|------------------|-----|
| **DGA Detection** | `dga.go` | Shannon entropy (>3.5) + bigram frequency | `dga_candidate` |
| **Beaconing** | `beacon.go` | Coefficient of variation (<0.15 = regular callbacks) | `beaconing` |
| **DNS Tunneling** | `tunnel.go` | Subdomain length >30, base64/hex patterns, high TXT volume | `dns_tunnel` |
| **DNS Rebinding** | `rebinding.go` | Public→private IP transition detection | `dns_rebinding` |
| **DNS Bypass** | `bypass.go` | Hardcoded resolver queries (8.8.8.8, 1.1.1.1) | `dns_bypass` |
| **Threat Intel Match** | `enricher.go` | abuse.ch URLhaus, Feodo Tracker, SSLBL Bloom filter | `known_bad` |

**Enricher** (`enricher.go`) composites all signals into final anomaly score.

---

## Threat Intelligence Feeds

| Feed | Source | Type | TTL |
|------|--------|------|-----|
| URLhaus | abuse.ch | Malware distribution URLs | 7d (IPs), 30d (domains) |
| Feodo Tracker | abuse.ch | Botnet C2 IPs | 7d |
| SSLBL | abuse.ch | Malicious SSL/TLS certificates | 7d |

Storage: SQLite `threat_indicators` table with Bloom filter for O(1) lookups (~500KB for 100K indicators). All detection works offline — cached locally with TTL-based staleness. Stale indicators are demoted, not deleted.

---

## Protocol Coverage

### Implemented

| Protocol | Method | Location |
|----------|--------|----------|
| DNS (plaintext UDP/TCP 53) | Passive BPF capture via gopacket | `sensor/internal/dnscap/capture.go` |
| Encrypted DNS (DoH/DoT) | IP fingerprinting (Cloudflare, Google, OpenDNS) | `sensor/internal/dnscap/encrypt_detect.go` |
| nmap network scanning | Active ping + port scan | `sensor/internal/netscan/scanner.go` |
| Pi-hole polling | REST API every 60s | `backend/internal/dnspoller/pihole.go` |
| Subnet auto-detection | Interface enumeration | `sensor/internal/netinfo/interfaces.go` |

### Planned (Phase 2–3)

| Protocol | Library | Status | Notes |
|----------|---------|--------|-------|
| ARP monitoring | gopacket + afpacket | Phase 3 | Real-time MAC+IP pairs, <1% CPU on Pi 4 |
| mDNS / Bonjour | hashicorp/mdns | Phase 3 | Service types, TXT record model names |
| DHCP snooping | insomniacslk/dhcp | Phase 3 | Option 12 hostname, Option 60 vendor, Option 55 fingerprint |
| SSDP / UPnP | koron/go-ssdp + huin/goupnp | Phase 3 | NOTIFY announcements, device description XML |
| AdGuard Home polling | HTTP client | Phase 2 | Similar pattern to Pi-hole poller |
| Embedded DNS resolver | Go DNS library | Phase 2 | Users point devices at Vedetta for full visibility |
| iptables intercept | iptables DNAT rules | Phase 2 | Linux router mode, catches hardcoded DNS bypasses |

| NAT-PMP / PCP | Passive multicast monitor (port 5350/5351) | Phase 3 | Unexpected port forwards = strong compromise indicator |

### Not Currently Planned

| Protocol | Notes |
|----------|-------|
| IGMP | Multicast group management — low priority for threat detection |
| DLNA | Media streaming discovery — low threat signal, folds into UPnP |
| NBNS / NetBIOS | Windows name resolution — declining relevance, but common on mixed networks. Consider for Phase 4+ |

---

## Database Schema (SQLite)

### Migration History

| # | File | Purpose |
|---|------|---------|
| 001 | `init.sql` | Core tables: events, devices, retention_config |
| 002 | `scan_targets.sql` | Scan targets (VLANs, segments) |
| 003 | `threat_indicators.sql` | Threat intel with Bloom filter indexes |
| 004 | `sensors.sql` | Sensor registry |
| 005 | `sensor_primary.sql` | Primary sensor flag |
| 006 | `device_ip_segment_index.sql` | Composite index optimization |
| 007 | `device_fingerprints.sql` | device_type, os_family, os_version, confidence |
| 008 | `dns_source.sql` | DNS capture method tracking |
| 009 | `event_type_encrypted_dns.sql` | Encrypted DNS detection event type |
| 010 | `dns_capture_targets.sql` | DNS capture configuration |
| 011 | `event_enrichment.sql` | Tags, geo, threat indicator matches |
| 012 | `device_names_notes_ack.sql` | Custom names, notes, ack/suppression system |
| 013 | `whitelist_rules.sql` | Known-traffic whitelist for false positive reduction |

### Key Tables

**events** — PK: `event_id` (UUID). Fields: timestamp, event_type, source_hash, source_ip, domain, query_type, resolved_ip, blocked, anomaly_score, tags (JSON), geo, device_vendor, network_segment, dns_source, threat_desc, metadata, acknowledged, ack_reason.

**devices** — PK: `device_id` (UUID). Fields: ip_address, mac_address (dedup key), hostname, vendor, open_ports (JSON), segment, device_type, os_family, os_version, fingerprint_confidence, custom_name, notes.

**sensors** — PK: `sensor_id` (UUID). Fields: hostname, os, arch, cidr, version, status (online/offline), is_primary.

**suppression_rules** — Per-incident filters (domain + source_ip + tags).

**whitelist_rules** — Known-traffic patterns (domain glob, source IP glob, tag match). 20 defaults (Apple, mDNS, cloud, OS updates, IoT).

**threat_indicators** — PK: (indicator, source). Bloom filter indexed. TTL-based staleness.

---

## Frontend

Single-file React app (`App.jsx`) with Tailwind CSS dark theme.

| View | Features |
|------|----------|
| **Dashboard** | Stat cards (devices, sensors, threats, DNS queries), clickable navigation |
| **Devices** | Table with fingerprint data, segment filtering, detail modal with editable fields, bulk ack/suppress from threat history, CSV export |
| **Threats** | Grouped events (5-min window dedup), severity filters, pagination, inline ack/suppress with state management, grouped events modal, whitelist panel with toggle controls |
| **Sensors** | List with status, primary sensor toggle, setup guide |
| **Scan Targets** | Custom VLAN/segment management, per-target scanning |
| **Logs** | Audit trail |
| **Settings** | Retention, telemetry opt-in, interface selection |

---

## DNS Proxy Evaluation

Evaluated for potential integration as a Tier 2/3 DNS analysis option.

### Passive vs. Inline Tools

| Tool | Mode | Risk to Network | Fit for Vedetta |
|------|------|-----------------|-----------------|
| **Passivedns** | Passive (read-only) | None | Good — aligns with Vedetta philosophy |
| **DNSMonster** | Passive (Go-based) | None | Strong — same language, high throughput |
| **dnstap** | Passive (DNS server logs) | None | Good — if user runs local DNS |
| **DNSChef** | Inline (proxy) | High — single point of failure | Poor — risks network stability |
| **mitmproxy** | Inline (proxy) | High | Poor — overkill for home DNS |
| **CoreDNS** | Inline (server) | Medium | Possible as opt-in Tier 3 embedded resolver |

### Recommendation

**Do not integrate inline DNS proxy tools.** Vedetta's design principle is passive-first — never be the reason a home network goes down. The existing Tier 1 passive capture (gopacket BPF) covers plaintext DNS without risk. For encrypted DNS visibility:

1. **Tier 2 (Pi-hole/AdGuard polling)** — already partially implemented, zero risk
2. **Tier 3 (embedded resolver)** — opt-in only, user explicitly points devices at Vedetta
3. **Tier 4 (iptables intercept)** — Linux power users only, with clear warnings

DNSMonster's architecture (Go-based, passive, high throughput) is worth studying for sensor-side DNS processing patterns, but Vedetta's existing `dnscap` package already covers the core capture.

---

## Competitor Positioning

### Landscape

| Tool | Target | Resources | DNS Threat | Device Discovery | Setup | License |
|------|--------|-----------|------------|------------------|-------|---------|
| **Wazuh** | SMB/Enterprise | 4GB+ RAM | No | Agent-based | Moderate | Open source |
| **Security Onion** | SOC analysts | 24GB+ RAM | Yes (Suricata) | Network-based | Complex | Open source |
| **Pi-hole** | Home users | Minimal | Block-only | DHCP clients | Very easy | Open source |
| **Firewalla** | Home users | Appliance | Yes | Passive | Plug-and-play | Proprietary ($200-800) |
| **Zabbix** | Infrastructure ops | Varies | No | SNMP | Moderate | Open source |
| **OSSEC** | Legacy | Light | No | None | Moderate | Open source (stale) |
| **Snort/Suricata** | Network security | 4GB+ RAM | Yes (rules) | Traffic analysis | Moderate | Open source |
| **Vedetta** | **Home/SMB** | **<1GB RAM** | **Yes (5 engines)** | **Active + passive** | **Easy** | **Open source** |

### Vedetta's Differentiators

1. **DNS-first SIEM.** Five detection engines (DGA, beaconing, tunneling, rebinding, bypass) purpose-built for DNS threat hunting — no other home tool does this.

2. **Passive-first, never destabilize.** Sensor observes traffic without modifying it. No inline proxy, no DNS interception by default. Pi-hole-level safety with Wazuh-level depth.

3. **Unified device + threat correlation.** Combines nmap active scanning, passive DNS profiling, and threat intel matching in one platform. Wazuh needs agents on every device. Pi-hole only sees DNS clients. Firewalla is closed-source.

4. **Resource-appropriate.** Runs on a Raspberry Pi 4. Security Onion needs 24GB RAM. Wazuh recommends 16GB. Vedetta targets <1GB.

5. **Community threat network.** Opt-in anonymized telemetry creates a shared intelligence feed across Vedetta deployments — crowdsourced home network threat data that doesn't exist today.

6. **No vendor lock-in.** Open source, self-hosted, no cloud dependency, no subscription, no proprietary hardware.

---

## Planned Firewall Integrations

In priority order:

| # | Platform | Method | Status |
|---|----------|--------|--------|
| 1 | **UniFi** | REST API (86 endpoints, client list, IPS/IDS alerts, DPI) | Planned (M5) |
| 2 | **OpenWRT** | luci-rpc or ubus JSON-RPC | Planned (M5) |
| 3 | **pfSense / OPNsense** | Syslog (Fluent Bit on UDP 5140) + REST API | Planned (M5) |
| 4 | **MikroTik** | RouterOS API | Planned (M5) |

Generic `FirewallConnector` Go interface for community contributions.

---

## Security Status

| Area | Current State | Pre-V1 Requirement |
|------|---------------|--------------------|
| Sensor→Core auth | None | Shared secret `Authorization: Bearer` header |
| TLS | None (LAN-only) | Optional TLS for sensor→core communication |
| Request signing | None | HMAC-SHA256 of request body with shared secret |
| Sensor ID validation | None | Core rejects data from unregistered sensor IDs |
| Input validation | Basic | Rate limiting, request size limits |
| CORS | Open | Restrict to dashboard origin |

**Priority: HIGH.** Zabbix and Zenoss were historically exploited via weak agent-server authentication. Sensor-Core security hardening is a blocking requirement for V1 public release. Risk is low for LAN-only deployments but unacceptable for any internet-exposed instance.

---

## File Structure

```
vedetta/
├── backend/
│   ├── cmd/vedetta/main.go          # Entry point, migration runner, seed
│   ├── internal/
│   │   ├── api/router.go            # All HTTP handlers
│   │   ├── store/                    # SQLite CRUD (db.go, events.go, suppression.go, whitelist.go)
│   │   ├── discovery/               # nmap integration, subnet detection
│   │   ├── dnsintel/                # DGA, beaconing, tunnel, rebinding, bypass engines
│   │   ├── dnspoller/               # Pi-hole and AdGuard API pollers
│   │   ├── threatintel/             # abuse.ch feed integration + Bloom filter
│   │   └── models/event.go          # All data models
│   ├── go.mod
│   └── Dockerfile
├── sensor/
│   ├── cmd/sensor/main.go           # Sensor entry point
│   ├── internal/
│   │   ├── dnscap/                  # DNS packet capture + encrypted DNS detection
│   │   ├── netscan/                 # nmap scanner wrapper
│   │   ├── netinfo/                 # Interface enumeration
│   │   └── client/                  # Core API client
│   └── go.mod
├── frontend/
│   ├── src/App.jsx                  # Single-file React app
│   ├── nginx.conf                   # Reverse proxy config
│   └── Dockerfile
├── siem/
│   └── migrations/                  # 001–013 sequential SQL
├── docs/
│   ├── architecture.md              # This file
│   ├── roadmap.md                   # Full feature roadmap
│   ├── schema.md                    # Event schema reference
│   └── sensor-architecture.md       # Sensor design document
├── research/                        # 17 research docs (design decisions, competitor analysis)
├── scripts/
│   └── update-all.sh               # Pull + rebuild + verify deployment script
└── docker-compose.yml
```
