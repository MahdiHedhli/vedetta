# Implementation Roadmap — Research-Informed Priorities

> This document synthesizes findings from all research documents (01-08) and aligns them with the project roadmap at `docs/roadmap.md`. It proposes a phased plan that respects Vedetta's constraints: Pi 4 hardware floor, zero-config aspiration, and the M0-M7 milestone structure.

## Guiding Priorities

From the roadmap and competitive analysis, three things are clear:

1. **The ingest pipeline is the critical blocker.** Nothing in M2-M6 works until `/api/v1/ingest` exists and events flow from Fluent Bit → backend → SQLite. This is Priority 1 from the roadmap and must be completed first.

2. **DNS threat hunting is the highest-ROI feature.** Pi-hole/AdGuard logs are the richest data source on any home network. Competitors like Firewalla offer basic DNS blocking; Vedetta can offer DGA detection, beaconing analysis, C2 identification, and community intelligence. This is the wedge.

3. **Passive device fingerprinting is the UX differentiator.** Showing "Ring Doorbell Pro (IoT)" instead of "Amazon Technologies Inc." in the dashboard is the difference between a tool for enthusiasts and a tool for everyone.

## Phase 1: Unblock the Pipeline (Aligns with M1 completion + M2 + M3)

**Timeline: Immediate — these are the roadmap's stated next-session priorities**

| Task | Research Doc | Roadmap Item | Effort |
|------|-------------|--------------|--------|
| Fix sequential migration runner | — | Priority 1 (ISS-001) | S |
| Implement `POST /api/v1/ingest` | 02 | Priority 2 (ISS-002) | M |
| Implement `store.InsertEvents()` | 02 | ISS-004 | S |
| Implement `GET /api/v1/events` with full query support | 02 | ISS-003 | M |
| Implement retention enforcement (daily DELETE job) | 02 | M3 gap | S |
| Write `docs/sensor-architecture.md` | — | Priority 3 (ISS-005) | S |

**Why this order:** The migration runner must work before events can be stored. The ingest endpoint must exist before DNS events can flow. The events query API must work before the dashboard can display threats. The retention job prevents unbounded storage growth on Pi 4's limited SD card.

## Phase 2: DNS Threat Hunting Engine (Aligns with M2)

**Timeline: Immediately after Phase 1 — this is M2's core work**

| Task | Research Doc | Notes | Effort |
|------|-------------|-------|--------|
| Shannon entropy DGA scorer | 04 | Score domains during ingest, tag `dga_candidate` | S |
| Beaconing detector | 04 | Track per-source/per-domain query intervals | M |
| DNS tunnel detector | 04 | Flag long subdomains, encoding patterns | S |
| abuse.ch URLhaus integration | 05 | Download domain blocklist, Bloom filter lookup, tag `known_bad` | M |
| abuse.ch Feodo Tracker integration | 05 | C2 IP blocklist, cross-reference with resolved_ip | S |
| Threat intel local DB (`threat_indicators` table) | 05 | Schema + bulk import + TTL-based expiry | M |
| Event enrichment hook in ingest pipeline | 05 | Lookup domain/IP against threat_indicators during ingest | S |
| DNS events dashboard card | — | Replace hardcoded "—" with live query count + threat count | M |
| Threat events dashboard view | — | New tab showing high-anomaly-score events | L |

**Key dependency:** This phase requires Pi-hole to be reachable by the collector. The current Fluent Bit config tails `/var/log/pihole/pihole.log` via a shared Docker volume. Consider also adding a Pi-hole API poller (see doc 04) for environments where the volume mount isn't practical.

## Phase 3: Passive Discovery & Fingerprinting (Extends M1, Feeds M4 UX)

**Timeline: After M2 is functional**

| Task | Research Doc | Notes | Effort |
|------|-------------|-------|--------|
| ARP passive listener in sensor | 01 | gopacket + afpacket, BPF filter, real-time MAC+IP | M |
| DHCP sniffer in sensor | 01, 08 | Extract option 55 fingerprint, hostname, vendor class | M |
| mDNS listener in sensor | 01, 08 | Parse service types and TXT records | M |
| SSDP/UPnP listener in sensor | 01, 08 | Parse NOTIFY, fetch device descriptions | M |
| Bundle Fingerbank SQLite DB | 08 | DHCP option 55 → device type/OS/model lookup | S |
| Hostname pattern classifier | 08 | Regex-based device identification from DHCP/mDNS names | S |
| Multi-signal fusion scoring | 08 | Combine OUI + DHCP + mDNS + hostname → confidence score | M |
| Schema migration: add device fingerprint columns | 08 | device_type, os_family, os_version, discovery_method, confidence | S |
| API update: devices endpoint returns fingerprint data | 08 | Include type, OS, model, confidence in response | S |
| Dashboard: device icons and human-readable names | 08 | Replace vendor string with identified device name | M |

**Hardware validation:** All passive listeners combined use <2% CPU and <15MB RAM on Pi 4 (BPF-filtered, zero-copy via afpacket). Well within the roadmap's idle target of <200MB RAM, <5% CPU.

## Phase 4: Firewall Connectors (Aligns with M5)

**Timeline: After M4 setup wizard**

| Task | Research Doc | Notes | Effort |
|------|-------------|-------|--------|
| UniFi REST API connector | 03 | Poll client list, firewall events, threat management | L |
| pfSense/OPNsense syslog normalization | 03 | Fluent Bit parser for pf log format | M |
| Suricata EVE JSON integration (optional) | 03 | Docker Compose override, Fluent Bit input, new event type | L |
| DNS bypass detection | 04 | Alert when devices query external DNS directly | S |
| Firewall connector interface documentation | — | Enable community contributions | M |

**Note:** The UniFi connector is high-value because UniFi is the most common prosumer/SMB network stack. I see there's already a UniFi MCP available in the environment — worth exploring whether its data model maps to Vedetta's schema.

## Phase 5: Telemetry & Threat Network (Aligns with M6)

**Timeline: After M2 + M3 are solid**

| Task | Research Doc | Notes | Effort |
|------|-------------|-------|--------|
| Telemetry PII stripping pipeline | 06 | HMAC source IPs, remove hostnames, generalize device types | M |
| Telemetry batching + retry | 06 | 15-min windows, gzip, exponential backoff, local staging queue | M |
| Threat network: ClickHouse ingest | 06 | Accept batches, deduplicate, store | L |
| Threat network: domain reputation scoring | 06 | Consensus algorithm (study CrowdSec model) | L |
| Threat network: community feed API | 06 | top-domains, anomalies, emerging threats | L |
| Feed subscription in telemetry daemon | 06 | Pull community feeds, merge into local threat_indicators | M |
| Node reputation system | 06 | Trust scoring, anti-gaming protections | L |
| Community fingerprint contribution | 08 | Anonymous DHCP fingerprint + device type sharing | M |

**CrowdSec lesson:** Their consensus algorithm uses diversity criteria (reports from multiple ASNs) to prevent a single actor from poisoning the blocklist. Vedetta should implement equivalent safeguards for domain reputation.

## Phase 6: Advanced Detection (Post-V1 / V2 Scope)

These items are explicitly out of V1 scope per the roadmap but worth tracking:

| Task | Research Doc | Notes |
|------|-------------|-------|
| JA3/JA4 TLS fingerprinting | 01, 08 | Passive TLS ClientHello analysis, malware JA3 detection |
| TCP/IP stack fingerprinting (p0f-style) | 01, 08 | Modern OS signature database, contributed via threat network |
| Behavioral baseline engine | 03 | Per-device rolling statistics, deviation scoring |
| Lateral movement detection | 03 | Internal ARP traffic spike analysis |
| MITRE ATT&CK technique mapping | 03 | Tag events with ATT&CK technique IDs |
| Zeek integration (optional) | 03 | Deep protocol analysis for power users |
| AdGuard Home connector | 04 | API poller as Pi-hole alternative |
| CertStream NRD monitoring | 04, 05 | Real-time newly registered domain detection |
| DNS rebinding detection | 04 | Public→private IP transition alerting |
| GreyNoise IP enrichment | 05 | External IP classification (noise vs. targeted) |
| OTX pulse subscription | 05 | AlienVault curated threat intelligence |

## Effort Legend

- **S** (Small): <4 hours, single file/function, well-defined scope
- **M** (Medium): 4-16 hours, multiple files, some design decisions
- **L** (Large): 16+ hours, new subsystem, architectural decisions, testing required

## Critical Path

```
Phase 1 (Pipeline)
  ├── Migration runner fix ──► Ingest endpoint ──► Events query API
  │                                  │
  │                                  ▼
  │                           Phase 2 (DNS Hunting)
  │                             ├── DGA scorer
  │                             ├── Beaconing detector
  │                             ├── Threat intel feeds
  │                             └── Dashboard threat view
  │                                  │
  │                                  ▼
  │                           Phase 5 (Telemetry + Threat Network)
  │
  └── Sensor architecture doc
        │
        ▼
  Phase 3 (Passive Discovery)
    ├── ARP/DHCP/mDNS listeners
    ├── Fingerbank integration
    └── Dashboard device identification
          │
          ▼
    Phase 4 (Firewall Connectors)
      ├── UniFi connector
      ├── pfSense syslog
      └── Optional Suricata
```

Phases 1→2→5 are the main critical path (pipeline → detection → community intelligence).
Phase 3→4 can proceed in parallel once Phase 1 is done.

## Resource Constraints on Pi 4

Running budget for idle resource usage (target: <200MB RAM, <5% CPU):

| Component | RAM | CPU | Status |
|-----------|-----|-----|--------|
| Go backend | ~30MB | <1% | Existing |
| React frontend (nginx) | ~10MB | <1% | Existing |
| Fluent Bit collector | ~5MB | <1% | Existing |
| SQLite (WAL mode) | ~20MB | <1% | Existing |
| Telemetry daemon | ~15MB | <1% | Stub |
| Threat network backend | ~20MB | <1% | Stub |
| Passive listeners (ARP/DHCP/mDNS) | ~15MB | <2% | Phase 3 |
| Fingerbank DB | ~4MB | 0% | Phase 3 |
| Threat intel DB | ~10MB | <1% | Phase 2 |
| **Total estimated** | **~130MB** | **<8%** | **Under budget** |

Adding optional Suricata would add ~200-400MB RAM, pushing close to the 4GB ceiling. This is why Suricata should remain optional (Docker Compose override) and is recommended only for 8GB Pi 4 or x86 hardware.
