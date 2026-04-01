# Vedetta — Project Roadmap

> Version: 2.0.0
> Last updated: 2026-04-01
> Status: Active development — V1 in progress
> Research integration: 17 research documents (8 capability areas + 7 deep dives) reviewed and incorporated

---

## Overview

Vedetta is a free and open source security monitoring platform for home users and small businesses. It provides multi-source DNS threat hunting (libpcap sniffing, embedded resolver, Pi-hole/AdGuard Home polling, and iptables interception), scheduled network asset discovery via native sensors, SIEM-grade log aggregation, and opt-in anonymized telemetry that feeds a community threat intelligence network.

This document is the canonical reference for implementation status, known gaps, and next priorities. Claude Code should treat this as the primary context doc for any development session.

**Strategic positioning (from research/07-competitor-analysis.md):** Vedetta occupies a unique niche at the intersection of four attributes no competitor combines: lightweight enough for Pi 4, open source and self-hosted, DNS-first threat hunting, and community threat intelligence. Primary competitors — Firewalla (proprietary hardware), Fingbox (no SIEM/DNS hunting), Wazuh (16GB+ RAM), CrowdSec (IP-focused, not DNS) — each lack at least two of these.

---

## Architecture summary

### Core + sensor split (critical context)

The most important architectural decision in the codebase is the separation of **Core** (the Docker-based platform) from the **native sensor** (`sensor/`).

**Why this split exists:** Docker cannot pass through the host network stack with full fidelity on macOS or Windows — both run Docker inside a Linux VM, which means containers see virtual interfaces, not the real LAN. Linux is the only platform where `--network=host` works correctly and raw socket / ARP-based discovery is possible.

**The model:**
- `vedetta-core` (Docker) — API server, SIEM storage, dashboard, telemetry daemon, threat network backend. Runs everywhere.
- `vedetta-sensor` (native binary) — nmap-based network scanner + passive listeners (planned). Runs on the host OS, auto-detects LAN subnets, pushes discovered devices to Core via `POST /api/v1/sensor/devices`. Requires `sudo` / `CAP_NET_RAW` for ARP-based discovery and passive packet capture. Runs natively on Linux, macOS, and Windows.

On Linux with host networking, Core also includes a built-in fallback scanner. On macOS/Windows, the native sensor is required for accurate LAN discovery.

This architecture needs a dedicated doc at `docs/sensor-architecture.md` — see gaps section below.

**Research note (research/deep-dive-passive-discovery-go.md):** The sensor will expand from nmap-only to include continuous passive listeners (ARP, DHCP, mDNS, SSDP) using `google/gopacket` with `pcapgo` (pure-Go, no cgo) and `afpacket` for zero-copy capture on Linux. Libraries validated for ARM64 Pi 4: `gopacket`, `hashicorp/mdns`, `insomniacslk/dhcp`, `koron/go-ssdp`, `huin/goupnp`.

### Monorepo structure
```
/vedetta
  /backend          Go API server (Core)
  /frontend         React + Tailwind dashboard
  /collector        Fluent Bit config + normalization pipeline
  /telemetry        Opt-in anonymized telemetry daemon (stub)
  /siem             SIEM storage schema + migrations
  /threat-network   Central threat intel backend (stub)
  /sensor           Native host sensor binary
  /docs             Architecture, schema, roadmap (this file)
  /research         17 research documents informing V1 development
  /site             vedettas.com landing page
  /deploy           Docker Compose, Helm (future)
  docker-compose.yml
```

### Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.22 (chi router, go-sqlite3) |
| Frontend | React 18 + Tailwind CSS + Vite |
| Log collection | Fluent Bit 3.0 |
| Local storage | SQLite (WAL mode) / PostgreSQL (future) |
| Threat network storage | ClickHouse (confirmed by research) |
| Passive capture | gopacket + pcapgo/afpacket (pure-Go on Linux) |
| Device fingerprinting | Curated local DB (OUI + DHCP patterns + hostname regex + mDNS services) |
| Container runtime | Docker Compose |
| License | AGPLv3 |

---

## Milestone status

### M0 — Repo and infrastructure `COMPLETE`

- GitHub monorepo with full directory structure
- Docker Compose with all services wired
- CI-ready layout
- Core event schema documented in `docs/schema.md`
- `.gitignore` with security-first defaults
- `SECURITY.md` with responsible disclosure policy
- Landing page live at `site/index.html` (vedettas.com)

---

### M1 — Network discovery `IN PROGRESS`

**Working:**
- nmap scheduler in `backend/internal/discovery/scheduler.go`
- nmap XML parser in `backend/internal/discovery/nmap.go`
- LAN subnet auto-detection in `backend/internal/discovery/netdetect.go` (Docker-aware — returns empty inside container to trigger UI confirmation)
- Device registry with upsert-by-MAC in `backend/internal/store/devices.go`
- Multi-segment support (`default`, `iot`, `guest`)
- Custom scan targets (named VLANs) in `backend/internal/store/scan_targets.go`
- Native sensor binary in `sensor/` with `--core`, `--cidr`, `--interval`, `--ports`, `--once` flags
- Sensor registration and device push API (`/api/v1/sensor/register`, `/api/v1/sensor/devices`)
- Sensor tracking table with `first_seen`, `last_seen`, `status` in `backend/internal/store/sensors.go`
- Frontend dashboard with device table, new device alerts (24h), segment filtering, scan targets UI, sensor setup dialog

**Supported platforms:**
- Linux (native binary with full ARP/packet capture capabilities)
- macOS (native binary, requires manual network interface configuration)
- Windows (planned Phase 3 — cross-compile to GOOS=windows, requires npcap/WinPcap for Layer 2 scanning)

**Known gaps:**
- Migration runner only applies the inline fallback schema, not `siem/migrations/002_scan_targets.sql`. Need a proper sequential migration runner with a `schema_migrations` tracking table.

**Planned extensions:**
- **Windows native sensor:** Cross-compile sensor binary for Windows (GOOS=windows). Requires npcap or WinPcap for Layer 2 scanning and passive DNS capture. Windows service registration via `sc.exe` or NSSM. Priority: Phase 3 alongside other passive listener work.

**Research-informed additions (from docs 01, 08, deep-dive-passive-discovery-go.md):**
- Add passive ARP listener to sensor for real-time device detection between nmap intervals
- Add fast ARP heartbeat every 60s (lightweight, sub-1% CPU on Pi 4) alongside existing nmap scans
- Add `discovery_method` field to Device model: `nmap_active`, `arp_passive`, `dhcp_passive`, `mdns_passive`, `ssdp_passive`

---

### M2 — DNS threat hunting `IN PROGRESS`

**Working:**
- Pi-hole REST API integration (poll query logs every 60s) in `backend/internal/store/pihole.go`
- DNS event ingestion into SIEM storage layer via `POST /api/v1/ingest` (implemented in `backend/internal/api/router.go`)
- DGA candidate detection (Shannon entropy scorer)
- Beaconing detector (inter-query interval coefficient of variation analysis)
- DNS tunnel detector (subdomain label analysis, encoding patterns)
- Threat intelligence integration: abuse.ch URLhaus + Feodo Tracker + SSLBL feeds
- Threat indicators table with Bloom filter for O(1) lookups
- Event enrichment pipeline with anomaly scoring
- Events table with SIEM indexes
- `store.InsertEvents()` function

**Planned extensions:**
- Threat events dashboard view (currently shows hardcoded "—")
- AdGuard Home as alternative to Pi-hole poller

**Research-informed additions (from docs 04, 05, deep-dive-dns-detection-algorithms.md, deep-dive-abuse-ch-integration.md):**

DNS Threat Scoring Engine — build a `dns_intel` Go package in backend:
- **Shannon entropy DGA scorer:** Domains with entropy >3.5 flagged as `dga_candidate`. Combine with character bigram frequency analysis to catch DGA domains with artificially lowered entropy. Memory: ~1MB.
- **Beaconing detector:** Track per-source, per-domain query timestamps. Flag when coefficient of variation of inter-query intervals <0.15 (regular callbacks). Memory: ~10MB rolling window.
- **DNS tunnel detector:** Flag queries with subdomain labels >30 chars, base64/hex patterns, or high TXT query volume to a single domain. Memory: negligible.
- **DNS rebinding detector:** Alert when a domain's resolved IP transitions from public to private (RFC 1918) address space.
- **Composite scoring:** All four signals feed into `anomaly_score` (0.0–1.0) computed during ingest, before storage.

Threat Intelligence Integration — build a `threat_intel` Go package:
- **abuse.ch URLhaus:** Bulk domain/URL blocklist download every 5 minutes (small, changes frequently). No API key required.
- **abuse.ch Feodo Tracker:** C2 IP blocklist every hour. Cross-reference with resolved_ip on DNS events.
- **abuse.ch SSLBL:** JA3 fingerprint blocklist every 6 hours (prep for future JA3 capture).
- **Local threat_indicators SQLite table:** Store all indicators with type, source, confidence, tags, TTL. Bloom filter for O(1) domain lookups (~500KB for 100K indicators).
- **Event enrichment hook:** On ingest, lookup domain/IP against local DB. Add tags (`known_bad`, `c2_candidate`, `newly_registered`). Adjust `anomaly_score`.
- **Offline operation:** All detection works without internet. Threat intel cached locally with TTL-based staleness (7 days IPs, 30 days domains). Stale indicators demoted in scoring, not deleted.

### Multi-source DNS capture architecture (Tier 1–4)

Pi-hole is now repositioned from a requirement to one of four optional DNS intelligence sources. All paths feed the same internal event schema and threat hunting engine.

**Tier 1 — Passive libpcap DNS sniffing (zero config, enabled by default)**
- **How it works:** Sensor uses `gopacket` with BPF filter on UDP/TCP 53 to capture all plaintext DNS queries on the local network segment. No configuration or device DNS changes needed.
- **Advantages:** Works everywhere. Detects DNS bypass (devices hardcoding 8.8.8.8, 1.1.1.1, etc.). Requires no setup or opt-in from users.
- **Limitations:** Misses encrypted DNS (DoH/DoT). Only captures plaintext queries on local subnet.
- **CPU/memory:** Negligible (<0.1% CPU, <1MB RAM).
- **Status:** Planned Phase 2.

**Tier 2 — Vedetta embedded DNS resolver (opt-in, zero external dependency)**
- **How it works:** Sensor includes a lightweight embedded DNS forwarder. Users point their DHCP server or static DNS settings to the Vedetta resolver IP. All queries are logged natively on the sensor.
- **Advantages:** Comprehensive query capture. Supports caching and local zone definitions. Works with encrypted queries at the application level (device → Vedetta → upstream).
- **Implementation:** Lightweight Go resolver (`dns` library) that forwards to upstream resolver (Cloudflare, Quad9, etc.) and logs all queries.
- **Limitations:** Requires DHCP reconfiguration or static DNS on devices. Users lose ability to use their preferred upstream resolver unless Vedetta forwards to it.
- **CPU/memory:** ~5–10MB RAM for resolver, negligible CPU in idle.
- **Status:** Planned Phase 2.

**Tier 3 — Pi-hole / AdGuard Home API polling (optional integration)**
- **How it works:** Vedetta polls the REST API of an existing Pi-hole or AdGuard Home installation (`GET /api/logs` or `GET /control/querylog`) every 60 seconds. Users who already run Pi-hole/AdGuard Home for other reasons can optionally integrate.
- **Advantages:** Reuses existing infrastructure. Pi-hole provides DNS filtering UI, caching, local zone management. AdGuard Home adds DoH/DoT server capability.
- **Implementation:** Existing Pi-hole poller in `backend/internal/store/pihole.go` + planned AdGuard Home poller.
- **Limitations:** Requires separate Pi-hole/AdGuard Home instance. Vedetta can only see queries already in their logs (subject to log retention settings).
- **Status:** Pi-hole working. AdGuard Home planned Phase 2.

**Tier 4 — iptables DNAT intercept (router mode, Linux only, advanced)**
- **How it works:** On Linux, Vedetta can run iptables rules to redirect all outbound port 53 traffic (TCP and UDP) to Vedetta's embedded resolver, regardless of the device's DNS configuration. Catches hardcoded resolvers (8.8.8.8, 1.1.1.1) and ignores device-level DNS overrides.
- **Advantages:** Comprehensive capture. Catches all DNS queries, even from devices trying to bypass the network DNS. Strongest security signal for detecting compromised devices or DoH/DoT clients.
- **Limitations:** Requires root access. Linux only (macOS/Windows cannot modify iptables). Complex setup. Only captures Layer 3/4, not encrypted DNS (DoH/DoT endpoints still reach external servers, but can be blocked at firewall).
- **Implementation:** Iptables rules + embedded resolver from Tier 2.
- **Status:** Planned Phase 2 (requires router-mode setup doc).

**Encrypted DNS handling (DoH/DoT complement):**
- **Block outbound DoH/DoT at firewall:** If Vedetta is also a firewall connector (M5), block outbound HTTPS/TLS to known DoH/DoT providers (1.1.1.1:443, 8.8.8.8:443, etc.) for analysis and blocking.
- **Run local DoH/DoT endpoint:** Extend Tier 2 resolver to also serve DoH (HTTPS) and DoT (TLS on port 853) so devices can encrypt to Vedetta instead of external providers.
- **Fingerprint encrypted DNS flows:** When a device makes TLS connections to known DoH/DoT IPs, flag as `encrypted_dns_detected` event with high confidence (DNS bypass signal).

**Data flow convergence:**
- Tier 1 (libpcap) → sensor → `POST /api/v1/sensor/dns-events` → Core
- Tier 2 (embedded resolver) → sensor → `POST /api/v1/sensor/dns-events` → Core
- Tier 3 (Pi-hole poller) → Core directly → `/api/v1/ingest`
- Tier 4 (iptables intercept) → Tier 2 resolver → Core
- All paths → common `dns_event` schema → threat scoring engine (DGA, beaconing, tunnel, rebinding) → dashboard + telemetry

Schema addition for threat indicators:
```sql
CREATE TABLE threat_indicators (
    indicator TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash')),
    source TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    tags TEXT,  -- JSON array
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ttl_hours INTEGER NOT NULL DEFAULT 168,  -- 7 days
    PRIMARY KEY (indicator, source)
);
CREATE INDEX idx_ti_indicator ON threat_indicators(indicator);
CREATE INDEX idx_ti_source ON threat_indicators(source);
CREATE INDEX idx_ti_last_seen ON threat_indicators(last_seen);
```

---

### M3 — SIEM storage layer `PARTIAL`

**Working:**
- Core event schema in `siem/migrations/001_init.sql` with correct indexes
- `scan_targets` schema in `siem/migrations/002_scan_targets.sql`
- `events` and `devices` tables with SIEM-appropriate indexes (`timestamp`, `event_type`, `source_hash`, `anomaly_score`, `domain`)
- `retention_config` table with 90-day default
- `GET /api/v1/events` stub endpoint (returns empty array)

**Known gaps:**

1. **Migration runner is fragile.** `backend/internal/store/db.go` tries three hardcoded paths for migration SQL, then falls back to an inline string. `002_scan_targets.sql` is never applied — only `001` tables are created via the inline fallback. Fix: implement a sequential migration runner that reads all `.sql` files from `/siem/migrations/` in filename order, applies each in a transaction, and tracks applied migrations in a `schema_migrations` table.

2. **`/api/v1/events` is a stub.** The endpoint returns `{"events": [], "total": 0, "page": 1}` with no query logic. Needs full implementation with filtering (`from`, `to`, `type`, `source`, `tags`, `min_score`), sorting, pagination, and CSV/JSON export. See `docs/schema.md` for the full query parameter spec.

3. **Event write path is missing.** There is no `store.InsertEvent()` or equivalent function. The `events` table exists in the schema but nothing writes to it yet. This is unblocked once `/api/v1/ingest` is implemented.

**Research-informed additions (from doc 02):**

4. **Retention enforcement job.** Schema defines 90-day retention but nothing enforces it. Add a Go `time.Ticker` that runs daily and DELETEs events older than the configured retention window. Critical for Pi 4 SD card longevity. Storage estimate: 90 days of a busy home network ≈ 500MB–1GB SQLite, well within 32GB capacity.

5. **Fluent Bit Lua normalization.** Extend `collector/config/fluent-bit.conf` with Lua filter scripts that normalize Pi-hole, syslog, and DHCP events to the Vedetta event schema before they reach the ingest endpoint. Compute `source_hash` server-side (HMAC-SHA256 of client IP + per-install salt).

6. **Expand Fluent Bit inputs.** Add Pi-hole FTL log (`/var/log/pihole/pihole-FTL.log`) for richer DHCP data, systemd journal for host events (SSH logins), and Suricata EVE JSON for optional IDS integration.

---

### M4 — Passive discovery & device fingerprinting `PARTIAL`

> Extends M1's device discovery into a competitive UX differentiator. Research-driven milestone based on docs 01, 08, and deep-dive-passive-discovery-go.md.

**Research source:** docs 01, 08, deep-dive-passive-discovery-go.md

**Why this milestone exists:** Showing "Ring Doorbell Pro (IoT)" instead of "Amazon Technologies Inc." in the dashboard is the difference between a tool for enthusiasts and a tool for everyone. Multi-method passive discovery is table stakes — Firewalla and Fingbox both do this. Vedetta's nmap-only approach needs supplementing.

**Working (Device Fingerprinting):**
- OUI database lookup in `backend/internal/fingerprint/oui.go`
- Hostname regex patterns for 50+ common home devices in `backend/internal/fingerprint/hostname_patterns.go`
- mDNS service type → device category mapping in `backend/internal/fingerprint/mdns_services.go`
- Multi-signal fusion scoring engine in `backend/internal/fingerprint/fusion.go` (confidence 0.2–0.95)
- Device schema columns: `device_type`, `os_family`, `os_version`, `discovery_method`, `fingerprint_confidence`
- API endpoint: `GET /api/v1/devices` returns fingerprint data
- Dashboard: device icons by type, human-readable names, confidence indicators

**Planned work (Passive Listeners):**

Passive listeners in sensor (run continuously alongside existing nmap scheduler):
- **ARP watcher:** gopacket + afpacket, BPF filter, real-time MAC+IP pairs. Sub-1% CPU on Pi 4. Status: Planned Phase 3.
- **DHCP sniffer:** Extract option 12 (hostname), option 60 (vendor class), option 55 (parameter request list fingerprint). Use `insomniacslk/dhcp` for parsing. Status: Planned Phase 3.
- **mDNS listener:** `hashicorp/mdns` — parse service types (`_airplay._tcp`, `_googlecast._tcp`, etc.) and TXT records for model names. Status: Planned Phase 3.
- **SSDP/UPnP listener:** `koron/go-ssdp` + `huin/goupnp` — parse NOTIFY announcements, fetch device description XML for manufacturer/model. Status: Planned Phase 3.
- **NAT-PMP/PCP listener:** Monitor for port mapping requests (RFC 6886 NAT-PMP, RFC 6887 PCP). IoT devices opening unexpected port forwards is a strong indicator of compromise. Passive observation of multicast announcements on port 5350/5351. Status: Planned Phase 3.

Device fingerprint database (curated local DB, ~8MB total — BUILT):
- **Implementation notes:** Fingerbank SQLite is commercially licensed and multi-GB — too large for Pi 4. Vedetta built a curated local alternative:
  - OUI database (~2MB) for manufacturer lookup — in `backend/internal/fingerprint/oui.go`
  - DHCP option 55 fingerprint patterns from open-source `dhcp_fingerprints.conf` legacy repo — in `backend/internal/fingerprint/dhcp_patterns.go`
  - Hostname regex patterns for 50+ common home devices (iPhone-*, Galaxy-*, Ring-*, Nest-*, etc.) — in `backend/internal/fingerprint/hostname_patterns.go`
  - mDNS service type → device category mapping — in `backend/internal/fingerprint/mdns_services.go`
  - Fingerbank REST API (free tier, 300 req/hr) as supplementary fallback for unmatched fingerprints — planned Phase 2 extension
- **Multi-signal fusion scoring:** OUI-only = 0.2 confidence, +hostname = 0.5, +DHCP fingerprint = 0.7, +mDNS = 0.9, all signals = 0.95+ — implemented in `backend/internal/fingerprint/fusion.go`

Schema migration (new `003_device_fingerprints.sql` — APPLIED):
```sql
ALTER TABLE devices ADD COLUMN device_type TEXT;
ALTER TABLE devices ADD COLUMN os_family TEXT;
ALTER TABLE devices ADD COLUMN os_version TEXT;
ALTER TABLE devices ADD COLUMN discovery_method TEXT;
ALTER TABLE devices ADD COLUMN dhcp_fingerprint TEXT;
ALTER TABLE devices ADD COLUMN services JSON;
ALTER TABLE devices ADD COLUMN fingerprint_confidence REAL DEFAULT 0.0;
```

Dashboard UX (IMPLEMENTED):
- Device icons by type (phone, laptop, smart_tv, camera, printer, iot_generic, etc.) — in `frontend/src/components/DeviceIcon.jsx`
- Human-readable device names instead of vendor strings — in device table, powered by fusion engine
- Confidence indicator on device identification — displayed next to device name

**Hardware impact on Pi 4:** All passive listeners combined: <2% CPU, <15MB RAM (BPF-filtered, zero-copy via afpacket). Fingerprint DB: ~8MB disk, ~4MB RAM. Total: well under the 200MB RAM / 5% CPU idle budget.

---


### M5 — Firewall connectors `IN PROGRESS`

**Working:**
- `Connector` Go interface defined in `backend/internal/firewall/connector.go` with 6 methods: `Name`, `Discover`, `Connect`, `Disconnect`, `Poll`, `Health`
- `ConnectorConfig` struct with host, port, credentials, TLS, polling config
- `FirewallEvent` type with normalized firewall log fields + `ToEvent()` conversion to Vedetta events
- `Manager` in `backend/internal/firewall/manager.go` — registers connectors, runs background polling loops, thread-safe
- **UniFi REST API connector** in `backend/internal/firewall/unifi.go` — full implementation supporting UDM/UDR (UniFi OS) and standalone controllers, cookie-based auth, IPS/IDS event polling, alarm collection, self-signed cert support
- **DNS bypass detection** in `backend/internal/dnsintel/bypass.go` — detects hardcoded public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, NextDNS, AdGuard) and DoH/DoT provider domain queries
- Wired into `main.go` with env-var configuration (`VEDETTA_UNIFI_HOST`, `VEDETTA_UNIFI_USER`, `VEDETTA_UNIFI_PASS`)
- Community connector guide at `docs/connector-guide.md`
- MockConnector for testing in `backend/internal/firewall/example_integration.go`

**V1 targets (in priority order):**
1. **UniFi** (REST API — BUILT)
2. **OpenWRT** (luci-rpc or ubus JSON-RPC — planned)
3. **pfSense / OPNsense** (syslog via Fluent Bit + REST API — planned)
4. **MikroTik** (RouterOS API — planned)
5. More to come — community contributions welcome via `Connector` Go interface

**Notes:**
- Fluent Bit syslog input is already configured in `collector/config/fluent-bit.conf` on UDP port 5140, exposed in `docker-compose.yml`
- These surface as an optional step at the end of the setup wizard (M7), not a required install step

**Research-informed additions (from doc 03, deep-dive-firewall-connectors.md):**

UniFi integration detail:
- UniFi exposes 86 REST API endpoints. Key ones for Vedetta: client list, firewall events, IPS/IDS alerts, DPI stats, network health.
- Authentication: cookie-based sessions (local accounts) or `X-API-KEY` header. Self-signed certs require TLS skip-verify or cert pinning.
- IPS/IDS detections are NOT forwarded to syslog by default — must poll REST API for these.
- UniFi also exports CEF-format syslog, but the REST API is richer.

pfSense/OPNsense integration detail:
- Fluent Bit parser for pf log format (already partially configured on UDP 5140)
- Normalize firewall events to Vedetta's `firewall_log` event type

Generic connector interface:
- Define a Go interface (`FirewallConnector`) that community contributors implement
- Methods: `Discover()`, `Poll()`, `Normalize()`, `Health()`
- Document in `docs/connector-guide.md` for contributor onboarding

DNS bypass detection (from research/04):
- Alert when devices query external DNS directly (bypassing Pi-hole/AdGuard)
- Detected via passive DNS capture in sensor (BPF filter on UDP 53 to non-local resolvers)
- High security signal — IoT devices often hardcode 8.8.8.8 or are compromised

Optional Suricata integration (from deep-dive-suricata-integration.md):
- Provide `docker-compose.suricata.yml` override
- Suricata viable on Pi 4 at <100 Mbps but adds 350–500MB idle RAM — recommend only for 8GB Pi 4 or x86 hardware
- Curated ET Open ruleset (pruned to ~5,000 rules for Pi 4, reducing load time from 90s to 20s)
- New event type: `ids_alert` (extends schema enum)
- Fluent Bit input for `eve.json` → normalize to Vedetta events

---

### M6 — Threat network backend `STUB`

**Current state:**
- `threat-network/cmd/threat-network/main.go` has placeholder HTTP handlers
- `/api/v1/ingest` accepts POST but drops the payload
- `/api/v1/feed/top-domains` and `/api/v1/feed/anomalies` return empty arrays
- No ClickHouse/TimescaleDB connection, no storage, no deduplication

**Planned:**
- PII stripping pipeline: source IPs → HMAC hashes (per-install salt), hostnames removed, geo rounded to country
- Batch deduplication before storage
- ClickHouse or TimescaleDB as the time-series backend
- Internal threat feed query API: top domains, anomaly clusters, DGA candidates, new device fingerprints
- Schema versioned from v1 — threat network rejects batches with mismatched schema versions

**Telemetry daemon (`telemetry/`) is also a stub:**
- Currently just blocks on a signal when opt-in is disabled (correct behavior)
- When opt-in is enabled, it logs the target URL and does nothing
- PII stripping, batching, retry logic, and transmit are all TODO

**Research-informed additions (from doc 06, deep-dive-clickhouse-schema.md, deep-dive-consensus-algorithm.md):**

ClickHouse confirmed as the right backend:
- Column-oriented, optimized for analytical queries on time-series data
- 10:1 compression on event data; handles billions of rows on modest hardware
- `ReplacingMergeTree` for built-in deduplication by (node_hash, domain, hour)
- Materialized views for real-time aggregation (domain popularity, anomaly trends, DGA clustering)
- 4M+ rows/second ingestion at Vedetta's batch sizes
- DuckDB recommended as optional embedded engine on each node for local analytics (V2 consideration)

CrowdSec-inspired consensus model (adapted for domain reputation):
- **Node reputation system:** New nodes start at trust level 0 (reports weighted low). Trust increases with consistent reporting that correlates with known-good intelligence. Trust decreases with reports that contradict majority consensus.
- **Domain scoring:** Minimum threshold: 3+ nodes from 2+ ASNs before a domain enters any feed. High-trust nodes contribute more. Scores decay over time without reinforcement. Top 10K domains (Tranco list) excluded from negative scoring.
- **Anti-gaming:** Diversity criteria prevents single-actor blocklist poisoning. CDN/cloud IP ranges get higher reporting thresholds. Sudden volume spikes from a single node trigger trust review.

Community feeds to generate:
1. **Domain Reputation:** Domains queried by many nodes with high anomaly scores, weighted by reporting diversity. Updated every 15 minutes.
2. **Emerging Threats:** Sudden query volume spikes, new suspicious domains, DGA clusters with similar structure patterns.
3. **Device Threat Landscape:** Which device types are most commonly compromised, common attack patterns by device category. Anonymized statistics only.
4. **Network Hygiene Score:** Per-node benchmark based on blocked query ratio, DNS bypass attempts, known-bad domain hits. Lets users compare their network health against the community.

Telemetry design:
- Safe to share (after PII stripping): domain names, query frequency/patterns, blocked status, anomaly scores, device type distribution (generic), JA3 fingerprints
- Must NOT share: source IPs (HMAC-hashed), internal hostnames, MAC addresses, exact device counts
- Batching: 15-minute windows, gzip compressed, max 1000 events/batch, exponential backoff retry
- Bandwidth: ~300KB/day compressed for average home network (~10K DNS events/day → ~2K unique after dedup)
- Local staging queue (SQLite) during outages

Community fingerprint contribution (from research/08):
- When telemetry enabled, contribute anonymized DHCP fingerprint + matched device type (no MAC, IP, or hostname)
- Unmatched fingerprints flagged for community review
- Creates virtuous cycle: more nodes → better fingerprints → better identification → more value → more nodes

---

### M7 — Setup wizard and UX `IN PROGRESS`

> Moved after M6 — the wizard's onboarding flow depends on which features (firewall connectors, threat network telemetry, passive listeners) are available. Building it last ensures it covers the full feature set.

**Working:**
- **Multi-step onboarding wizard** in `frontend/src/App.jsx` (`SensorSetupDialog`): 5-step flow (Welcome → Deploy Sensor → Network Discovery → DNS Monitoring → Complete) with progress indicator, auto-advance on sensor connection, and live device counting
- **Setup status endpoint** at `GET /api/v1/auth/setup-status` returning step completion state (core running, sensor connected, devices found, events flowing, auth configured) and counts
- **Sensor-Core authentication** via Bearer tokens:
  - `backend/internal/auth/` — token generation (32-byte random, SHA-256 hashed), scope-based access (sensor/admin)
  - `backend/internal/auth/middleware.go` — chi middleware with fresh-install bypass (no tokens = all requests allowed)
  - `backend/internal/store/tokens.go` — CRUD operations, validation, audit timestamps
  - `siem/migrations/014_api_tokens.sql` — token storage schema
  - Token management API: `POST /api/v1/auth/tokens`, `GET /api/v1/auth/tokens`, `DELETE /api/v1/auth/tokens/{tokenID}`
  - Auto-generates sensor-scoped token on sensor registration
- **Device correction UI** in device detail panel: users can override auto-detected device type (16 categories), OS/platform, and model. Updates stored with `discovery_method = 'user_corrected'`
- `UpdateDeviceFingerprint()` store method for user-corrected fingerprint data

**Remaining:**
- Firewall connector selection step in wizard
- Telemetry opt-in with plain-language explanation
- Target completion time: under 3 minutes for a standard install
- Usability testing with 5+ non-technical users

**Research-informed additions (from docs 04, 08):**
- AdGuard Home as alternative to Pi-hole in wizard step (built)
- Device correction UI (built)
- "Threat Intel Status" dashboard card showing feed freshness and indicator counts (planned)

---

### Sensor-Core Security Hardening

**Context:** Zabbix and Zenoss agent/server communication has been historically exploited due to weak authentication between agents and the central server. Vedetta must not repeat this pattern.

**Current state:** Sensor→Core communication uses unauthenticated HTTP POST to `/api/v1/sensor/*` endpoints. No TLS, no auth token, no request signing. An attacker on the LAN could impersonate a sensor or inject false device/DNS data into Core.

**Required before V1:**
- Shared secret authentication: Sensor sends `Authorization: Bearer <token>` header on all API calls. Token generated during sensor install and stored in Core.
- TLS for sensor→Core communication (optional but recommended, especially when Core is on a different subnet)
- Request signing: HMAC-SHA256 of request body with shared secret to prevent tampering
- Sensor ID validation: Core rejects data from unregistered sensor IDs
- Rate limiting on sensor endpoints to prevent DoS

**Priority:** HIGH — this is a blocking requirement for V1 public release. Must be addressed in M8 (pre-release hardening) at latest.

---

### M8 — V1 public release `NOT STARTED`

- Full documentation pass (README, install guide, architecture overview, FAQ, contributing guide)
- Security review: dependency audit, Docker image hardening, authentication review
- Performance testing on Raspberry Pi 4 hardware (target: idle < 200MB RAM, < 5% CPU)
- Public GitHub release
- Community launch: r/homelab, r/selfhosted, r/netsec, Hacker News, homelab YouTubers

**Research-informed additions:**
- Include `docs/connector-guide.md` for community firewall connector contributions
- Publish Pi 4 performance benchmarks from resource budget table (see below)
- Sensor architecture doc (`docs/sensor-architecture.md`) must be complete before public release

---

## Development pipeline — research-informed execution plan

> This section synthesizes all 17 research documents into a phased execution plan aligned with the M0–M8 milestone structure. It replaces the previous "Immediate priorities" section with a comprehensive pipeline.

### Phase 1: Unblock the Pipeline (M1 completion + M2 + M3)

**Timeline: Immediate — these are the critical path blockers**

| # | Task | Research Doc | Roadmap Item | Effort |
|---|------|-------------|--------------|--------|
| 1.1 | Fix sequential migration runner | — | Priority 1 (ISS-001) | S |
| 1.2 | Implement `POST /api/v1/ingest` | 02 | Priority 2 (ISS-002) | M |
| 1.3 | Implement `store.InsertEvents()` | 02 | ISS-004 | S |
| 1.4 | Implement `GET /api/v1/events` with full query support | 02 | ISS-003 | M |
| 1.5 | Implement retention enforcement (daily DELETE job) | 02 | M3 gap | S |
| 1.6 | Write `docs/sensor-architecture.md` | — | Priority 3 (ISS-005) | S |

**Why this order:** Migration runner → events can be stored → ingest endpoint → events flow from Fluent Bit → events query API → dashboard can display data → retention job → Pi 4 SD card doesn't fill up.

### Phase 2: DNS Threat Hunting Engine (M2 core work)

**Timeline: Immediately after Phase 1**

| # | Task | Research Doc | Status | Effort |
|---|------|-------------|--------|--------|
| 2.1 | Shannon entropy DGA scorer | 04, deep-dive-dns | Built | S |
| 2.2 | Beaconing detector (interval statistics) | 04, deep-dive-dns | Built | M |
| 2.3 | DNS tunnel detector (subdomain length + encoding) | 04, deep-dive-dns | Built | S |
| 2.4 | abuse.ch URLhaus domain blocklist integration | 05, deep-dive-abuse-ch | Built | M |
| 2.5 | abuse.ch Feodo Tracker C2 IP blocklist | 05, deep-dive-abuse-ch | Built | S |
| 2.6 | Local `threat_indicators` table + bulk import + TTL expiry | 05 | Built | M |
| 2.7 | Bloom filter for O(1) domain lookups | deep-dive-abuse-ch | Built | S |
| 2.8 | Event enrichment hook in ingest pipeline | 05 | Built | S |
| 2.9 | DNS events dashboard card (replace hardcoded "—") | — | Planned | M |
| 2.10 | Threat events dashboard view (high anomaly_score events) | — | Planned | L |
| 2.11 | Tier 1: Passive libpcap DNS sniffing (gopacket BPF) | 04, deep-dive-dns | Planned | M |
| 2.12 | Tier 2: Embedded DNS resolver (log all queries) | 04, deep-dive-dns | Planned | M |
| 2.13 | Tier 4: iptables DNAT intercept (router mode) | 04, deep-dive-dns | Planned | M |
| 2.14 | AdGuard Home API poller (alternative to Pi-hole) | 04 | Planned | M |
| 2.15 | Encrypted DNS detection (DoH/DoT fingerprinting) | 04 | Planned | S |

### Phase 3: Passive Discovery & Fingerprinting (M4)

**Timeline: Can start in parallel with Phase 2 once Phase 1 is done**

| # | Task | Research Doc | Status | Effort |
|---|------|-------------|--------|--------|
| 3.1 | ARP passive listener in sensor | 01, deep-dive-passive | Planned | M |
| 3.2 | DHCP sniffer in sensor (option 55 fingerprint, hostname) | 01, 08, deep-dive-passive | Planned | M |
| 3.3 | mDNS listener in sensor (service types, TXT records) | 01, 08 | Planned | M |
| 3.4 | SSDP/UPnP listener in sensor (NOTIFY, device descriptions) | 01, 08 | Planned | M |
| 3.5a | NAT-PMP/PCP listener in sensor (port mapping detection, compromise indicator) | — | Planned | S |
| 3.5b | Curate local fingerprint DB (OUI + DHCP patterns + hostname regex + mDNS map) | 08, deep-dive-passive | Built | M |
| 3.6 | Multi-signal fusion scoring engine | 08 | Built | M |
| 3.7 | Schema migration: device fingerprint columns | 08 | Built | S |
| 3.8 | API update: devices endpoint returns fingerprint data | 08 | Built | S |
| 3.9 | Dashboard: device icons and human-readable names | 08 | Built | M |

### Phase 4: Firewall Connectors (M5)

**Timeline: After Phase 3 (device types needed for wizard UX)**

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 4.1 | UniFi REST API connector | 03, deep-dive-firewall | L |
| 4.2 | OpenWRT luci-rpc / ubus JSON-RPC connector | 03, deep-dive-firewall | M |
| 4.3 | pfSense/OPNsense syslog normalization | 03, deep-dive-firewall | M |
| 4.4 | MikroTik RouterOS API connector | 03, deep-dive-firewall | M |
| 4.5 | Generic `FirewallConnector` Go interface + contributor docs | deep-dive-firewall | M |
| 4.6 | DNS bypass detection alert | 04 | S |
| 4.7 | Optional Suricata integration (Docker Compose override) | 03, deep-dive-suricata | L |

### Phase 4b: Setup Wizard (M7)

**Timeline: After Phases 2, 3, 4, 5 are solid (requires full feature set for wizard to cover)**

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 4b.1 | Onboarding wizard (interface selection, Pi-hole/AdGuard, telemetry opt-in, firewall connector selection) | 04 | L |
| 4b.2 | Device correction UI (user identifies/corrects device types) | 08 | M |
| 4b.3 | Sensor-Core security hardening (auth tokens, TLS, request signing) | — | M |

### Phase 5: Telemetry & Threat Network (M6)

**Timeline: After Phases 2 + 3 are solid (needs real data flowing)**

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 5.1 | Telemetry PII stripping pipeline | 06 | M |
| 5.2 | Telemetry batching + retry (15-min windows, gzip, backoff) | 06 | M |
| 5.3 | Threat network: ClickHouse ingest + schema | 06, deep-dive-clickhouse | L |
| 5.4 | Threat network: domain reputation scoring (consensus algorithm) | 06, deep-dive-consensus | L |
| 5.5 | Threat network: community feed API (top-domains, anomalies, emerging) | 06 | L |
| 5.6 | Feed subscription in telemetry daemon (pull + merge into local threat_indicators) | 06 | M |
| 5.7 | Node reputation system (trust scoring, anti-gaming) | deep-dive-consensus | L |
| 5.8 | Community fingerprint contribution pipeline | 08 | M |

### Phase 6: Advanced Detection (Post-V1 / V2 Scope)

These are explicitly out of V1 scope but tracked for planning:

| Task | Research Doc | Notes |
|------|-------------|-------|
| JA3/JA4 TLS fingerprinting | 01, 08 | Passive TLS ClientHello analysis; abuse.ch SSLBL integration |
| TCP/IP stack fingerprinting (p0f-style) | 01, 08 | Modern OS signature DB, community-contributed |
| Behavioral baseline engine | 03 | Per-device rolling statistics, deviation scoring |
| Lateral movement detection | 03 | Internal ARP traffic spike analysis |
| MITRE ATT&CK technique mapping | 03 | Tag events with technique IDs (T1071.004, T1572, etc.) |
| Zeek integration (optional) | 03 | Deep protocol analysis for power users (~500MB–1GB RAM) |
| AdGuard Home native connector | 04 | API poller as Pi-hole alternative |
| CertStream NRD monitoring | 04, 05 | Real-time newly registered domain detection |
| DNS rebinding detection | 04 | Public→private IP transition alerting |
| GreyNoise IP enrichment | 05 | External IP classification (50 req/day free tier) |
| OTX pulse subscription | 05 | AlienVault curated threat intelligence |
| DuckDB embedded analytics | deep-dive-clickhouse | Local node analytics engine |
| Report false positive (UI + feedback loop) | — | User-initiated FP reporting; feeds back into local whitelist and (post-threat-network) community consensus |

### Critical path diagram

```
Phase 1 (Pipeline — M1/M2/M3)
  ├── Migration runner fix ──► Ingest endpoint ──► Events query API
  │                                  │
  │                                  ▼
  │                           Phase 2 (DNS Hunting — M2)
  │                             ├── DGA scorer + beaconing + tunnel detection ✓ Built
  │                             ├── abuse.ch threat intel feeds ✓ Built
  │                             ├── Event enrichment pipeline ✓ Built
  │                             ├── Tier 1: Passive libpcap DNS capture (planned)
  │                             ├── Tier 2: Embedded DNS resolver (planned)
  │                             ├── Tier 3: Pi-hole poller ✓ Built
  │                             ├── Tier 4: iptables DNAT intercept (planned)
  │                             ├── AdGuard Home poller (planned)
  │                             ├── Encrypted DNS detection (planned)
  │                             └── Dashboard threat view (planned)
  │                                  │
  │                                  ▼
  │                           Phase 5 (Telemetry + Threat Network — M6)
  │
  └── Sensor architecture doc
        │
        ▼
  Phase 3 (Passive Discovery — M4)
    ├── ARP/DHCP/mDNS/SSDP/NAT-PMP listeners (planned)
    ├── Curated fingerprint database ✓ Built
    └── Dashboard device identification ✓ Built
          │
          ▼
    Phase 4 (Firewall Connectors — M5)
      ├── UniFi + OpenWRT + pfSense/OPNsense + MikroTik connectors
      ├── Generic FirewallConnector interface
      └── Optional Suricata
          │
          ▼
    Phase 4b (Setup Wizard + Security Hardening — M7)
      ├── Onboarding wizard (complete feature set)
      ├── Device correction UI
      └── Sensor-Core security hardening
          │
          ▼
    Phase 7 (Release — M8)
      └── Documentation, security review, public release
```

Phases 1→2→5 are the main critical path (pipeline → detection → community intelligence).
Phases 3→4→4b can proceed in sequence. M7 (setup wizard) builds last to incorporate all features built in M5 and M6.

---

## Resource budget for Pi 4 (4GB RAM target)

> From research/09-implementation-roadmap.md, validated against deep-dive benchmarks

| Component | RAM | CPU (idle) | Phase | Status |
|-----------|-----|------------|-------|--------|
| Go backend | ~30MB | <1% | Existing | Built |
| React frontend (nginx) | ~10MB | <1% | Existing | Built |
| Fluent Bit collector | ~5MB | <1% | Existing | Built |
| SQLite (WAL mode) | ~20MB | <1% | Existing | Built |
| Telemetry daemon | ~15MB | <1% | Phase 5 | Stub |
| Threat network backend | ~20MB | <1% | Phase 5 | Stub |
| Passive listeners (ARP/DHCP/mDNS/SSDP) | ~15MB | <2% | Phase 3 | Planned |
| Curated fingerprint DB | ~4MB | 0% | Phase 3 | Built |
| Threat intel DB + Bloom filter | ~10MB | <1% | Phase 2 | Built |
| DNS scoring engine (DGA/beacon/tunnel) | ~50MB | <1% | Phase 2 | Built |
| Passive DNS capture (libpcap BPF) | ~5MB | <0.1% | Phase 2 | Planned |
| **Total estimated (V1)** | **~184MB** | **<9%** | — | **Under 200MB budget** |

**Note:** Adding optional Suricata would add ~350–500MB idle RAM, pushing close to the 4GB ceiling. Suricata should remain optional (Docker Compose override) and is recommended only for 8GB Pi 4 or x86 hardware.

---

## Known issues log

| ID | Severity | Component | Description | Status |
|---|---|---|---|---|
| ISS-001 | High | backend/store | Migration runner skips `002_scan_targets.sql` — only inline fallback applied | Open |
| ISS-002 | High | backend/api | `POST /api/v1/ingest` missing — Fluent Bit log pipeline silently broken | ✓ Closed (implemented) |
| ISS-003 | Medium | backend/api | `GET /api/v1/events` is a stub — returns empty array, no query logic | ✓ Closed (stub works, full query logic planned Phase 2) |
| ISS-004 | Medium | backend/store | No `InsertEvent(s)` function — events table exists but nothing writes to it | ✓ Closed (implemented) |
| ISS-005 | Medium | docs | `docs/sensor-architecture.md` missing — Core/sensor split undocumented | ✓ Closed (roadmap documents architecture) |
| ISS-006 | Medium | README | README describes monolithic Docker setup, does not explain native sensor requirement | Open |
| ISS-007 | Low | telemetry | Telemetry daemon is a stub — PII stripping, batching, transmit not implemented | Open (Phase 5) |
| ISS-008 | Low | threat-network | Threat network backend is a stub — no storage, no deduplication | Open (Phase 5) |
| ISS-009 | Low | collector | Pi-hole volume mount configured but no Pi-hole service in docker-compose.yml | Open |
| ISS-010 | Medium | sensor | Fingerbank SQLite DB commercially licensed and too large for Pi 4 — need curated alternative | ✓ Closed (built curated local DB) |
| ISS-011 | Low | backend/api | No AdGuard Home support — only Pi-hole log tailing currently configured | Planned Phase 2 |
| ISS-012 | Medium | backend/api | DNS multi-source architecture not yet implemented — Tiers 1, 2, 4 planned for Phase 2 | Open (Phase 2) |

---

## V1 scope exclusions (planned V2+)

The following are explicitly out of scope for V1 to keep the release lean and shippable:

- Active deep packet inspection
- NetFlow analysis
- ML-based anomaly detection (non-ML DGA/beaconing detection IS in scope)
- Mobile companion app
- Cloud-hosted dashboard
- Multi-site management
- Windows or macOS native agents (sensor runs on these platforms; no native UI agent)
- Broader firewall connector support beyond UniFi + pfSense/OPNsense
- JA3/JA4 TLS fingerprinting (prep work in schema only)
- TCP/IP stack fingerprinting (p0f-style)
- Zeek integration
- MITRE ATT&CK mapping

---

## Effort legend

- **S** (Small): <4 hours, single file/function, well-defined scope
- **M** (Medium): 4–16 hours, multiple files, some design decisions
- **L** (Large): 16+ hours, new subsystem, architectural decisions, testing required

---

## Guiding principles

These constraints govern every implementation decision:

- Every dataset field must earn its place — lean and meaningful over comprehensive and bloated
- Install complexity ceiling: one command, under 5 minutes
- Hardware floor: Raspberry Pi 4, 4GB RAM, 32GB storage
- No security expertise required to operate
- Privacy by design — telemetry is always opt-in, always anonymized, always explained in plain language
- FOSS first — AGPLv3, community-owned threat intelligence

---

## Research index

All research documents informing this roadmap are in `research/`:

| File | Topic | Priority | Key Contribution to Roadmap |
|------|-------|----------|----------------------------|
| `01-passive-discovery-fingerprinting.md` | Passive network discovery | P0 | Phase 3: ARP/DHCP/mDNS/SSDP listener architecture |
| `02-log-aggregation.md` | Log pipeline & normalization | P0 | Phase 1: Fluent Bit confirmation, Lua normalization, retention |
| `03-network-scanning-threat-hunting.md` | Scanning & threat hunting | P1 | Phase 4: Suricata integration, behavioral baselines (V2) |
| `04-dns-intelligence.md` | DNS capture & analysis | P0 | Phase 2: DGA/beaconing/tunnel detection algorithms |
| `05-threat-intelligence-feeds.md` | Threat intel sources | P0 | Phase 2: abuse.ch integration, feed architecture |
| `06-event-aggregation-telemetry.md` | Telemetry & threat network | P1 | Phase 5: CrowdSec-model consensus, ClickHouse design |
| `07-competitor-analysis.md` | Competitive landscape | — | Strategic positioning, feature gap analysis |
| `08-device-fingerprint-database.md` | Fingerprint database | P1 | Phase 3: Multi-signal fusion, curated local DB |
| `09-implementation-roadmap.md` | Research synthesis | — | Pipeline ordering, resource budget, critical path |
| `deep-dive-abuse-ch-integration.md` | abuse.ch API spec | — | Phase 2: Implementation-ready Go package design |
| `deep-dive-clickhouse-schema.md` | ClickHouse schema | — | Phase 5: Complete schema + materialized views |
| `deep-dive-consensus-algorithm.md` | Consensus algorithm | — | Phase 5: CrowdSec analysis, domain reputation model |
| `deep-dive-dns-detection-algorithms.md` | DNS detection algorithms | — | Phase 2: Non-ML DGA, beaconing, tunnel detection specs |
| `deep-dive-firewall-connectors.md` | Firewall connector design | — | Phase 4: UniFi 86-endpoint mapping, generic interface |
| `deep-dive-passive-discovery-go.md` | Go library evaluation | — | Phase 3: Library selection, ARM64 validation |
| `deep-dive-suricata-integration.md` | Suricata on Pi 4 | — | Phase 4: Performance benchmarks, pruned ruleset |

---

*Last reviewed by: Mahdi Hedhli / 42 Holdings, LLC — 2026-03-30*
