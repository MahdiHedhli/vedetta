# Vedetta — Project Roadmap

> Version: 2.0.0
> Last updated: 2026-03-30
> Status: Active development — V1 in progress
> Research integration: 17 research documents (8 capability areas + 7 deep dives) reviewed and incorporated

---

## Overview

Vedetta is a free and open source security monitoring platform for home users and small businesses. It provides passive DNS-based threat hunting, scheduled network asset discovery via native sensors, SIEM-grade log aggregation, and opt-in anonymized telemetry that feeds a community threat intelligence network.

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

**Known gaps:**
- Migration runner only applies the inline fallback schema, not `siem/migrations/002_scan_targets.sql`. Need a proper sequential migration runner with a `schema_migrations` tracking table.

**Research-informed additions (from docs 01, 08, deep-dive-passive-discovery-go.md):**
- Add passive ARP listener to sensor for real-time device detection between nmap intervals
- Add fast ARP heartbeat every 60s (lightweight, sub-1% CPU on Pi 4) alongside existing nmap scans
- Add `discovery_method` field to Device model: `nmap_active`, `arp_passive`, `dhcp_passive`, `mdns_passive`, `ssdp_passive`

---

### M2 — DNS threat hunting `BLOCKED`

**Planned:**
- Pi-hole REST API integration (poll query logs every 60s)
- DNS event ingestion into SIEM storage layer
- Anomaly detection rules: beaconing, DGA candidates, newly registered domains, known-bad blocklists (abuse.ch, URLhaus)
- Threat events dashboard view

**Blocker:**
- `POST /api/v1/ingest` endpoint does not exist in `backend/internal/api/router.go`
- Fluent Bit (`collector/config/fluent-bit.conf`) is configured to push to this endpoint — all DNS and firewall log events are silently dropped
- This endpoint must be implemented before M2 can proceed

**Implementation notes for `/api/v1/ingest`:**
- Accept JSON body matching the core event schema (see `docs/schema.md` and `backend/internal/models/event.go`)
- Validate `event_type` against allowed enum values
- Write to `events` table in SQLite
- Return `{"accepted": N}` with count of events written
- Must handle batches (array of events) not just single events, since Fluent Bit batches by default

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

Multi-DNS-source support:
- **AdGuard Home** as Pi-hole alternative via `GET /control/querylog` API poller (research/04)
- **Passive DNS capture** in sensor: gopacket BPF filter on UDP 53, detects devices bypassing local resolver (hardcoded 8.8.8.8 etc.) — high-value security signal
- **DNS bypass alerting:** Flag devices making direct queries to external resolvers

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

### M3.5 — Passive discovery & device fingerprinting `NEW — NOT STARTED`

> Inserted between M3 and M4 based on research findings. This extends M1's device discovery into a competitive UX differentiator.

**Research source:** docs 01, 08, deep-dive-passive-discovery-go.md

**Why this milestone exists:** Showing "Ring Doorbell Pro (IoT)" instead of "Amazon Technologies Inc." in the dashboard is the difference between a tool for enthusiasts and a tool for everyone. Multi-method passive discovery is table stakes — Firewalla and Fingbox both do this. Vedetta's nmap-only approach needs supplementing.

**Planned work:**

Passive listeners in sensor (run continuously alongside existing nmap scheduler):
- **ARP watcher:** gopacket + afpacket, BPF filter, real-time MAC+IP pairs. Sub-1% CPU on Pi 4.
- **DHCP sniffer:** Extract option 12 (hostname), option 60 (vendor class), option 55 (parameter request list fingerprint). Use `insomniacslk/dhcp` for parsing.
- **mDNS listener:** `hashicorp/mdns` — parse service types (`_airplay._tcp`, `_googlecast._tcp`, etc.) and TXT records for model names.
- **SSDP/UPnP listener:** `koron/go-ssdp` + `huin/goupnp` — parse NOTIFY announcements, fetch device description XML for manufacturer/model.

Device fingerprint database (curated local DB, ~8MB total):
- **Important:** Fingerbank SQLite is now commercially licensed and multi-GB — too large for Pi 4 embedded use. Build a curated local alternative:
  - OUI database (~2MB) for manufacturer lookup
  - DHCP option 55 fingerprint patterns from open-source `dhcp_fingerprints.conf` legacy repo
  - Hostname regex patterns for 50+ common home devices (iPhone-*, Galaxy-*, Ring-*, Nest-*, etc.)
  - mDNS service type → device category mapping
  - Fingerbank REST API (free tier, 300 req/hr) as supplementary fallback for unmatched fingerprints
- **Multi-signal fusion scoring:** OUI-only = 0.2 confidence, +hostname = 0.5, +DHCP fingerprint = 0.7, +mDNS = 0.9, all signals = 0.95+

Schema migration (new `003_device_fingerprints.sql`):
```sql
ALTER TABLE devices ADD COLUMN device_type TEXT;
ALTER TABLE devices ADD COLUMN os_family TEXT;
ALTER TABLE devices ADD COLUMN os_version TEXT;
ALTER TABLE devices ADD COLUMN discovery_method TEXT;
ALTER TABLE devices ADD COLUMN dhcp_fingerprint TEXT;
ALTER TABLE devices ADD COLUMN services JSON;
ALTER TABLE devices ADD COLUMN fingerprint_confidence REAL DEFAULT 0.0;
```

Dashboard UX:
- Device icons by type (phone, laptop, smart_tv, camera, printer, iot_generic, etc.)
- Human-readable device names instead of vendor strings
- Confidence indicator on device identification

**Hardware impact on Pi 4:** All passive listeners combined: <2% CPU, <15MB RAM (BPF-filtered, zero-copy via afpacket). Fingerprint DB: ~8MB disk, ~4MB RAM. Total: well under the 200MB RAM / 5% CPU idle budget.

---

### M4 — Setup wizard and UX `NOT STARTED`

**Planned:**
- Onboarding wizard: network interface selection, Pi-hole/AdGuard Home connection (auto-detect or manual), telemetry opt-in with plain-language explanation, optional firewall connector setup
- Target completion time: under 3 minutes for a standard install
- Usability testing with 5+ non-technical users

**Notes:**
- The sensor setup dialog (`SensorSetupDialog` in `frontend/src/App.jsx`) is a good foundation — it surfaces when no sensors and no devices are detected
- The subnet confirmation flow is partially scaffolded via `/api/v1/scan/subnets` and `PUT /api/v1/scan/cidr`

**Research-informed additions (from docs 04, 08):**
- Add AdGuard Home as alternative to Pi-hole in wizard (increasingly popular, has DoH/DoT built-in)
- Add device correction UI: let users manually identify/correct device types, stored locally and optionally contributed to community fingerprint DB
- Add "Threat Intel Status" dashboard card showing feed freshness and indicator counts

---

### M5 — Firewall connectors `NOT STARTED`

**Planned V1 targets:**
- UniFi (REST API — most prevalent in prosumer/SMB segment)
- pfSense or OPNsense (syslog via Fluent Bit input plugin)

**Notes:**
- Fluent Bit syslog input is already configured in `collector/config/fluent-bit.conf` on UDP port 5140, exposed in `docker-compose.yml`
- Connector interface should be documented so community contributors can add new ones
- These surface as an optional step at the end of the setup wizard (M4), not a required install step

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

### M7 — V1 public release `NOT STARTED`

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

> This section synthesizes all 17 research documents into a phased execution plan aligned with the M0–M7 milestone structure. It replaces the previous "Immediate priorities" section with a comprehensive pipeline.

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

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 2.1 | Shannon entropy DGA scorer | 04, deep-dive-dns | S |
| 2.2 | Beaconing detector (interval statistics) | 04, deep-dive-dns | M |
| 2.3 | DNS tunnel detector (subdomain length + encoding) | 04, deep-dive-dns | S |
| 2.4 | abuse.ch URLhaus domain blocklist integration | 05, deep-dive-abuse-ch | M |
| 2.5 | abuse.ch Feodo Tracker C2 IP blocklist | 05, deep-dive-abuse-ch | S |
| 2.6 | Local `threat_indicators` table + bulk import + TTL expiry | 05 | M |
| 2.7 | Bloom filter for O(1) domain lookups | deep-dive-abuse-ch | S |
| 2.8 | Event enrichment hook in ingest pipeline | 05 | S |
| 2.9 | DNS events dashboard card (replace hardcoded "—") | — | M |
| 2.10 | Threat events dashboard view (high anomaly_score events) | — | L |

### Phase 3: Passive Discovery & Fingerprinting (M3.5)

**Timeline: Can start in parallel with Phase 2 once Phase 1 is done**

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 3.1 | ARP passive listener in sensor | 01, deep-dive-passive | M |
| 3.2 | DHCP sniffer in sensor (option 55 fingerprint, hostname) | 01, 08, deep-dive-passive | M |
| 3.3 | mDNS listener in sensor (service types, TXT records) | 01, 08 | M |
| 3.4 | SSDP/UPnP listener in sensor (NOTIFY, device descriptions) | 01, 08 | M |
| 3.5 | Curate local fingerprint DB (OUI + DHCP patterns + hostname regex + mDNS map) | 08, deep-dive-passive | M |
| 3.6 | Multi-signal fusion scoring engine | 08 | M |
| 3.7 | Schema migration: device fingerprint columns | 08 | S |
| 3.8 | API update: devices endpoint returns fingerprint data | 08 | S |
| 3.9 | Dashboard: device icons and human-readable names | 08 | M |

### Phase 4: Setup Wizard & Firewall Connectors (M4 + M5)

**Timeline: After Phase 3 (device types needed for wizard UX)**

| # | Task | Research Doc | Effort |
|---|------|-------------|--------|
| 4.1 | Onboarding wizard (interface selection, Pi-hole/AdGuard, telemetry opt-in) | 04 | L |
| 4.2 | UniFi REST API connector | 03, deep-dive-firewall | L |
| 4.3 | pfSense/OPNsense syslog normalization | 03, deep-dive-firewall | M |
| 4.4 | Generic `FirewallConnector` Go interface + contributor docs | deep-dive-firewall | M |
| 4.5 | DNS bypass detection alert | 04 | S |
| 4.6 | Device correction UI (user identifies/corrects device types) | 08 | M |
| 4.7 | Optional Suricata integration (Docker Compose override) | 03, deep-dive-suricata | L |

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

### Critical path diagram

```
Phase 1 (Pipeline — M1/M2/M3)
  ├── Migration runner fix ──► Ingest endpoint ──► Events query API
  │                                  │
  │                                  ▼
  │                           Phase 2 (DNS Hunting — M2)
  │                             ├── DGA scorer + beaconing + tunnel detection
  │                             ├── abuse.ch threat intel feeds
  │                             ├── Event enrichment pipeline
  │                             └── Dashboard threat view
  │                                  │
  │                                  ▼
  │                           Phase 5 (Telemetry + Threat Network — M6)
  │
  └── Sensor architecture doc
        │
        ▼
  Phase 3 (Passive Discovery — M3.5)
    ├── ARP/DHCP/mDNS/SSDP listeners
    ├── Curated fingerprint database
    └── Dashboard device identification
          │
          ▼
    Phase 4 (Wizard + Firewall Connectors — M4/M5)
      ├── Setup wizard
      ├── UniFi + pfSense connectors
      └── Optional Suricata
```

Phases 1→2→5 are the main critical path (pipeline → detection → community intelligence).
Phases 3→4 can proceed in parallel once Phase 1 is done.

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
| Curated fingerprint DB | ~4MB | 0% | Phase 3 | Planned |
| Threat intel DB + Bloom filter | ~10MB | <1% | Phase 2 | Planned |
| DNS scoring engine (DGA/beacon/tunnel) | ~50MB | <1% | Phase 2 | Planned |
| **Total estimated (V1)** | **~179MB** | **<9%** | — | **Under 200MB budget** |

**Note:** Adding optional Suricata would add ~350–500MB idle RAM, pushing close to the 4GB ceiling. Suricata should remain optional (Docker Compose override) and is recommended only for 8GB Pi 4 or x86 hardware.

---

## Known issues log

| ID | Severity | Component | Description |
|---|---|---|---|
| ISS-001 | High | backend/store | Migration runner skips `002_scan_targets.sql` — only inline fallback applied |
| ISS-002 | High | backend/api | `POST /api/v1/ingest` missing — Fluent Bit log pipeline silently broken |
| ISS-003 | Medium | backend/api | `GET /api/v1/events` is a stub — returns empty array, no query logic |
| ISS-004 | Medium | backend/store | No `InsertEvent(s)` function — events table exists but nothing writes to it |
| ISS-005 | Medium | docs | `docs/sensor-architecture.md` missing — Core/sensor split undocumented |
| ISS-006 | Medium | README | README describes monolithic Docker setup, does not explain native sensor requirement |
| ISS-007 | Low | telemetry | Telemetry daemon is a stub — PII stripping, batching, transmit not implemented |
| ISS-008 | Low | threat-network | Threat network backend is a stub — no storage, no deduplication |
| ISS-009 | Low | collector | Pi-hole volume mount configured but no Pi-hole service in docker-compose.yml |
| ISS-010 | Medium | sensor | Fingerbank SQLite DB commercially licensed and too large for Pi 4 — need curated alternative |
| ISS-011 | Low | backend/api | No AdGuard Home support — only Pi-hole log tailing currently configured |

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
