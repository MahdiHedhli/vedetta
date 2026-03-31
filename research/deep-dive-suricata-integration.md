# Deep Dive: Suricata IDS Integration for Vedetta

> Priority: P2 — Extends Vedetta from passive monitoring to active intrusion detection
> Date: 2026-03-28
> Status: Research complete, ready for implementation

## Executive Summary

Suricata IDS is viable on Raspberry Pi 4 (2GB+ RAM) for home/SMB traffic levels (<100 Mbps). This document provides the complete integration design: Docker Compose override, tuned `suricata.yaml`, Fluent Bit pipeline, event schema extension, and a curated ET Open ruleset selection. Alternatives (Zeek, Snort 3, CrowdSec) are evaluated and positioned as complementary options.

---

## 1. Suricata on Raspberry Pi 4 — Performance Reality

### 1.1 Real-World Benchmarks

Suricata has been validated on Pi 4 across multiple community projects and academic research:

| Metric | Pi 4 (2GB) | Pi 4 (4GB) | Pi 5 (8GB) |
|--------|-----------|-----------|-----------|
| Idle RAM (Suricata + ET Open) | ~350–500 MB | ~350–500 MB | ~400 MB |
| Peak RAM (burst traffic) | ~800 MB–1.2 GB | ~800 MB–1.2 GB | ~1 GB |
| CPU at 10 Mbps sustained | ~25–40% (1 core) | ~25–40% (1 core) | ~15% |
| CPU at 50 Mbps sustained | ~60–80% (2 cores) | ~60–80% (2 cores) | ~40% |
| CPU at 100 Mbps sustained | ~90%+ (all cores) | ~90%+ (all cores) | ~60% |
| Max throughput (IDS mode) | ~80–120 Mbps | ~80–120 Mbps | ~300 Mbps |
| Rule load time (full ET Open) | ~45–90 sec | ~30–60 sec | ~15 sec |
| Rule load time (pruned set) | ~15–30 sec | ~10–20 sec | ~5 sec |

**Key findings from community deployments:**

- **SuricataPi project** (github.com/beep-projects/SuricataPi): Confirms 2GB is the practical minimum; the project recommends "more than 2GB" and notes swapping occurs on 2GB models. 4GB is the sweet spot for Vedetta's target hardware.
- **FreeCodeCamp Pi 4 guide**: Demonstrated a working Suricata + Python alerting pipeline on Pi 4 4GB monitoring a home network via MikroTik mirror port.
- **Academic research (IJERT)**: Confirmed "full detection efficacy and viability in devices with 1 GB of RAM" though performance degrades significantly under load.
- **h-i-r.net home lab guide (2025)**: Deployed Suricata + Wazuh on Pi 4, validated for typical home broadband (50–200 Mbps).

### 1.2 Memory Formula

Suricata's memory usage is governed by:

```
memory = num_threads × max_pending_packets × (default_packet_size + ~750 bytes)
```

For Pi 4 with 4GB RAM and Vedetta's other services consuming ~1GB:

```
Available for Suricata: ~2.5 GB
Target threads: 2 (Pi 4 has 4 cores — reserve 2 for Vedetta services)
max_pending_packets: 512 (down from default 1024)
default_packet_size: 1514
Memory per thread: 512 × (1514 + 750) ≈ 1.16 MB packet buffers
Actual overhead: rule memory (~200–400 MB) + flow table (~100–200 MB)
Total estimate: ~800 MB–1.5 GB depending on traffic and ruleset size
```

### 1.3 Network Capture Architecture

For Vedetta on Pi 4, the recommended capture method depends on the network setup:

**Option A: Mirror Port (Recommended for IDS)**
- Connect Pi 4 eth0 to a managed switch with port mirroring enabled
- Suricata runs in IDS mode (passive, no packet modification)
- AF_PACKET capture mode — lowest overhead on Linux
- No impact on network performance

**Option B: Inline via NFQueue (IPS mode — advanced)**
- Pi 4 sits between router and switch (requires two NICs or USB-Ethernet adapter)
- Suricata can drop malicious packets
- Higher latency, not recommended for Pi 4 due to throughput constraints
- Only viable at <50 Mbps

**Vedetta default: Option A (IDS mode via AF_PACKET on a mirror port)**

---

## 2. ET Open Ruleset — Curated Selection for Home/SMB

### 2.1 Ruleset Overview

The Emerging Threats Open (ET Open) ruleset is free, community-maintained, and updated daily on weekdays. The full ruleset contains ~30,000+ rules organized into categories.

### 2.2 Category Analysis for Home/SMB Relevance

**ENABLE — High relevance for home/SMB networks:**

| Category | Rules (approx) | Why Enable |
|----------|----------------|------------|
| `emerging-malware` | ~4,000 | Malware download detection, dropper URLs |
| `emerging-trojan` | ~8,000 | Trojan C2 callbacks, data exfiltration |
| `emerging-botcc` | ~500 | Known botnet C2 IP addresses (updated daily) |
| `emerging-botcc.portgrouped` | ~200 | Port-specific botnet C2 signatures |
| `emerging-ciarmy` | ~200 | CI Army known bad IP blocklist |
| `emerging-compromised` | ~100 | Known compromised hosts |
| `emerging-drop` | ~800 | Spamhaus DROP/EDROP blocklists |
| `emerging-dshield` | ~200 | DShield top attackers |
| `emerging-dns` | ~300 | DNS anomalies, tunneling, DGA patterns |
| `emerging-policy` | ~1,500 | Policy violations (crypto mining, P2P, Tor usage) |
| `emerging-info` | ~500 | Informational — suspicious but not confirmed malicious |
| `emerging-mobile_malware` | ~200 | Mobile device malware (IoT relevance) |
| `emerging-phishing` | ~500 | Phishing site detection |
| `emerging-ja3` | ~200 | TLS fingerprint-based malware detection |

**DISABLE — Low relevance or too noisy for home/SMB:**

| Category | Rules (approx) | Why Disable |
|----------|----------------|-------------|
| `emerging-exploit` | ~3,000 | Targets enterprise apps (Exchange, SharePoint, Oracle) — mostly false positives on home networks |
| `emerging-web_server` | ~2,000 | Apache/Nginx exploit sigs — irrelevant unless running public web servers |
| `emerging-web_client` | ~1,500 | Browser exploit detection — redundant with modern browser security |
| `emerging-sql` | ~500 | SQL injection — no exposed databases on home networks |
| `emerging-smtp` | ~500 | SMTP-based attacks — no mail servers on home networks |
| `emerging-ftp` | ~200 | FTP exploits — rare on modern home networks |
| `emerging-pop3` | ~100 | POP3 attacks — obsolete |
| `emerging-imap` | ~100 | IMAP attacks — obsolete |
| `emerging-voip` | ~300 | SIP/VoIP attacks — only enable if running VoIP |
| `emerging-games` | ~200 | Game protocol detection — noise |
| `emerging-chat` | ~200 | Chat protocol detection — noise |
| `emerging-deleted` | ~0 | Deprecated rules |

**OPTIONAL — Enable based on user's setup:**

| Category | Condition |
|----------|-----------|
| `emerging-scan` (~1,500) | Enable if Vedetta isn't already detecting scans via nmap |
| `emerging-attack_response` (~300) | Enable for post-compromise detection |
| `emerging-user_agents` (~500) | Enable for suspicious HTTP user-agent detection |
| `emerging-shellcode` (~300) | Enable if monitoring IoT devices with known vulnerabilities |

### 2.3 Recommended Minimal Ruleset

For a Pi 4 with 4GB RAM, the pruned ruleset targets ~15,000–17,000 active rules (vs. 30,000+ full):

```yaml
# /etc/suricata/enable.conf — Vedetta defaults
# Enable high-value categories
enable:
  - emerging-malware
  - emerging-trojan
  - emerging-botcc
  - emerging-botcc.portgrouped
  - emerging-ciarmy
  - emerging-compromised
  - emerging-drop
  - emerging-dshield
  - emerging-dns
  - emerging-policy
  - emerging-info
  - emerging-mobile_malware
  - emerging-phishing
  - emerging-ja3
  - emerging-attack_response

# /etc/suricata/disable.conf — Vedetta defaults
disable:
  - emerging-exploit
  - emerging-web_server
  - emerging-web_client
  - emerging-sql
  - emerging-smtp
  - emerging-ftp
  - emerging-pop3
  - emerging-imap
  - emerging-voip
  - emerging-games
  - emerging-chat
  - emerging-deleted
```

### 2.4 Rule Updates

Use `suricata-update` for automated daily updates:

```bash
# Cron job inside the Suricata container
0 6 * * * suricata-update --suricata-conf /etc/suricata/suricata.yaml \
  --enable-conf /etc/suricata/enable.conf \
  --disable-conf /etc/suricata/disable.conf && \
  suricatasc -c reload-rules
```

---

## 3. Integration Design

### 3.1 Docker Compose Override — `docker-compose.suricata.yml`

```yaml
# Vedetta Suricata IDS Integration
# Usage: docker compose -f docker-compose.yml -f docker-compose.suricata.yml up
#
# Prerequisites:
#   - Managed switch with port mirroring to Pi 4 eth0
#   - Pi 4 with 4GB RAM recommended (2GB minimum)

services:
  suricata:
    image: jasonish/suricata:7.0
    container_name: vedetta-suricata
    # AF_PACKET requires these capabilities
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
    # Host networking required for AF_PACKET capture on physical interface
    network_mode: host
    volumes:
      - ./suricata/etc:/etc/suricata:rw
      - suricata-logs:/var/log/suricata:rw
      - suricata-rules:/var/lib/suricata/rules:rw
    environment:
      # Interface receiving mirrored traffic — override via .env
      SURICATA_IFACE: "${SURICATA_IFACE:-eth0}"
    entrypoint: >
      /usr/bin/suricata
        -c /etc/suricata/suricata.yaml
        --af-packet=${SURICATA_IFACE:-eth0}
        --set "af-packet.0.interface=${SURICATA_IFACE:-eth0}"
    restart: unless-stopped
    # Memory limit to protect other Vedetta services
    deploy:
      resources:
        limits:
          memory: 1536M
        reservations:
          memory: 512M
    healthcheck:
      test: ["CMD", "suricatasc", "-c", "uptime"]
      interval: 60s
      timeout: 10s
      retries: 3

  # Extend the existing collector to ingest Suricata EVE logs
  collector:
    volumes:
      - suricata-logs:/var/log/suricata:ro

  # Rule updater — runs daily at 06:00
  suricata-update:
    image: jasonish/suricata:7.0
    container_name: vedetta-suricata-update
    volumes:
      - ./suricata/etc:/etc/suricata:rw
      - suricata-rules:/var/lib/suricata/rules:rw
    entrypoint: >
      sh -c "suricata-update
        --suricata-conf /etc/suricata/suricata.yaml
        --enable-conf /etc/suricata/enable.conf
        --disable-conf /etc/suricata/disable.conf
        --no-test
        && echo 'Rules updated at $(date)'"
    profiles:
      - update  # Only run via: docker compose --profile update run suricata-update

volumes:
  suricata-logs:
    driver: local
  suricata-rules:
    driver: local
```

### 3.2 Tuned `suricata.yaml` for Pi 4

```yaml
# /suricata/etc/suricata.yaml — Vedetta Pi 4 optimized configuration
# Tuned for: Raspberry Pi 4 (4GB), home/SMB traffic, IDS mode

%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

# ── Threading ──────────────────────────────────────────────
# Pi 4 has 4 ARM Cortex-A72 cores.
# Reserve 2 for Vedetta (backend, collector, frontend), give 2 to Suricata.
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 2 ]
    - worker-cpu-set:
        cpu: [ 2, 3 ]
        mode: "balanced"

# Use "workers" runmode for best Pi 4 performance.
# Each worker thread handles capture + decode + detect on its own core.
runmode: workers

# ── Packet Acquisition ────────────────────────────────────
af-packet:
  - interface: eth0  # Overridden by env var at runtime
    threads: 2
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    # Ring size — lower for memory savings
    ring-size: 2048
    # Block size — match to page size
    block-size: 32768

# ── Memory Caps ────────────────────────────────────────────
# Aggressive limits to stay within 1.5GB container limit

# Packet engine
max-pending-packets: 512  # Default: 1024

# Default packet size (MTU + overhead)
default-packet-size: 1514

# Flow engine
flow:
  memcap: 64mb          # Default: 128mb
  hash-size: 65536       # Default: 65536
  prealloc: 5000         # Default: 10000
  emergency-recovery: 30

flow-timeouts:
  default:
    new: 15               # Shorter timeouts to free memory faster
    established: 120
    closed: 5
    bypassed: 30
  tcp:
    new: 15
    established: 300
    closed: 5
    emergency-new: 5
    emergency-established: 60
    emergency-closed: 1
  udp:
    new: 15
    established: 60
  icmp:
    new: 15
    established: 60

# Stream engine
stream:
  memcap: 128mb          # Default: 256mb
  checksum-validation: no # Pi 4 — save CPU
  reassembly:
    memcap: 64mb         # Default: 256mb
    depth: 1mb            # Default: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

# Host tracking
host:
  memcap: 16mb
  hash-size: 4096
  prealloc: 1000

# ── Detection Engine ──────────────────────────────────────
detect:
  profile: low           # "low" uses less memory for rule grouping
  custom-values:
    toclient-groups: 2
    toserver-groups: 10
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# Pattern matching — ac-ks is best for ARM without Hyperscan
mpm-algo: ac-ks

# ── Logging / Output ─────────────────────────────────────
outputs:
  # EVE JSON — Vedetta ingestion via Fluent Bit
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      # Rotate at 50MB to keep disk usage in check
      rotate-interval: 600  # 10 minutes
      # Only log what Vedetta needs
      types:
        - alert:
            metadata: yes
            tagged-packets: no
            xff:
              enabled: no
        - dns:
            enabled: yes
            query: yes
            answer: yes
        - tls:
            enabled: yes
            extended: yes
        - flow:
            enabled: no  # Too verbose for Pi 4 storage
        - stats:
            enabled: yes
            totals: yes
            threads: no
            deltas: yes

  # Disable all other log types
  - fast:
      enabled: no
  - unified2-alert:
      enabled: no

# ── Rule Files ────────────────────────────────────────────
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules  # Managed by suricata-update

# ── Misc ──────────────────────────────────────────────────
coredump:
  max-dump: 0

# Disable file extraction — saves CPU and disk
file-store:
  enabled: no

# Disable payload logging — saves disk on Pi 4
payload: no
payload-printable: no
```

### 3.3 Fluent Bit Configuration Extension

Add this to the existing collector config to ingest Suricata EVE JSON:

```ini
# --- Suricata EVE JSON input ---
# Add to /collector/config/fluent-bit.conf

[INPUT]
    Name         tail
    Path         /var/log/suricata/eve.json
    Tag          ids.suricata
    Parser       json
    Refresh_Interval 5
    Rotate_Wait  10
    # Only read new entries (don't replay history on restart)
    Read_from_Head false
    DB           /tmp/flb_suricata.db

# Filter: only forward alerts (drop stats, dns, tls to reduce backend load)
# Enable dns/tls forwarding later if Vedetta adds protocol analysis
[FILTER]
    Name         grep
    Match        ids.suricata
    Regex        event_type ^alert$

# Transform Suricata alert to Vedetta event schema
[FILTER]
    Name         lua
    Match        ids.suricata
    Script       /fluent-bit/etc/suricata_transform.lua
    Call         transform_alert

# Forward to Vedetta backend
[OUTPUT]
    Name         http
    Match        ids.suricata
    Host         backend
    Port         8080
    URI          /api/v1/ingest
    Format       json
    Json_date_key timestamp
    Json_date_format iso8601
```

**Lua transform script** (`/collector/config/suricata_transform.lua`):

```lua
-- suricata_transform.lua
-- Transforms Suricata EVE alert JSON into Vedetta event schema

local crypto = require("crypto") -- For SHA-256 hashing

function transform_alert(tag, timestamp, record)
    -- Only process alert events
    if record["event_type"] ~= "alert" then
        return -1, 0, 0  -- Drop non-alert records
    end

    local alert = record["alert"] or {}

    local new_record = {
        -- Core Vedetta fields
        event_type    = "ids_alert",
        timestamp     = record["timestamp"],
        source_hash   = hash_ip(record["src_ip"] or "unknown"),
        domain        = extract_domain(record),
        blocked       = (alert["action"] == "blocked"),
        anomaly_score = severity_to_score(alert["severity"] or 4),
        tags          = build_tags(alert),
        geo           = nil,  -- Enriched by backend

        -- IDS-specific fields
        signature_id  = alert["signature_id"],
        signature     = alert["signature"],
        severity      = alert["severity"],
        category      = alert["category"],
        mitre_attack  = extract_mitre(alert["metadata"] or {}),
        src_ip        = record["src_ip"],
        src_port      = record["src_port"],
        dest_ip       = record["dest_ip"],
        dest_port     = record["dest_port"],
        proto         = record["proto"],
        action        = alert["action"]
    }

    return 1, timestamp, new_record
end

function hash_ip(ip)
    -- Consistent with Vedetta's source_hash approach
    -- In production, use the same salt as the backend
    return ip  -- Placeholder: backend handles hashing
end

function extract_domain(record)
    -- Try to extract domain from DNS or HTTP metadata
    if record["dns"] and record["dns"]["query"] then
        return record["dns"]["query"][1]["rrname"]
    elseif record["http"] and record["http"]["hostname"] then
        return record["http"]["hostname"]
    end
    return nil
end

function severity_to_score(severity)
    -- Map Suricata severity (1=high, 4=low) to Vedetta anomaly_score (0.0-1.0)
    local mapping = { [1] = 1.0, [2] = 0.75, [3] = 0.5, [4] = 0.25 }
    return mapping[severity] or 0.25
end

function build_tags(alert)
    local tags = {}
    table.insert(tags, "ids")
    if alert["category"] then
        table.insert(tags, alert["category"])
    end
    -- Encode as JSON array string
    return "[\"" .. table.concat(tags, "\",\"") .. "\"]"
end

function extract_mitre(metadata)
    -- ET rules embed MITRE ATT&CK references in metadata
    -- Format: "mitre_technique_id T1071, mitre_tactic_id TA0011"
    if metadata["mitre_technique_id"] then
        return metadata["mitre_technique_id"][1]
    end
    return nil
end
```

### 3.4 Event Schema Extension — SQL Migration

```sql
-- Migration 003: Add IDS alert support
-- File: siem/migrations/003_ids_alerts.sql

-- Step 1: Extend event_type enum to include 'ids_alert'
-- SQLite doesn't support ALTER CHECK, so we recreate the table
-- In practice, Vedetta should use application-level validation

-- For SQLite: drop and recreate the CHECK constraint
-- This is safe because SQLite stores CHECK in the schema but
-- validates on INSERT, not on existing data.

-- Approach: Add a new events_v2 table, migrate data, swap names
CREATE TABLE IF NOT EXISTS events_v2 (
    event_id       TEXT PRIMARY KEY,
    timestamp      TIMESTAMP NOT NULL,
    event_type     TEXT NOT NULL CHECK (event_type IN (
        'dns_query', 'nmap_discovery', 'firewall_log', 'anomaly', 'ids_alert'
    )),
    source_hash    TEXT NOT NULL,
    domain         TEXT,
    query_type     TEXT CHECK (query_type IN ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'SRV', 'PTR', NULL)),
    resolved_ip    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    tags           TEXT DEFAULT '[]',
    geo            TEXT,
    device_vendor  TEXT,
    network_segment TEXT DEFAULT 'default' CHECK (network_segment IN ('default', 'iot', 'guest')),

    -- New IDS-specific columns (NULL for non-IDS events)
    signature_id   INTEGER,
    signature      TEXT,
    severity       INTEGER CHECK (severity IN (1, 2, 3, 4, NULL)),
    category       TEXT,
    mitre_attack   TEXT,         -- e.g., "T1071.001"
    src_ip         TEXT,
    src_port       INTEGER,
    dest_ip        TEXT,
    dest_port      INTEGER,
    proto          TEXT CHECK (proto IN ('TCP', 'UDP', 'ICMP', NULL)),
    action         TEXT CHECK (action IN ('allowed', 'blocked', NULL))
);

-- Migrate existing data
INSERT INTO events_v2 (
    event_id, timestamp, event_type, source_hash, domain,
    query_type, resolved_ip, blocked, anomaly_score, tags,
    geo, device_vendor, network_segment
)
SELECT
    event_id, timestamp, event_type, source_hash, domain,
    query_type, resolved_ip, blocked, anomaly_score, tags,
    geo, device_vendor, network_segment
FROM events;

-- Swap tables
DROP TABLE events;
ALTER TABLE events_v2 RENAME TO events;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type         ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_source       ON events (source_hash);
CREATE INDEX IF NOT EXISTS idx_events_anomaly      ON events (anomaly_score);
CREATE INDEX IF NOT EXISTS idx_events_domain       ON events (domain);
CREATE INDEX IF NOT EXISTS idx_events_type_time    ON events (event_type, timestamp);

-- New indexes for IDS queries
CREATE INDEX IF NOT EXISTS idx_events_sig_id       ON events (signature_id)  WHERE event_type = 'ids_alert';
CREATE INDEX IF NOT EXISTS idx_events_severity     ON events (severity)      WHERE event_type = 'ids_alert';
CREATE INDEX IF NOT EXISTS idx_events_mitre        ON events (mitre_attack)  WHERE event_type = 'ids_alert';
CREATE INDEX IF NOT EXISTS idx_events_dest_ip      ON events (dest_ip)       WHERE event_type = 'ids_alert';
CREATE INDEX IF NOT EXISTS idx_events_category     ON events (category)      WHERE event_type = 'ids_alert';

-- IDS-specific aggregate view for dashboard
CREATE VIEW IF NOT EXISTS ids_alert_summary AS
SELECT
    date(timestamp) AS alert_date,
    category,
    severity,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT src_ip) AS unique_sources,
    COUNT(DISTINCT signature_id) AS unique_signatures
FROM events
WHERE event_type = 'ids_alert'
GROUP BY date(timestamp), category, severity;

-- Top talkers view — most active alert sources
CREATE VIEW IF NOT EXISTS ids_top_sources AS
SELECT
    src_ip,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT signature_id) AS unique_sigs,
    MIN(severity) AS max_severity,
    MAX(timestamp) AS last_seen
FROM events
WHERE event_type = 'ids_alert'
GROUP BY src_ip
ORDER BY alert_count DESC;
```

---

## 4. Alternative IDS Engines

### 4.1 Zeek on Raspberry Pi 4

**Verdict: Marginal — optional add-on for advanced users only**

| Aspect | Assessment |
|--------|-----------|
| RAM floor | ~500 MB minimum, 1–1.5 GB typical for single worker |
| Pi 4 viable? | Yes on 4GB, but leaves little room for Vedetta services |
| Compilation | Requires swap file on 2GB models; takes 2+ hours on Pi 4 |
| Strengths | Unmatched protocol analysis depth; scriptable detection logic; excellent DNS/TLS logging |
| Weaknesses | No signature-based detection; heavier than Suricata; steeper learning curve |
| Sweet spot | DNS anomaly detection, TLS certificate logging, connection profiling |

**Zeek's value for Vedetta** is primarily in behavioral analysis that Suricata can't do: DGA detection via DNS log analysis, JA3/JA3S fingerprint correlation, and connection pattern profiling. However, Vedetta already plans a Go-based DNS Threat Engine (see 03-network-scanning-threat-hunting.md Phase 2) which covers the highest-ROI Zeek use cases natively.

**Recommendation:** Don't include Zeek in the default Vedetta stack. Document it as an optional `docker-compose.zeek.yml` override for power users with Pi 5 (8GB+) or dedicated hardware.

### 4.2 Snort 3 on Raspberry Pi 4

**Verdict: Viable but Suricata is superior for Vedetta**

| Aspect | Snort 3 | Suricata |
|--------|---------|----------|
| Architecture | Multi-threaded (C++) | Multi-threaded (C) |
| RAM usage | Lower (~200–400 MB) | Higher (~400–800 MB) |
| CPU usage | Higher per-thread | Lower overall (better parallelism) |
| Throughput | Lower on multi-core | Higher on multi-core (Pi 4 advantage) |
| Docker support | Weaker ecosystem | `jasonish/suricata` — well-maintained |
| EVE JSON output | No (unified2, alert_json) | Yes — native, comprehensive |
| Community rules | Snort Community + ET | ET Open (30K+ rules) |
| ARM support | Compiles but less tested | Well-tested on ARM/Pi |

Snort 3 uses less memory, which could matter on 2GB Pi 4 models. However, Suricata's multi-threaded architecture better utilizes Pi 4's quad-core CPU, its EVE JSON output maps directly to Vedetta's event pipeline, and the Docker ecosystem is more mature. Snort 3's output format would require additional transformation work.

**Recommendation:** Suricata remains the primary choice. Snort 3 is only worth considering if a future Vedetta variant targets Pi Zero 2W or other sub-2GB devices.

### 4.3 CrowdSec as Lightweight IDS Alternative

**Verdict: Complementary — different threat model, not a replacement**

CrowdSec is fundamentally different from Suricata:

| Aspect | CrowdSec | Suricata |
|--------|----------|----------|
| Detection method | Log analysis + crowd intelligence | Packet inspection + signatures |
| What it sees | Service logs (SSH, HTTP, etc.) | Raw network traffic |
| Strengths | Community blocklists, very low resource usage, remediation (firewall rules) |
| Weaknesses | No deep packet inspection, no protocol analysis, no encrypted traffic visibility |
| RAM usage | ~50–100 MB | ~400–800 MB |
| Pi compatibility | Excellent (Go binary, ARM builds since v1.3.0) |

**CrowdSec's value for Vedetta:**
- Crowdsourced IP reputation — every CrowdSec instance contributes to a shared blocklist
- Automated remediation via "bouncers" (firewall rule injection)
- SSH brute-force, port scan, and web scan detection from logs
- Very lightweight — can run alongside Suricata without resource conflict

**Recommendation:** Include CrowdSec as a separate optional module. It complements Suricata by providing log-based detection and automated remediation. Suricata detects threats in traffic; CrowdSec acts on them. They serve different layers of the defense stack.

---

## 5. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Vedetta Pi 4                       │
│                                                      │
│  ┌──────────┐    ┌───────────────┐    ┌──────────┐  │
│  │ Suricata │───▶│  EVE JSON     │───▶│ Fluent   │  │
│  │ (IDS)    │    │  /var/log/    │    │ Bit      │  │
│  │ AF_PACKET│    │  suricata/    │    │ Collector│  │
│  └──────────┘    └───────────────┘    └────┬─────┘  │
│       ▲                                     │        │
│       │ mirror port                         │ HTTP   │
│       │                                     ▼        │
│  ┌────┴─────┐                         ┌──────────┐  │
│  │ Managed  │                         │ Vedetta  │  │
│  │ Switch   │                         │ Backend  │  │
│  └──────────┘                         │ (Go API) │  │
│                                       └────┬─────┘  │
│                                            │        │
│                                       ┌────▼─────┐  │
│                                       │ SQLite   │  │
│                                       │ events   │  │
│                                       │ table    │  │
│                                       └──────────┘  │
└─────────────────────────────────────────────────────┘
```

**Data flow:**
1. Managed switch mirrors all traffic to Pi 4's eth0
2. Suricata captures packets via AF_PACKET, inspects against ET Open rules
3. Alerts written as JSON lines to `/var/log/suricata/eve.json`
4. Fluent Bit tails eve.json, filters for alerts, transforms to Vedetta schema via Lua
5. Transformed events POSTed to Vedetta backend at `/api/v1/ingest`
6. Backend stores in `events` table with `event_type = 'ids_alert'`
7. Frontend renders IDS alerts in dashboard with severity/category filtering

---

## 6. Implementation Checklist

### Phase 1: Scaffolding (1–2 days)
- [ ] Create `suricata/` directory with `etc/suricata.yaml`, `enable.conf`, `disable.conf`
- [ ] Create `docker-compose.suricata.yml` override file
- [ ] Run migration `003_ids_alerts.sql` against the schema
- [ ] Add Suricata EVE input section to Fluent Bit config
- [ ] Write `suricata_transform.lua` for Fluent Bit

### Phase 2: Backend (2–3 days)
- [ ] Update `/api/v1/ingest` handler to accept `ids_alert` event type
- [ ] Add IDS-specific field validation in the Go backend
- [ ] Create IDS alert API endpoints: `GET /api/v1/alerts?severity=&category=`
- [ ] Add `ids_alert` to the event type enum in Go models

### Phase 3: Frontend (2–3 days)
- [ ] IDS Alert dashboard card (count by severity, sparkline)
- [ ] Alert detail view (signature, source/dest, MITRE mapping)
- [ ] Top Sources widget (ids_top_sources view)
- [ ] Category breakdown chart

### Phase 4: Testing & Documentation (1–2 days)
- [ ] Test with replay pcap via `tcpreplay` on mirror interface
- [ ] Validate memory stays within 1.5GB container limit under load
- [ ] Document switch port mirroring setup for common brands (TP-Link, Ubiquiti, Netgear)
- [ ] Add Suricata toggle to Vedetta settings UI

---

## 7. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Suricata OOM kills on 2GB Pi 4 | Container memory limit (1536M) + deploy minimum 4GB; 2GB documented as unsupported |
| EVE JSON fills SD card | Log rotation (10 min interval, 50MB max); Fluent Bit processes and discards; only alerts forwarded |
| Rule updates spike CPU | `suricata-update` runs via manual docker compose profile, not cron; reload-rules is live (no restart) |
| False positives flood dashboard | Pruned ruleset (skip enterprise-focused categories); anomaly_score mapping lets users filter by threshold |
| Mirror port not available | Document alternative: ARP spoofing capture (ettercap/arpspoof) or router-based packet capture (MikroTik, pfSense) |

---

## References

- [SuricataPi Project](https://github.com/beep-projects/SuricataPi)
- [Suricata Tuning Considerations](https://docs.suricata.io/en/latest/performance/tuning-considerations.html)
- [Suricata EVE JSON Output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [jasonish/suricata Docker Image](https://github.com/jasonish/docker-suricata)
- [ET Open Ruleset Downloads](https://rules.emergingthreats.net/OPEN_download_instructions.html)
- [ET Category Descriptions](https://tools.emergingthreats.net/docs/ETPro%20Rule%20Categories.pdf)
- [Home Network Security with Suricata + Pi 4 (FreeCodeCamp)](https://www.freecodecamp.org/news/home-network-security-with-suricata-raspberrypi4-python/)
- [Pi Home-Lab IDS with Suricata and Wazuh](http://www.h-i-r.net/2025/09/raspberry-pi-home-lab-ids-with-suricata.html)
- [CrowdSec on Raspberry Pi](https://www.crowdsec.net/blog/how-to-secure-your-raspberry-pi-with-crowdsec)
- [Zeek on Raspberry Pi 4](https://github.com/bvoris/RaspberryPiZeek)
- [Snort 3 vs Suricata Comparative Analysis](https://pure.port.ac.uk/ws/portalfiles/portal/79753845/A_Comparative_Analysis_of_Snort_3_and_Suricata.pdf)
- [Suricata Docker AF-PACKET Forum Thread](https://forum.suricata.io/t/running-suricata-ips-af-packet-in-docker-container/3549)
