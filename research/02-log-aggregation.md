# Log Aggregation Pipeline

> Priority: P0 — Currently the biggest gap in the Vedetta pipeline

## Current State in Vedetta

Vedetta has a Fluent Bit collector configured with two inputs:
1. **Pi-hole DNS logs** — tails `/var/log/pihole/pihole.log` with a custom regex parser
2. **Firewall syslog** — listens on UDP 5140 for RFC 3164 syslog

Both outputs route to `POST /api/v1/ingest` on the backend. However, **the ingest endpoint is not implemented** — events arrive but are discarded. This is the single largest functional gap in the platform.

## Research Findings

### 1. Log Sources Relevant to Home/SMB Networks

| Source | Protocol | Value |
|--------|----------|-------|
| Pi-hole / AdGuard Home | File tail or API | DNS queries, blocked domains, client IPs |
| Router/firewall syslog | Syslog (UDP/TCP) | Connection logs, NAT table, dropped packets |
| DHCP server | Syslog or lease file | Device connects/disconnects, IP assignments |
| Suricata / Snort alerts | EVE JSON or syslog | IDS/IPS alerts with MITRE mappings |
| Vedetta sensor events | HTTP POST | Device discovery, port changes |
| systemd journal | journald | Host-level events (login, service changes) |
| UPnP/SSDP events | Internal | Port mapping requests (IoT devices opening ports) |

### 2. Lightweight Log Aggregation Stacks

**Fluent Bit (current choice) — Keep It**
- Already in the stack. 450KB binary, ~2MB RAM footprint. Perfect for Pi 4.
- Supports 80+ input plugins: tail, syslog, mqtt, systemd, tcp, http.
- Lua scripting for inline transformation and enrichment.
- Output to HTTP, SQLite, file, or stdout.
- Verdict: Correct choice. No need to replace — extend it.

**Vector (Datadog, open source)**
- Rust-based, more performant than Fluent Bit at scale, but heavier (~30MB binary).
- Better transforms (VRL scripting language) and built-in schema validation.
- Overkill for Pi 4 target but worth noting for larger deployments.

**Alternatives considered and rejected:**
- Logstash (Java, 500MB+ RAM — disqualified for Pi)
- Filebeat (lightweight but limited transformation)
- syslog-ng (good but Fluent Bit already does everything needed)

### 3. Normalization Strategy

Vedetta's event schema defines four event types: `dns_query`, `nmap_discovery`, `firewall_log`, `anomaly`. The normalization layer must map diverse log formats to this schema.

**Recommended approach: Fluent Bit Lua filters**

```lua
-- Example: normalize Pi-hole DNS log to Vedetta event schema
function normalize_pihole(tag, timestamp, record)
    local event = {
        event_type = "dns_query",
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        domain = record["domain"],
        query_type = record["query_type"] or "A",
        blocked = (record["action"] == "blocked"),
        source_hash = sha256(record["client"] .. INSTALL_SALT),
        anomaly_score = 0.0,
        tags = {}
    }
    return 1, timestamp, event
end
```

### 4. What Wazuh and Security Onion Do Differently

**Wazuh** uses agents on endpoints that forward logs to a central server. The server runs decoders (XML rule files) that parse 500+ log formats, then rule chains that generate alerts. This is powerful but heavyweight — the Wazuh server alone recommends 4GB+ RAM.

**Security Onion** bundles Suricata + Zeek + Wazuh + Elastic. Full SOC stack. Requires 16GB+ RAM minimum. Not viable for Pi 4 but instructive for feature design.

**Takeaway for Vedetta:** Borrow the *concepts* (decoders, rule chains, alert correlation) but implement them as lightweight Fluent Bit Lua scripts + Go-side enrichment. Keep the Pi 4 constraint front and center.

### 5. Retention and Storage

Current schema uses SQLite with 90-day configurable retention. For log volume estimates on a home network:
- DNS queries: ~5,000-50,000/day → ~150K-1.5M/month
- Firewall logs: ~1,000-10,000/day → ~30K-300K/month
- Device events: ~100-500/day → ~3K-15K/month

At ~200 bytes per normalized event, 90 days of a busy home network ≈ 500MB-1GB SQLite. Well within Pi 4 capacity with a 32GB SD card.

**Recommendation:** Add a retention enforcement job (Go `time.Ticker`) that runs daily and DELETEs events older than the configured retention window. This is defined in the schema but not yet implemented.

## Recommended Implementation

### Step 1: Implement the Ingest Endpoint (Immediate, Blocking)

The `/api/v1/ingest` endpoint must:
1. Accept Fluent Bit JSON payloads (array of normalized events)
2. Validate against the event schema (required fields, enum constraints)
3. Compute `source_hash` server-side (HMAC-SHA256 of client IP + install salt)
4. Calculate initial `anomaly_score` (0.0 for now; enrichment comes later)
5. Batch INSERT into SQLite `events` table
6. Return `202 Accepted` with count of ingested events

### Step 2: Expand Fluent Bit Inputs

Add these inputs to `fluent-bit.conf`:

```ini
# DHCP lease events (dnsmasq-style, common on Pi-hole)
[INPUT]
    Name        tail
    Path        /var/log/pihole/pihole-FTL.log
    Tag         dhcp.pihole
    Parser      pihole_ftl

# Systemd journal (host events)
[INPUT]
    Name        systemd
    Tag         host.systemd
    Systemd_Filter  _SYSTEMD_UNIT=ssh.service

# Suricata EVE JSON (if Suricata is installed)
[INPUT]
    Name        tail
    Path        /var/log/suricata/eve.json
    Tag         ids.suricata
    Parser      json
    Refresh_Interval 5
```

### Step 3: Implement the Events Query API

The `/api/v1/events` endpoint must support the query parameters already defined in the schema: `from`, `to`, `type`, `source`, `tags`, `min_score`, `sort`, `order`, `page`, `limit`, `format`.

### Step 4: Retention Enforcement

```go
// Run daily at 3am
func (s *Store) EnforceRetention() error {
    var days int
    s.db.QueryRow("SELECT retention_days FROM retention_config LIMIT 1").Scan(&days)
    cutoff := time.Now().AddDate(0, 0, -days).UTC().Format(time.RFC3339)
    _, err := s.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
    return err
}
```

## References

- Fluent Bit documentation: https://docs.fluentbit.io/
- Fluent Bit Lua filters: https://docs.fluentbit.io/manual/pipeline/filters/lua
- Wazuh architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
- Vector: https://vector.dev/
- Pi-hole FTL log format: https://docs.pi-hole.net/ftldns/
