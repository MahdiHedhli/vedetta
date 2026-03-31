# Event Aggregation & Telemetry for the Vedetta Threat Network

> Priority: P1 — Unique competitive moat; first crowdsourced threat intel corpus from home/SMB networks

## Current State in Vedetta

The telemetry daemon is stubbed — it checks `VEDETTA_TELEMETRY_OPTIN`, and if not "true", blocks indefinitely. The threat network backend accepts POST to `/api/v1/ingest` but discards the payload. Feed endpoints (`/api/v1/feed/top-domains`, `/api/v1/feed/anomalies`) return empty lists.

The architecture is designed but not built: local nodes strip PII from events, batch them, and transmit to the central threat network which aggregates, deduplicates, and exposes community feeds.

## Research Findings

### 1. CrowdSec as Architectural Blueprint

CrowdSec is the closest open-source analog to what Vedetta's threat network aims to be. Key design decisions worth borrowing:

**Agent Architecture:**
- Local agent parses logs and detects attacks using "scenarios" (behavioral patterns)
- When an attack is detected, the agent shares the attacker IP + scenario with the central API
- In return, the agent receives a community blocklist of IPs reported by other agents
- Consensus algorithm determines which IPs make it into the community blocklist

**Trust & Quality:**
- Reputation system for reporting nodes (new nodes are untrusted, gain trust over time)
- Diversity criteria: an IP must be reported by multiple nodes across different ASNs to be listed
- Expert system rules encode why an attacker is threatening (volume, diversity, recency)
- False positive management: IPs in known CDN/cloud ranges get higher thresholds

**Vedetta application:** The Vedetta threat network should implement a similar consensus model for domain reputation rather than IP reputation (since home users see DNS traffic, not direct attacks).

### 2. Telemetry Design: What to Share

Vedetta's telemetry must be useful for the community while being privacy-safe. Here's what each node should contribute:

**Safe to share (after PII stripping):**
- Domain names queried (already public information)
- Query frequency and temporal patterns (beaconing signals)
- Whether the domain was blocked
- Anomaly scores assigned by local detection engines
- Device vendor/type distribution (anonymized — "3 IoT devices, 2 phones")
- JA3/JA4 fingerprints observed
- Port scan results from external probes (what the internet sees)

**Must NOT share:**
- Source IP addresses (replace with HMAC hash using per-install salt)
- Internal hostnames
- MAC addresses
- Exact device counts or identifiers
- Any personally identifiable information

**PII Stripping Pipeline:**
```go
type TelemetryEvent struct {
    EventType    string   `json:"event_type"`
    Domain       string   `json:"domain,omitempty"`
    QueryType    string   `json:"query_type,omitempty"`
    Blocked      bool     `json:"blocked"`
    AnomalyScore float64  `json:"anomaly_score"`
    Tags         []string `json:"tags"`
    Geo          string   `json:"geo"`           // Country code only
    DeviceType   string   `json:"device_type"`   // Generic category
    SourceHash   string   `json:"source_hash"`   // HMAC of IP + salt
    NodeHash     string   `json:"node_hash"`     // HMAC of install ID
    SchemaVersion int     `json:"schema_version"`
}

func StripPII(event Event, salt []byte) TelemetryEvent {
    return TelemetryEvent{
        EventType:    event.EventType,
        Domain:       event.Domain,
        QueryType:    event.QueryType,
        Blocked:      event.Blocked,
        AnomalyScore: event.AnomalyScore,
        Tags:         event.Tags,
        Geo:          event.Geo,  // Already country-level
        DeviceType:   generalizeDeviceType(event.DeviceVendor),
        SourceHash:   hmacSHA256(event.SourceIP, salt),
        NodeHash:     hmacSHA256(installID, salt),
        SchemaVersion: 1,
    }
}
```

### 3. Batching & Transmission

**Batch strategy:**
- Accumulate events locally for 15 minutes (configurable)
- Batch into a single POST (gzip compressed)
- Maximum batch size: 1000 events (prevent abuse)
- Retry with exponential backoff on failure (1s, 2s, 4s, 8s, max 5min)
- Queue events locally (SQLite staging table) during outages

**Bandwidth estimate:**
- Average home network: ~10,000 DNS events/day
- After deduplication (collapse repeated queries to same domain): ~2,000 unique events/day
- At ~150 bytes per telemetry event: ~300KB/day compressed
- Well within acceptable for any home internet connection

### 4. Central Threat Network Backend

**Storage: ClickHouse (as designed)**

ClickHouse is the right choice for the central backend:
- Column-oriented, optimized for analytical queries on time-series data
- Handles billions of rows on modest hardware
- Built-in deduplication (`ReplacingMergeTree`)
- Excellent compression (10:1 typical for event data)
- SQL interface for analysis queries

**Alternative: TimescaleDB**
- PostgreSQL extension, easier to operate if team knows Postgres
- Good compression and time-series optimization
- Slightly worse performance than ClickHouse for pure analytical workloads
- Better for mixed read/write patterns

**Recommendation:** ClickHouse for the central threat network (read-heavy analytical workload). TimescaleDB as a simpler alternative if operational complexity is a concern.

### 5. Community Feed Generation

The threat network should produce feeds that nodes subscribe to:

**Feed 1: Domain Reputation**
- Domains queried by many nodes that score high in anomaly detection
- Weighted by: number of reporting nodes, anomaly score consistency, diversity of ASNs
- Output: JSON list of {domain, reputation_score, tags, first_seen, report_count}
- Update frequency: Every 15 minutes

**Feed 2: Emerging Threats**
- Domains with sudden spike in query volume across the network
- New domains not seen before that immediately show suspicious characteristics
- DGA clusters: Groups of domains with similar entropy/structure patterns
- Output: JSON with trend data (sparkline of query volume over 24h)

**Feed 3: Device Threat Landscape**
- Which device types (IoT cameras, smart speakers, etc.) are most commonly compromised
- Common ports opened on compromised device types
- Anonymized statistics, not individual device data

**Feed 4: Network Hygiene Score**
- Per-node (anonymized) hygiene score based on: blocked query ratio, number of IoT devices, DNS bypass attempts, known-bad domain hits
- Allows users to benchmark their network health against the community

### 6. Consensus and Anti-Gaming

The threat network must resist manipulation:

**Node Reputation:**
- New nodes start at trust level 0 (reports accepted but weighted low)
- Trust increases with: consistent reporting, correlation with known-good intelligence, report age
- Trust decreases with: reports that contradict majority consensus, sudden volume spikes, reports for known-good domains

**Domain Scoring:**
- Minimum reporting threshold: 3+ nodes from 2+ ASNs before a domain enters any feed
- Weighted scoring: high-trust nodes contribute more to reputation
- Decay: Reputation scores decay over time if not reinforced by continued reports
- Whitelist: Top 10K domains (Tranco list) are excluded from negative scoring

## Recommended Implementation

### Phase 1: Telemetry Daemon (Immediate)

Complete the stubbed telemetry daemon:
1. Read events from local SQLite (events table)
2. Strip PII using the pipeline above
3. Batch into 15-minute windows
4. POST to threat network as gzip JSON
5. Track last-synced timestamp to avoid re-sending

### Phase 2: Threat Network Ingest (Short-term)

Build the central backend:
1. Accept batches, validate schema version
2. Deduplicate by (node_hash, domain, hour) — collapse repeated reports
3. Store in ClickHouse `telemetry_events` table
4. Build materialized views for aggregation (domain popularity, anomaly trends)

### Phase 3: Community Feeds (Medium-term)

1. Implement domain reputation scoring (consensus algorithm)
2. Generate feed endpoints with JSON output
3. Add feed subscription to the telemetry daemon (pull feeds on schedule)
4. Wire feeds into the local threat intel DB for event enrichment

### Phase 4: Node Reputation System (Long-term)

1. Track per-node reporting quality
2. Implement trust scoring
3. Add anti-gaming protections
4. Dashboard showing community health metrics

## References

- CrowdSec architecture: https://docs.crowdsec.net/docs/intro/
- CrowdSec consensus: https://www.crowdsec.net/our-data
- ClickHouse documentation: https://clickhouse.com/docs
- TimescaleDB: https://docs.timescale.com/
- HMAC-SHA256 in Go: https://pkg.go.dev/crypto/hmac
- Tranco Top Sites: https://tranco-list.eu/
- M-Trends 2026: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026
