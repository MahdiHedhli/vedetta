# Deep Dive: ClickHouse Schema & Deployment for the Vedetta Threat Network

> Research date: 2026-03-28
> Status: Design specification — ready for implementation in M6
> Prerequisite reading: `research/06-event-aggregation-telemetry.md`, `docs/roadmap.md` (M6 section)

---

## 1. Executive Summary

The Vedetta threat network needs a time-series analytical backend that can ingest batched telemetry from thousands of distributed nodes, deduplicate reports, aggregate domain reputation scores, and serve community threat feeds with sub-second latency — all on minimal infrastructure (Raspberry Pi 4 class, 2–4 GB RAM).

This document specifies the complete ClickHouse schema, materialized view pipeline, API layer, Docker deployment configuration, and a comparison with three alternatives (TimescaleDB, QuestDB, DuckDB). The recommendation is **ClickHouse for the central backend** and **DuckDB as an optional embedded engine on each node** for local analytics.

---

## 2. Why ClickHouse

ClickHouse is a column-oriented OLAP database built for analytical queries over time-series and event data. The properties that make it ideal for Vedetta's threat network:

**Storage efficiency.** ClickHouse achieves 10:1 compression ratios on event data. Column storage means repetitive low-cardinality fields like `event_type`, `geo`, and `device_type` compress extremely well. Benchmarks show ClickHouse uses 1.7x less disk than the next most efficient time-series DB.

**Analytical query speed.** Vectorized execution processes columns in CPU-cache-friendly batches. Aggregating millions of domain reputation scores across time windows runs in milliseconds, not seconds. ClickHouse dominates queries that aggregate across large time windows or high-cardinality dimensions — exactly the pattern for feed generation.

**Batch ingestion model.** ClickHouse performs best with batches of 10,000+ rows, which aligns perfectly with Vedetta's 15-minute batching strategy (nodes accumulate events then POST a batch). ClickHouse handles 4M+ rows/second ingestion at this batch size.

**Built-in deduplication.** `ReplacingMergeTree` provides background deduplication by ORDER BY key, eliminating duplicate reports from the same node for the same domain within the same time window.

**Materialized views.** Incremental materialized views process each inserted batch in real-time, maintaining pre-aggregated tables for domain reputation, emerging threats, and DGA clustering — no separate ETL pipeline required.

**Runs on minimal hardware.** With tuning, ClickHouse runs in a Docker container with 1–2 GB RAM allocated. Not comfortable, but viable for early-stage deployment. 4 GB is the sweet spot for Vedetta's expected volume (thousands of nodes, millions of events/day).

---

## 3. Schema Design

### 3.1 Core Events Table: `telemetry_events`

This is the raw event store. Every telemetry batch from every node lands here. Partitioned by month (matching the research recommendation for most workloads), ordered by domain + timestamp for fast domain-centric queries.

```sql
CREATE TABLE IF NOT EXISTS telemetry_events
(
    -- Identity
    event_id         UUID DEFAULT generateUUIDv4(),
    node_hash        String,           -- HMAC of install ID (PII-stripped)
    source_hash      String,           -- HMAC of source IP + per-install salt

    -- Event data
    event_type       LowCardinality(String),  -- 'dns_query', 'dns_block', 'anomaly', 'port_scan'
    domain           String,
    query_type       LowCardinality(String),  -- 'A', 'AAAA', 'CNAME', 'MX', 'TXT', etc.
    blocked          UInt8,                    -- 0 or 1
    anomaly_score    Float32,                  -- 0.0 to 1.0
    tags             Array(LowCardinality(String)),  -- ['beaconing', 'dga', 'newly_registered']

    -- Context (PII-stripped)
    geo              LowCardinality(String),   -- ISO 3166-1 alpha-2 country code
    device_type      LowCardinality(String),   -- 'iot_camera', 'smart_speaker', 'phone', 'desktop', 'unknown'

    -- Metadata
    schema_version   UInt8,
    ingested_at      DateTime DEFAULT now(),
    event_timestamp  DateTime,

    -- Deduplication version (latest wins)
    _version         UInt64 DEFAULT toUnixTimestamp(now())
)
ENGINE = ReplacingMergeTree(_version)
PARTITION BY toYYYYMM(event_timestamp)
ORDER BY (domain, node_hash, event_type, toStartOfHour(event_timestamp))
TTL event_timestamp + INTERVAL 12 MONTH DELETE
SETTINGS
    index_granularity = 8192,
    ttl_only_drop_parts = 1;
```

**Design decisions:**

- **ORDER BY `(domain, node_hash, event_type, toStartOfHour(event_timestamp))`** — This is both the sort key and the deduplication key. Reports from the same node for the same domain, event type, and hour are collapsed into one row (latest version wins). This provides hour-level deduplication without losing cross-hour granularity.
- **`ReplacingMergeTree(_version)`** — Background merges deduplicate rows with the same ORDER BY key, keeping the row with the highest `_version`. Queries that need guaranteed deduplication use `FINAL` or the `argMax` pattern.
- **`PARTITION BY toYYYYMM(event_timestamp)`** — Monthly partitions balance partition count against part size. At expected volumes (millions of events/month), each partition will contain a manageable number of parts.
- **`LowCardinality(String)`** — Used for all low-cardinality dimensions (event_type, query_type, geo, device_type). This encodes values as dictionary-compressed integers, dramatically reducing storage and speeding up GROUP BY.
- **`TTL ... + INTERVAL 12 MONTH DELETE`** — Automatic data lifecycle. Events older than 12 months are dropped during background merges. `ttl_only_drop_parts = 1` ensures TTL only drops entire parts (more efficient than row-level deletion).
- **`Array(LowCardinality(String))` for tags** — Flexible tagging without schema changes. Supports `hasAny()` and `hasAll()` for efficient array filtering.

### 3.2 Node Registry: `node_registry`

Tracks every reporting node, their trust score, and activity. Used for consensus weighting and anti-gaming.

```sql
CREATE TABLE IF NOT EXISTS node_registry
(
    node_hash       String,
    first_seen      DateTime,
    last_seen       DateTime,
    trust_score     Float32 DEFAULT 0.0,   -- 0.0 (untrusted) to 1.0 (fully trusted)
    report_count    UInt64 DEFAULT 0,
    geo             LowCardinality(String),
    asn             UInt32 DEFAULT 0,       -- Autonomous System Number for diversity checks
    schema_version  UInt8,

    _version        UInt64 DEFAULT toUnixTimestamp(now())
)
ENGINE = ReplacingMergeTree(_version)
ORDER BY (node_hash)
SETTINGS index_granularity = 512;
```

**Design decisions:**

- **`ReplacingMergeTree`** on `node_hash` — Each node has exactly one row. When a batch arrives, we INSERT a new row with updated `last_seen`, `report_count`, and `trust_score`. Background merges collapse to the latest version.
- **`asn` field** — Critical for the consensus algorithm. A domain must be reported by nodes in 2+ ASNs before it enters any feed (prevents single-network poisoning).
- **Low `index_granularity` (512)** — The node registry is small (thousands to tens of thousands of rows). Smaller granularity means faster point lookups by `node_hash`.

### 3.3 Materialized View: `domain_reputation`

Pre-aggregated domain reputation scores. Updated incrementally on every insert to `telemetry_events`. This is the primary data source for the `GET /api/v1/feed/top-domains` endpoint.

```sql
-- Target table (AggregatingMergeTree stores intermediate aggregation states)
CREATE TABLE IF NOT EXISTS domain_reputation
(
    domain              String,
    time_bucket         DateTime,          -- Hourly buckets

    -- Aggregated metrics
    total_reports       AggregateFunction(count, UInt64),
    unique_nodes        AggregateFunction(uniq, String),
    unique_asns         AggregateFunction(uniq, UInt32),
    avg_anomaly_score   AggregateFunction(avg, Float32),
    max_anomaly_score   AggregateFunction(max, Float32),
    block_count         AggregateFunction(sum, UInt64),
    tag_set             AggregateFunction(groupUniqArray, String),
    geo_diversity       AggregateFunction(uniq, String),
    device_types        AggregateFunction(groupUniqArray, String)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (domain, time_bucket)
TTL time_bucket + INTERVAL 6 MONTH DELETE;

-- Materialized view (triggers on INSERT to telemetry_events)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_domain_reputation
TO domain_reputation
AS
SELECT
    domain,
    toStartOfHour(event_timestamp)        AS time_bucket,

    countState()                           AS total_reports,
    uniqState(node_hash)                   AS unique_nodes,
    -- ASN lookup: join against node_registry at query time, or denormalize
    uniqState(assumeNotNull(0::UInt32))    AS unique_asns,  -- placeholder; see note below
    avgState(anomaly_score)                AS avg_anomaly_score,
    maxState(anomaly_score)                AS max_anomaly_score,
    sumState(toUInt64(blocked))            AS block_count,
    groupUniqArrayState(arrayJoin(tags))   AS tag_set,
    uniqState(geo)                         AS geo_diversity,
    groupUniqArrayState(device_type)       AS device_types
FROM telemetry_events
GROUP BY domain, time_bucket;
```

**ASN enrichment note:** The materialized view processes each batch as it arrives. At INSERT time, the node's ASN is not directly available in the telemetry event (it lives in `node_registry`). Two approaches:

1. **Denormalize at ingest** — The API layer looks up the node's ASN from `node_registry` and adds it to the event before INSERT. This is the recommended approach: add an `asn` column to `telemetry_events` and populate it server-side.
2. **Join at query time** — When reading from `domain_reputation`, join against `node_registry` for ASN diversity. Simpler schema but slower queries.

We recommend approach 1. The updated `telemetry_events` CREATE TABLE above should include an `asn UInt32 DEFAULT 0` column (added in final implementation).

**Querying the aggregated view:**

```sql
-- Top 50 domains by reputation score in the last 24 hours
SELECT
    domain,
    countMerge(total_reports)           AS reports,
    uniqMerge(unique_nodes)             AS nodes,
    avgMerge(avg_anomaly_score)         AS avg_score,
    maxMerge(max_anomaly_score)         AS max_score,
    sumMerge(block_count)               AS blocks,
    groupUniqArrayMerge(tag_set)        AS tags,
    uniqMerge(geo_diversity)            AS countries
FROM domain_reputation
WHERE time_bucket >= now() - INTERVAL 24 HOUR
GROUP BY domain
HAVING nodes >= 3 AND avg_score >= 0.5
ORDER BY (avg_score * ln(nodes + 1)) DESC
LIMIT 50;
```

### 3.4 Materialized View: `emerging_threats`

Detects domains with sudden volume spikes. Compares the current hour's report count to the trailing 24-hour average.

```sql
-- Target table for hourly volume snapshots
CREATE TABLE IF NOT EXISTS domain_hourly_volume
(
    domain          String,
    hour_bucket     DateTime,
    report_count    UInt64,
    unique_nodes    UInt32,
    avg_score       Float32
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour_bucket)
ORDER BY (domain, hour_bucket)
TTL hour_bucket + INTERVAL 30 DAY DELETE;

-- Materialized view: populate hourly volume on insert
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_domain_hourly_volume
TO domain_hourly_volume
AS
SELECT
    domain,
    toStartOfHour(event_timestamp)   AS hour_bucket,
    count()                          AS report_count,
    uniq(node_hash)                  AS unique_nodes,
    avg(anomaly_score)               AS avg_score
FROM telemetry_events
GROUP BY domain, hour_bucket;
```

**Emerging threats query (used by the API):**

```sql
-- Domains with volume spike > 3x their 24h average, appearing in the last 2 hours
WITH hourly AS (
    SELECT
        domain,
        hour_bucket,
        report_count,
        unique_nodes,
        avg_score,
        avg(report_count) OVER (
            PARTITION BY domain
            ORDER BY hour_bucket
            ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING
        ) AS trailing_avg
    FROM domain_hourly_volume
    WHERE hour_bucket >= now() - INTERVAL 48 HOUR
)
SELECT
    domain,
    report_count                          AS current_count,
    trailing_avg,
    report_count / greatest(trailing_avg, 1) AS spike_ratio,
    unique_nodes,
    avg_score
FROM hourly
WHERE hour_bucket >= now() - INTERVAL 2 HOUR
  AND trailing_avg > 0
  AND report_count / greatest(trailing_avg, 1) > 3.0
  AND unique_nodes >= 2
ORDER BY spike_ratio DESC
LIMIT 100;

-- Sparkline data for a specific domain (24h, hourly buckets)
SELECT
    hour_bucket,
    report_count,
    unique_nodes,
    avg_score
FROM domain_hourly_volume
WHERE domain = {domain:String}
  AND hour_bucket >= now() - INTERVAL 24 HOUR
ORDER BY hour_bucket;
```

### 3.5 Materialized View: `dga_clusters`

Groups domains by entropy and structural similarity to identify DGA (Domain Generation Algorithm) candidates.

```sql
-- Target table for domain structural features (computed at ingest time)
CREATE TABLE IF NOT EXISTS domain_features
(
    domain              String,
    tld                 LowCardinality(String),
    sld_length          UInt16,         -- Second-level domain length
    sld_entropy         Float32,        -- Shannon entropy of the SLD
    consonant_ratio     Float32,        -- Ratio of consonants to total chars
    digit_ratio         Float32,        -- Ratio of digits to total chars
    has_hyphen          UInt8,
    subdomain_depth     UInt8,          -- Number of subdomain levels
    first_seen          DateTime,
    last_seen           DateTime,
    total_reports       UInt64,
    unique_nodes        UInt32,
    avg_anomaly_score   Float32,

    _version            UInt64 DEFAULT toUnixTimestamp(now())
)
ENGINE = ReplacingMergeTree(_version)
ORDER BY (domain)
TTL last_seen + INTERVAL 90 DAY DELETE;

-- Materialized view: extract structural features on insert
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_domain_features
TO domain_features
AS
SELECT
    domain,

    -- Extract TLD (last segment after '.')
    arrayElement(splitByChar('.', domain), -1)              AS tld,

    -- SLD = second-to-last segment
    length(arrayElement(splitByChar('.', domain),
        greatest(length(splitByChar('.', domain)) - 1, 1))) AS sld_length,

    -- Shannon entropy approximation of the SLD
    -- (Full entropy calc is done application-side; this is a proxy)
    length(arrayElement(splitByChar('.', domain),
        greatest(length(splitByChar('.', domain)) - 1, 1)))
        / greatest(10.0, 1.0)                              AS sld_entropy,

    -- Character composition ratios (computed as approximations)
    0.0                                                     AS consonant_ratio,
    0.0                                                     AS digit_ratio,
    if(position(domain, '-') > 0, 1, 0)                    AS has_hyphen,
    toUInt8(length(splitByChar('.', domain)) - 1)           AS subdomain_depth,

    min(event_timestamp)                                    AS first_seen,
    max(event_timestamp)                                    AS last_seen,
    count()                                                 AS total_reports,
    uniq(node_hash)                                         AS unique_nodes,
    avg(anomaly_score)                                      AS avg_anomaly_score
FROM telemetry_events
GROUP BY domain;
```

**Implementation note:** ClickHouse SQL has limited string analysis functions. The entropy, consonant ratio, and digit ratio calculations should be computed **application-side** (in the Go API ingest handler) and stored as denormalized columns in `telemetry_events`. The materialized view above provides the structural skeleton; the real feature computation happens in the ingest pipeline:

```go
// Compute in the Go ingest handler before INSERT
func domainEntropy(domain string) float64 {
    sld := extractSLD(domain)
    freq := make(map[rune]float64)
    for _, c := range sld {
        freq[c]++
    }
    entropy := 0.0
    l := float64(len(sld))
    for _, count := range freq {
        p := count / l
        entropy -= p * math.Log2(p)
    }
    return entropy
}
```

**DGA candidate query:**

```sql
-- Domains with high entropy, high digit ratio, reported by multiple nodes
SELECT
    domain,
    sld_length,
    sld_entropy,
    consonant_ratio,
    digit_ratio,
    subdomain_depth,
    total_reports,
    unique_nodes,
    avg_anomaly_score,
    first_seen,
    last_seen
FROM domain_features FINAL
WHERE sld_entropy > 3.5
  AND sld_length > 8
  AND (digit_ratio > 0.3 OR consonant_ratio > 0.7)
  AND unique_nodes >= 2
  AND last_seen >= now() - INTERVAL 7 DAY
ORDER BY sld_entropy DESC, unique_nodes DESC
LIMIT 200;
```

---

## 4. API Layer Design

The threat network API is a Go service (consistent with the rest of the Vedetta backend) using the `chi` router. It connects to ClickHouse via the `clickhouse-go` driver.

### 4.1 `POST /api/v1/ingest` — Batch Telemetry Submission

**Purpose:** Accept PII-stripped telemetry batches from Vedetta nodes.

```
POST /api/v1/ingest
Content-Type: application/json
X-Node-Hash: <hmac_of_install_id>
X-Schema-Version: 1

Body: {
  "events": [
    {
      "event_type": "dns_query",
      "domain": "suspicious.example.com",
      "query_type": "A",
      "blocked": true,
      "anomaly_score": 0.87,
      "tags": ["beaconing", "newly_registered"],
      "geo": "US",
      "device_type": "iot_camera",
      "source_hash": "a1b2c3...",
      "event_timestamp": "2026-03-28T14:30:00Z"
    }
  ]
}

Response 200: { "accepted": 47, "rejected": 3, "errors": ["event[12]: invalid event_type 'foo'"] }
Response 400: { "error": "schema_version mismatch: expected 1, got 2" }
Response 429: { "error": "rate limit exceeded", "retry_after": 60 }
```

**Server-side processing pipeline:**

1. **Validate** `X-Schema-Version` header — reject mismatched versions
2. **Validate** each event against the schema (required fields, enum values, score ranges)
3. **Enrich** — look up the node's ASN from `node_registry` and attach to each event
4. **Compute** domain features (entropy, consonant ratio, digit ratio) for each unique domain in the batch
5. **Batch INSERT** into `telemetry_events` (ClickHouse performs best with bulk inserts)
6. **Upsert** `node_registry` — update `last_seen`, increment `report_count`
7. **Rate limit** — per-node: max 1 batch per 5 minutes, max 1000 events per batch

### 4.2 `GET /api/v1/feed/top-domains` — Domain Reputation Feed

**Purpose:** Return the highest-confidence malicious domains based on community consensus.

```
GET /api/v1/feed/top-domains?min_reports=10&min_score=0.6&time_window=24h&limit=100

Response 200: {
  "generated_at": "2026-03-28T15:00:00Z",
  "time_window": "24h",
  "domains": [
    {
      "domain": "c2-beacon.evil.example",
      "reputation_score": 0.94,
      "report_count": 847,
      "unique_nodes": 312,
      "unique_countries": 28,
      "avg_anomaly_score": 0.91,
      "tags": ["beaconing", "c2"],
      "first_seen": "2026-03-27T08:12:00Z",
      "last_seen": "2026-03-28T14:58:00Z"
    }
  ]
}
```

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_reports` | int | 5 | Minimum total reports across all nodes |
| `min_score` | float | 0.5 | Minimum average anomaly score |
| `min_nodes` | int | 3 | Minimum unique reporting nodes |
| `time_window` | duration | 24h | Lookback window (1h, 6h, 24h, 7d, 30d) |
| `tags` | string[] | — | Filter by tag (comma-separated) |
| `limit` | int | 100 | Max results (cap: 1000) |
| `format` | string | json | `json` or `csv` |

**Underlying query:** Reads from `domain_reputation` using `*Merge()` aggregate functions (see Section 3.3).

### 4.3 `GET /api/v1/feed/anomalies` — Emerging Threats

**Purpose:** Domains with sudden volume spikes indicating a new campaign or outbreak.

```
GET /api/v1/feed/anomalies?min_spike_ratio=3.0&min_nodes=2&limit=50

Response 200: {
  "generated_at": "2026-03-28T15:00:00Z",
  "anomalies": [
    {
      "domain": "newmalware-payload.example",
      "spike_ratio": 12.4,
      "current_hour_count": 1240,
      "trailing_24h_avg": 100,
      "unique_nodes": 89,
      "avg_anomaly_score": 0.78,
      "sparkline_24h": [0, 0, 2, 5, 8, 12, 100, 150, 200, 340, 500, 680, 800, 900, 1000, 1050, 1100, 1150, 1180, 1200, 1210, 1220, 1230, 1240]
    }
  ]
}
```

**Sparkline data:** An array of 24 integers representing hourly report counts over the last 24 hours. Generated from the `domain_hourly_volume` table with a single query.

### 4.4 `GET /api/v1/feed/dga-candidates` — DGA Clusters

**Purpose:** Domains that exhibit algorithmically-generated characteristics.

```
GET /api/v1/feed/dga-candidates?min_entropy=3.5&min_nodes=2&limit=200

Response 200: {
  "generated_at": "2026-03-28T15:00:00Z",
  "candidates": [
    {
      "domain": "x8k2m9p4q1.example.com",
      "sld_entropy": 4.12,
      "sld_length": 10,
      "digit_ratio": 0.5,
      "consonant_ratio": 0.8,
      "subdomain_depth": 1,
      "total_reports": 34,
      "unique_nodes": 12,
      "avg_anomaly_score": 0.72,
      "first_seen": "2026-03-28T06:00:00Z"
    }
  ]
}
```

### 4.5 `GET /api/v1/node/status` — Node Health & Trust

**Purpose:** Authenticated per-node endpoint returning the node's own health and trust data.

```
GET /api/v1/node/status
X-Node-Hash: <hmac_of_install_id>

Response 200: {
  "node_hash": "abc123...",
  "trust_score": 0.72,
  "report_count": 15847,
  "first_seen": "2026-01-15T10:00:00Z",
  "last_seen": "2026-03-28T14:45:00Z",
  "rank_percentile": 82,
  "community_stats": {
    "total_nodes": 4821,
    "total_domains_tracked": 284719,
    "events_last_24h": 12847291
  }
}
```

**Authentication:** Each node authenticates with its `X-Node-Hash` header. In V1 this is a simple bearer identity (the HMAC itself is the credential). V2 should introduce proper API keys with rotation.

---

## 5. Docker Deployment

### 5.1 Docker Compose Service

```yaml
# Append to the existing docker-compose.yml
services:
  clickhouse:
    image: clickhouse/clickhouse-server:24.12-alpine
    container_name: vedetta-clickhouse
    restart: unless-stopped
    ports:
      - "8123:8123"    # HTTP interface (used by Go driver)
      - "9000:9000"    # Native TCP interface
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - clickhouse_logs:/var/log/clickhouse-server
      - ./threat-network/clickhouse/config.xml:/etc/clickhouse-server/config.d/vedetta.xml:ro
      - ./threat-network/clickhouse/users.xml:/etc/clickhouse-server/users.d/vedetta.xml:ro
      - ./threat-network/clickhouse/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    environment:
      CLICKHOUSE_DB: vedetta_threats
      CLICKHOUSE_USER: vedetta
      CLICKHOUSE_PASSWORD: "${CLICKHOUSE_PASSWORD:-vedetta_dev}"
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    healthcheck:
      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]
      interval: 10s
      timeout: 5s
      retries: 3

  threat-network:
    build:
      context: ./threat-network
      dockerfile: Dockerfile
    container_name: vedetta-threat-network
    restart: unless-stopped
    ports:
      - "8090:8090"
    environment:
      CLICKHOUSE_DSN: "clickhouse://vedetta:${CLICKHOUSE_PASSWORD:-vedetta_dev}@clickhouse:9000/vedetta_threats"
      LISTEN_ADDR: ":8090"
    depends_on:
      clickhouse:
        condition: service_healthy

volumes:
  clickhouse_data:
  clickhouse_logs:
```

### 5.2 Low-Memory ClickHouse Configuration

**`threat-network/clickhouse/config.xml`** — Tuned for 2 GB container limit:

```xml
<?xml version="1.0"?>
<clickhouse>
    <!-- Memory management for small servers -->
    <max_server_memory_usage_to_ram_ratio>0.8</max_server_memory_usage_to_ram_ratio>

    <!-- Mark cache: reduce from default 5GB to fit in 2GB container -->
    <mark_cache_size>134217728</mark_cache_size>  <!-- 128 MB -->

    <!-- Uncompressed cache: disable for low memory -->
    <uncompressed_cache_size>0</uncompressed_cache_size>

    <!-- Merge tree settings -->
    <merge_tree>
        <!-- Limit background merge memory usage -->
        <max_bytes_to_merge_at_max_space_in_pool>536870912</max_bytes_to_merge_at_max_space_in_pool>  <!-- 512 MB -->
        <!-- Reduce number of concurrent merges -->
        <background_pool_size>2</background_pool_size>
        <!-- Keep free disk space -->
        <min_free_disk_space_bytes>1073741824</min_free_disk_space_bytes>  <!-- 1 GB -->
    </merge_tree>

    <!-- Logging -->
    <logger>
        <level>warning</level>
        <size>50M</size>
        <count>2</count>
    </logger>

    <!-- Listen on all interfaces inside Docker -->
    <listen_host>0.0.0.0</listen_host>

    <!-- Disable unused protocols to save memory -->
    <mysql_port remove="true"/>
    <postgresql_port remove="true"/>
    <interserver_http_port remove="true"/>
</clickhouse>
```

**`threat-network/clickhouse/users.xml`** — Per-query memory limits:

```xml
<?xml version="1.0"?>
<clickhouse>
    <profiles>
        <default>
            <!-- Per-query memory limit: 500 MB -->
            <max_memory_usage>524288000</max_memory_usage>
            <!-- All queries combined: 1 GB -->
            <max_memory_usage_for_all_queries>1073741824</max_memory_usage_for_all_queries>
            <!-- Optimize ReplacingMergeTree FINAL queries -->
            <do_not_merge_across_partitions_select_final>1</do_not_merge_across_partitions_select_final>
            <!-- Max execution time per query: 30 seconds -->
            <max_execution_time>30</max_execution_time>
        </default>
    </profiles>
</clickhouse>
```

### 5.3 Init Script

**`threat-network/clickhouse/init.sql`** — Creates database and all tables/views on first startup:

```sql
CREATE DATABASE IF NOT EXISTS vedetta_threats;

-- Paste all CREATE TABLE and CREATE MATERIALIZED VIEW statements
-- from Section 3 here, prefixed with:
-- USE vedetta_threats;
```

---

## 6. Database Comparison

### 6.1 Comparison Matrix

| Criterion | ClickHouse | TimescaleDB | QuestDB | DuckDB |
|---|---|---|---|---|
| **Architecture** | Column-oriented OLAP | Row-oriented (Postgres extension) | Column-oriented, append-only | Embedded column-oriented OLAP |
| **Deployment** | Standalone server / Docker | Requires PostgreSQL | Standalone server / Docker | In-process library (no server) |
| **Min RAM** | 2 GB (tuned) | 2 GB (Postgres baseline) | 2 GB | ~100 MB (embedded) |
| **Compression** | Excellent (10:1 typical) | Good (5–7:1 with Postgres TOAST) | Excellent (columnar) | Excellent (columnar + Parquet) |
| **Batch ingestion** | 4M rows/s (batches >10K) | Better for small batches (<1K) | 4M rows/s | N/A (embedded) |
| **Analytical queries** | Best-in-class | 1.9x faster on RTABench, 6.8x slower on ClickBench | Fast for short-range, slower for wide scans | Fast for local datasets |
| **Deduplication** | Built-in (ReplacingMergeTree) | Upsert via ON CONFLICT | No native dedup | No native dedup |
| **Materialized views** | Incremental, real-time | Refresh-based (periodic) | No materialized views | No materialized views |
| **SQL compatibility** | ClickHouse SQL (non-standard extensions) | Full PostgreSQL SQL | PostgreSQL-compatible subset | Full SQL (DuckDB dialect) |
| **Joins** | Limited (best for denormalized data) | Full relational joins | Limited | Full relational joins |
| **Ecosystem** | Growing; Go driver mature | PostgreSQL ecosystem (massive) | Smaller; good REST API | Rapidly growing; Python/Node bindings |
| **Operational complexity** | Medium (single binary, but tuning needed) | Low (if you know Postgres) | Low (minimal config) | None (embedded) |
| **License** | Apache 2.0 | Apache 2.0 (community) / Proprietary (managed) | Apache 2.0 | MIT |
| **Best for Vedetta** | Central threat network backend | Alternative if team prefers Postgres | High-frequency streaming (overkill here) | Local node analytics |

### 6.2 TimescaleDB: Detailed Assessment

**Schema equivalent:**

```sql
-- TimescaleDB equivalent of telemetry_events
CREATE TABLE telemetry_events (
    event_id         UUID DEFAULT gen_random_uuid(),
    node_hash        TEXT NOT NULL,
    source_hash      TEXT,
    event_type       TEXT NOT NULL,
    domain           TEXT NOT NULL,
    query_type       TEXT,
    blocked          BOOLEAN DEFAULT FALSE,
    anomaly_score    REAL DEFAULT 0.0,
    tags             TEXT[],
    geo              TEXT,
    device_type      TEXT,
    schema_version   SMALLINT DEFAULT 1,
    ingested_at      TIMESTAMPTZ DEFAULT now(),
    event_timestamp  TIMESTAMPTZ NOT NULL
);

SELECT create_hypertable('telemetry_events', 'event_timestamp',
    chunk_time_interval => INTERVAL '1 month');

CREATE INDEX idx_te_domain ON telemetry_events (domain, event_timestamp DESC);
CREATE INDEX idx_te_node ON telemetry_events (node_hash, event_timestamp DESC);

-- Deduplication via upsert
CREATE UNIQUE INDEX idx_te_dedup ON telemetry_events
    (domain, node_hash, event_type, date_trunc('hour', event_timestamp));

-- Continuous aggregate (TimescaleDB's materialized view equivalent)
CREATE MATERIALIZED VIEW domain_reputation_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', event_timestamp) AS hour_bucket,
    domain,
    count(*) AS total_reports,
    count(DISTINCT node_hash) AS unique_nodes,
    avg(anomaly_score) AS avg_score,
    max(anomaly_score) AS max_score,
    sum(blocked::int) AS block_count
FROM telemetry_events
GROUP BY hour_bucket, domain;

-- Refresh policy: update every 15 minutes, covering the last 2 hours
SELECT add_continuous_aggregate_policy('domain_reputation_hourly',
    start_offset => INTERVAL '2 hours',
    end_offset => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '15 minutes');

-- Retention policy
SELECT add_retention_policy('telemetry_events', INTERVAL '12 months');
```

**Pros for Vedetta:**
- Full PostgreSQL — team likely has more Postgres experience than ClickHouse experience
- Continuous aggregates are simpler than ClickHouse's AggregateFunction state pattern
- Upsert deduplication is immediate (not background merge)
- Rich ecosystem: pg_cron, PostGIS, pg_trgm for fuzzy domain matching

**Cons for Vedetta:**
- Row-oriented storage means worse compression (roughly 2x more disk than ClickHouse for the same data)
- Slower analytical queries on large datasets (6.8x slower on aggregate-heavy benchmarks)
- Continuous aggregates refresh periodically, not incrementally per-insert
- Higher baseline memory usage for PostgreSQL

**Verdict:** TimescaleDB is a strong alternative if operational simplicity is prioritized over raw analytical performance. For V1 with hundreds of nodes, TimescaleDB would work fine. ClickHouse becomes clearly superior at scale (thousands of nodes, billions of events).

### 6.3 QuestDB: Detailed Assessment

**Pros:**
- Fastest ingestion (4M+ rows/s on modest hardware)
- Low-latency point queries (27x faster than ClickHouse on "last point" queries)
- Lightweight, minimal configuration
- Good REST API for integration
- Apache 2.0 license

**Cons:**
- No materialized views — all aggregation must happen at query time or in application code
- No built-in deduplication — application must handle it
- Smaller ecosystem and community
- Append-only model makes updates (like trust score adjustments) awkward
- Limited SQL support for complex analytical queries (window functions less mature)

**Verdict:** QuestDB is optimized for high-frequency streaming telemetry (financial markets, IoT sensors). Vedetta's 15-minute batch model doesn't leverage QuestDB's streaming ingestion advantage. The lack of materialized views is a dealbreaker — Vedetta needs pre-aggregated feeds updated in real-time without a separate ETL pipeline.

### 6.4 DuckDB: A Complementary Role

DuckDB is not a replacement for the central backend — it has no server mode and is designed to be embedded in an application process. However, it fills a valuable complementary role:

**Use case: Local node analytics.**

Each Vedetta node already stores events in SQLite. DuckDB could be embedded in the Go binary to provide:

- Local anomaly scoring with analytical SQL (window functions, percentiles)
- Pre-aggregation before telemetry submission (reduce bandwidth)
- Local dashboard queries without hitting the central backend
- Parquet export for offline analysis

**Example: Local beaconing detection with DuckDB:**

```sql
-- Detect domains with regular query intervals (beaconing)
SELECT
    domain,
    count(*) AS query_count,
    avg(interval_seconds) AS avg_interval,
    stddev(interval_seconds) AS interval_stddev,
    avg_interval / greatest(interval_stddev, 0.01) AS regularity_score
FROM (
    SELECT
        domain,
        epoch(event_timestamp - lag(event_timestamp) OVER (
            PARTITION BY domain ORDER BY event_timestamp
        )) AS interval_seconds
    FROM events
    WHERE event_timestamp > now() - INTERVAL '24 hours'
)
WHERE interval_seconds IS NOT NULL
GROUP BY domain
HAVING query_count > 20 AND regularity_score > 5.0
ORDER BY regularity_score DESC;
```

**Verdict:** DuckDB is not a candidate for the central backend but is a strong candidate for embedding in the Vedetta node binary (future M8+ milestone). It would let nodes do sophisticated local analytics without any additional infrastructure.

---

## 7. Capacity Planning

### 7.1 Expected Volume (V1 Launch)

| Metric | Estimate |
|---|---|
| Active nodes | 500–5,000 |
| Events per node per day | ~2,000 (after dedup) |
| Total events per day | 1M–10M |
| Event size (compressed) | ~15 bytes/row in ClickHouse |
| Daily storage growth | 15–150 MB/day |
| Monthly storage | 0.5–4.5 GB/month |
| 12-month retention | 6–54 GB total |

### 7.2 Hardware Recommendations

**Minimum viable (Raspberry Pi 4 / small VPS):**
- CPU: 4 cores (ARM64 or x86_64)
- RAM: 4 GB (2 GB for ClickHouse, 2 GB for Go API + OS)
- Storage: 64 GB SSD (handles ~12 months at moderate scale)
- Network: 10 Mbps symmetric (more than sufficient)

**Comfortable (small cloud VM):**
- CPU: 4–8 cores
- RAM: 8 GB
- Storage: 200 GB SSD
- Network: 100 Mbps

### 7.3 Scaling Path

1. **V1 (single node):** Single ClickHouse instance, single Go API process. Handles up to ~10M events/day.
2. **V1.5 (read replicas):** Add ClickHouse read replicas for feed queries. Write path stays single-node.
3. **V2 (sharded):** Shard `telemetry_events` by domain hash across multiple ClickHouse nodes. `domain_reputation` stays on a single aggregation node.

---

## 8. Implementation Checklist

The following files need to be created or modified to implement this design:

```
threat-network/
├── clickhouse/
│   ├── config.xml            # Low-memory server config (Section 5.2)
│   ├── users.xml             # Query memory limits (Section 5.2)
│   └── init.sql              # All CREATE TABLE/VIEW statements (Section 3)
├── cmd/threat-network/
│   └── main.go               # Update: add ClickHouse connection, real handlers
├── internal/
│   ├── clickhouse/
│   │   └── client.go         # ClickHouse client wrapper (connect, insert, query)
│   ├── ingest/
│   │   ├── handler.go        # POST /api/v1/ingest handler
│   │   ├── validator.go      # Schema validation, PII verification
│   │   └── enricher.go       # ASN lookup, domain feature computation
│   ├── feed/
│   │   ├── top_domains.go    # GET /api/v1/feed/top-domains
│   │   ├── anomalies.go      # GET /api/v1/feed/anomalies
│   │   └── dga.go            # GET /api/v1/feed/dga-candidates
│   ├── node/
│   │   └── status.go         # GET /api/v1/node/status
│   └── domain/
│       └── features.go       # Domain entropy, consonant ratio, digit ratio computation
├── Dockerfile
└── go.mod
```

**Dependencies to add:**
- `github.com/ClickHouse/clickhouse-go/v2` — Official Go driver for ClickHouse
- `github.com/go-chi/chi/v5` — HTTP router (consistent with main backend)

---

## 9. Open Questions

1. **ASN resolution:** How do we determine a node's ASN? Options: (a) node self-reports via a lookup service like `ipinfo.io` at startup, (b) the threat network infers it from the node's source IP on the ingest request. Option (b) is simpler but less accurate behind NATs.

2. **Feed caching:** Should feed endpoints cache results (e.g., 5-minute Redis/in-memory cache) or query ClickHouse on every request? At V1 scale, direct queries are fine. At scale, a 5-minute cache with stale-while-revalidate is recommended.

3. **Tranco whitelist:** The domain reputation view should exclude Tranco Top 10K domains. Should this be a ClickHouse dictionary (fast lookup) or an application-side filter? Dictionary is cleaner but adds operational complexity.

4. **Schema versioning:** When `telemetry_events` schema changes, old materialized views break. Strategy: version the table names (`telemetry_events_v2`) and migrate views, or use ALTER TABLE to add columns with defaults?

---

## References

- [ClickHouse Time-Series Schema Design](https://oneuptime.com/blog/post/2026-01-21-clickhouse-table-schemas-time-series/view)
- [ClickHouse ReplacingMergeTree Docs](https://clickhouse.com/docs/engines/table-engines/mergetree-family/replacingmergetree)
- [ReplacingMergeTree Best Practices (Tinybird)](https://www.tinybird.co/blog/clickhouse-replacingmergetree-example)
- [ClickHouse Materialized Views Best Practices](https://clickhouse.com/docs/best-practices/use-materialized-views)
- [Deploying Single-Node ClickHouse on Small Servers (Altinity)](https://altinity.com/blog/deploying-single-node-clickhouse-on-small-servers)
- [ClickHouse in Less than 2GB RAM in Docker](https://jamesoclaire.com/2024/12/20/clickhouse-in-less-than-2gb-ram-in-docker/)
- [ClickHouse vs TimescaleDB Comparison](https://www.tinybird.co/blog/clickhouse-vs-timescaledb)
- [QuestDB vs ClickHouse Benchmark](https://questdb.com/blog/clickhouse-vs-questdb-comparison/)
- [1-Node ClickHouse in Production](https://anthonynsimon.com/blog/clickhouse-deployment/)
- [ClickHouse Docker Deployment Architectures](https://clickhouse.com/blog/clickhouse-architectures-with-docker-compose)
- [DuckDB Embedded Analytics](https://motherduck.com/duckdb-book-summary-chapter1/)
- Vedetta internal: `research/06-event-aggregation-telemetry.md`
- Vedetta internal: `docs/roadmap.md` (M6 section)
