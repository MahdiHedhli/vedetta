# Deep Dive: abuse.ch Ecosystem API Integration Specification

> **Status**: Implementation-Ready Specification
> **Author**: Automated Research Agent
> **Date**: 2026-03-27
> **Parent Doc**: `05-threat-intelligence-feeds.md`
> **Target Platform**: Vedetta on Raspberry Pi 4 (4GB RAM, ARM64)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [URLhaus API](#2-urlhaus-api)
3. [Feodo Tracker](#3-feodo-tracker)
4. [SSLBL JA3 Fingerprints](#4-sslbl-ja3-fingerprints)
5. [ThreatFox API](#5-threatfox-api)
6. [Feed Download Scheduler Design](#6-feed-download-scheduler-design)
7. [SQLite Storage Layer](#7-sqlite-storage-layer)
8. [Bloom Filter for Fast Domain Lookups](#8-bloom-filter-for-fast-domain-lookups)
9. [Offline Graceful Degradation](#9-offline-graceful-degradation)
10. [Go Implementation: HTTP Client Package](#10-go-implementation-http-client-package)
11. [Bulk Import SQLite Queries](#11-bulk-import-sqlite-queries)
12. [Deployment and Operational Notes](#12-deployment-and-operational-notes)

---

## 1. Executive Summary

The abuse.ch ecosystem is the single highest-ROI free threat intelligence source for Vedetta. It provides four complementary feeds—URLhaus (malware distribution URLs), Feodo Tracker (botnet C2 IPs), SSLBL (malicious JA3/TLS fingerprints), and ThreatFox (general IOCs)—all operated by abuse.ch in partnership with Spamhaus. Every feed is free, most require no API key for bulk downloads, and the data quality is community-verified.

This document provides implementation-ready specifications: exact HTTP request/response formats, Go code for the HTTP client, SQLite bulk import queries, Bloom filter sizing calculations, and a polling scheduler tuned for a Raspberry Pi 4's constrained resources.

**Key design decisions:**
- Bulk CSV/JSON downloads for all four feeds (no per-query API calls during normal operation)
- On-demand API lookups only for ThreatFox IOC enrichment on high-anomaly events
- SQLite with WAL mode for concurrent read/write
- Bloom filter as a fast-path pre-check before SQLite lookups
- TTL-based staleness scoring for offline operation

---

## 2. URLhaus API

### 2.1 Overview

URLhaus tracks malware distribution URLs reported by the infosec community. It is the most frequently updated abuse.ch feed and the most relevant for DNS-based detection in Vedetta.

- **Base URL**: `https://urlhaus-api.abuse.ch/v1/`
- **Authentication**: Auth-Key required (free, obtain at https://auth.abuse.ch/)
- **Rate Limits**: Fair use policy; no hard numeric limit published. Bulk download endpoints have no rate limit. Per-query API endpoints should be called conservatively (recommend ≤1 req/sec).
- **Data Freshness**: URLs are added in real-time as reporters submit them. The recent URLs endpoint returns entries added in the last 3 days.
- **Update Frequency**: Continuous; bulk CSV export regenerated every 5 minutes.

### 2.2 Endpoints

#### 2.2.1 Bulk Download — Recent URLs (Primary for Vedetta)

This is the preferred method for Vedetta. Download the full list on schedule rather than querying per-event.

```
GET https://urlhaus-api.abuse.ch/v1/urls/recent/
Header: Auth-Key: <your-auth-key>
```

**Response** (JSON array, truncated):
```json
{
  "query_status": "ok",
  "urls": [
    {
      "id": 2584937,
      "urlhaus_reference": "https://urlhaus.abuse.ch/url/2584937/",
      "url": "http://malicious-example.com/payload.exe",
      "url_status": "online",
      "host": "malicious-example.com",
      "date_added": "2026-03-27 10:15:30 UTC",
      "threat": "malware_download",
      "blacklists": {
        "spamhaus_dbl": "spammer_domain",
        "surbl": "listed"
      },
      "reporter": "abuse_ch",
      "larted": "true",
      "tags": ["elf", "mirai"]
    }
  ]
}
```

**Key fields for Vedetta**:
| Field | Type | Use in Vedetta |
|-------|------|----------------|
| `host` | string | Primary lookup key — matches against DNS queries |
| `url_status` | string | `online` / `offline` / `unknown` — weight scoring |
| `threat` | string | `malware_download` / `malware_c2` — maps to Vedetta tags |
| `tags` | array | Malware family names — stored as indicator tags |
| `date_added` | string | Used for TTL and freshness calculation |

#### 2.2.2 Bulk Download — CSV Export

```
GET https://urlhaus-api.abuse.ch/downloads/csv_recent/
```

Lighter weight than JSON. CSV columns:
```
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
```

#### 2.2.3 Host Lookup (On-Demand Enrichment)

```
POST https://urlhaus-api.abuse.ch/v1/host/
Header: Auth-Key: <your-auth-key>
Content-Type: application/x-www-form-urlencoded
Body: host=suspicious-domain.xyz
```

**Response**:
```json
{
  "query_status": "ok",
  "urlhaus_reference": "https://urlhaus.abuse.ch/host/suspicious-domain.xyz/",
  "host": "suspicious-domain.xyz",
  "url_count": 3,
  "blacklists": {
    "spamhaus_dbl": "not listed",
    "surbl": "not listed"
  },
  "urls": [
    {
      "id": 123456,
      "url": "http://suspicious-domain.xyz/mal.exe",
      "url_status": "offline",
      "date_added": "2026-03-20 08:30:00 UTC",
      "threat": "malware_download",
      "tags": ["emotet"]
    }
  ]
}
```

#### 2.2.4 URL Lookup

```
POST https://urlhaus-api.abuse.ch/v1/url/
Header: Auth-Key: <your-auth-key>
Content-Type: application/x-www-form-urlencoded
Body: url=http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/
```

#### 2.2.5 Payload Lookup (by hash)

```
POST https://urlhaus-api.abuse.ch/v1/payload/
Header: Auth-Key: <your-auth-key>
Content-Type: application/x-www-form-urlencoded
Body: md5_hash=12c1a3276381c24e2bc15b23bafa693a
      (or sha256_hash=...)
```

### 2.3 Optimal Polling Strategy for Raspberry Pi 4

| Method | Interval | Bandwidth | CPU Impact |
|--------|----------|-----------|------------|
| Bulk JSON recent URLs | Every 5 min | ~200-500 KB/fetch | Low (JSON parse) |
| Bulk CSV recent | Every 5 min | ~100-300 KB/fetch | Very low (CSV parse) |
| Per-host lookup | On-demand only | ~1 KB/query | Negligible |

**Recommendation**: Download bulk CSV every 5 minutes. Use per-host lookup only for high-anomaly events (anomaly_score > 0.7) that miss in the local DB—this caps API calls to a handful per day for a typical home network.

---

## 3. Feodo Tracker

### 3.1 Overview

Feodo Tracker tracks botnet command-and-control (C2) servers associated with Emotet (Heodo), Dridex, TrickBot, QakBot, and other banking trojans. This is IP-based intelligence—Vedetta checks resolved IPs against this list.

- **Base URL**: `https://feodotracker.abuse.ch/`
- **Authentication**: None required for blocklist downloads
- **Rate Limits**: None for bulk downloads. Generate every 5 minutes; fetch no more often than every 5 minutes.
- **Data Freshness**: Blocklist regenerated every 5 minutes
- **Update Frequency**: Real-time as C2s are discovered; list export every 5 min

### 3.2 Available Blocklist Formats

#### 3.2.1 Recommended IP Blocklist (Plain Text)

Best for firewall integration. Contains only IPs confirmed active in the last 30 days.

```
GET https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
```

**Format**: One IP per line, comment lines start with `#`
```
# Feodo Tracker Botnet C2 IP Blocklist (Recommended)
# Generated: 2026-03-27 10:00:00 UTC
#
# This blocklist only contains botnet C2s that are
# confirmed to be online/active in the last 30 days.
#
103.141.137.122
104.168.44.129
107.170.10.50
...
```

Typically ~200-400 IPs. Very small download (~5-10 KB).

#### 3.2.2 Full IP Blocklist (JSON)

Contains all tracked C2 IPs including historical/offline ones. More useful for Vedetta's enrichment since we want to flag connections to historically bad IPs too.

```
GET https://feodotracker.abuse.ch/downloads/ipblocklist.json
```

**Response**:
```json
[
  {
    "ip_address": "103.141.137.122",
    "port": 443,
    "status": "online",
    "hostname": null,
    "as_number": 135161,
    "as_name": "GMO-Z.COM PTE. LTD.",
    "country": "SG",
    "first_seen": "2026-03-15 08:30:00 UTC",
    "last_online": "2026-03-27 09:45:00 UTC",
    "malware": "QakBot"
  },
  {
    "ip_address": "104.168.44.129",
    "port": 8080,
    "status": "offline",
    "hostname": null,
    "as_number": 36352,
    "as_name": "ColoCrossing",
    "country": "US",
    "first_seen": "2026-01-10 14:20:00 UTC",
    "last_online": "2026-02-28 16:00:00 UTC",
    "malware": "Dridex"
  }
]
```

**Key fields for Vedetta**:
| Field | Type | Use in Vedetta |
|-------|------|----------------|
| `ip_address` | string | Primary lookup key — match against resolved IPs |
| `port` | int | Secondary matching — flag if dest port matches |
| `status` | string | `online`/`offline` — affects confidence score |
| `malware` | string | Maps to Vedetta indicator tags |
| `first_seen` | string | TTL/freshness calculation |
| `last_online` | string | Key for staleness scoring; null = never confirmed |

#### 3.2.3 CSV Format

```
GET https://feodotracker.abuse.ch/downloads/ipblocklist.csv
```

**Columns**:
```
first_seen_utc,dst_ip,dst_port,last_online,c2_status,c2_malware,country,as_number,as_name
```

#### 3.2.4 Aggressive Blocklist

Includes IPs from the last 30 days plus associated infrastructure. Larger list, more false positives.

```
GET https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt
```

### 3.3 Optimal Polling Strategy

| Method | Interval | Bandwidth | CPU Impact |
|--------|----------|-----------|------------|
| JSON full blocklist | Every 15 min | ~50-100 KB | Low |
| Recommended TXT | Every 15 min | ~5-10 KB | Negligible |
| CSV full | Every 15 min | ~30-60 KB | Low |

**Recommendation**: Download JSON full blocklist every 15 minutes. The list is small (~500-1000 entries) and JSON gives us all the metadata we need (malware family, status, port). The 15-minute interval balances freshness against Pi 4 resource usage given the list regenerates every 5 minutes.

---

## 4. SSLBL JA3 Fingerprints

### 4.1 Overview

SSLBL (SSL Blacklist) maintains a blacklist of malicious JA3 fingerprints collected from analyzing 25M+ malware PCAPs. JA3 is a method of fingerprinting TLS client hello messages—if Vedetta can compute JA3 hashes from observed TLS handshakes, it can match them against known-malicious fingerprints.

- **Base URL**: `https://sslbl.abuse.ch/`
- **Authentication**: None required
- **Rate Limits**: Fetch no more often than every 5 minutes
- **Data Freshness**: CSV regenerated every 5 minutes
- **Important caveat**: These fingerprints have NOT been fully tested against known-good traffic and may produce false positives. Use as a signal boost, not a hard block.

### 4.2 JA3 Fingerprint Blacklist (CSV)

```
GET https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
```

**Format**: CSV with comment header lines (starting with `#`)

```csv
# SSLBL JA3 Fingerprint Blacklist
# Generated: 2026-03-27 10:00:00 UTC
#
# This CSV contains JA3 fingerprints that have been identified
# as being associated with malware or botnet C2 traffic.
#
# Note: These fingerprints have not been tested against known
# good traffic and may cause false positives.
#
# ja3_md5,first_seen,last_seen,listing_reason
51c64c77e60f3980eea90869b68c58a8,2019-07-16 10:30:00,2026-03-27 08:00:00,Tofsee
e7d705a3286e19ea42f587b344ee6865,2019-06-12 14:20:00,2026-03-25 12:00:00,Emotet
6734f37431670b3ab4292b8f60f29984,2019-11-05 09:15:00,2026-03-26 22:00:00,TrickBot
a0e9f5d64349fb13191bc781f81f42e1,2020-01-20 16:40:00,2026-03-20 10:00:00,Dridex
72a589da586844d7f0818ce684948eea,2019-09-30 11:05:00,2026-03-27 06:00:00,CobaltStrike
...
```

**CSV columns**:
| Column | Type | Description |
|--------|------|-------------|
| `ja3_md5` | string (32 hex chars) | MD5 hash of the JA3 fingerprint |
| `first_seen` | datetime string | When fingerprint was first identified |
| `last_seen` | datetime string | When fingerprint was last seen in malware traffic |
| `listing_reason` | string | Malware family name (e.g., "Emotet", "CobaltStrike", "Dridex") |

**Typical size**: ~200-400 entries, ~15-25 KB file.

### 4.3 Additional SSLBL Blacklists

```
# SSL Certificate Blacklist (SHA1 fingerprints)
GET https://sslbl.abuse.ch/blacklist/sslblacklist.csv

# Columns: Listingdate,SHA1,Listingreason
# Useful if Vedetta inspects certificate fingerprints

# IP Blacklist (IPs associated with malicious SSL)
GET https://sslbl.abuse.ch/blacklist/sslipblacklist.csv

# Columns: Firstseen,DstIP,DstPort
# Overlaps somewhat with Feodo Tracker
```

### 4.4 Optimal Polling Strategy

| Method | Interval | Bandwidth | CPU Impact |
|--------|----------|-----------|------------|
| JA3 CSV | Every 6 hours | ~15-25 KB | Negligible |
| SSL cert CSV | Every 6 hours | ~50-100 KB | Low |
| IP blacklist CSV | Every 6 hours | ~20-40 KB | Negligible |

**Recommendation**: Download JA3 CSV every 6 hours. The list is very stable (new entries added infrequently) and small. JA3 matching is only useful if Vedetta implements TLS handshake capture, which is a Phase 2+ feature. Store the data now for future use. The low update frequency makes this the lightest feed on Pi 4 resources.

---

## 5. ThreatFox API

### 5.1 Overview

ThreatFox is the most general-purpose feed in the abuse.ch ecosystem—it aggregates IOCs (IPs, domains, URLs, hashes) associated with malware, submitted by the community. It includes MITRE ATT&CK mappings and malware family classification.

- **Base URL**: `https://threatfox-api.abuse.ch/api/v1/`
- **Authentication**: Auth-Key required (free, obtain at https://auth.abuse.ch/)
- **Rate Limits**: Fair use policy. Bulk export available without API calls.
- **Data Freshness**: IOCs added in real-time. Since 2025-05-01, IOCs older than 6 months are expired and removed from the API.
- **Update Frequency**: Continuous; bulk export regenerated periodically

### 5.2 API Endpoints

All endpoints use `POST` to `https://threatfox-api.abuse.ch/api/v1/` with JSON body and the `Auth-Key` header.

#### 5.2.1 Get Recent IOCs (Primary for Vedetta Bulk Download)

```bash
curl -H "Auth-Key: YOUR-AUTH-KEY" \
     -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "get_iocs", "days": 7 }'
```

**Response**:
```json
{
  "query_status": "ok",
  "data": [
    {
      "id": "1558251",
      "ioc": "194.87.71.2:443",
      "threat_type": "botnet_cc",
      "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
      "ioc_type": "ip:port",
      "ioc_type_desc": "ip:port combination that is used for botnet C&C communication",
      "malware": "win.cobalt_strike",
      "malware_printable": "Cobalt Strike",
      "malware_alias": "Agentemis,BEACON,CobaltStrike",
      "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
      "confidence_level": 75,
      "first_seen": "2026-03-20 14:30:00 UTC",
      "last_seen": null,
      "reporter": "abuse_ch",
      "reference": "https://bazaar.abuse.ch/sample/abc123/",
      "tags": ["CobaltStrike", "c2"]
    }
  ]
}
```

**Key fields for Vedetta**:
| Field | Type | Use in Vedetta |
|-------|------|----------------|
| `ioc` | string | The indicator value (IP:port, domain, URL, hash) |
| `ioc_type` | string | `ip:port`, `domain`, `url`, `md5`, `sha256` |
| `threat_type` | string | `botnet_cc`, `payload_delivery`, `payload` |
| `malware_printable` | string | Human-readable malware name |
| `confidence_level` | int | 0-100; maps to Vedetta's 0.0-1.0 confidence |
| `first_seen` | string | TTL calculation |
| `tags` | array | Direct mapping to Vedetta indicator tags |

#### 5.2.2 Search IOC

```bash
curl -H "Auth-Key: YOUR-AUTH-KEY" \
     -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "search_ioc", "search_term": "139.180.203.104" }'
```

#### 5.2.3 Search by File Hash

```bash
curl -H "Auth-Key: YOUR-AUTH-KEY" \
     -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "search_hash", "hash": "2151c4b970eff0071948dbbc19066aa4" }'
```

#### 5.2.4 Query IOC by ID

```bash
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "ioc", "id": 41 }'
```

#### 5.2.5 Query by Tag

```bash
curl -H "Auth-Key: YOUR-AUTH-KEY" \
     -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "taginfo", "tag": "CobaltStrike", "limit": 100 }'
```

#### 5.2.6 Query by Malware Family

```bash
curl -H "Auth-Key: YOUR-AUTH-KEY" \
     -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "malwareinfo", "malware": "win.cobalt_strike", "limit": 100 }'
```

#### 5.2.7 Get IOC Types

```bash
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "types" }'
```

#### 5.2.8 Get Malware List

```bash
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "malware_list" }'
```

#### 5.2.9 Get Tag List

```bash
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
     -d '{ "query": "tag_list" }'
```

### 5.3 Bulk Export (No API Key Required)

ThreatFox also provides bulk CSV/JSON exports that don't require API authentication:

```
GET https://threatfox.abuse.ch/export/json/recent/
GET https://threatfox.abuse.ch/export/csv/recent/
```

These are the preferred method for scheduled downloads on Vedetta.

### 5.4 Optimal Polling Strategy

| Method | Interval | Bandwidth | CPU Impact |
|--------|----------|-----------|------------|
| Bulk export JSON (7 days) | Every 30 min | ~500 KB-2 MB | Moderate (JSON parse) |
| `get_iocs` API (1 day) | Every 30 min | ~200-500 KB | Low-Moderate |
| `search_ioc` on-demand | Per high-anomaly event | ~1 KB | Negligible |

**Recommendation**: Use bulk export JSON every 30 minutes for scheduled ingestion. Use `search_ioc` API for on-demand enrichment of events with anomaly_score > 0.7 that miss in local DB. The 30-minute interval reflects ThreatFox's slower ingestion rate compared to URLhaus.

---

## 6. Feed Download Scheduler Design

### 6.1 Bulk Download vs. On-Demand Query Decision Matrix

| Feed | Strategy | Rationale |
|------|----------|-----------|
| URLhaus recent URLs | **Bulk download** (CSV) | Small, fast-changing, domain-based matching is Vedetta's primary use case |
| Feodo Tracker IPs | **Bulk download** (JSON) | Small list (~500 IPs), need full metadata for enrichment |
| SSLBL JA3 | **Bulk download** (CSV) | Tiny list (~300 entries), very stable, no API needed |
| ThreatFox IOCs | **Bulk download** (JSON export) + **On-demand** query | Bulk for scheduled sync; on-demand for enriching flagged events |
| URLhaus host lookup | **On-demand only** | Supplement bulk data for high-confidence investigations |
| ThreatFox search_ioc | **On-demand only** | Enrich events that score > 0.7 anomaly but miss in local DB |

### 6.2 Scheduler Configuration

```go
type FeedSchedule struct {
    Name     string
    URL      string
    Interval time.Duration
    Parser   FeedParser
    Priority int // Lower = higher priority for bandwidth allocation
}

var DefaultSchedule = []FeedSchedule{
    {
        Name:     "urlhaus_recent",
        URL:      "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        Interval: 5 * time.Minute,
        Parser:   ParseURLhausJSON,
        Priority: 1,
    },
    {
        Name:     "feodo_blocklist",
        URL:      "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        Interval: 15 * time.Minute,
        Parser:   ParseFeodoJSON,
        Priority: 2,
    },
    {
        Name:     "threatfox_recent",
        URL:      "https://threatfox.abuse.ch/export/json/recent/",
        Interval: 30 * time.Minute,
        Parser:   ParseThreatFoxJSON,
        Priority: 3,
    },
    {
        Name:     "sslbl_ja3",
        URL:      "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        Interval: 6 * time.Hour,
        Parser:   ParseSSLBLCSV,
        Priority: 4,
    },
}
```

### 6.3 Jitter and Backoff

To avoid thundering herd on the Pi and to be polite to abuse.ch:

```go
const (
    maxJitter     = 30 * time.Second  // Random jitter added to each interval
    initialBackoff = 1 * time.Minute  // Backoff on HTTP error
    maxBackoff     = 1 * time.Hour    // Cap backoff
    backoffFactor  = 2.0              // Exponential backoff multiplier
)
```

### 6.4 Bandwidth Budget

On a Raspberry Pi 4 with a typical home connection:

| Feed | Per-Fetch Size | Fetches/Day | Daily Bandwidth |
|------|---------------|-------------|-----------------|
| URLhaus CSV | ~300 KB | 288 | ~84 MB |
| Feodo JSON | ~75 KB | 96 | ~7 MB |
| ThreatFox JSON | ~1 MB | 48 | ~48 MB |
| SSLBL JA3 CSV | ~20 KB | 4 | ~0.08 MB |
| **Total** | | **436** | **~139 MB/day** |

This is well within Pi 4 capabilities. If bandwidth is constrained, reduce URLhaus to every 15 minutes (28 MB/day) and ThreatFox to every hour (24 MB/day), bringing total to ~59 MB/day.

---

## 7. SQLite Storage Layer

### 7.1 Schema (extends `threat_indicators` from 05-threat-intelligence-feeds.md)

```sql
-- Core indicator table (as defined in parent doc, with additions)
CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash_md5', 'hash_sha256', 'ip_port')),
    source TEXT NOT NULL CHECK(source IN ('urlhaus', 'feodotracker', 'sslbl', 'threatfox', 'greynoise', 'otx', 'manual')),
    confidence REAL NOT NULL DEFAULT 0.5 CHECK(confidence >= 0.0 AND confidence <= 1.0),
    tags TEXT,  -- JSON array, e.g. '["emotet","c2"]'
    first_seen TEXT NOT NULL,  -- ISO 8601
    last_seen TEXT NOT NULL,   -- ISO 8601
    ttl_hours INTEGER NOT NULL DEFAULT 168,  -- 7 days default
    -- abuse.ch-specific metadata
    malware_family TEXT,       -- e.g. "Emotet", "CobaltStrike", "QakBot"
    threat_type TEXT,          -- e.g. "botnet_cc", "malware_download", "payload_delivery"
    status TEXT,               -- e.g. "online", "offline"
    port INTEGER,              -- For ip:port indicators (Feodo, ThreatFox)
    country TEXT,              -- 2-letter country code
    as_number INTEGER,         -- ASN for IP indicators
    raw_reference TEXT,        -- URL back to abuse.ch entry
    PRIMARY KEY (indicator, source)
);

-- Indexes for fast lookup patterns
CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator);
CREATE INDEX IF NOT EXISTS idx_ti_type ON threat_indicators(type);
CREATE INDEX IF NOT EXISTS idx_ti_source ON threat_indicators(source);
CREATE INDEX IF NOT EXISTS idx_ti_last_seen ON threat_indicators(last_seen);
CREATE INDEX IF NOT EXISTS idx_ti_malware ON threat_indicators(malware_family);
CREATE INDEX IF NOT EXISTS idx_ti_confidence ON threat_indicators(confidence DESC);

-- Feed metadata table for tracking sync state
CREATE TABLE IF NOT EXISTS feed_sync_state (
    feed_name TEXT PRIMARY KEY,
    last_sync TEXT NOT NULL,     -- ISO 8601
    last_success TEXT,           -- ISO 8601
    entries_count INTEGER DEFAULT 0,
    http_etag TEXT,              -- For conditional GET
    http_last_modified TEXT,     -- For conditional GET
    consecutive_failures INTEGER DEFAULT 0,
    next_sync TEXT               -- ISO 8601, computed from interval + backoff
);

-- Indicator staleness view
CREATE VIEW IF NOT EXISTS v_indicator_freshness AS
SELECT
    indicator,
    type,
    source,
    confidence,
    malware_family,
    last_seen,
    ttl_hours,
    CASE
        WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours THEN 'fresh'
        WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours * 2 THEN 'stale'
        ELSE 'expired'
    END AS freshness,
    -- Effective confidence: decays as indicator ages past TTL
    CASE
        WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours THEN confidence
        ELSE confidence * MAX(0.1, 1.0 - ((julianday('now') - julianday(last_seen)) * 24 - ttl_hours) / (ttl_hours * 2.0))
    END AS effective_confidence
FROM threat_indicators;
```

### 7.2 SQLite Configuration for Pi 4

```sql
-- WAL mode for concurrent reads during bulk import
PRAGMA journal_mode = WAL;

-- Reduce sync frequency (acceptable since this is cache data)
PRAGMA synchronous = NORMAL;

-- 16 MB cache (conservative for Pi 4's 4GB RAM)
PRAGMA cache_size = -16000;

-- Memory-mapped I/O: 64 MB (helps with read performance)
PRAGMA mmap_size = 67108864;

-- Page size 4096 (matches ARM page size)
PRAGMA page_size = 4096;
```

### 7.3 Storage Estimates

| Feed | Avg Indicators | Row Size (est.) | Table Size |
|------|---------------|-----------------|------------|
| URLhaus | ~10,000 active domains | ~200 bytes | ~2 MB |
| Feodo Tracker | ~500 IPs | ~250 bytes | ~0.13 MB |
| SSLBL JA3 | ~300 fingerprints | ~150 bytes | ~0.05 MB |
| ThreatFox | ~5,000 IOCs (6-month window) | ~250 bytes | ~1.25 MB |
| **Total** | **~15,800** | | **~3.5 MB** |

With indexes: ~5-8 MB total. Negligible on Pi 4.

---

## 8. Bloom Filter for Fast Domain Lookups

### 8.1 Why a Bloom Filter

Vedetta's DNS monitoring generates high-volume events. Every DNS query needs to be checked against the threat intel DB. A Bloom filter provides O(1) pre-check: if the filter says "not present," skip the SQLite lookup entirely. Only on a positive hit do we go to SQLite for full metadata.

### 8.2 Sizing Calculations

The Bloom filter parameters depend on the number of expected elements (n) and the desired false positive rate (p).

**Formula**: Optimal bit array size `m = -(n * ln(p)) / (ln(2))^2`
**Formula**: Optimal hash functions `k = (m/n) * ln(2)`

| n (indicators) | p (false positive rate) | m (bits) | m (MB) | k (hash functions) | Notes |
|----------------|------------------------|----------|--------|-------------------|-------|
| 20,000 | 1% (0.01) | 191,702 | 0.023 | 7 | Good balance |
| 20,000 | 0.1% (0.001) | 287,553 | 0.034 | 10 | Better accuracy |
| 20,000 | 0.01% (0.0001) | 383,404 | 0.046 | 13 | Overkill for home use |
| 50,000 | 1% (0.01) | 479,253 | 0.057 | 7 | Future growth |
| 50,000 | 0.1% (0.001) | 718,880 | 0.086 | 10 | Recommended target |
| 100,000 | 0.1% (0.001) | 1,437,759 | 0.172 | 10 | Maximum headroom |

**Recommendation**: Size for n=50,000 at p=0.1% (0.001). This gives ~86 KB of memory—trivial on Pi 4—with 10 hash functions and room for growth as more feeds are added. At this size, for every 1,000 DNS queries, only ~1 will falsely trigger a SQLite lookup.

### 8.3 Implementation

```go
package threatintel

import (
    "hash"
    "hash/fnv"
    "math"
    "sync"
)

// BloomFilter provides probabilistic set membership testing
// for fast-path threat indicator lookups.
type BloomFilter struct {
    mu       sync.RWMutex
    bits     []uint64
    numBits  uint64
    numHash  uint64
    count    uint64
}

// NewBloomFilter creates a Bloom filter optimized for n elements
// at false positive rate p.
func NewBloomFilter(n uint64, p float64) *BloomFilter {
    m := uint64(math.Ceil(-float64(n) * math.Log(p) / (math.Log(2) * math.Log(2))))
    k := uint64(math.Ceil(float64(m) / float64(n) * math.Log(2)))

    // Round up to nearest 64-bit boundary
    words := (m + 63) / 64

    return &BloomFilter{
        bits:    make([]uint64, words),
        numBits: words * 64,
        numHash: k,
    }
}

// Add inserts an indicator into the Bloom filter.
func (bf *BloomFilter) Add(indicator string) {
    bf.mu.Lock()
    defer bf.mu.Unlock()

    h1, h2 := bf.hashes([]byte(indicator))
    for i := uint64(0); i < bf.numHash; i++ {
        pos := (h1 + i*h2) % bf.numBits
        bf.bits[pos/64] |= 1 << (pos % 64)
    }
    bf.count++
}

// MayContain returns true if the indicator MIGHT be in the set.
// False means definitely not present. True means check SQLite.
func (bf *BloomFilter) MayContain(indicator string) bool {
    bf.mu.RLock()
    defer bf.mu.RUnlock()

    h1, h2 := bf.hashes([]byte(indicator))
    for i := uint64(0); i < bf.numHash; i++ {
        pos := (h1 + i*h2) % bf.numBits
        if bf.bits[pos/64]&(1<<(pos%64)) == 0 {
            return false
        }
    }
    return true
}

// Reset clears the filter for rebuild after a feed refresh.
func (bf *BloomFilter) Reset() {
    bf.mu.Lock()
    defer bf.mu.Unlock()

    for i := range bf.bits {
        bf.bits[i] = 0
    }
    bf.count = 0
}

// hashes computes two independent hashes using FNV for double hashing.
func (bf *BloomFilter) hashes(data []byte) (uint64, uint64) {
    h := fnv.New128a()
    h.Write(data)
    sum := h.Sum(nil)

    h1 := uint64(sum[0])<<56 | uint64(sum[1])<<48 | uint64(sum[2])<<40 | uint64(sum[3])<<32 |
        uint64(sum[4])<<24 | uint64(sum[5])<<16 | uint64(sum[6])<<8 | uint64(sum[7])
    h2 := uint64(sum[8])<<56 | uint64(sum[9])<<48 | uint64(sum[10])<<40 | uint64(sum[11])<<32 |
        uint64(sum[12])<<24 | uint64(sum[13])<<16 | uint64(sum[14])<<8 | uint64(sum[15])

    return h1, h2
}

// Count returns the number of elements added.
func (bf *BloomFilter) Count() uint64 {
    bf.mu.RLock()
    defer bf.mu.RUnlock()
    return bf.count
}
```

### 8.4 Rebuild Strategy

The Bloom filter is rebuilt after every bulk feed import. Since the filter is tiny (~86 KB), a full rebuild is cheaper than incremental updates and avoids the monotonic false-positive degradation problem.

```go
func (db *ThreatIntelDB) RebuildBloomFilter() error {
    newFilter := NewBloomFilter(50000, 0.001)

    rows, err := db.db.Query("SELECT indicator FROM threat_indicators")
    if err != nil {
        return fmt.Errorf("bloom rebuild query: %w", err)
    }
    defer rows.Close()

    for rows.Next() {
        var indicator string
        if err := rows.Scan(&indicator); err != nil {
            return fmt.Errorf("bloom rebuild scan: %w", err)
        }
        newFilter.Add(indicator)
    }

    db.mu.Lock()
    db.bloomFilter = newFilter
    db.mu.Unlock()

    return nil
}
```

---

## 9. Offline Graceful Degradation

### 9.1 TTL-Based Staleness Scoring

When Vedetta cannot reach abuse.ch feeds (ISP outage, air-gapped network), indicators degrade gracefully using a TTL-based decay function.

```go
// EffectiveConfidence calculates the time-decayed confidence of an indicator.
// Fresh indicators retain full confidence. Stale indicators decay linearly.
// Expired indicators retain a 10% floor (still useful as weak signals).
func EffectiveConfidence(indicator Indicator, now time.Time) float64 {
    age := now.Sub(indicator.LastSeen)
    ttl := indicator.TTL

    switch {
    case age <= ttl:
        // Fresh: full confidence
        return indicator.Confidence
    case age <= ttl*2:
        // Stale: linear decay from 100% to 10% of confidence
        decay := 1.0 - 0.9*(float64(age-ttl)/float64(ttl))
        return indicator.Confidence * decay
    default:
        // Expired: floor at 10% of original confidence
        return indicator.Confidence * 0.1
    }
}
```

### 9.2 Default TTL Values by Source

| Source | Default TTL | Rationale |
|--------|------------|-----------|
| URLhaus (online status) | 24 hours | Malware URLs go offline quickly |
| URLhaus (offline status) | 7 days | Domain may still be reused |
| Feodo Tracker (online) | 48 hours | C2 IPs rotate but are reused |
| Feodo Tracker (offline) | 14 days | Historical C2 IPs still suspicious |
| SSLBL JA3 | 90 days | JA3 fingerprints are stable |
| ThreatFox (high confidence) | 7 days | Depends on IOC type |
| ThreatFox (low confidence) | 3 days | Lower confidence = shorter shelf life |

### 9.3 Offline Detection and Status Reporting

```go
type FeedHealth struct {
    FeedName           string
    LastSuccessfulSync time.Time
    ConsecutiveFailures int
    IsStale            bool   // True if last sync > 2x interval
    StalenessRatio     float64 // 0.0 = fresh, 1.0 = all indicators expired
    IndicatorCount     int
    FreshCount         int
    StaleCount         int
    ExpiredCount       int
}

func (db *ThreatIntelDB) GetFeedHealth() ([]FeedHealth, error) {
    // Query feed_sync_state joined with indicator freshness counts
    query := `
        SELECT
            fs.feed_name,
            fs.last_success,
            fs.consecutive_failures,
            fs.entries_count,
            COUNT(CASE WHEN v.freshness = 'fresh' THEN 1 END) as fresh_count,
            COUNT(CASE WHEN v.freshness = 'stale' THEN 1 END) as stale_count,
            COUNT(CASE WHEN v.freshness = 'expired' THEN 1 END) as expired_count
        FROM feed_sync_state fs
        LEFT JOIN v_indicator_freshness v ON v.source = fs.feed_name
        GROUP BY fs.feed_name
    `
    // ... execute and return
}
```

---

## 10. Go Implementation: HTTP Client Package

### 10.1 Core HTTP Client

```go
package threatintel

import (
    "context"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// Client is the HTTP client for all abuse.ch API interactions.
type Client struct {
    httpClient *http.Client
    authKey    string // abuse.ch Auth-Key (free)
    userAgent  string
}

// NewClient creates an abuse.ch API client configured for Pi 4.
func NewClient(authKey string) *Client {
    return &Client{
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                MaxIdleConns:        5,
                MaxIdleConnsPerHost: 2,
                IdleConnTimeout:     90 * time.Second,
                // Conservative for Pi 4: limit concurrent connections
                MaxConnsPerHost:     2,
            },
        },
        authKey:   authKey,
        userAgent: "Vedetta/1.0 (home-siem; +https://github.com/vedetta-project)",
    }
}

// doGet performs a GET request with standard headers.
func (c *Client) doGet(ctx context.Context, rawURL string) (*http.Response, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
    if err != nil {
        return nil, fmt.Errorf("creating request: %w", err)
    }
    req.Header.Set("User-Agent", c.userAgent)
    if c.authKey != "" {
        req.Header.Set("Auth-Key", c.authKey)
    }
    return c.httpClient.Do(req)
}

// doPost performs a POST request with form-encoded or JSON body.
func (c *Client) doPost(ctx context.Context, rawURL string, contentType string, body string) (*http.Response, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
    if err != nil {
        return nil, fmt.Errorf("creating request: %w", err)
    }
    req.Header.Set("User-Agent", c.userAgent)
    req.Header.Set("Content-Type", contentType)
    if c.authKey != "" {
        req.Header.Set("Auth-Key", c.authKey)
    }
    return c.httpClient.Do(req)
}
```

### 10.2 URLhaus Feed Downloader

```go
// URLhausEntry represents a single entry from the URLhaus recent feed.
type URLhausEntry struct {
    ID              int      `json:"id"`
    URLhausRef      string   `json:"urlhaus_reference"`
    URL             string   `json:"url"`
    URLStatus       string   `json:"url_status"`
    Host            string   `json:"host"`
    DateAdded       string   `json:"date_added"`
    Threat          string   `json:"threat"`
    Tags            []string `json:"tags"`
    Reporter        string   `json:"reporter"`
}

type URLhausRecentResponse struct {
    QueryStatus string         `json:"query_status"`
    URLs        []URLhausEntry `json:"urls"`
}

// FetchURLhausRecent downloads the recent URLs feed.
func (c *Client) FetchURLhausRecent(ctx context.Context) ([]Indicator, error) {
    resp, err := c.doGet(ctx, "https://urlhaus-api.abuse.ch/v1/urls/recent/")
    if err != nil {
        return nil, fmt.Errorf("urlhaus fetch: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("urlhaus HTTP %d", resp.StatusCode)
    }

    var result URLhausRecentResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("urlhaus decode: %w", err)
    }

    if result.QueryStatus != "ok" {
        return nil, fmt.Errorf("urlhaus query status: %s", result.QueryStatus)
    }

    indicators := make([]Indicator, 0, len(result.URLs))
    for _, u := range result.URLs {
        confidence := 0.7
        if u.URLStatus == "online" {
            confidence = 0.9
        } else if u.URLStatus == "offline" {
            confidence = 0.5
        }

        ttl := 7 * 24 * time.Hour // 7 days default
        if u.URLStatus == "online" {
            ttl = 24 * time.Hour // Online URLs get shorter TTL
        }

        threatType := "malware_download"
        if u.Threat != "" {
            threatType = u.Threat
        }

        indicators = append(indicators, Indicator{
            Value:         u.Host,
            Type:          "domain",
            Source:        "urlhaus",
            Confidence:    confidence,
            Tags:          u.Tags,
            FirstSeen:     parseAbuseCHTime(u.DateAdded),
            LastSeen:      time.Now(),
            TTL:           ttl,
            MalwareFamily: inferMalwareFamily(u.Tags),
            ThreatType:    threatType,
            Status:        u.URLStatus,
            RawReference:  u.URLhausRef,
        })
    }

    return indicators, nil
}

// LookupHost queries URLhaus for a specific host (on-demand enrichment).
func (c *Client) LookupURLhausHost(ctx context.Context, host string) ([]Indicator, error) {
    body := url.Values{"host": {host}}.Encode()
    resp, err := c.doPost(ctx, "https://urlhaus-api.abuse.ch/v1/host/",
        "application/x-www-form-urlencoded", body)
    if err != nil {
        return nil, fmt.Errorf("urlhaus host lookup: %w", err)
    }
    defer resp.Body.Close()

    var result struct {
        QueryStatus string         `json:"query_status"`
        Host        string         `json:"host"`
        URLCount    int            `json:"url_count"`
        URLs        []URLhausEntry `json:"urls"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("urlhaus host decode: %w", err)
    }

    if result.QueryStatus == "no_results" {
        return nil, nil // Clean host
    }

    // Convert to indicators...
    indicators := make([]Indicator, 0, 1)
    if result.URLCount > 0 {
        indicators = append(indicators, Indicator{
            Value:      host,
            Type:       "domain",
            Source:     "urlhaus",
            Confidence: min(0.5+float64(result.URLCount)*0.1, 0.95),
            Tags:       []string{"urlhaus_known"},
            FirstSeen:  parseAbuseCHTime(result.URLs[0].DateAdded),
            LastSeen:   time.Now(),
            TTL:        7 * 24 * time.Hour,
        })
    }

    return indicators, nil
}
```

### 10.3 Feodo Tracker Feed Downloader

```go
// FeodoEntry represents a C2 IP from Feodo Tracker.
type FeodoEntry struct {
    IPAddress  string `json:"ip_address"`
    Port       int    `json:"port"`
    Status     string `json:"status"`
    Hostname   string `json:"hostname"`
    ASNumber   int    `json:"as_number"`
    ASName     string `json:"as_name"`
    Country    string `json:"country"`
    FirstSeen  string `json:"first_seen"`
    LastOnline string `json:"last_online"`
    Malware    string `json:"malware"`
}

// FetchFeodoBlocklist downloads the full Feodo Tracker IP blocklist.
func (c *Client) FetchFeodoBlocklist(ctx context.Context) ([]Indicator, error) {
    resp, err := c.doGet(ctx, "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if err != nil {
        return nil, fmt.Errorf("feodo fetch: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("feodo HTTP %d", resp.StatusCode)
    }

    var entries []FeodoEntry
    if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
        return nil, fmt.Errorf("feodo decode: %w", err)
    }

    indicators := make([]Indicator, 0, len(entries))
    for _, e := range entries {
        confidence := 0.8
        ttl := 14 * 24 * time.Hour
        if e.Status == "online" {
            confidence = 0.95
            ttl = 48 * time.Hour
        }

        firstSeen := parseAbuseCHTime(e.FirstSeen)
        lastSeen := parseAbuseCHTime(e.LastOnline)
        if lastSeen.IsZero() {
            lastSeen = firstSeen
        }

        indicators = append(indicators, Indicator{
            Value:         e.IPAddress,
            Type:          "ipv4",
            Source:        "feodotracker",
            Confidence:    confidence,
            Tags:          []string{"c2", "botnet", strings.ToLower(e.Malware)},
            FirstSeen:     firstSeen,
            LastSeen:      lastSeen,
            TTL:           ttl,
            MalwareFamily: e.Malware,
            ThreatType:    "botnet_cc",
            Status:        e.Status,
            Port:          e.Port,
            Country:       e.Country,
            ASNumber:      e.ASNumber,
        })
    }

    return indicators, nil
}
```

### 10.4 SSLBL JA3 Feed Downloader

```go
// FetchSSLBLJA3 downloads and parses the JA3 fingerprint blacklist CSV.
func (c *Client) FetchSSLBLJA3(ctx context.Context) ([]Indicator, error) {
    resp, err := c.doGet(ctx, "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv")
    if err != nil {
        return nil, fmt.Errorf("sslbl fetch: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("sslbl HTTP %d", resp.StatusCode)
    }

    reader := csv.NewReader(resp.Body)
    reader.Comment = '#'
    reader.TrimLeadingSpace = true

    var indicators []Indicator

    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            continue // Skip malformed rows
        }
        if len(record) < 4 {
            continue
        }

        // Columns: ja3_md5, first_seen, last_seen, listing_reason
        ja3Hash := strings.TrimSpace(record[0])
        firstSeen := parseAbuseCHTime(strings.TrimSpace(record[1]))
        lastSeen := parseAbuseCHTime(strings.TrimSpace(record[2]))
        listingReason := strings.TrimSpace(record[3])

        if len(ja3Hash) != 32 {
            continue // Not a valid MD5 hash
        }

        indicators = append(indicators, Indicator{
            Value:         ja3Hash,
            Type:          "ja3",
            Source:        "sslbl",
            Confidence:    0.6, // Lower due to documented false positive risk
            Tags:          []string{"ja3", "tls_fingerprint", strings.ToLower(listingReason)},
            FirstSeen:     firstSeen,
            LastSeen:      lastSeen,
            TTL:           90 * 24 * time.Hour, // 90 days — JA3 fingerprints are stable
            MalwareFamily: listingReason,
            ThreatType:    "malicious_tls",
        })
    }

    return indicators, nil
}
```

### 10.5 ThreatFox Feed Downloader

```go
// ThreatFoxIOC represents a single IOC from ThreatFox.
type ThreatFoxIOC struct {
    ID              string   `json:"id"`
    IOC             string   `json:"ioc"`
    ThreatType      string   `json:"threat_type"`
    ThreatTypeDesc  string   `json:"threat_type_desc"`
    IOCType         string   `json:"ioc_type"`
    IOCTypeDesc     string   `json:"ioc_type_desc"`
    Malware         string   `json:"malware"`
    MalwarePrintable string  `json:"malware_printable"`
    MalwareAlias    string   `json:"malware_alias"`
    MalwareMalpedia string   `json:"malware_malpedia"`
    ConfidenceLevel int      `json:"confidence_level"`
    FirstSeen       string   `json:"first_seen"`
    LastSeen        *string  `json:"last_seen"` // nullable
    Reporter        string   `json:"reporter"`
    Reference       string   `json:"reference"`
    Tags            []string `json:"tags"`
}

type ThreatFoxResponse struct {
    QueryStatus string         `json:"query_status"`
    Data        []ThreatFoxIOC `json:"data"`
}

// FetchThreatFoxRecent downloads recent IOCs from ThreatFox.
func (c *Client) FetchThreatFoxRecent(ctx context.Context, days int) ([]Indicator, error) {
    body := fmt.Sprintf(`{"query": "get_iocs", "days": %d}`, days)
    resp, err := c.doPost(ctx, "https://threatfox-api.abuse.ch/api/v1/",
        "application/json", body)
    if err != nil {
        return nil, fmt.Errorf("threatfox fetch: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("threatfox HTTP %d", resp.StatusCode)
    }

    var result ThreatFoxResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("threatfox decode: %w", err)
    }

    if result.QueryStatus != "ok" {
        return nil, fmt.Errorf("threatfox query status: %s", result.QueryStatus)
    }

    indicators := make([]Indicator, 0, len(result.Data))
    for _, ioc := range result.Data {
        indicatorType := mapThreatFoxIOCType(ioc.IOCType)
        indicatorValue := ioc.IOC
        port := 0

        // Parse ip:port format
        if ioc.IOCType == "ip:port" {
            parts := strings.SplitN(ioc.IOC, ":", 2)
            indicatorValue = parts[0]
            indicatorType = "ipv4"
            if len(parts) == 2 {
                fmt.Sscanf(parts[1], "%d", &port)
            }
        }

        confidence := float64(ioc.ConfidenceLevel) / 100.0
        ttl := 7 * 24 * time.Hour
        if confidence < 0.5 {
            ttl = 3 * 24 * time.Hour
        }

        firstSeen := parseAbuseCHTime(ioc.FirstSeen)
        lastSeen := time.Now()
        if ioc.LastSeen != nil {
            lastSeen = parseAbuseCHTime(*ioc.LastSeen)
        }

        indicators = append(indicators, Indicator{
            Value:         indicatorValue,
            Type:          indicatorType,
            Source:        "threatfox",
            Confidence:    confidence,
            Tags:          ioc.Tags,
            FirstSeen:     firstSeen,
            LastSeen:      lastSeen,
            TTL:           ttl,
            MalwareFamily: ioc.MalwarePrintable,
            ThreatType:    ioc.ThreatType,
            Port:          port,
            RawReference:  ioc.Reference,
        })
    }

    return indicators, nil
}

// SearchThreatFoxIOC performs an on-demand lookup for a specific indicator.
func (c *Client) SearchThreatFoxIOC(ctx context.Context, searchTerm string) ([]Indicator, error) {
    body := fmt.Sprintf(`{"query": "search_ioc", "search_term": "%s"}`, searchTerm)
    resp, err := c.doPost(ctx, "https://threatfox-api.abuse.ch/api/v1/",
        "application/json", body)
    if err != nil {
        return nil, fmt.Errorf("threatfox search: %w", err)
    }
    defer resp.Body.Close()

    var result ThreatFoxResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    // Same conversion logic as FetchThreatFoxRecent...
    // (omitted for brevity — same mapping applies)
    return nil, nil
}

// Helper: map ThreatFox IOC types to Vedetta indicator types
func mapThreatFoxIOCType(tfType string) string {
    switch tfType {
    case "ip:port":
        return "ip_port"
    case "domain":
        return "domain"
    case "url":
        return "url"
    case "md5":
        return "hash_md5"
    case "sha256":
        return "hash_sha256"
    default:
        return tfType
    }
}

// Helper: parse abuse.ch datetime format "2026-03-27 10:15:30 UTC"
func parseAbuseCHTime(s string) time.Time {
    layouts := []string{
        "2006-01-02 15:04:05 MST",
        "2006-01-02 15:04:05",
        "2006-01-02",
    }
    for _, layout := range layouts {
        if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
            return t
        }
    }
    return time.Time{}
}

// Helper: infer malware family from URLhaus tags
func inferMalwareFamily(tags []string) string {
    knownFamilies := map[string]bool{
        "emotet": true, "trickbot": true, "dridex": true,
        "qakbot": true, "qbot": true, "mirai": true,
        "gozi": true, "formbook": true, "lokibot": true,
        "agenttesla": true, "cobaltstrike": true, "raccoon": true,
    }
    for _, tag := range tags {
        lower := strings.ToLower(tag)
        if knownFamilies[lower] {
            return tag
        }
    }
    return ""
}
```

---

## 11. Bulk Import SQLite Queries

### 11.1 Upsert Pattern (INSERT OR REPLACE)

```sql
-- Bulk import with conflict resolution: update if newer data
INSERT INTO threat_indicators (
    indicator, type, source, confidence, tags,
    first_seen, last_seen, ttl_hours,
    malware_family, threat_type, status, port, country, as_number, raw_reference
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(indicator, source) DO UPDATE SET
    confidence = MAX(excluded.confidence, threat_indicators.confidence),
    tags = excluded.tags,
    last_seen = CASE
        WHEN excluded.last_seen > threat_indicators.last_seen THEN excluded.last_seen
        ELSE threat_indicators.last_seen
    END,
    ttl_hours = excluded.ttl_hours,
    malware_family = COALESCE(excluded.malware_family, threat_indicators.malware_family),
    threat_type = COALESCE(excluded.threat_type, threat_indicators.threat_type),
    status = excluded.status,
    port = COALESCE(excluded.port, threat_indicators.port),
    country = COALESCE(excluded.country, threat_indicators.country),
    as_number = COALESCE(excluded.as_number, threat_indicators.as_number),
    raw_reference = COALESCE(excluded.raw_reference, threat_indicators.raw_reference);
```

### 11.2 Go Bulk Import with Transaction Batching

```go
// BulkImport imports indicators in batches within a single transaction.
// Designed for Pi 4: batch size 500 balances memory vs. transaction overhead.
func (db *ThreatIntelDB) BulkImport(source string, indicators []Indicator) error {
    const batchSize = 500

    tx, err := db.db.Begin()
    if err != nil {
        return fmt.Errorf("begin tx: %w", err)
    }
    defer tx.Rollback()

    stmt, err := tx.Prepare(`
        INSERT INTO threat_indicators (
            indicator, type, source, confidence, tags,
            first_seen, last_seen, ttl_hours,
            malware_family, threat_type, status, port, country, as_number, raw_reference
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator, source) DO UPDATE SET
            confidence = MAX(excluded.confidence, threat_indicators.confidence),
            tags = excluded.tags,
            last_seen = CASE
                WHEN excluded.last_seen > threat_indicators.last_seen THEN excluded.last_seen
                ELSE threat_indicators.last_seen
            END,
            ttl_hours = excluded.ttl_hours,
            malware_family = COALESCE(excluded.malware_family, threat_indicators.malware_family),
            threat_type = COALESCE(excluded.threat_type, threat_indicators.threat_type),
            status = excluded.status,
            port = COALESCE(NULLIF(excluded.port, 0), threat_indicators.port),
            country = COALESCE(excluded.country, threat_indicators.country),
            as_number = COALESCE(NULLIF(excluded.as_number, 0), threat_indicators.as_number),
            raw_reference = COALESCE(excluded.raw_reference, threat_indicators.raw_reference)
    `)
    if err != nil {
        return fmt.Errorf("prepare stmt: %w", err)
    }
    defer stmt.Close()

    for i, ind := range indicators {
        tagsJSON, _ := json.Marshal(ind.Tags)

        _, err := stmt.Exec(
            ind.Value, ind.Type, ind.Source, ind.Confidence, string(tagsJSON),
            ind.FirstSeen.Format(time.RFC3339), ind.LastSeen.Format(time.RFC3339),
            int(ind.TTL.Hours()),
            nilIfEmpty(ind.MalwareFamily), nilIfEmpty(ind.ThreatType),
            nilIfEmpty(ind.Status), nilIfZero(ind.Port),
            nilIfEmpty(ind.Country), nilIfZero(ind.ASNumber),
            nilIfEmpty(ind.RawReference),
        )
        if err != nil {
            return fmt.Errorf("exec row %d: %w", i, err)
        }

        // Commit and start new transaction every batchSize rows
        if (i+1)%batchSize == 0 && i+1 < len(indicators) {
            if err := tx.Commit(); err != nil {
                return fmt.Errorf("commit batch: %w", err)
            }
            tx, err = db.db.Begin()
            if err != nil {
                return fmt.Errorf("begin new tx: %w", err)
            }
            stmt, err = tx.Prepare(`... same SQL ...`)
            if err != nil {
                return fmt.Errorf("prepare new stmt: %w", err)
            }
        }
    }

    if err := tx.Commit(); err != nil {
        return fmt.Errorf("final commit: %w", err)
    }

    // Update sync state
    _, err = db.db.Exec(`
        INSERT INTO feed_sync_state (feed_name, last_sync, last_success, entries_count)
        VALUES (?, datetime('now'), datetime('now'), ?)
        ON CONFLICT(feed_name) DO UPDATE SET
            last_sync = datetime('now'),
            last_success = datetime('now'),
            entries_count = excluded.entries_count,
            consecutive_failures = 0
    `, source, len(indicators))

    return err
}

func nilIfEmpty(s string) interface{} {
    if s == "" { return nil }
    return s
}

func nilIfZero(n int) interface{} {
    if n == 0 { return nil }
    return n
}
```

### 11.3 Lookup Query (Used by Event Enrichment)

```sql
-- Fast lookup: first check Bloom filter in Go, then this query
SELECT
    indicator, type, source, confidence, tags,
    first_seen, last_seen, ttl_hours,
    malware_family, threat_type, status, port,
    -- Compute effective confidence inline
    CASE
        WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours THEN confidence
        WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours * 2 THEN
            confidence * MAX(0.1, 1.0 - 0.9 * ((julianday('now') - julianday(last_seen)) * 24 - ttl_hours) / ttl_hours)
        ELSE confidence * 0.1
    END AS effective_confidence
FROM threat_indicators
WHERE indicator = ?
ORDER BY effective_confidence DESC
LIMIT 5;
```

### 11.4 Cleanup Queries

```sql
-- Remove indicators that are 3x past TTL (truly ancient data)
DELETE FROM threat_indicators
WHERE (julianday('now') - julianday(last_seen)) * 24 > ttl_hours * 3;

-- Get indicator counts by source (for dashboard)
SELECT source, COUNT(*) as total,
    SUM(CASE WHEN (julianday('now') - julianday(last_seen)) * 24 <= ttl_hours THEN 1 ELSE 0 END) as fresh,
    SUM(CASE WHEN (julianday('now') - julianday(last_seen)) * 24 > ttl_hours THEN 1 ELSE 0 END) as stale
FROM threat_indicators
GROUP BY source;

-- Vacuum after large deletions (run weekly, not during peak)
-- Note: VACUUM requires 2x the DB size in free disk space temporarily
VACUUM;
```

---

## 12. Deployment and Operational Notes

### 12.1 Auth-Key Management

Both URLhaus and ThreatFox require a free Auth-Key from https://auth.abuse.ch/. Vedetta should:

1. Store the key in a config file (`/etc/vedetta/threat-intel.yaml`) with 0600 permissions
2. Support environment variable override: `VEDETTA_ABUSECH_AUTH_KEY`
3. Fail gracefully if no key is configured — bulk downloads for Feodo Tracker and SSLBL work without authentication
4. Include a first-run setup wizard step that prompts for the key

### 12.2 Resource Budget on Raspberry Pi 4

| Resource | Budget | Notes |
|----------|--------|-------|
| RAM for threat intel | ~20 MB | SQLite cache (16MB) + Bloom filter (86KB) + HTTP buffers |
| Disk for DB | ~10 MB | Generous estimate with all indexes |
| CPU for feed parsing | <5% per cycle | JSON/CSV parsing is lightweight |
| Network bandwidth | ~140 MB/day | Default schedule; tunable down to ~60 MB/day |
| Goroutines | 1 scheduler + 1 per active download | Max 2 concurrent downloads |

### 12.3 Monitoring and Alerting

The feed scheduler should expose metrics for Vedetta's internal health dashboard:

- `threat_intel_feed_last_sync_timestamp{feed="urlhaus"}` — when each feed was last synced
- `threat_intel_feed_errors_total{feed="feodotracker"}` — cumulative download errors
- `threat_intel_indicators_total{source="sslbl"}` — count of indicators per source
- `threat_intel_bloom_filter_checks_total` — total Bloom filter queries
- `threat_intel_bloom_filter_hits_total` — positive Bloom filter results (includes false positives)
- `threat_intel_sqlite_lookups_total` — SQLite queries triggered by Bloom hits
- `threat_intel_enrichments_total` — events successfully enriched

### 12.4 Testing Strategy

1. **Unit tests**: Mock HTTP responses with recorded abuse.ch payloads (save real responses as testdata)
2. **Integration tests**: Hit real APIs in CI with a test Auth-Key (rate-limited, run nightly)
3. **Fuzz tests**: Feed parsers should be fuzz-tested with malformed CSV/JSON
4. **Bloom filter validation**: After each rebuild, spot-check 100 known indicators for correct membership

### 12.5 Future Enhancements

- **Conditional GET**: Use `If-None-Match` (ETag) and `If-Modified-Since` headers to skip unchanged feeds — reduces bandwidth by ~50% during stable periods
- **Delta updates**: For URLhaus, track the highest `id` seen and only process newer entries
- **STIX export**: Generate STIX 2.1 bundles from the local DB for sharing with the Vedetta threat network
- **MalwareBazaar integration**: Add hash-based lookups when Vedetta gains file inspection capabilities
- **YARAify integration**: Download YARA rules for local file scanning (Phase 3+)

---

## References

- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
- [Feodo Tracker Blocklist](https://feodotracker.abuse.ch/blocklist/)
- [SSLBL JA3 Fingerprints](https://sslbl.abuse.ch/ja3-fingerprints/)
- [ThreatFox Community API](https://threatfox.abuse.ch/api/)
- [abuse.ch Auth Portal](https://auth.abuse.ch/)
- [Go abuse.ch toolkit (rollwagen/abusech)](https://pkg.go.dev/github.com/rollwagen/abusech/threatfox)
- [andpalmier's abuse.ch CLI toolkit](https://andpalmier.com/posts/abuse-ch-toolkit/)
- [Spamhaus abuse.ch Real-Time Feeds Documentation](https://docs.spamhaus.com/real-time-feeds/docs/source/50-abuse-ch-real-time-feeds/600-feeds-ach.html)
