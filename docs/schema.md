# Vedetta — Core Event Schema

> Version: 1.0.0-draft
> Last updated: 2026-03-25

## Design Principles

Every field must earn its place. The schema is lean and meaningful — no bloat, no redundant fields. It supports SIEM-style queries (time range, event type, source, tags, anomaly score) while remaining lightweight enough to run on a Raspberry Pi 4 with SQLite.

## Event Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_id` | `string` (UUID v4) | Yes | Unique event identifier |
| `timestamp` | `string` (ISO 8601) | Yes | Event creation time in UTC |
| `event_type` | `enum` | Yes | One of: `dns_query`, `encrypted_dns_detected`, `nmap_discovery`, `firewall_log`, `anomaly` |
| `source_hash` | `string` (SHA-256) | Yes | Hash of local IP + per-install salt. Preserves correlation without exposing IPs. |
| `domain` | `string` | No | Queried domain (DNS events) |
| `query_type` | `enum` | No | DNS record type: `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `SRV`, `PTR` |
| `resolved_ip` | `string` (IPv4/v6) | No | Resolved IP address |
| `blocked` | `boolean` | Yes | Whether the query/connection was blocked (default: `false`) |
| `anomaly_score` | `float` | Yes | 0.0 (normal) to 1.0 (highly anomalous). Default: `0.0` |
| `tags` | `string[]` | No | Classification tags (see Tag Vocabulary below) |
| `geo` | `string` | No | ISO 3166-1 alpha-2 country code of resolved IP |
| `device_vendor` | `string` | No | Vendor name from OUI lookup or nmap fingerprint |
| `network_segment` | `enum` | No | One of: `default`, `iot`, `guest` |
| `dns_source` | `string` | No | DNS capture method that generated this event: `passive_capture`, `pihole`, `adguard`, `embedded_resolver`, `iptables_intercept` |

### Example

```json
{
  "event_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "timestamp": "2026-03-25T14:30:00Z",
  "event_type": "dns_query",
  "source_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "suspicious-domain.xyz",
  "query_type": "A",
  "resolved_ip": "198.51.100.42",
  "blocked": false,
  "anomaly_score": 0.87,
  "tags": ["dga_candidate", "newly_registered"],
  "geo": "RU",
  "device_vendor": "Espressif",
  "network_segment": "iot"
}
```

## Tag Vocabulary

Tags are freeform strings, but the following are recognized by Vedetta's detection rules:

| Tag | Meaning |
|-----|---------|
| `c2_candidate` | Domain matches known C2 patterns or blocklists |
| `dga_candidate` | Domain exhibits DGA characteristics (high entropy, random-looking) |
| `newly_registered` | Domain registered within the last 30 days |
| `known_bad` | Domain appears on abuse.ch, URLhaus, or similar blocklists |
| `beaconing` | Regular, periodic DNS queries suggesting beaconing behavior |
| `new_device` | Previously unseen device on the network |
| `port_change` | Device open ports changed since last scan |
| `high_volume` | Unusually high query volume from this source |

## Device Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `device_id` | `string` (UUID v4) | Yes | Unique device identifier |
| `first_seen` | `string` (ISO 8601) | Yes | When device was first discovered |
| `last_seen` | `string` (ISO 8601) | Yes | Most recent scan that found this device |
| `ip_address` | `string` | Yes | Current IP address |
| `mac_address` | `string` | Yes | MAC address (primary key for deduplication) |
| `hostname` | `string` | No | mDNS or DHCP hostname if available |
| `vendor` | `string` | No | Vendor from OUI or nmap fingerprint |
| `open_ports` | `int[]` | No | Currently open TCP ports |
| `segment` | `enum` | No | Network segment: `default`, `iot`, `guest` |

## Storage

### Local Node (SQLite / PostgreSQL)

- All events written to a normalized, indexed local store
- Default retention: **90 days** (user-configurable)
- Indexes on: `timestamp`, `event_type`, `source_hash`, `tags`, `anomaly_score`
- Migration files in `/siem/migrations/`

### Threat Network (ClickHouse)

- Receives **anonymized** event batches only from opted-in nodes
- PII stripping: source IPs → HMAC hashes (per-install salt), hostnames removed, geo rounded to country
- Deduplication before storage
- Schema versioned from day one

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/events` | Query events with filtering, sorting, pagination |
| `GET` | `/api/v1/events/stats` | Aggregate event statistics (counts by type, top domains, threats) |
| `GET` | `/api/v1/events/timeline` | Hourly event counts for last 24 hours (for dashboard charts) |
| `GET` | `/api/v1/devices` | List discovered devices |
| `GET` | `/api/v1/status` | Service health and version |
| `POST` | `/api/v1/ingest` | Internal: receive normalized events from collector |
| `POST` | `/api/v1/sensor/dns` | Receive DNS queries from sensor passive capture |

### Event Query Parameters

| Param | Type | Description |
|-------|------|-------------|
| `from` | ISO 8601 | Start of time range |
| `to` | ISO 8601 | End of time range |
| `type` | string | Filter by event_type |
| `source` | string | Filter by source_hash |
| `tags` | string (comma-separated) | Filter by tags |
| `min_score` | float | Minimum anomaly_score |
| `sort` | string | Field to sort by (default: `timestamp`) |
| `order` | `asc` / `desc` | Sort order (default: `desc`) |
| `page` | int | Page number (default: `1`) |
| `limit` | int | Results per page (default: `50`, max: `500`) |
| `format` | `json` / `csv` | Response format (default: `json`) |

### Event Stats Response

`GET /api/v1/events/stats` returns:

```json
{
  "total_count": 42150,
  "threat_count": 287,
  "last_24h_count": 1540,
  "count_by_type": {
    "dns_query": 35000,
    "nmap_discovery": 2100,
    "firewall_log": 4500,
    "anomaly": 550
  },
  "top_10_domains": [
    {"domain": "google.com", "count": 8420},
    {"domain": "github.com", "count": 3100}
  ],
  "top_10_blocked_domains": [
    {"domain": "malware.com", "count": 45},
    {"domain": "c2.evil.net", "count": 23}
  ]
}
```

### Event Timeline Response

`GET /api/v1/events/timeline` returns 24 hourly buckets for the last 24 hours:

```json
{
  "timeline": [
    {"hour": "2026-03-30T00:00:00Z", "count": 42},
    {"hour": "2026-03-30T01:00:00Z", "count": 58},
    {"hour": "2026-03-30T02:00:00Z", "count": 0},
    ...
    {"hour": "2026-03-30T23:00:00Z", "count": 103}
  ]
}
```

## Schema Versioning

The schema version is tracked as an integer, starting at `1`. Every breaking change increments the version. The future community threat-network path is expected to enforce schema compatibility when that backend is fully implemented.
