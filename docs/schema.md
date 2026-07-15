# Vedetta — Core Event Schema

> Version: 1.1.0-beta
> Last updated: 2026-07-12

## Design Principles

Every field must earn its place. The schema is lean and meaningful — no bloat, no redundant fields. It supports SIEM-style queries (time range, event type, source, tags, anomaly score) while remaining lightweight enough to run on a Raspberry Pi 4 with SQLite.

## Event Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_id` | `string` | Yes | Core-owned unique event key. Adapters derive replay-stable RFC 9562 UUIDv8 IDs. For generic collector ingest, a caller's upstream ID is preserved in source metadata as audit/replay material while Core namespaces the database key with normalized record content. |
| `timestamp` | `string` (ISO 8601) | Yes | Event creation time in UTC |
| `event_type` | `enum` | Yes | One of: `dns_query`, `encrypted_dns_detected`, `nmap_discovery`, `firewall_log`, `anomaly` |
| `source_hash` | `string` (HMAC-SHA-256) | Yes | Core-owned pseudonym of the local source IP using a private per-install key. Ingest callers cannot choose it. |
| `source_ip` | `string` | No | Raw local client IP used for local identity resolution. It is not exported by community telemetry. |
| `domain` | `string` | No | Queried domain (DNS events) |
| `query_type` | `string` | No | DNS record type (for example `A`, `AAAA`, `CNAME`, `SOA`, `SVCB`, or `HTTPS`) |
| `resolved_ip` | `string` (IPv4/v6) | No | Resolved IP address |
| `blocked` | `boolean` | Yes | Source-reported enforcement flag. Core derives `blocked`, `allowed`, or `observed` evidence/finding outcome from source semantics; missing enforcement is not treated as allowed. |
| `outcome` | `enum` | Yes | Core-derived enforcement context: `blocked`, `allowed`, or `observed`. Persisted with the raw event; legacy/missing enforcement defaults to `observed`. |
| `anomaly_score` | `float` | Yes | 0.0 (normal) to 1.0 (highly anomalous). Default: `0.0` |
| `tags` | `string[]` | No | Classification tags (see Tag Vocabulary below) |
| `geo` | `string` | No | ISO 3166-1 alpha-2 country code of resolved IP |
| `device_vendor` | `string` | No | Vendor name from OUI lookup or nmap fingerprint |
| `network_segment` | `string` | No | Event-time segment/VLAN label. `default` means the adapter could not observe a more specific segment. |
| `dns_source` | `string` | No | DNS capture method that generated this event: `passive_capture`, `pihole`, `adguard`, `embedded_resolver`, `iptables_intercept` |
| `server_ip` | `string` | No | DNS server / resolver IP (from sensor response packets for actionability; source/destination identification) |
| `metadata` | `object` (JSON) | No | Namespaced source and Core enrichment data, including all DNS answers/CNAMEs when available. |
| `acknowledged` | `boolean` | Yes | Per-event operator review marker. It does not change a linked finding or future matching activity. |
| `ack_reason` | `string` | No | Optional operator note attached to that raw-event acknowledgement. |
| `device_id` | `string` | No | Historical stable device identity resolved at the event timestamp; null/empty means unresolved. Soft merges never rewrite it. |
| `canonical_device_id` | `string` | No | Read-time canonical asset after audited soft-merge redirects. Equal to `device_id` when unmerged and changes back on merge undo. |
| `identity_confidence` | `float` | Yes | Deterministic resolution confidence from 0.0 to 1.0. |
| `identity_reason` | `string` | No | Resolver decision such as stable evidence, temporal address binding, conflict, or unresolved. |
| `identity_evidence` | `object` (JSON) | No | Bounded explanation of the identity decision. |
| `origin` | `string` | No | Authenticated ingestion adapter (`sensor_dns`, `collector`, `pihole`, `adguard`, `unifi_rest`). |
| `sensor_id` | `string` | No | Authenticated sensor context where applicable. |
| `disposition` | `enum` | Yes | `active` or `suppressed`; suppression never deletes the event or its detection evidence. |
| `suppression_rule_id` | `string` | No | Matching event-wide suppression rule, when one applies. |

Event acknowledgement, finding lifecycle, and finding suppression are separate state:
acknowledgement records review of one raw event; finding status records the incident's
Open/Investigating/Resolved lifecycle; finding suppression is an audited policy for
future matching findings. None implicitly mutates either of the other two.

### Example

```json
{
  "event_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "timestamp": "2026-03-25T14:30:00Z",
  "event_type": "dns_query",
  "source_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "suspicious-domain.xyz",
  "query_type": "A",
  "resolved_ip": "198.51.100.42",
  "blocked": false,
  "outcome": "observed",
  "anomaly_score": 0.87,
  "tags": ["dga_candidate", "newly_registered"],
  "geo": "RU",
  "device_vendor": "Espressif",
  "network_segment": "iot",
  "server_ip": "8.8.8.8",
  "metadata": { "dns_answers": ["198.51.100.42"], "dga": { "entropy": 4.2 } }
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
| `ip_address` | `string` | Yes | Current compatibility projection, not historical identity truth |
| `mac_address` | `string` | Yes | Current observed MAC; stable identity can also use stronger evidence and temporal context |
| `hostname` | `string` | No | mDNS or DHCP hostname if available |
| `vendor` | `string` | No | Vendor from OUI or nmap fingerprint |
| `open_ports` | `int[]` | No | Currently open TCP ports |
| `segment` | `enum` | No | Network segment: `default`, `iot`, `guest` |
| `model` | `string` | No | Device model from passive discovery (mDNS/DHCP/SSDP) or nmap |
| `services` | `string[]` | No | Advertised services from passive discovery (for actionability) |
| `discovery_source` | `string` | No | How the device was discovered (e.g. passive_mdns, active_nmap) |

Core also maintains:

- `device_address_history`: timestamped IP/MAC ownership by segment and sensor.
- `device_identity_evidence`: locally HMACed DHCP client IDs, SSDP UUIDs,
  selected mDNS evidence, MAC/hostname context, provenance, and confidence.
- `device_identity_actions`: audited operator confirmations and reversible soft
  merge redirects. A beta "split" undoes an exact recorded merge; it does not
  repartition arbitrary historical evidence.

Existing event rows are not backfilled from a device's current IP.

## Detection Evidence And Findings

Every production ingestion route passes through one processor before persistence.
The processor normalizes the event, resolves its event-time device, extracts typed
observables, evaluates threat intelligence and deterministic detectors, applies
context and suppression, calculates priority once, and atomically persists one
event with its evidence/finding mutations.

`event_detection_evidence` stores immutable typed detector results: detector and
category, observable type/value, threat source/confidence/freshness, rationale,
score contribution, enforcement outcome, device context, and structured details.
Community evidence may be retained and linked when it corroborates trusted evidence,
but cannot independently create a finding or raise its priority.

`findings` aggregates actionable evidence by stable identity, detector, and
normalized observable. It records generation, first/last seen, occurrence and
outcome counts, maximum score/current priority, lifecycle status, recommendation,
disposition, and the last supporting event. Exact many-to-many tables link each
finding to its supporting events and evidence. Lifecycle history is append-only.
Finding reads preserve the historical `device_id` and expose the current
soft-merge target separately as `canonical_device_id`, matching event reads.

Open and Investigating are active lifecycle states. Resolved findings recur into
the same generation within seven quiet days; later recurrence creates a linked
generation. Finding outcome is `blocked`, `allowed`, or `observed`; it becomes `mixed`
when occurrences contain more than one of those three states. Suppression changes
disposition independently of lifecycle.

`finding_suppression_rules` stores exact detector + observable policies scoped to a
canonical device or, for unresolved findings, a fallback source identity. The
finding-level admin action immediately changes disposition without mutating evidence or
lifecycle. Rules are deactivated rather than deleted. `finding_suppression_history`
records activation/deactivation actor, reason, affected finding when applicable, and
timestamp.

Migration 025 adds the following asset-centered tables:

- `device_address_history`, `device_identity_evidence`, and
  `device_identity_actions`
- `event_detection_evidence`
- `findings`, `finding_events`, `finding_evidence`, and
  `finding_status_history`
- `finding_suppression_rules` and `finding_suppression_history`
- `collection_source_health`

Migration 026 adds retained sensor lifecycle state:

- `removed_at`, `removed_by_token_id`, and `removal_reason` on `sensors`
- `sensor_lifecycle_events` for append-only removal/reactivation history

Removed sensor rows are identity tombstones. They remain in Core so a generic
enrollment code can never reclaim a previously used sensor ID; reactivation
requires an admin-minted reset code bound to that exact ID.

## Storage

### Local Node (SQLite)

- All events written to a normalized, indexed local store
- Default raw-event retention: **90 days** (user-configurable)
- Events linked to a durable finding are retained so open/resolved finding
  drill-down does not silently lose its evidence. Ordinary unlinked raw events
  continue to age out.
- Indexes cover event time/source/device, temporal identity, detector observables,
  finding state/priority/device, and source health.
- Migration files in `/siem/migrations/`

### Threat Network (separate Go + SQLite service)

- Receives privacy-reduced, pseudonymous known-bad signal records from nodes with
  telemetry enabled (on by default, opt-out). The exact signal/batch/registration
  fields, reporter linkage, precise server timing, and retention are documented in
  [`PRIVACY.md`](../PRIVACY.md).
- Internal source IPs, MACs, hostnames, and raw DNS query names are not serialized.
- Core independently downloads the public snapshot every 15 minutes by default;
  community matches are advisory/corroborating and cannot create or raise a
  finding by themselves.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/events` | Query events with filtering, sorting, pagination |
| `GET` | `/api/v1/events/stats` | Aggregate event statistics (counts by type, top domains, threats) |
| `GET` | `/api/v1/events/timeline` | Hourly event counts for last 24 hours (for dashboard charts) |
| `GET` | `/api/v1/findings` | Query durable findings by lifecycle, priority, disposition, or stable device |
| `GET` | `/api/v1/findings/{id}` | Finding, exact evidence, lifecycle history, and paged supporting events |
| `PATCH` | `/api/v1/findings/{id}/status` | Admin lifecycle transition with audited reason |
| `POST` | `/api/v1/findings/{id}/suppress` | Admin create/reuse an exact typed suppression policy |
| `GET` | `/api/v1/finding-suppressions` | List active and inactive typed finding suppression rules |
| `DELETE` | `/api/v1/finding-suppressions/{rule_id}` | Admin deactivate a rule and restore directly matched findings to actionable disposition |
| `GET` | `/api/v1/findings/stats` | Current actionable priority, affected asset/source, and resolution counts (`affected_devices` is the compatibility field name) |
| `GET` | `/api/v1/health/detection` | Collection and threat-feed freshness/error state |
| `GET` | `/api/v1/devices` | List discovered devices |
| `POST` | `/api/v1/devices/{id}/confirm` | Admin-confirm an identity evidence binding |
| `POST` | `/api/v1/devices/merge` | Admin soft-merge duplicate device records |
| `POST` | `/api/v1/device-merges/{action_id}/split` | Admin undo an audited merge |
| `GET` | `/api/v1/status` | Service health and version |
| `POST` | `/api/v1/ingest` | Internal: receive normalized collector events; records need a timestamp or upstream ID and Core owns/namespaces stored event keys |
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

Core applies numbered, forward-only SQLite migrations and mirrors the latest
schema in its inline fallback. Migrations 025 and 026 are additive, but their
rollback path is the pre-upgrade database backup plus the matching prior image;
in-place down migrations are unsupported.
