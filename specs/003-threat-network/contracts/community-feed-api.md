# Contract: Community Feed API (threat-network → consumers)

> Owner: `specs/003-threat-network/`
> Schema version: 1
> Status: Draft
> Consumers: Core `backend/internal/threatintel` feed scheduler (future), third-party
> tooling. Consumption pattern is identical to polling an abuse.ch feed.
>
> All examples are SYNTHETIC per the constitution's environment-data rules:
> RFC 5737 IPs (192.0.2.x / 198.51.100.x / 203.0.113.x), example MACs
> (00:00:5E:00:53:xx), placeholder domains under `.example` / `example.net`.
> The ingest-side wire format is owned by
> `specs/002-telemetry-service/contracts/telemetry-export.md` and is NOT redefined here.

## Semantics (contractual, not advisory-in-name-only)

- **Advisory-only.** Every item carries `advisory: true` and
  `recommended_action: "advise"`. Schema v1 defines no other action value. Consumers
  MUST NOT auto-block or raise an alert solely because an indicator appears in this
  feed; feed membership may only add context or adjust scoring of locally observed
  activity.
- **Versioned.** `schema_version` is present on every response. Additive fields may
  appear within v1 and MUST be ignored if unknown. Removals, renames, or semantic
  changes require v2 (new value, same endpoint) with v1 served for at least one release.
- **No provenance leakage.** Items never contain reporter identifiers, source IPs,
  asset counts of any single network, or any per-deployment data — only network-wide
  aggregates.

## Endpoint

```
GET /api/v1/feed/community
```

Authentication: none (public read, like abuse.ch list downloads). Per-IP rate limits
apply; clients should honor `ttl_seconds` and `ETag` instead of tight polling.

### Query parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `cursor` | string | (none) | Opaque cursor from a previous response's `next_cursor`. Returns items updated after that point. Omit for a full snapshot from the beginning. |
| `limit` | int | 1000 | Max items per page (1–5000). |
| `min_confidence` | float | 0.0 | Only items with `confidence >= min_confidence`. |
| `kind` | string | (none) | Filter: `domain_indicator`, `etld1_indicator`, or `behavior_cluster`. |

### Request headers

| Header | Use |
| --- | --- |
| `If-None-Match` | Pass the previous `ETag`; server answers `304 Not Modified` when the feed is unchanged. |
| `Accept` | `application/json` (only format in v1). |

## Response — 200 OK

```json
{
  "schema_version": 1,
  "feed": "community",
  "generated_at": "2026-07-03T14:30:00Z",
  "ttl_seconds": 900,
  "advisory": true,
  "total_items": 42,
  "returned_items": 3,
  "next_cursor": "b3BhcXVlLWN1cnNvci0wMDAz",
  "items": [
    {
      "feed_id": "7f1c9a2e-5b64-4d0a-9c1f-3e8a2b6d4c01",
      "kind": "domain_indicator",
      "indicator": "beacon-check.badhost.example",
      "indicator_type": "domain",
      "confidence": 0.96,
      "severity": "high",
      "advisory": true,
      "recommended_action": "advise",
      "sources_required": 2,
      "sources_observed": 5,
      "reasons": ["known_bad", "c2_candidate", "cross_reporter_match"],
      "first_seen": "2026-06-28T09:00:00Z",
      "last_seen": "2026-07-03T13:00:00Z",
      "published_at": "2026-06-29T10:15:00Z",
      "updated_at": "2026-07-03T14:15:00Z",
      "expires_at": "2026-08-02T13:00:00Z"
    },
    {
      "feed_id": "2a8d4f60-1e3b-4c7d-8a05-6b9c0d1e2f13",
      "kind": "etld1_indicator",
      "indicator": "dga-zone.example.net",
      "indicator_type": "etld_plus_one",
      "confidence": 0.83,
      "severity": "low",
      "advisory": true,
      "recommended_action": "advise",
      "sources_required": 4,
      "sources_observed": 4,
      "reasons": ["dga_candidate", "newly_registered", "cross_reporter_match"],
      "first_seen": "2026-07-01T00:00:00Z",
      "last_seen": "2026-07-03T12:00:00Z",
      "published_at": "2026-07-02T08:30:00Z",
      "updated_at": "2026-07-03T14:15:00Z",
      "expires_at": "2026-07-10T12:00:00Z"
    },
    {
      "feed_id": "9c3e5a17-6d2f-4b08-b4a1-0e7f8d9a1b25",
      "kind": "behavior_cluster",
      "indicator": "dns_beaconing_candidate",
      "indicator_type": "behavior",
      "confidence": 0.81,
      "severity": "low",
      "advisory": true,
      "recommended_action": "advise",
      "sources_required": 4,
      "sources_observed": 6,
      "reasons": ["beaconing_candidate", "cross_reporter_match"],
      "first_seen": "2026-06-30T18:00:00Z",
      "last_seen": "2026-07-03T11:00:00Z",
      "published_at": "2026-07-01T19:00:00Z",
      "updated_at": "2026-07-03T14:15:00Z",
      "expires_at": "2026-07-10T11:00:00Z"
    }
  ]
}
```

Response headers: `ETag: "feed-v1-<opaque>"`, `Cache-Control: max-age=900`.

### Field reference (items)

| Field | Type | Description |
| --- | --- | --- |
| `feed_id` | uuid | Stable id for this feed item. |
| `kind` | enum | `domain_indicator` \| `etld1_indicator` \| `behavior_cluster`. |
| `indicator` | string | Exact domain, registered domain (eTLD+1), or behavior tag. Never an IP, never an internal/special-use name. |
| `indicator_type` | enum | `domain` \| `etld_plus_one` \| `behavior` — maps to Core `threatintel.Indicator.Type`. |
| `confidence` | float 0–1 | Consensus confidence (see plan.md model). Rises with the number of distinct matured reporter credentials (not proof of distinct operators); capped at 0.99. |
| `severity` | enum | `high` \| `medium` \| `low` — context for scoring, not an action level. |
| `advisory` | bool | Always `true` in v1. |
| `recommended_action` | enum | Always `"advise"` in v1. |
| `sources_required` | int | Promotion threshold that applied to this item. |
| `sources_observed` | int | Distinct reporters observed in the current 7-day window. |
| `reasons` | []string | Union of reporters' `local_reasons` (002-contract §6 vocabulary: `known_bad`, `c2_candidate`, `dga_candidate`, `beaconing_candidate`, `newly_registered`, ...) plus server-added tags (`cross_reporter_match`). Additive vocabulary. |
| `first_seen` / `last_seen` | RFC 3339 | Network-wide observation bounds (hour-bucket precision). |
| `published_at` / `updated_at` | RFC 3339 | Feed lifecycle timestamps; `updated_at` drives cursoring. |
| `expires_at` | RFC 3339 | After this instant the item is no longer served. Consumers treat it as the indicator TTL. |

Mapping to Core's `threatintel.Indicator`: `indicator`→`indicator`,
`indicator_type`→`type`, `"vedetta-community"`→`source`, `confidence`→`confidence`,
`reasons`→`tags`, `first_seen`/`last_seen` direct, `expires_at`→`ttl`.

## Response — 304 Not Modified

Empty body; returned when `If-None-Match` matches the current `ETag`.

## Errors

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `INVALID_CURSOR` | Cursor unparseable or from a different schema version. Client restarts without cursor. |
| 400 | `INVALID_PARAMETER` | Bad `limit`/`min_confidence`/`kind`. |
| 429 | `RATE_LIMIT_EXCEEDED` | Per-IP limit hit; body includes `retry_after_seconds`. |
| 503 | `SERVICE_UNAVAILABLE` | Temporary; retry with backoff, serve cached items meanwhile. |

Error body shape:

```json
{
  "schema_version": 1,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Per-IP feed request limit exceeded",
    "retry_after_seconds": 300
  }
}
```

## Consumer obligations

1. Honor `ttl_seconds` / `ETag`; poll no more often than every 15 minutes.
2. Drop items past `expires_at` even if a poll is missed.
3. Treat items as advisory context only (see Semantics). Local suppression and
   scoring rules always win over feed membership.
4. Ignore unknown fields; reject only on `schema_version` mismatch.

## Companion endpoints (for completeness; details in plan.md)

| Method | Path | Contract owner |
| --- | --- | --- |
| `GET /api/v1/status` | health + schema version | this spec (trivial: `{"status":"ok","service":"vedetta-threat-network","schema_version":1}`) |
| `POST /api/v1/reporters/register` | reporter credential issuance | this spec (shape frozen in `docs/threat-intel-mvp.md`; formalized in plan.md) |
| `POST /api/v1/ingest` | telemetry batch upload | `specs/002-telemetry-service/contracts/telemetry-export.md` |
