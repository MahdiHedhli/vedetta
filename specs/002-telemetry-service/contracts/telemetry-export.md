# Contract: Telemetry Export Wire Format (schema_version 1)

> Owner: `specs/002-telemetry-service/` (producer)
> Validator: `specs/003-threat-network/spec.md` (consumer — MUST reject anything not conforming)
> Basis: `docs/threat-intel-mvp.md` (VED-008)
> Status: Draft — frozen on approval; changes are additive-only within schema_version 1
> All example values are synthetic (RFC 5737 / RFC 2606 / documentation MACs). No real
> network data appears in this file, ever.

## 1. Transport

- HTTPS only in production (`http://` permitted only for local compose development).
- `POST <threat-network>/api/v1/ingest`
- `Content-Type: application/json`, `Content-Encoding: gzip`
- Authentication headers (all four required):

```text
Authorization: VedettaReporter <reporter_id>
X-Vedetta-Timestamp: <unix-seconds>
X-Vedetta-Nonce: <random-uuid-v4>
X-Vedetta-Signature: hex(HMAC-SHA256(reporter_secret, timestamp + "\n" + nonce + "\n" + sha256hex(uncompressed_body)))
```

The receiver MUST reject: invalid signatures, timestamps older/newer than 300 s,
reused nonces, and duplicate `batch_id` (idempotent replay → `200` with
`"duplicate": true`, no re-processing).

## 2. Reporter registration (precondition)

`POST /api/v1/reporters/register`

Request:

```json
{
  "schema_version": 1,
  "install_id": "1f7b6d2e-8f0a-4c4e-9b1d-3a5c7e9f0b2d",
  "vedetta_version": "0.1.0-dev",
  "capabilities": [
    "known_bad_domain_hit",
    "high_confidence_domain_candidate",
    "behavior_summary"
  ]
}
```

Response (`201`):

```json
{
  "reporter_id": "9a1c2b3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d",
  "reporter_secret": "c2VjcmV0LWJhc2U2NC1leGFtcGxlLW9ubHk=",
  "config": {
    "min_upload_interval_seconds": 900,
    "max_batch_items": 250
  }
}
```

`install_id` is a locally generated random UUID — it carries no hardware, network, or
operator identity. `reporter_secret` is stored node-side with `0600` permissions.

## 3. Batch envelope

Exactly one JSON object per request:

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | `1` |
| `batch_id` | string (UUID v4) | yes | unique per batch; server dedup key |
| `generated_at` | string (RFC3339 UTC) | yes | batch creation time |
| `window_start` | string (RFC3339 UTC) | yes | inclusive; hour-aligned or tick-aligned |
| `window_end` | string (RFC3339 UTC) | yes | exclusive; `> window_start` |
| `signals` | array | yes | 1..`max_batch_items` (default 250) items |

No other top-level keys are permitted. Receivers MUST reject unknown top-level keys
(strict mode) — this is the poisoning/privacy tripwire, not lenient parsing.

## 4. Signal records

Common fields (every signal):

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `signal_id` | string (UUID v4) | yes | unique; server dedup key with `batch_id` |
| `kind` | string enum | yes | `known_bad_domain_hit` \| `high_confidence_domain_candidate` \| `behavior_summary` |
| `time_bucket` | string (RFC3339 UTC) | yes | truncated to the hour (`:00:00Z`); NEVER an exact event time |
| `local_confidence` | number | yes | `0.0`–`1.0` |
| `local_reasons` | array of string enum | yes | 1..8 items from the reason vocabulary (§6); no free text |
| `observation_count` | integer | yes | ≥1; capped at 10000 |
| `distinct_asset_count` | integer | yes | ≥1; capped at 500; a COUNT only — never asset identifiers |

### 4.1 `known_bad_domain_hit`

Exact domain permitted ONLY for this kind (already matched a trusted local threat
source or very-high-confidence detector).

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `domain` | string | yes | lowercase FQDN, ≤253 chars, public suffix only (§5) |
| `etld_plus_one` | string | yes | PSL reduction of `domain` |
| `blocked_count` | integer | no | ≥0, ≤ `observation_count` |

### 4.2 `high_confidence_domain_candidate`

Exact domain WITHHELD; eTLD+1 only.

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `etld_plus_one` | string | yes | public suffix only (§5); MUST NOT be present alongside a `domain` key — `domain` is forbidden on this kind |

### 4.3 `behavior_summary`

No domain material at all.

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `behavior` | string enum | yes | `dns_beaconing_candidate` \| `dga_burst_candidate` \| `dns_tunneling_candidate` \| `new_domain_volume_anomaly` |

`domain` and `etld_plus_one` are forbidden on this kind.

## 5. Forbidden content (receiver MUST reject the whole batch)

These rules are the privacy contract. Any single violation rejects the entire batch
with `422` and a machine-readable reason; the producer never retries a `4xx` batch.

1. Any JSON key not defined in §3/§4 for its position (strict schema).
2. Any IP address literal anywhere in any string value — including RFC 1918
   (`10.*`, `172.16-31.*`, `192.168.*`), link-local, loopback, and public IPs.
3. Any MAC-address-shaped value (`xx:xx:xx:xx:xx:xx` and common variants).
4. Any domain/etld value that is: single-label; under `.local`, `.lan`, `.home`,
   `.internal`, `.corp`, `home.arpa`, or `in-addr.arpa`/`ip6.arpa`; an IP literal;
   or not reducible under the Public Suffix List.
5. Exact timestamps finer than hour granularity in `time_bucket`.
6. Any `local_reasons` value outside the vocabulary (§6).
7. Hostnames, usernames, email addresses, URLs with paths/queries (domain only, no
   URL syntax: values containing `/`, `?`, `#`, `@`, or whitespace are rejected).
8. Per-asset identifiers of any form. Aggregate counts only. (`source_hash` HMACs are
   used INSIDE the node to compute `distinct_asset_count` and are not part of this
   wire format; a batch containing a `source_hash` key is rejected under rule 1.)

## 6. Reason vocabulary (schema_version 1)

`known_bad`, `c2_candidate`, `dga_candidate`, `tunneling_candidate`,
`beaconing_candidate`, `newly_registered`, `dns_rebinding_candidate`,
`public_resolver_bypass`, `threat_feed_match`, `high_entropy`.

Additions are allowed within schema_version 1 (additive-only); receivers MUST accept
unknown vocabulary values from HIGHER minor revisions by ignoring the reason, but the
producer MUST NOT emit values outside its pinned vocabulary.

## 7. Complete synthetic example

Uncompressed request body (values are RFC 2606 documentation domains; counts are
fabricated):

```json
{
  "schema_version": 1,
  "batch_id": "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
  "generated_at": "2026-07-03T14:15:02Z",
  "window_start": "2026-07-03T14:00:00Z",
  "window_end": "2026-07-03T14:15:00Z",
  "signals": [
    {
      "signal_id": "3c5e7a9b-2d4f-4a6c-8e0b-1f3a5c7e9b0d",
      "kind": "known_bad_domain_hit",
      "time_bucket": "2026-07-03T14:00:00Z",
      "domain": "c2-payload.badzone.example",
      "etld_plus_one": "badzone.example",
      "local_confidence": 0.99,
      "local_reasons": ["known_bad", "threat_feed_match", "c2_candidate"],
      "observation_count": 4,
      "distinct_asset_count": 2,
      "blocked_count": 4
    },
    {
      "signal_id": "8d0f2a4c-6e8b-4c0d-a2e4-3b5d7f9a1c2e",
      "kind": "high_confidence_domain_candidate",
      "time_bucket": "2026-07-03T14:00:00Z",
      "etld_plus_one": "qxv-rotator.example",
      "local_confidence": 0.91,
      "local_reasons": ["dga_candidate", "newly_registered", "high_entropy"],
      "observation_count": 17,
      "distinct_asset_count": 1
    },
    {
      "signal_id": "5f7b9d1e-3a5c-4e7f-b1d3-2c4e6a8b0d1f",
      "kind": "behavior_summary",
      "time_bucket": "2026-07-03T14:00:00Z",
      "behavior": "dns_beaconing_candidate",
      "local_confidence": 0.81,
      "local_reasons": ["beaconing_candidate"],
      "observation_count": 6,
      "distinct_asset_count": 2
    }
  ]
}
```

Success response (`202`):

```json
{
  "accepted": 3,
  "rejected": 0,
  "batch_id": "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
  "duplicate": false
}
```

Rejection example (`422` — whole batch, rule 2 violation):

```json
{
  "error": "forbidden_content",
  "rule": "no_ip_literals",
  "detail": "signal 1: string value matches IP pattern",
  "batch_id": "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e"
}
```

(Illustration of what rule 2 catches: a signal whose `etld_plus_one` were
`"192.0.2.7"` — an IP literal, shown here with an RFC 5737 documentation address —
must reject the entire batch.)

## 8. Never exported (normative summary)

Raw source IPs, resolved/server IPs, MAC addresses (e.g. anything shaped like
`00:00:5E:00:53:2A`), hostnames (e.g. `nas-placeholder-01`), device inventories,
device vendors/models, network segments, SSIDs, exact per-event timestamps, raw query
history, free-form metadata/threat descriptions, geo fields, per-asset hashes or
tokens of any kind. If a future signal class needs any of these, it requires a new
spec, a privacy review, and a schema_version bump — not an additive change.

## 9. Versioning

- This document defines `schema_version: 1`. Producers pin it; the validator in
  specs/003-threat-network/spec.md enforces it strictly.
- Additive within v1: new optional signal fields, new reason-vocabulary values, new
  `kind` values (receivers reject unknown kinds from LOWER-capability reporters via
  the registration `capabilities` list).
- Breaking (rename/remove/semantic change): requires `schema_version: 2`, one release
  of dual-emission support, and updates to both this file and specs/003's validator
  fixtures. Shared golden-file fixtures live beside this contract and are consumed by
  both services' test suites.
