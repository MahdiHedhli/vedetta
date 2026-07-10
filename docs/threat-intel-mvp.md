# Vedetta Threat-Intel MVP

> Last updated: 2026-04-21
> Status: Draft alpha design (historical). This is the **original design brief**. The
> shipped behavior has since changed: telemetry is now **on by default (opt-out)** — set
> `VEDETTA_TELEMETRY_OPTIN=false` or use the dashboard toggle to disable it — not off by
> default as sketched below. For current behavior and configuration see
> [threat-network-operations.md](threat-network-operations.md).

## Why This Exists

Vedetta's local deployment should remain useful without any cloud dependency. If we add community intelligence, it should be:

- optional
- off by default
- privacy-conscious
- advisory first, not auto-remediation

This document defines the narrowest MVP that can produce useful shared intelligence without turning Vedetta into a raw telemetry collection system.

## Goals

- Let opted-in Vedetta Core deployments contribute a small set of privacy-reduced, high-signal observations.
- Aggregate those observations into a community feed that can improve local scoring.
- Start with free-tier-friendly infrastructure and a simple operational model.
- Keep the trust boundary tight enough that poisoning and privacy mistakes are hard to make by accident.

## Non-Goals

- Do not upload every DNS query.
- Do not upload full device inventories.
- Do not upload raw IP addresses, MAC addresses, hostnames, SSIDs, or internal domain names.
- Do not make community intel a required dependency for local detections.
- Do not let one noisy or malicious reporter create global intel by itself.
- Do not auto-block from community intel alone in the MVP.

## Product Guardrails

- Sensors never talk to the public threat-network directly.
- Opt-in happens at the Core deployment level.
- Local detection and local enrichment remain the primary product value.
- Shared intelligence is a secondary, research-style layer until it earns more trust.

## MVP Shape

```text
vedetta-sensor
   |
   | local device + DNS observations
   v
vedetta-core backend
   |- local scoring and enrichment
   |- privacy reduction and export eligibility
   `- telemetry outbox
            |
            | signed, batched, opt-in only
            v
vedetta-telemetry
            |
            | HTTPS
            v
vedetta-threat-network
   |- reporter registration
   |- batch ingest
   |- aggregation + promotion
   `- advisory feed
            |
            | pull
            v
vedetta-telemetry
            |
            | local internal API
            v
vedetta-core backend
   `- community intel cache used as an additive signal
```

## What Leaves The Node

The MVP should only export privacy-reduced summaries that are already high signal locally.

### Exportable signal classes

1. `known_bad_domain_hit`
   Exact domain allowed only when it already matched a trusted local threat source or a very high-confidence detector.

2. `high_confidence_domain_candidate`
   Suspicious domain candidate with coarse supporting features. Exact subdomain should be withheld unless the confidence gate is met.

3. `behavior_summary`
   Coarse counts such as beaconing-like activity, DGA-like bursts, tunneling-like patterns, or unusual new-domain volume, bucketed in time and detached from raw client identity.

### Explicitly excluded from export

- raw query history
- exact client identifiers
- private or special-use names such as `.local`, `.lan`, `home.arpa`, reverse-lookup names, or single-label names
- full timestamps for every event
- full resolved IP history
- full device inventories

## Privacy Model

Privacy reduction should happen inside Vedetta Core before the telemetry service exports anything.

### Local export rules

- Only export records already marked exportable by backend logic.
- Replace exact event times with hour buckets.
- Keep only counts of affected local assets, never the asset identifiers.
- Allow exact domains only for high-confidence public indicators.
- Down-scope lower-confidence candidates to `eTLD+1` plus feature tags, or withhold them entirely.
- Strip private, internal, special-use, and obviously local-only names before they enter the telemetry outbox.

### Reporter identity

- Each opted-in Core registers as a `reporter`.
- The threat-network stores a random reporter identifier and a secret hash, not operator identity.
- The service does not require account profiles, names, or email for the MVP.

### Feed consumption

- Community feed items are advisory only.
- In MVP, they can raise local suspicion or add context, but they do not create automatic global block rules by themselves.

## External API Contract

The current `threat-network` stub can grow into four public endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/status` | Service health and schema version |
| `POST` | `/api/v1/reporters/register` | Register or rotate a reporter credential |
| `POST` | `/api/v1/ingest` | Accept signed telemetry batches |
| `GET` | `/api/v1/feed/pull` | Return promoted feed items since a cursor |

## Reporter Registration

Registration should be explicit and operator-controlled.

### Request

```json
{
  "schema_version": 1,
  "install_id": "local-random-uuid",
  "vedetta_version": "0.1.0-dev",
  "capabilities": [
    "known_bad_domain_hit",
    "high_confidence_domain_candidate",
    "behavior_summary"
  ]
}
```

### Response

```json
{
  "reporter_id": "uuid",
  "reporter_secret": "base64-secret",
  "config": {
    "min_upload_interval_seconds": 900,
    "max_batch_items": 250
  }
}
```

`reporter_secret` is stored locally by Core or telemetry with user-only permissions, similar to the sensor token flow.

## Batch Authentication And Replay Protection

Every ingest request should use TLS plus a signed-request scheme:

- `Authorization: VedettaReporter <reporter_id>`
- `X-Vedetta-Timestamp: <unix-seconds>`
- `X-Vedetta-Nonce: <random-uuid>`
- `X-Vedetta-Signature: hex(HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + sha256(body)))`

Threat-network should reject:

- stale timestamps
- reused nonces
- duplicate `batch_id`
- invalid signatures

This is cheap to verify in a Cloudflare Worker and prevents trivial replay or spoofing.

## Ingest Batch Schema

```json
{
  "schema_version": 1,
  "batch_id": "uuid",
  "generated_at": "2026-04-21T19:15:00Z",
  "window_start": "2026-04-21T19:00:00Z",
  "window_end": "2026-04-21T19:15:00Z",
  "signals": [
    {
      "signal_id": "uuid",
      "kind": "known_bad_domain_hit",
      "time_bucket": "2026-04-21T19:00:00Z",
      "domain": "bad.example",
      "etld_plus_one": "example",
      "local_confidence": 0.99,
      "local_reasons": ["known_bad", "c2_candidate"],
      "observation_count": 4,
      "distinct_asset_count": 2,
      "blocked_count": 1
    },
    {
      "signal_id": "uuid",
      "kind": "high_confidence_domain_candidate",
      "time_bucket": "2026-04-21T19:00:00Z",
      "etld_plus_one": "suspicious-zone.example",
      "local_confidence": 0.88,
      "local_reasons": ["dga_candidate", "newly_registered"],
      "observation_count": 9,
      "distinct_asset_count": 3
    },
    {
      "signal_id": "uuid",
      "kind": "behavior_summary",
      "time_bucket": "2026-04-21T19:00:00Z",
      "behavior": "dns_beaconing_candidate",
      "local_confidence": 0.81,
      "observation_count": 6,
      "distinct_asset_count": 2
    }
  ]
}
```

### Notes

- `domain` is optional and should only be present when the local export gate allows exact publication.
- `distinct_asset_count` is a count only, never a host list.
- Lower-confidence records should never include resolved IPs or exact client details.

## Threat-Network Storage Model

This MVP does not need heavy infrastructure.

### D1 tables

- `reporters`
- `ingest_receipts`
- `signals_raw`
- `signal_aggregates`
- `feed_items`
- `reporter_rate_limits`

### Optional R2 usage

- store a very small, short-retention sample of already privacy-reduced batches for debugging
- do not store raw DNS firehose data

### Queues

- not required for the first cut
- add later if synchronous Worker writes become a bottleneck

## Promotion Rules

The feed should be conservative.

### Automatic promotion

Promote a signal into the advisory feed only when at least one of the following is true:

1. An exact domain was already tagged `known_bad` locally and was seen by at least `2` distinct reporters within `7` days.
2. An exact domain was seen by at least `3` distinct reporters within `7` days and the aggregate confidence stays at or above `0.90`.
3. An `eTLD+1` candidate or behavior cluster was seen by at least `4` distinct reporters within `7` days and the aggregate confidence stays at or above `0.80`.

### Manual-review bucket

Hold the signal for review only, and do not publish it back to nodes, when:

- it comes from a single reporter
- it is high volume from one reporter but not corroborated elsewhere
- it contains a novel pattern that is interesting but not yet well-supported

### Decay

- candidate feed items expire after `7` days unless refreshed
- high-confidence malicious indicators can live for `30` days, then must be refreshed
- scores decay when corroboration stops

## Feed Item Shape

```json
{
  "cursor": "opaque-cursor",
  "items": [
    {
      "feed_id": "uuid",
      "kind": "domain_indicator",
      "indicator": "bad.example",
      "confidence": 0.97,
      "severity": "high",
      "sources_required": 3,
      "sources_observed": 4,
      "reasons": ["known_bad", "c2_candidate", "cross_reporter_match"],
      "first_seen": "2026-04-18T00:00:00Z",
      "last_seen": "2026-04-21T19:00:00Z",
      "expires_at": "2026-05-21T19:00:00Z"
    }
  ]
}
```

Core should treat this feed as one more enrichment source, not as a standalone enforcement engine.

## Abuse Controls

Because this is crowd-derived security data, anti-poisoning controls are part of the MVP, not a later nice-to-have.

- rate-limit per reporter and per IP
- cap how much any single reporter can influence a promotion score
- deduplicate on `batch_id` and `signal_id`
- maintain a denylist for abusive reporters
- keep feed promotion thresholds above one reporter
- prefer additive scoring over direct auto-blocking
- keep operator opt-in explicit and revocable

## Free-Infrastructure Deployment Shape

This MVP assumes the Cloudflare-first shape discussed in the earlier thread.

### Recommended first deployment

- **Cloudflare Worker**
  Handles registration, ingest, feed pull, and cron-driven aggregation jobs.
- **Cloudflare D1**
  Stores reporters, receipts, raw privacy-reduced signals, aggregates, and feed items.
- **Cloudflare R2** (optional)
  Stores a tiny capped archive of already privacy-reduced sample batches for debugging.

### Keep out of scope for the first cut

- a public web dashboard for the threat-network
- raw event search
- multi-stage async pipelines
- analyst-facing case management

If batching stays at 15-minute intervals and the payloads remain aggregate-first, this is a realistic alpha shape for tens of opted-in nodes.

## Upgrade Path And Production Fit

Cloudflare is a good way to start because the free-tier MVP and the first paid production shape can use the same basic architecture:

- the same Worker API surface
- the same D1 schema
- the same optional R2 archive
- Queues added only if ingest bursts justify buffering

That means the first upgrade path is operational, not architectural:

1. start on the free tier
2. move to Workers Paid when batch volume or retention needs exceed free limits
3. enable D1 read replication for lower-latency feed reads
4. add Queues if direct write spikes become noisy

### What should still make us cautious

- D1 read replication improves reads, but writes still go to the primary database
- each D1 database is single-threaded, so long or unindexed queries will cap throughput quickly
- the design stays viable longer if we keep the cloud data model narrow and aggregate-first

### Practical conclusion

Cloudflare can plausibly serve as the production platform for the early advisory-feed version of this feature, including a low-thousands-node rollout, as long as:

- uploads remain batched
- the telemetry contract stays privacy-reduced
- the service avoids raw-event analytics in D1

If the feature grows into a high-write or long-retention analytics system, the Cloudflare edge API can still remain in place while the hot data layer is sharded further or moved to a more analytics-oriented store.

## Vedetta Core Changes

1. Add an explicit telemetry opt-in state and config store.
2. Add backend logic that decides which local observations are exportable.
3. Add a `telemetry_outbox` concept with cursoring and acknowledgement.
4. Add internal endpoints for telemetry to:
   - fetch exportable batches
   - acknowledge sent batches
   - import promoted feed items
5. Add a local `community_intel` table used as a non-authoritative enrichment source.
6. Add UI copy that explains exactly what leaves the node and what never does.

## Telemetry Service Changes

1. Register the Core deployment as a reporter after explicit opt-in.
2. Read only the privacy-reduced outbox, not the raw event store.
3. Batch and sign uploads.
4. Poll the advisory feed on a safe interval such as every 15 minutes.
5. Push feed items back into Core through an internal authenticated path.
6. Surface delivery, retry, and last-feed-sync status for operators.

## Threat-Network Service Changes

1. Replace the stub endpoints with real registration, ingest, and feed handlers.
2. Verify signatures, timestamps, nonces, and batch ids.
3. Persist signals and recompute aggregates on an interval.
4. Apply conservative promotion thresholds and expiry logic.
5. Emit only advisory feed items with confidence and provenance fields.
6. Add a small operator-only review path behind strict access control if manual inspection becomes necessary.

## Rollout Phases

### Phase 0

Document the model, freeze the export contract, and keep the feature off by default everywhere.

### Phase 1

Implement local export gating in Core plus signed upload in telemetry. Threat-network accepts batches and stores them, but does not yet publish a live feed.

### Phase 2

Turn on conservative feed promotion for exact high-confidence domain indicators only.

### Phase 3

Add lower-confidence cluster and behavior summaries if the first phase produces useful, low-noise results.

## MVP Success Criteria

- An opted-in node can register, upload, and sync without exposing raw household or business telemetry.
- Threat-network can reject spoofed or replayed ingest attempts.
- The system can surface a small advisory feed that improves local scoring without becoming a mandatory dependency.
- One reporter alone cannot create shared intelligence for everyone else.
- The full stack remains cheap enough to run as an alpha research network.
