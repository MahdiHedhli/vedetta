# Plan: Community Threat-Network Backend (Ingest, Consensus, Advisory Feed)

> Spec: `specs/003-threat-network/spec.md`
> Status: Draft
> Created: 2026-07-03

## Architecture Overview

The threat-network is a standalone Go service (module
`github.com/vedetta-network/vedetta/threat-network`, Go 1.22, listens on
`THREAT_NETWORK_PORT`, default 9090) that runs OFF-node as community infrastructure.
It sits outside the Core + Sensor + Collector model on purpose:

```
[vedetta-sensor]──local──▶[vedetta-core backend]        (on the user's network)
                               │ privacy reduction + export gate (spec 002)
                               ▼
                          [vedetta-telemetry]           (on the user's network)
                               │ signed HTTPS batches, opt-in only
                               ▼
                  ┌────────────────────────────────┐
                  │  vedetta-threat-network :9090   │   (community infra, this spec)
                  │  ├─ auth: reporter registry +   │
                  │  │        HMAC request signing  │
                  │  ├─ ingest: validate → privacy  │
                  │  │        re-gate → dedup →     │
                  │  │        SQLite                │
                  │  ├─ consensus job (periodic):   │
                  │  │        aggregate → promote → │
                  │  │        decay                 │
                  │  └─ feed: GET advisory items    │
                  └────────────────────────────────┘
                               │ public GET (like abuse.ch)
                               ▼
                  [Core threatintel feed scheduler]     (future consumption spec)
```

Components inside the service (new packages under `threat-network/internal/`):

| Package | Responsibility |
| --- | --- |
| `store` | SQLite open/migrate (sequential runner mirroring Core's `schema_migrations` pattern), CRUD for reporters/signals/aggregates/feed items, retention purge |
| `auth` | Reporter registration, secret hashing, HMAC-SHA256 signed-request verification, nonce/timestamp replay protection, denylist |
| `ingest` | Contract validation against `specs/002-telemetry-service/contracts/telemetry-export.md`, server-side privacy re-gate, dedup, per-reporter caps |
| `consensus` | Windowed aggregation, promotion rules, confidence model, decay, allowlist guard |
| `feed` | Feed item materialization, cursoring, ETag |
| `api` | HTTP handlers, per-IP rate limiting (in-memory token bucket), JSON envelope |

Sensors never talk to this service. Core never talks to it directly in V1 either —
only the telemetry daemon (spec 002) uploads, and the feed is a public GET.

## Data Flow

End to end (naming exact endpoints, tables, services):

1. **Opt-in / registration:** operator enables telemetry in Core → telemetry daemon
   calls `POST /api/v1/reporters/register` with `{schema_version, install_id,
   vedetta_version, capabilities}` → service stores a row in `reporters`
   (random `reporter_id`, SHA-256 hash of the issued secret, capabilities, timestamps)
   and returns `{reporter_id, reporter_secret, config{min_upload_interval_seconds:900,
   max_batch_items:250}}`. The raw secret is never stored.
2. **Upload:** telemetry daemon POSTs a batch to `POST /api/v1/ingest` with headers
   `Authorization: VedettaReporter <reporter_id>`, `X-Vedetta-Timestamp`,
   `X-Vedetta-Nonce`, `X-Vedetta-Signature = hex(HMAC-SHA256(secret,
   timestamp + "\n" + nonce + "\n" + sha256(body)))`. Body is the telemetry-export
   batch (spec 002 contract): `{schema_version, batch_id, generated_at, window_start,
   window_end, signals[]}` with signal kinds `known_bad_domain_hit`,
   `high_confidence_domain_candidate`, `behavior_summary`.
3. **Auth gate:** verify signature; reject timestamps outside ±5 minutes; reject
   nonce reuse (table `nonces`, 24 h retention); reject denylisted/unknown reporters.
   A duplicate `batch_id` (table `ingest_receipts`) is NOT an error: idempotent
   replay → `200` with `"duplicate": true`, no re-processing (002 contract §1).
   All rejections are 4xx with machine-readable codes.
4. **Validation + privacy re-gate:** each signal is validated per kind (required
   fields, `local_confidence` ∈ [0,1], counts ≥ 0, `time_bucket` on an hour boundary
   within the batch window); signals failing these structural checks are rejected
   individually and reflected in the `rejected` count. Privacy-gate violations reject
   the ENTIRE batch with `422` and body `{error, rule, detail, batch_id}` (002
   contract §5; the producer never retries a 4xx batch): any indicator that is a
   private/special-use/single-label name (`.local`, `.lan`, `.home`, `.internal`,
   `.corp`, `home.arpa`, `in-addr.arpa`/`ip6.arpa`, bare labels — the full
   002-contract §5 rule-4 list), an IP literal, or any field that smells like an
   asset identifier. This duplicates Core's export gate on purpose — defense in depth.
5. **Dedup + store:** compute `indicator_key` = exact domain (kind 1), `etld_plus_one`
   (kind 2), or `behavior` (kind 3). Insert into `signals` with
   `UNIQUE(reporter_id, kind, indicator_key, time_bucket)`; conflicting rows update
   counts/confidence via upsert (max of confidences, sum-capped counts) rather than
   duplicating. Write an `ingest_receipts` row; respond `202` with
   `{accepted, rejected, batch_id, duplicate}` (002 contract §7).
6. **Consensus job:** every 15 minutes, aggregate `signals` over a trailing 7-day
   window per `(kind, indicator_key)` into `signal_aggregates`, apply promotion rules
   and the allowlist guard, and upsert promoted rows into `feed_items`. Apply decay/
   expiry to existing feed items.
7. **Publish:** `GET /api/v1/feed/community?cursor=&limit=` serves non-expired
   `feed_items`, ordered by `published_at`, with `ETag` and `ttl_seconds: 900`.
   Contract: `specs/003-threat-network/contracts/community-feed-api.md`.
8. **Future consumption (out of scope here):** Core's
   `backend/internal/threatintel.FeedScheduler` gains a `fetchVedettaCommunity()`
   alongside `fetchURLhaus()` etc., bulk-importing items as `Indicator{source:
   "vedetta-community"}` — the feed shape is designed to map 1:1 onto that struct.

## Schema Changes

**No Core schema changes.** `siem/migrations/` is untouched — this service owns its
own SQLite database with its own sequential migration chain at
`threat-network/migrations/` (same pattern as Core: `schema_migrations` tracking
table, never edit a committed migration). Driver: `github.com/mattn/go-sqlite3`
(consistent with `backend/go.mod`). WAL mode, `busy_timeout` set.

`threat-network/migrations/001_init.sql`:

| Table | Columns (type, default) | Notes |
| --- | --- | --- |
| `schema_migrations` | `version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL` | mirror of Core's runner |
| `reporters` | `reporter_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, capabilities TEXT NOT NULL DEFAULT '[]', vedetta_version TEXT, created_at TEXT NOT NULL, last_seen_at TEXT, status TEXT NOT NULL DEFAULT 'active', denylist_reason TEXT` | no operator identity, ever |
| `nonces` | `reporter_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at TEXT NOT NULL, PRIMARY KEY (reporter_id, nonce)` | purged after 24 h |
| `ingest_receipts` | `batch_id TEXT PRIMARY KEY, reporter_id TEXT NOT NULL, received_at TEXT NOT NULL, signal_count INTEGER NOT NULL, accepted_count INTEGER NOT NULL, rejected_count INTEGER NOT NULL` | batch replay dedup + ops visibility; purged after 30 d |
| `signals` | `id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id TEXT NOT NULL, kind TEXT NOT NULL, indicator_key TEXT NOT NULL, domain TEXT, etld_plus_one TEXT, behavior TEXT, time_bucket TEXT NOT NULL, local_confidence REAL NOT NULL, local_reasons TEXT NOT NULL DEFAULT '[]', observation_count INTEGER NOT NULL DEFAULT 0, distinct_asset_count INTEGER NOT NULL DEFAULT 0, blocked_count INTEGER NOT NULL DEFAULT 0, received_at TEXT NOT NULL, UNIQUE(reporter_id, kind, indicator_key, time_bucket)` | the dedup key; counts only — no asset identifiers; purged after 30 d |
| `signal_aggregates` | `kind TEXT NOT NULL, indicator_key TEXT NOT NULL, distinct_reporters INTEGER NOT NULL, aggregate_confidence REAL NOT NULL, total_observations INTEGER NOT NULL, reasons TEXT NOT NULL DEFAULT '[]', has_known_bad INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, computed_at TEXT NOT NULL, PRIMARY KEY (kind, indicator_key)` | recomputed each consensus run |
| `feed_items` | `feed_id TEXT PRIMARY KEY, kind TEXT NOT NULL, indicator TEXT NOT NULL, indicator_type TEXT NOT NULL, confidence REAL NOT NULL, severity TEXT NOT NULL, sources_required INTEGER NOT NULL, sources_observed INTEGER NOT NULL, reasons TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, published_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, UNIQUE(kind, indicator)` | the advisory feed; `cursor` derives from `(updated_at, feed_id)` |
| `reporter_counters` | `reporter_id TEXT NOT NULL, day TEXT NOT NULL, signals_accepted INTEGER NOT NULL DEFAULT 0, distinct_indicators INTEGER NOT NULL DEFAULT 0, allowlist_flags INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (reporter_id, day)` | per-reporter daily caps + abuse flags |
| `allowlist_domains` | `etld_plus_one TEXT PRIMARY KEY, rank INTEGER, loaded_at TEXT NOT NULL` | static top-domains snapshot seeded at migration/startup |

Indexes: `signals(indicator_key, received_at)`, `signals(reporter_id, received_at)`,
`feed_items(updated_at)`, `nonces(seen_at)`.

## API & Wire Contracts

Endpoints (all JSON; `schema_version: 1` throughout):

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/status` | none | health + schema version (kept from stub) |
| `POST` | `/api/v1/reporters/register` | none (per-IP rate-limited) | issue reporter credential |
| `POST` | `/api/v1/ingest` | HMAC signed request | accept telemetry batches |
| `GET` | `/api/v1/feed/community` | none (public, like abuse.ch) | advisory feed, cursored, ETag |

- **Ingest request body** = the telemetry-export contract owned by
  `specs/002-telemetry-service/contracts/telemetry-export.md`. This service validates
  against it and MUST NOT extend it; changes go through spec 002 first.
- **Feed response** = `specs/003-threat-network/contracts/community-feed-api.md`
  (in this directory) with synthetic examples. Advisory-only is contractual:
  `advisory: true` and `recommended_action: "advise"` on every item in schema v1.
- **Backward compatibility:** reporters (telemetry daemons) and this service upgrade
  independently. Rules: unknown JSON keys are rejected in strict mode per 002 §3/§5
  rule 1 (whole-batch `422` — the privacy tripwire owns this; leniency would let
  un-vetted fields leak through); new signal
  kinds are rejected per-signal (reflected in the `rejected` count), never a
  whole-batch failure;
  removing/renaming a field or changing semantics requires bumping `schema_version`
  and accepting the old version for at least one release. The stub endpoints
  `/api/v1/feed/top-domains` and `/api/v1/feed/anomalies` keep returning empty
  payloads for one release (deprecated), then are removed.

## Detection & Enrichment

This service performs aggregation, not detection. The consensus/confidence model is
the simplified core of `research/deep-dive-consensus-algorithm.md` §2.3, with trust
weighting removed (all reporters weigh 1.0) and ASN diversity removed:

For each `(kind, indicator_key)` over a trailing 7-day window:

```
per-reporter contribution = max(local_confidence) across that reporter's signals
                            (each reporter counts ONCE — the per-reporter influence cap)
avg_conf            = mean(per-reporter contributions)
distinct_reporters  = count of unique reporter_ids
reporter_factor     = min(1.0, distinct_reporters / 5)
feed_confidence     = min(0.99, avg_conf * (0.7 + 0.3 * reporter_factor))
```

Promotion into `feed_items` (thresholds from `docs/threat-intel-mvp.md`) requires the
allowlist guard to pass AND at least one of:

1. exact domain with a `known_bad` local reason, `distinct_reporters >= 2` within 7 days;
2. exact domain, `distinct_reporters >= 3` within 7 days AND `avg_conf >= 0.90`;
3. eTLD+1 candidate or behavior cluster, `distinct_reporters >= 4` within 7 days AND
   `avg_conf >= 0.80`.

Otherwise the aggregate stays in the hold/manual-review state (a DB state, no UI in
V1): single-reporter indicators, uncorroborated high-volume reporters, novel patterns.

- **Allowlist guard:** if the indicator's eTLD+1 is in `allowlist_domains`, never
  promote, and increment the reporting reporters' `allowlist_flags` (poisoning
  signal). Mirrors the deep-dive's Tranco override with a static V1 snapshot.
- **Severity mapping:** `known_bad`-corroborated → `high`; rule-2 domains → `medium`;
  rule-3 clusters → `low`. Severity is context for Core scoring, not an action level.
- **Decay/expiry:** rule-1 items get `expires_at = last_seen + 30d`; rules 2–3 get
  `last_seen + 7d`. Each consensus run refreshes `last_seen`/`confidence` while
  corroboration continues; expired items disappear from the feed (kept revoked in the
  table for audit). Confidence is recomputed each run, so it decays naturally as old
  signals age out of the 7-day window.

No existing Core detectors are affected by this spec (consumption is a follow-up).

## SNR Tuning Plan

Shipped WITH the feature (not deferred):

- Multi-reporter promotion thresholds — one reporter can never create shared intel.
- Allowlist guard blocking popular-domain promotion + poisoning flag on offenders.
- Advisory-only contract: consumers may add context/score, never alert on feed
  membership alone and never block. Enforced in the wire format
  (`recommended_action: "advise"` is the only value in schema v1).
- Feed cap: 5,000 items max, highest confidence first — bounds downstream import noise.
- Decay: uncorroborated items self-remove in 7 days.

Validation loop before the feed is called "supported":

1. **Simulated traffic:** integration fixtures replay synthetic multi-reporter batches
   (RFC 5737 / `*.example` data) asserting: no single-reporter promotion; threshold
   boundaries (2/3/4 reporters, 0.90/0.80 gates) behave exactly; allowlisted eTLD+1
   never promotes; decay removes stale items; a flooding reporter hits caps without
   affecting other reporters' aggregates.
2. **Live alpha:** run Phase-1 style (ingest + aggregate, feed endpoint dark) with the
   first opted-in nodes; review `signal_aggregates` and would-be promotions for a week;
   only then enable the feed. This mirrors Rollout Phases 1–2 of
   `docs/threat-intel-mvp.md`.
3. Core-side consumption gets its own spec and SNR pass before feed items influence
   any user-visible scoring.

## Failure Modes & Limits

- **Telemetry daemon can't reach the service:** entirely the daemon's problem by
  design (spec 002 outbox retries); local detection never depends on this service.
- **Malformed batches:** structurally invalid signals are rejected per-signal and
  reflected in the `rejected` count of the `202` body (per-signal detail is logged
  server-side, never added to the wire); privacy-gate violations reject the whole
  batch with `422` and body `{error, rule, detail, batch_id}` (002 contract §5);
  whole-batch 400 only for envelope/schema-version failures. A duplicate `batch_id`
  is not an error (idempotent `200` with `duplicate: true`). All error codes machine-
  readable (`INVALID_SIGNATURE`, `STALE_TIMESTAMP`, `NONCE_REUSED`,
  `RATE_LIMIT_EXCEEDED`, `INVALID_SCHEMA`, `REPORTER_DENYLISTED`).
- **Floods:** per-IP token bucket (in-memory, never persisted) at the HTTP layer;
  per-reporter limits: max 250 signals/batch (registration config), max 4 batches/hour,
  max 1,000 accepted signals/day, max 200 distinct new indicators/day
  (`reporter_counters`). Over-cap → 429 with `retry_after_seconds`. Repeat abusers →
  `status='denylisted'`.
- **SQLite contention:** single-writer service; WAL mode; consensus job runs in the
  same process on a 15-minute ticker; ingest writes are small transactions. At tens of
  reporters × 250 signals / 15 min this is orders of magnitude under SQLite limits.
- **Disk growth:** retention purge daily — `signals` and `ingest_receipts` > 30 days,
  `nonces` > 24 h, revoked `feed_items` > 90 days.
- **Service dies mid-consensus:** aggregates/feed upserts are idempotent recomputations
  from `signals`; next run heals.
- **Clock skew:** ±5 min timestamp window on signed requests; document NTP requirement
  for reporters.
- **Pi 4 note:** zero on-node footprint (service is off-node); the telemetry daemon's
  budget is spec 002's concern.

## Constitution Check

The spec's constitution table holds for this technical approach. Points of tension
checked:

- **Privacy/opt-in (strongest constraint):** the design stores no PII (random
  reporter_id + secret hash only; per-IP limiter is memory-only; counts-only signal
  fields; hour buckets; server-side privacy re-gate rejects anything resembling
  internal names or IP literals). Feed output contains only aggregate, corroborated
  indicators. Complies.
- **Local value first:** service is additive infrastructure; no Core code path gains a
  dependency on it. Complies.
- **Migrations rule:** constitution names `siem/migrations/` for schema changes; this
  service introduces a sibling chain at `threat-network/migrations/` following the same
  sequential/never-edit rule. This is an extension of the rule's intent, not an
  exception — recorded here for transparency.
- **One data source at a time:** this spec adds no new Core data source; the community
  feed becomes a Core source only via a future spec, keeping the UniFi-first sequencing
  intact.
- **AGPLv3 / no lock-in:** single Go binary + SQLite, self-hostable; anyone can run
  their own network. Complies. (A Cloudflare deployment remains possible but is not
  required — see spec Open Questions.)

## Test Strategy

- **Unit:**
  - `auth`: HMAC verify (good/bad signature, skewed timestamp, nonce reuse), secret
    hashing, denylist.
  - `ingest`: contract validation per signal kind, privacy re-gate table-driven tests
    (`.local`, `.lan`, `.home`, `.internal`, `.corp`, `home.arpa`, single-label,
    IP-literal, `in-addr.arpa` all rejected),
    dedup upsert semantics, per-reporter caps.
  - `consensus`: threshold boundary tests (1 vs 2 reporters known_bad; 2 vs 3 at
    0.89/0.90; 3 vs 4 at 0.79/0.80), confidence formula, allowlist guard, decay,
    per-reporter influence cap (100 signals from one reporter count once).
  - `feed`: cursor stability, ETag, expiry filtering, 5,000-item cap.
- **Integration (httptest against the real mux + temp SQLite):** register → signed
  ingest → run consensus → pull feed end-to-end with synthetic fixtures; replayed
  batch answered idempotently (`200`, `duplicate: true`, no re-processing); flooding
  reporter throttled while a second reporter is unaffected;
  golden-file check of the feed response against `contracts/community-feed-api.md`
  examples.
- **Migration test:** fresh-install chain applies cleanly to an empty DB; runner is
  idempotent on re-run (required by the constitution for any schema change — applied
  here to the service's own chain).
- **Manual verification:** `go run ./cmd/threat-network`, drive with `curl` using the
  contract's synthetic examples; verify `/api/v1/status`, a signed ingest round-trip,
  and feed output; confirm the Docker image still builds (`threat-network/Dockerfile`).
- **Build gate:** `go build ./... && go test ./...` in `threat-network/` added to the
  pre-commit expectations alongside backend/sensor (constitution build rule).
