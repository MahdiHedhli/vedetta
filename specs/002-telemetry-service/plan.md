# Plan: Telemetry Service (Opt-In Privacy-Reduced Export)

> Spec: `specs/002-telemetry-service/spec.md`
> Status: Draft
> Created: 2026-07-03

> **Superseded (shipped behavior, see #37):** telemetry ships **ON by default (opt-out)** — only `VEDETTA_TELEMETRY_OPTIN=false` disables it; sharing is **pseudonymous, not anonymous** (stable per-instance `reporter_id` stored server-side, see PRIVACY.md); and consensus uses **distinct matured reporter credentials**, not proven-independent operators. The design-era "opt-in / off by default / anonymous / independent reporters" language below predates these decisions — read it through this note.

## Architecture Overview

The telemetry daemon is the existing `telemetry` container in the Core Docker Compose
stack (inert only when explicitly opted out via `VEDETTA_TELEMETRY_OPTIN=false`; it ships on by default). It sits strictly
between Core's read API and the public threat network; sensors never touch it.

```text
vedetta-core backend (Docker)
   GET /api/v1/events  (Core token auth)
        |
        v
vedetta-telemetry (this feature, Docker, module github.com/vedetta-network/vedetta/telemetry)
   [1] batch reader   — cursor-driven poll of Core events API
   [2] export gate    — eligibility rules (tags/confidence/private-name filters)
   [3] PII stripper   — allowlist projection to ExportCandidate
   [4] aggregator     — ExportCandidates -> signals (counts, hour buckets)
   [5] transmitter    — sign, gzip, POST; retry/backoff; bounded disk spool
   [6] status server  — localhost /healthz + /status
        |
        v  HTTPS, signed batches
vedetta-threat-network  POST /api/v1/ingest   (specs/003-threat-network/spec.md)
```

Packages (new, inside `telemetry/`):

| Package | Responsibility |
| --- | --- |
| `internal/config` | env parsing, defaults, opt-in gate |
| `internal/corereader` | Core events API client + cursor persistence |
| `internal/export` | eligibility gate, allowlist stripper, aggregator (the privacy boundary) |
| `internal/transmit` | reporter registration, request signing, backoff, spool |
| `internal/status` | `/healthz`, `/status` HTTP surface |
| `cmd/telemetry` | wiring, opt-in check, signal handling (replaces the stub TODO) |

## Data Flow

Source → normalization → ingest → storage → enrichment → UI, end to end (telemetry
consumes the tail of the existing pipeline and adds an egress branch):

1. **Source:** already-enriched events in Core SQLite, produced by sensor/collector
   ingest (`POST /api/v1/ingest`, `handleIngest` in `backend/internal/api/router.go`)
   and DNS pipelines. Telemetry adds no new capture.
2. **Read:** every `tick_interval` (default 15 min), `corereader` calls
   `GET /api/v1/events` on `VEDETTA_CORE_URL` with `VEDETTA_CORE_TOKEN`, requesting
   events newer than the persisted cursor (RFC3339 timestamp + last event ID
   tie-breaker), paging until drained. Cursor is persisted to
   `$VEDETTA_TELEMETRY_STATE_DIR/cursor.json` after each fully processed page —
   at-least-once semantics; duplicates are absorbed by `signal_id` idempotency and
   server-side dedup.
3. **Gate (`export.Eligible`):** an event enters the pipeline only if ALL hold:
   - `event_type` is `dns_query` or `anomaly`;
   - not `acknowledged`; not tagged `whitelisted`/`suppressed`/`deduplicated`-only;
   - domain is public: rejects empty, single-label, `.local`, `.lan`, `.home`,
     `.internal`, `home.arpa`, `.arpa` reverse zones, IP-literal lookups, and
     punycode that decodes to private-looking names;
   - confidence rule (initial values, tunable via env):
     - `known_bad_domain_hit`: tagged `known_bad` (trusted local threat source match),
       any score; exact domain allowed.
     - `high_confidence_domain_candidate`: `anomaly_score >= 0.85` AND at least one of
       tags `c2_candidate`, `dga_candidate`, `tunneling_candidate`,
       `newly_registered`; reduced to eTLD+1 (vendored Public Suffix List snapshot).
     - `behavior_summary`: score `0.70–0.85` with behavior tags → counts only, no
       domain at all.
     - Anything below: withheld entirely.
4. **Strip (`export.Strip`):** allowlist projection (see API & Wire Contracts). Output
   type `ExportCandidate` structurally cannot hold forbidden fields.
5. **Aggregate (`export.Aggregate`):** group candidates by (kind, domain-or-eTLD+1
   -or-behavior, hour bucket); collapse `source_hash` sets into
   `distinct_asset_count`; sum `observation_count` and `blocked_count`; take max
   confidence; union reason tags. `source_hash` values are discarded here — they never
   reach the wire.
6. **Transmit (`transmit`):** wrap signals in the batch envelope
   (contracts/telemetry-export.md), cap at `max_batch_items` (split into multiple
   batches if needed), gzip, sign headers
   (`Authorization: VedettaReporter <reporter_id>`, `X-Vedetta-Timestamp`,
   `X-Vedetta-Nonce`, `X-Vedetta-Signature =
   hex(HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + sha256(body)))`), POST to
   `<VEDETTA_THREAT_NETWORK_URL>/api/v1/ingest`.
7. **Storage touched:** none in Core (read-only). Telemetry-local state dir only:
   `cursor.json`, `reporter.json` (0600), `salt` (0600), `spool/*.json.gz`.
8. **UI:** none in this phase; operators use `GET /status`.

## Schema Changes

**None.** No new migration in `siem/migrations/` — telemetry is read-only against Core
and keeps its own state in flat files inside the container volume. Justification: the
constitution requires migrations for schema changes; this feature makes none. The
future `telemetry_outbox` / `community_intel` tables (deferred, see spec Out of Scope)
will each arrive as new sequential migrations in their own follow-up spec. Because
there is no schema change, the fresh-install migration test in the Final Gate is a
no-regression check (chain still applies cleanly, currently 17 migrations).

## API & Wire Contracts

### Consumed (existing, unchanged)

- `GET /api/v1/events?from=<RFC3339>&limit=<n>&sort=timestamp&order=asc` on Core —
  read-only, Core-token auth, using the endpoint's existing `from`/`limit`/`page`/
  `sort`/`order` parameters (`backend/internal/api/router.go` `handleEvents`).
  No backend changes required; if these prove insufficient, any additions to the
  events API are additive query params only (backward compatible).

### Produced (new, crosses a service boundary → contract file)

- `POST /api/v1/reporters/register` and `POST /api/v1/ingest` on the threat network.
  Exact exported-record JSON schema, signing headers, validation rules, and synthetic
  examples are frozen in **`specs/002-telemetry-service/contracts/telemetry-export.md`**.
  That file is the single source of truth the threat-network service
  (specs/003-threat-network/spec.md) validates against.

### PII stripper allowlist (the privacy boundary, enforced in code + tests)

Fields that may exist on an `ExportCandidate` (everything else is dropped by
construction — the struct has no other fields):

| Allowlisted field | Source (Core `models.Event`) | Transform |
| --- | --- | --- |
| `kind` | derived from gate rule | enum of 3 signal kinds |
| `domain` | `domain` | only for `known_bad_domain_hit`; lowercased, validated public |
| `etld_plus_one` | `domain` | PSL reduction; only export form for candidates |
| `behavior` | derived from tags | enum (e.g. `dns_beaconing_candidate`) |
| `time_bucket` | `timestamp` | truncated to hour, UTC |
| `local_confidence` | `anomaly_score` | clamped [0,1] |
| `local_reasons` | `tags` | intersection with a fixed reason vocabulary (no free text) |
| `blocked` | `blocked` | boolean as-is |
| `source_hash` | `source_ip` | HMAC-SHA256 with telemetry-local salt; **internal only — collapsed to `distinct_asset_count` by the aggregator, never serialized to the wire** |

Explicitly forbidden (must appear in stripper tests as inputs that never pass):
`source_ip`, `resolved_ip`, `server_ip`, `event_id`, exact `timestamp`, `device_vendor`,
`network_segment`, `dns_source`, `threat_desc`, `metadata`, `geo`, hostnames, MAC
addresses, custom names/notes, query payloads, and any free-form string field.
(`geo` is withheld in MVP even though country-level: reporter geography is derivable
server-side from the connection and need not ride in records.)

### Backward compatibility

- Every batch carries `schema_version: 1`. Contract changes are additive-only; removing
  or renaming a field requires a major schema_version bump plus one release of
  dual-emission, mirroring the constitution's wire-format alias rule. Telemetry and
  threat-network upgrade independently; the server MUST accept all schema versions it
  has ever published validators for, or reject with a structured error the daemon
  surfaces on `/status`.

## Detection & Enrichment

No local detectors are added, removed, or re-scored in this phase. Interactions with
existing detection state are read-only and one-directional:

- Suppression/whitelist/ack state **gates export** (suppressed or acked events never
  leave), so operator tuning automatically tightens telemetry too.
- Existing tags (`known_bad`, `c2_candidate`, `dga_candidate`, tunneling/beaconing
  tags) drive kind selection via a fixed vocabulary map; unknown tags are dropped,
  never forwarded.
- Community-feed-driven enrichment (raising local suspicion from network intel) is
  explicitly deferred with feed consumption.

## SNR Tuning Plan

No new inbound source → no new local alert noise; the tuning work here protects the
**community corpus** and ships WITH the feature:

- Export gate thresholds (`0.85` candidate floor, `0.70` behavior floor, `known_bad`
  tag requirement for exact domains) shipped as env-tunable defaults.
- Private/special-use name filter (mirrors `docs/threat-intel-mvp.md` exclusions)
  with table-driven tests.
- Reason-vocabulary intersection prevents free-text tag leakage and vocabulary drift.
- **Validation loop before the export path is called "supported":**
  1. *Simulated:* replay a synthetic event corpus (RFC 5737 IPs, `.example` domains,
     `00:00:5E:00:53:xx` MACs) through the full pipeline; assert exported batch matches
     golden files and contains zero forbidden values (automated leak scan: regex for
     RFC1918/link-local IPs, MAC patterns, `.local`/`.lan`/`home.arpa`, non-vocabulary
     strings).
  2. *Live:* run opted-in against a real node for ≥72h in dry-run mode
     (`VEDETTA_TELEMETRY_DRYRUN=true`: full pipeline, batches written to spool + logged
     via `/status`, no egress); operator reviews every would-be exported record; record
     the review result in the tasks Final Gate. Only then enable real egress.

## Failure Modes & Limits

| Failure | Behavior |
| --- | --- |
| Opted out (`VEDETTA_TELEMETRY_OPTIN=false`) | Fully inert: no reads, no egress, no state writes; sleeps until signal. |
| Core API unreachable / 401 | Tick skipped, cursor unchanged, error surfaced on `/status`; retry next tick. No data loss (events remain in Core, subject to Core's 90-day retention — a multi-week outage loses only telemetry, never local data). |
| Threat network unreachable / 5xx | Exponential backoff 1s→2s→4s→8s… capped 5 min within a tick; batch then persisted to spool. Spool bounded: max 50 batches or 24h, oldest dropped first (acceptable loss — telemetry is best-effort by design). |
| Threat network 4xx (schema/signature rejected) | Batch NOT retried (poison-pill guard); moved to `spool/rejected/` (capped at 5, oldest dropped) for operator inspection; error on `/status`. |
| Malformed event from Core | Skipped, counted (`events_skipped_malformed` on `/status`), never crashes the tick. |
| Event flood (local incident) | Per-tick read cap (default 5,000 events) + `max_batch_items` split cap (default 4 batches/tick) → bounded memory and upstream volume even during a storm; aggregation collapses repeats so floods raise counts, not record volume. |
| Clock skew | Signature timestamp comes from local clock; server rejects stale timestamps → surfaced as 4xx on `/status` with a "check NTP" hint. |
| Registration secret lost/corrupt | Daemon re-registers with a NEW install UUID (old reporter identity is orphaned server-side and ages out via specs/003 decay rules). |
| Pi 4 budget | ≤15 MB RSS, near-0% CPU between ticks; ~2k eligible events/day worst case aggregates to well under 250 signals/tick; ≤ ~300 KB/day egress gzip'd. |

## Constitution Check

The spec's constitution table holds for this technical approach; re-verified points and
one tension:

- **Privacy/opt-in:** the allowlist is enforced structurally (`ExportCandidate` cannot
  represent forbidden fields) plus tested behaviorally (leak-scan on serialized
  output). `source_hash` uses a **telemetry-local** salt generated at first opt-in
  (0600), deliberately distinct from Core's per-install salt so Core-side hashes and
  exported aggregates can never be joined. Dry-run mode gives operators a full audit
  before first egress.
- **Local value first:** Core has zero code changes; telemetry failure of any kind
  cannot affect local detection.
- **No new dependencies:** Go stdlib + a vendored PSL snapshot; no new services
  required to run Core.
- **Environment data handling:** all fixtures/golden files use RFC 5737 / RFC 2606 /
  `00:00:5E:00:53:xx` synthetic values only.
- **Tension called out:** the constitution says migrations for every schema change —
  this plan stores telemetry state in flat files rather than SQLite, so no migration
  exists to track state-file format. Mitigation: `cursor.json`/`reporter.json` carry
  their own `version` field and the daemon migrates or regenerates them on load
  (regeneration is always safe: worst case is re-registration or re-reading recent
  events, absorbed by idempotency).

## Test Strategy

- **Unit (bulk of coverage, in `telemetry/`):**
  - `export`: table-driven tests for the eligibility gate (every exclusion rule),
    the stripper (forbidden fields never pass — see tasks T3.x, including a
    reflection/JSON round-trip test asserting the serialized signal contains ONLY
    contract keys), PSL reduction, hour bucketing, aggregation math, reason-vocabulary
    intersection.
  - `transmit`: signature vector tests (fixed secret/timestamp/nonce/body → known hex),
    backoff schedule, spool cap/rotation, 4xx-no-retry behavior.
  - `corereader`: cursor persistence, paging, resume-after-crash (httptest fake Core).
- **Integration:** docker-compose test with a stub threat-network (httptest binary)
  asserting: opt-in off → zero requests; opt-in on → register + signed valid batch;
  network down → spool then drain. Golden-file check of a full synthetic batch against
  `contracts/telemetry-export.md` examples (the same fixtures specs/003 uses for its
  validator — shared contract tests keep both sides honest).
- **Leak scan (privacy regression gate):** automated scan of every serialized test
  batch for RFC1918/link-local/IP-literal patterns, MAC regex, private suffixes, and
  any JSON key outside the contract; runs in CI as part of `go test ./...`.
- **Manual verification:** 72h live dry-run review (see SNR Tuning Plan) on a real
  node; `/status` fields eyeballed; kill/restart mid-tick to confirm cursor idempotency.
- **Fresh-install migration test:** required by template — no schema change here, so
  the check is that the existing 17-migration chain still applies cleanly and
  `go build ./... && go test ./... -short` stays green in `backend/`, `sensor/`, and
  the new `telemetry/` module.
