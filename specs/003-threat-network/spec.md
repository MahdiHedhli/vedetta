# Spec: Community Threat-Network Backend (Ingest, Consensus, Advisory Feed)

> Feature directory: `specs/003-threat-network/`
> Status: Draft
> **Superseded notes (#37 / #43):** this design doc predates two shipped decisions.
> (1) Telemetry ships **ON by default (opt-out)**, not opt-in/off-by-default; and
> sharing is **pseudonymous, not anonymous** (a stable per-instance `reporter_id`
> is stored server-side — see PRIVACY.md). (2) Consensus corroboration is by
> **distinct matured reporter credentials**, which is *not* proof of independent
> operators (advisory-only; see SECURITY.md). Where the text below says
> "anonymous"/"opt-in"/"independent reporters", read it through these notes.
> Backlog: VED-008 (contract), VED-011 (implementation)
> Created: 2026-07-03

## Summary

Replace the `threat-network` stub (`threat-network/cmd/threat-network/main.go`, TODO
"Validate, deduplicate, and store batch", listening on :9090) with a working community
backend: it registers opted-in reporters, accepts signed privacy-reduced telemetry
batches, deduplicates and stores them in SQLite, runs a simple multi-reporter consensus
job, and publishes a versioned, advisory-only community feed over GET. The user-visible
outcome: an opted-in Vedetta deployment can contribute high-signal observations and, in
return, every deployment can poll a community feed of corroborated indicators that
raises local scoring context — exactly like Core already polls abuse.ch feeds — without
any household data leaving the node and without community data ever auto-blocking
anything.

## Motivation & Evidence

- `docs/threat-intel-mvp.md` (Draft alpha design) defines the narrowest useful MVP:
  opt-in, privacy-reduced, advisory-first, one-reporter-can't-poison. This spec is its
  implementation contract for the threat-network side (Rollout Phases 1–2 of that doc).
- `research/deep-dive-consensus-algorithm.md` analyzes CrowdSec's consensus/trust model
  and adapts it to DNS domain reputation. V1 keeps only the core of that design —
  distinct-reporter consensus with confidence gates, allowlist protection, and decay —
  and explicitly cuts trust weighting, ASN diversity, FFT beaconing, canaries, and the
  ClickHouse analytics stack (see Out of Scope).
- `research/05-threat-intelligence-feeds.md` establishes the consumption pattern: Core's
  `backend/internal/threatintel` package already schedules abuse.ch feed downloads
  (URLhaus/Feodo/SSLBL) into a local `threat_indicators` store. The community feed is
  designed so that the same scheduler can poll it as "one more feed" later.
- Ground truth on current code (verified 2026-07-02): `threat-network` service is a stub
  with `/api/v1/status`, a no-op `/api/v1/ingest`, and empty feed endpoints;
  `telemetry/cmd/telemetry/main.go` is also a stub. The telemetry-side export pipeline
  is specified separately in `specs/002-telemetry-service/spec.md`; this spec consumes
  its wire contract (`specs/002-telemetry-service/contracts/telemetry-export.md`).

## User Stories

- As a homelab user who left telemetry on (the default), I want my Core's high-confidence
  detections to be contributed pseudonymously so that other users get earlier warning of
  the same C2/DGA domains — without my IPs, MACs, hostnames, or query history leaving
  my network.
- As a small business operator, I want Vedetta to consume a community feed of
  indicators corroborated by multiple distinct matured reporter credentials so that local alerts on
  those indicators get better context/scoring, while nothing is auto-blocked on
  community say-so alone.
- As the threat-network operator, I want signed requests, replay protection, rate
  limits, and per-reporter influence caps so that a single malicious or broken node
  cannot poison the feed or flood the service.
- As a privacy-conscious user evaluating opt-in, I want the server to store no PII and
  publish only aggregate, corroborated indicators so I can verify the guarantee from
  the schema and the published contract, not from marketing copy.

## Requirements

### Functional

- FR-1: `POST /api/v1/reporters/register` issues a random `reporter_id` + secret to an
  opting-in deployment; the server stores only the id and a hash of the secret (no
  account, email, or operator identity). Registration is explicit and revocable
  (denylist).
- FR-2: `POST /api/v1/ingest` accepts signed telemetry batches conforming to
  `specs/002-telemetry-service/contracts/telemetry-export.md` (signal kinds
  `known_bad_domain_hit`, `high_confidence_domain_candidate`, `behavior_summary`).
  Requests are authenticated with the HMAC signed-request scheme
  (timestamp + nonce + body hash); stale timestamps, reused nonces, and invalid
  signatures are rejected. A duplicate `batch_id` is an idempotent replay: `200`
  with `duplicate: true`, no re-processing (002 contract §1).
- FR-3: Ingest validates every signal against the contract (schema version, required
  fields per kind, confidence in [0,1], counts ≥ 0, hour-bucket timestamps) and
  server-side re-applies the privacy gate. Unknown fields, IP- or MAC-shaped values,
  configured special-use/internal or single-label names, and URL syntax reject the
  whole batch with `422` (002 contract §5). Invalid DNS names or lengths, Public
  Suffix List reduction failures, candidate values that are not eTLD+1, and known-bad
  eTLD+1 mismatches skip only the offending signal and increment the rejected count.
  Core should never send either class (defense in depth). These concrete checks cannot
  recognize every possible identifier embedded in an otherwise valid public domain.
- FR-4: Accepted signals are deduplicated on `(reporter_id, kind, indicator, time_bucket)`
  — one row per reporter per indicator per hour window — plus batch/signal-id replay
  dedup, and stored in SQLite.
- FR-5: A periodic consensus job aggregates signals per indicator over a trailing
  7-day window and promotes indicators into the advisory feed using the conservative
  thresholds from `docs/threat-intel-mvp.md` (≥2 reporters for locally-known-bad exact
  domains; ≥3 reporters at aggregate confidence ≥0.90 for exact domains; ≥4 reporters
  at ≥0.80 for eTLD+1/behavior clusters). Confidence rises with the number of
  distinct matured reporter credentials (not proof of distinct operators); a single reporter can never cause promotion.
- FR-6: Feed items decay: candidates expire after 7 days without refresh,
  known-bad-corroborated items after 30 days; expired items drop out of the feed.
- FR-7: `GET /api/v1/feed/community` publishes promoted items: versioned
  (`schema_version`), cursor-paginated, ETag-cacheable, advisory-only
  (`advisory: true`, `recommended_action: "advise"` on every item — never "block").
  The shape maps 1:1 onto Core's `threatintel.Indicator` (indicator, type, source,
  confidence, tags, first_seen, last_seen, TTL) so Core's existing feed scheduler can
  poll it like an abuse.ch feed. Contract: `contracts/community-feed-api.md`.
- FR-8: Abuse resistance ships with the feature, not after it: per-reporter and per-IP
  rate limits, max batch size, daily per-reporter signal and distinct-indicator caps,
  allowlist (top-domains) poisoning detection, and a reporter denylist.
- FR-9: No direct device/operator identifiers at rest: no operator account, persistent
  source-IP storage, or asset identifier. Per-IP rate-limit keys and last-access times
  remain in memory while active and until swept after 30 idle minutes; they do not enter
  SQLite or application logs. The service does
  store a stable reporter pseudonym and version/capabilities/times; linked signal domains,
  hourly event buckets, confidence/reasons/counts, and exact receipt/merge times; and batch
  receipts. Signal rows and receipts are retained ≤30 days. Reporter rows/counters,
  computed aggregates, and feed items have separate or incomplete expiry.
- FR-10: `GET /api/v1/status` reports health and schema version (already stubbed; kept).

### Non-Functional

- NFR-1: Pi 4 hardware floor — this service runs OFF-node (community infrastructure),
  so idle impact on user hardware is zero. The service itself must still be frugal:
  target comfortable operation for tens of alpha reporters on a 1 vCPU / 512 MB
  instance (SQLite, stdlib HTTP, no heavy dependencies), consistent with the
  free-infrastructure shape in `docs/threat-intel-mvp.md`.
- NFR-2: Works with Core + native sensor only — community intel is additive. Vedetta
  deployments that never opt in lose nothing; the feed is one optional enrichment
  source among several, exactly like Pi-hole and abuse.ch.
- NFR-3: Wire formats versioned from day one (`schema_version` on ingest and feed);
  reporters and the server upgrade independently, so unknown optional fields are
  ignored, and breaking changes require a new schema version.
- NFR-4: The full stack stays cheap enough to run as an alpha research network
  (SQLite file DB, single binary, Docker-deployable via existing
  `threat-network/Dockerfile`).

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | Indirectly | Sensors never talk to the threat-network (product guardrail in `docs/threat-intel-mvp.md`); only Core-side telemetry exports. No change to the Docker Core + native sensor split. |
| Pi-hole optional | Yes | Community feed is an additive enrichment source; nothing requires Pi-hole, and the feed is not required for any local detection. |
| Passive-first | Indirectly | Contributed signals derive from Core's existing passive detections; this feature adds no active scanning anywhere. |
| V1 scope (no LAN scan/exploit) | Yes | Pure data service. Advisory-only output; no enforcement, no auto-block, no remediation actions. Scope cuts listed below keep complexity down. |
| SNR re-tune for new sources | Yes | The community feed is a future new enrichment source for Core; promotion thresholds, allowlist guard, decay, and advisory-only semantics are the noise controls shipped WITH it (see SNR section). Core-side consumption gets its own SNR pass when it lands. |
| Privacy / opt-out telemetry | Yes — core constraint | On by default (opt-out) at Core level, privacy-reduced payloads only, pseudonymous reporter identity (stable per-instance `reporter_id` stored server-side, see PRIVACY.md), no direct PII at rest, server-side privacy gate re-check, advisory-only feed. This spec is the enforcement point for the constitution's "optional, privacy-conscious, secondary to local operation" rule — satisfied here by trivially-reversible opt-out rather than opt-in. |
| Environment data handling | Yes | All examples in this spec, plan, and contract use RFC 5737 IPs, `00:00:5E:00:53:xx` MACs, and placeholder domains (`*.example` / `*.example.net`). No real environment data is referenced. |

## Signal-to-Noise Impact

New noise patterns this feature can introduce and the tuning shipped with it:

- **Community false positives amplified network-wide.** A benign-but-odd domain
  (CDN rotation, telemetry endpoints, ad-tech) flagged by several nodes could enter the
  feed. Mitigations shipped in V1: multi-reporter promotion thresholds (never 1),
  aggregate-confidence gates (0.90 exact / 0.80 cluster), a top-domains allowlist that
  blocks promotion of popular eTLD+1s outright, decay so uncorroborated items fall out
  in 7 days, and `advisory` semantics so Core may only add context/score — never alert
  solely on feed membership and never block.
- **Poisoning as noise injection.** An attacker reporting garbage at volume is a noise
  source; rate limits, per-reporter daily caps, dedup per (reporter, indicator, hour),
  allowlist-poisoning flagging, and the denylist bound single-reporter influence.
- **Feed bloat.** Cap published feed at 5,000 items ordered by confidence; anything
  below the cap waits. Keeps Core-side import bounded and reviewable.
- **Validation loop before "supported":** Phase-gated rollout mirrors
  `docs/threat-intel-mvp.md` — ingest-and-store first (no live feed), then promotion of
  exact high-confidence domains only, then clusters. Simulated multi-reporter traffic
  (unit + integration fixtures) must demonstrate: no promotion from a single reporter,
  allowlisted domains never promoted, and decay removes stale items, before the feed
  endpoint is enabled in production.

## Out of Scope

Explicit V1 cuts, each with rationale:

- **Reporter reputation / trust weighting** (deep-dive §2.2 NodeTrust): all reporters
  weigh equally in V1; thresholds do the anti-poisoning work. Trust scoring needs
  months of reporter history that does not exist yet.
- **Cross-region federation / multi-instance sync:** one instance, one SQLite DB;
  federation is a scaling problem we do not have at tens of nodes.
- **ASN/geo diversity requirements** (deep-dive §2.4.1): the server would need to
  persist source-network metadata, which conflicts with the no-PII-at-rest rule; V1
  substitutes distinct-reporter counts only.
- **FFT beaconing scoring, ML poisoning clustering, canary domain network**
  (deep-dive §2.3/§2.4/§2.5): high-complexity hardening for a network that is still
  proving basic signal value.
- **ClickHouse / TimescaleDB analytics store** (deep-dive §3): SQLite matches the
  existing stack, the alpha volume, and the free-infra deployment shape; the schema is
  kept narrow and aggregate-first so a future move stays possible.
- **Multiple feed types, diff endpoint, hostfile/CSV output, network-health feed**
  (deep-dive §2.6/§4.5): one JSON advisory feed first.
- **Core-side feed consumption** (community_intel cache, scoring integration, UI
  copy): belongs to a follow-up spec once the feed exists; the contract here is
  designed for it.
- **Telemetry daemon implementation:** owned by `specs/002-telemetry-service/`.
- **Operator dashboard / analyst case management:** MVP explicitly excludes it.
- **Auto-blocking from community intel:** excluded by product guardrail; the API
  cannot express it (`recommended_action` is always `advise` in V1).

## Open Questions

- [ ] Should feed reads require reporter credentials, or stay public like abuse.ch?
      V1 ships public-read (advisory aggregate data, no secrets), revisit if abuse
      appears.
- [ ] Allowlist source: ship a static top-domains snapshot in the repo vs. weekly
      Tranco refresh job. V1 ships static snapshot; refresh job is a fast follow.
- [ ] Where does the threat-network run for the alpha — the Cloudflare Worker + D1
      shape from `docs/threat-intel-mvp.md`, or this Go binary on a small VM? This
      spec implements the Go binary (stack-consistent, self-hostable); the schema and
      API are kept D1/Worker-portable if the Cloudflare path wins later.
- [ ] Exact `sources_required`/`sources_observed` exposure in feed items: useful
      transparency vs. information an attacker can use to tune poisoning. V1 exposes
      them (transparency for an alpha research network); revisit at scale.
