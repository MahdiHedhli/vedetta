# Spec: Telemetry Service (Opt-In Privacy-Reduced Export)

> Feature directory: `specs/002-telemetry-service/`
> Status: Draft
> Backlog: VED-008 (contract), VED-010 (implementation)
> Created: 2026-07-03

## Summary

Implement the currently-stubbed telemetry daemon (`telemetry/cmd/telemetry/main.go`, TODO:
"batch reader, PII stripper, and transmitter") so that an **explicitly opted-in** Vedetta
Core deployment can contribute a small set of privacy-reduced, domain-level threat
observations to the community threat network (specs/003-threat-network/spec.md). The
service is **OFF by default**, exports **only an allowlisted set of fields** (no raw
internal IPs, MACs, or hostnames — `source_hash` HMAC only; domain-level indicators
only), and everything it produces downstream is **advisory-only** — community intel never
auto-blocks and is never a dependency for local detection. The user-visible outcome: a
node operator can flip one switch, verify on a status endpoint exactly what left the
node, and turn it off at any time with zero impact on local monitoring.

## Motivation & Evidence

- `docs/threat-intel-mvp.md` (VED-008 contract basis) defines the narrowest MVP for
  shared intelligence: opt-in, off by default, privacy-reduced, advisory-first. Phase 1
  of its rollout plan is exactly this feature: "local export gating plus signed upload
  in telemetry."
- `research/06-event-aggregation-telemetry.md` (P1): a crowdsourced threat-intel corpus
  from home/SMB DNS traffic is Vedetta's clearest competitive moat, modeled on
  CrowdSec's consensus architecture but domain-centric instead of IP-centric. It
  supplies the PII-stripping pipeline shape, batching parameters (15-minute windows,
  bounded batch size, exponential backoff), and bandwidth estimates (~300 KB/day).
- `docs/architecture.md` lists `telemetry` as "scaffolded" and states the guardrail this
  spec enforces: "telemetry is optional and off by default … future community sharing
  should remain opt-in and privacy-conscious."
- `docs/backlog.md` VED-008 (P1, Ready): "Build the opt-in threat-intel MVP contract …
  keep export privacy-reduced, advisory-only, and off by default."
- Ground truth (verified 2026-07-02): the Core backend already exposes
  `GET /api/v1/events`, `/events/stats`, `/events/timeline`, and a working
  `POST /api/v1/ingest`; `telemetry/cmd/telemetry/main.go` only checks
  `VEDETTA_TELEMETRY_OPTIN` and sleeps; `threat-network/cmd/threat-network/main.go` is a
  stub with TODOs. This spec covers the telemetry side; the receiving side is
  specs/003-threat-network/spec.md, which validates against
  `specs/002-telemetry-service/contracts/telemetry-export.md`.

## User Stories

- As a homelab user, I want telemetry to stay completely inert unless I explicitly opt
  in, so that my DNS history and device inventory never leave my network by default.
- As a small business operator who opts in, I want only privacy-reduced, domain-level
  threat summaries exported — never raw internal IPs, MAC addresses, or hostnames — so
  that contributing to community intelligence cannot leak my internal network layout.
- As an opted-in operator, I want a local status surface showing when the last batch was
  sent, how many signals it contained, and the last error, so that I can audit and trust
  the export path.
- As an MSP running Vedetta at client sites, I want opt-in to be per-deployment and
  revocable, and the exported schema to be a frozen, versioned contract, so that I can
  answer client privacy questions with a document instead of a code dive.
- As the threat-network operator (specs/003-threat-network/spec.md), I want every
  telemetry node to emit the exact same signed, versioned batch schema, so that ingest
  validation and anti-poisoning controls have a stable surface to enforce.

## Requirements

### Functional

- FR-1: The daemon MUST remain OFF by default. Unless `VEDETTA_TELEMETRY_OPTIN=true`
  (exact string), the process performs no Core reads, no network egress, no reporter
  registration, and no disk writes beyond its own log line — preserving today's
  "sleep until signal" behavior.
- FR-2: On first opt-in run, the daemon registers as a reporter with the threat network
  (`POST /api/v1/reporters/register` per `docs/threat-intel-mvp.md`), persists
  `reporter_id` + `reporter_secret` locally with `0600` permissions, and reuses them on
  restart. Registration sends only: schema version, a locally generated random install
  UUID, Vedetta version, and capability list.
- FR-3: **Batch reader** — on a configurable interval (default 15 minutes), the daemon
  reads new events since a persisted cursor from the Core events API
  (`GET /api/v1/events`, authenticated with a Core token). It never opens the Core
  SQLite file directly (API is the supported boundary; DB access is fallback-only if the
  API proves insufficient, and would be flagged in plan.md).
- FR-4: **Export gate** — only events that meet an explicit eligibility rule may enter
  the export pipeline: high-confidence threat detections (e.g., tagged `known_bad`,
  `c2_candidate`, `dga_candidate` above the confidence threshold). Acknowledged events,
  suppressed/whitelisted events, and events whose domain is private/special-use
  (`.local`, `.lan`, `home.arpa`, `.internal`, reverse-lookup names, single-label names)
  are NEVER exported.
- FR-5: **PII stripper** — eligible events pass through a strict **allowlist** projection
  (see plan.md and contracts/telemetry-export.md). Fields not on the allowlist are
  dropped by construction, not by blocklist. Forbidden forever: raw source IPs
  (`source_ip`), resolved/server IPs (`resolved_ip`, `server_ip`), MAC addresses,
  hostnames, custom device names, notes, network segments, free-form metadata, exact
  per-event timestamps (hour buckets only). The only device-linked value that may exist
  inside the pipeline is `source_hash` (HMAC-SHA256 of local IP with a per-install
  secret salt), and even that is collapsed into `distinct_asset_count` before anything
  leaves the node — the wire format carries counts, never per-asset tokens.
- FR-6: Exported indicators are **domain-level only**: an exact domain is exported only
  when it already matched a trusted local threat source or a very-high-confidence
  detector (`known_bad_domain_hit`); lower-confidence candidates are reduced to eTLD+1
  plus feature tags (`high_confidence_domain_candidate`) or withheld; coarse counts ship
  as `behavior_summary`. No raw query history, no full resolved-IP history, no device
  inventories.
- FR-7: **Transmitter** — batches are signed (HMAC-SHA256 request signature with
  timestamp + nonce per `docs/threat-intel-mvp.md`), gzip-compressed, capped at the
  server-advertised `max_batch_items` (default 250 signals), and POSTed to the threat
  network `POST /api/v1/ingest`. On failure: exponential backoff (1s, 2s, 4s, 8s …
  capped at 5 min) and a bounded on-disk spool; when the spool cap is reached the oldest
  batches are dropped (data loss here is acceptable — this is telemetry, not the SIEM).
- FR-8: **Health/status surface** — the daemon exposes a localhost-bound HTTP endpoint
  (`GET /healthz`, `GET /status`) reporting: opt-in state, reporter-registered state,
  cursor position, last batch time/size/result, spool depth, and last error. The status
  output itself contains no exported payload data beyond counts.
- FR-9: All behavior is configured via environment variables (documented in plan.md);
  no config file is required. Disabling opt-in (unset or any value other than `true`)
  returns the daemon to fully inert on next start.
- FR-10: Every exported batch carries `schema_version`; the record shape is frozen in
  `contracts/telemetry-export.md` and changes are additive-only (backward-compatibility
  rule below).

### Non-Functional

- NFR-1: Pi 4 hardware floor — the daemon idles at effectively zero CPU between ticks
  and stays under ~15 MB RSS; a 15-minute tick over a day of home-network volume
  (~10k DNS events/day, ~2k unique after local dedup) reads, strips, and ships in
  seconds. Total upstream bandwidth ≤ ~300 KB/day compressed. Fits inside the existing
  Core idle budget (<200 MB RAM, <5% CPU) without measurable impact.
- NFR-2: Works with Core + native sensor only. No new required dependencies: Pi-hole,
  AdGuard, UniFi, and the threat network itself are all optional. If the threat network
  is unreachable forever, local monitoring is completely unaffected.
- NFR-3: The exported-record contract is the trust boundary. It must be human-auditable
  in one page (contracts/telemetry-export.md) and enforceable by the receiver: the
  threat network (specs/003-threat-network/spec.md) rejects any batch containing
  non-allowlisted fields or private-looking values.
- NFR-4: Sensors never talk to the threat network directly; only this daemon does,
  and only via HTTPS in real deployments (plain HTTP allowed only for local compose
  development).

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | Yes (indirectly) | No sensor changes. Telemetry reads only from Core's API; sensors never talk to the threat network directly (product guardrail in `docs/threat-intel-mvp.md`). The Core+sensor split is untouched. |
| Pi-hole optional | Yes | No new required integrations. Telemetry consumes normalized Core events regardless of DNS source (passive capture, Pi-hole, AdGuard, embedded resolver) and is itself optional. |
| Passive-first | Yes (indirectly) | No new capture or scanning. Telemetry only re-exports summaries of what passive-first pipelines already detected. Zero gateway cooperation required. |
| V1 scope (no LAN scan/exploit) | Yes | Pure data export of existing detections. No new scanning, no exploit verification, no active probing. Scope is deliberately Phase-1-of-VED-008 only (upload path); feed consumption is cut (see Out of Scope). |
| SNR re-tune for new sources | Yes | Telemetry creates no new local alerts, so local SNR is unchanged. The SNR concern inverts: export quality gates (FR-4) keep node-side noise from poisoning the community corpus. See Signal-to-Noise Impact. |
| Privacy / opt-in telemetry | Yes — this IS the constraint | OFF by default (FR-1); explicit opt-in env var; allowlist-only export (FR-5); no raw IPs/MACs/hostnames ever; `source_hash` HMAC collapsed to counts before egress; advisory-only downstream; revocable at any time. Constitution: "Telemetry … is optional, opt-in, privacy-conscious, and secondary to local operation." |
| Environment data handling | Yes | All examples in this spec directory use RFC 5737 IPs, `00:00:5E:00:53:xx` MACs, RFC 2606 `.example` domains, and placeholder hostnames. No real network artifacts. The daemon's own design (allowlist export) is this constraint applied at runtime. |

## Signal-to-Noise Impact

This feature adds **no new local alert surface**: it produces no events, no dashboard
alerts, and no scoring changes in this phase (feed consumption is out of scope). Local
SNR is therefore unchanged. The SNR discipline applies in two inverted ways:

1. **Outbound noise = community poisoning.** A node that exports low-confidence junk
   degrades the shared corpus for everyone. Mitigation shipped WITH the feature: the
   export gate (FR-4) exports only detections that already cleared local suppression,
   whitelisting, and acknowledgment; lower-confidence candidates are down-scoped to
   eTLD+1 or withheld; batch size caps and server-side promotion thresholds
   (specs/003-threat-network/spec.md) prevent one node from manufacturing global signal.
2. **Operator trust noise.** A telemetry service that silently fails or silently
   over-shares erodes trust. Mitigation: the `/status` surface (FR-8) reports exactly
   what was sent and when, and the frozen one-page contract makes "what leaves the node"
   auditable.

Justified "no new local tuning needed": no new inbound data source is added in this
phase; the moment feed consumption lands (follow-up spec), community intel becomes an
inbound enrichment source and re-opens SNR tuning per the constitution.

## Out of Scope

- **Advisory feed pull/consumption** (`GET /api/v1/feed/community` per
  specs/003-threat-network/contracts/community-feed-api.md → local
  `community_intel` cache) — receiving-side value depends on the threat network
  producing a feed first; deferred to a follow-up spec after
  specs/003-threat-network/spec.md Phase 2 promotion exists. Keeps this change
  one-directional and auditable.
- **Core-side `telemetry_outbox` tables and internal export-gating endpoints** — the
  MVP gates eligibility inside the telemetry daemon using fields already on
  `GET /api/v1/events`; moving gating into Core (with schema migrations) is a later
  hardening step once the contract is proven.
- **Threat-network server implementation** (ingest validation, aggregation, promotion,
  anti-poisoning) — owned by specs/003-threat-network/spec.md; this spec only freezes
  the wire contract it validates against.
- **UI opt-in toggle and "what leaves the node" dashboard copy** — env-var opt-in is
  sufficient for alpha; UI affordances follow once the pipeline is trusted.
- **Per-event export (research-doc `TelemetryEvent` shape)** — considered and rejected
  for MVP in favor of aggregate signals per `docs/threat-intel-mvp.md`; per-event export
  raises re-identification risk for negligible aggregation benefit.
- **JA3/JA4 fingerprints, port-scan results, device-type distributions** — listed as
  "safe to share" in research/06 but cut from the MVP signal classes to keep the first
  contract minimal; each requires its own privacy review before joining the allowlist.
- **Windows support for the daemon** — matches the current platform reality
  (`docs/architecture.md`).

## Open Questions

- [ ] Core token provisioning: should Core auto-mint a least-privilege read-only token
      for the telemetry container (like sensor tokens), or is a manually supplied admin
      token acceptable for alpha? (Alpha assumption: manual `VEDETTA_CORE_TOKEN`.)
- [ ] Should the HMAC salt (`source_hash` input) be shared with Core's existing
      per-install salt or be telemetry-local? Telemetry-local is safer (Core hashes and
      telemetry hashes cannot be joined) and is the plan.md default — confirm.
- [ ] Exact local-confidence threshold mapping from `anomaly_score`/tags to the
      `known_bad_domain_hit` vs `high_confidence_domain_candidate` gate (plan.md
      proposes initial values; needs validation against live-node data before "supported").
- [ ] Does the eTLD+1 reduction need the full Public Suffix List embedded, or is a
      vendored snapshot acceptable for alpha? (Plan assumes vendored snapshot.)
