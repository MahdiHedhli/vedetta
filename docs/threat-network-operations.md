# Threat Network — Implementation, Hosting & Configuration

> Audience: the Vedetta operator/owner deciding whether and how to run the optional
> community threat-intelligence layer.
> Status: **implemented; telemetry is on by default (opt-out), advisory-only.** The default
> `docker-compose.yml` stack runs the telemetry client pointed at `https://feed.vedettas.com`.
> Disable it any time with `VEDETTA_TELEMETRY_OPTIN=false` (only the exact value `false`
> disables it) or from the dashboard telemetry toggle.
> Specs: [002-telemetry-service](../specs/002-telemetry-service/), [003-threat-network](../specs/003-threat-network/).
> Original design brief: [docs/threat-intel-mvp.md](threat-intel-mvp.md).

## TL;DR

- The community layer is **two separate services** you can run independently: a
  **telemetry client** (runs next to your Core, uploads privacy-reduced signals) and a
  **threat-network server** (a central service everyone reports to and polls).
- **The telemetry client runs by default.** In the default `docker-compose.yml` stack it is
  on (contributing privacy-reduced signals to `https://feed.vedettas.com`) and is opt-out:
  set `VEDETTA_TELEMETRY_OPTIN=false` (only the exact value `false` disables it) or flip the
  dashboard telemetry toggle. A first-run disclosure banner surfaces this on first launch.
  The threat-network **server** is **off-node** — it is *not* meant to run on your Raspberry Pi.
- **Most users configure nothing.** Telemetry is preconfigured in the default stack, and the
  other value for a normal deployment is *consuming* the advisory feed. Hosting your own
  server and pointing contribution at it are separate, optional decisions.
- **What I built is a portable Go + SQLite single binary**, not tied to any cloud. You
  decide where it runs (small VPS / free-tier VM / container host). The original brief
  sketched a Cloudflare Workers + D1 shape — that remains a valid alternative because the
  wire contract is frozen (see [Hosting](#hosting--infrastructure)).

---

## How it's implemented

Two components, one frozen wire contract between them.

```
   YOUR NETWORK (self-hosted)                    OFF-NODE (community infra)
 ┌──────────────────────────────┐            ┌──────────────────────────────┐
 │  Vedetta Core (Pi / x86)     │            │  Threat-Network server        │
 │  ├─ events DB                │            │  (Go binary + SQLite,         │
 │  └─ GET /api/v1/events ──────┼── read ──┐ │   :9090, /data volume)        │
 │                              │          │ │                               │
 │  Telemetry client (on by     ┼─ signed ─┼─┼─▶ POST /reporters/register    │
 │   default, opt-out) ─────────┼          │ │                               │
 │  • reads events via token    │  batches │ │   POST /ingest  (validate,    │
 │  • strips PII structurally   │  (HTTPS) │ │     privacy re-gate, dedup,    │
 │  • aggregates to 3 signals   │          │ │     consensus)                 │
 │  • signs + uploads           │          │ │                               │
 └──────────────────────────────┘          │ │   GET /feed/community ◀───────┼─ anyone
                                            │ │     (advisory-only, public)   │   polls
   ANY Vedetta Core ◀───────── poll feed ───┘ └──────────────────────────────┘
```

### Component 1 — Telemetry client (`telemetry/`, spec 002)

Runs alongside Core (its own container in `docker-compose.yml`) and is **on by default**
(opt-out via `VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle). Each tick, while
enabled, it:

1. **Reads** new events from Core over HTTP (`GET /api/v1/events`) using a read token,
   tracking a persisted cursor so it never re-sends.
2. **Strips PII structurally.** The export type (`ExportCandidate`) can only hold an
   allowlisted set of fields — raw source IPs, MACs, hostnames, and the raw device
   `source_hash` are dropped *by construction*, not by a blocklist. A device-linked
   `source_hash` is collapsed into a `distinct_asset_count` before anything leaves.
3. **Aggregates** to domain-level signals. The frozen wire contract defines three signal
   kinds — `known_bad_domain_hit` (exact domain allowed), `high_confidence_domain_candidate`
   (reduced to eTLD+1 via a vendored Public Suffix List), and `behavior_summary` (no domain
   at all) — but **for beta only `known_bad_domain_hit` is exported**;
   `high_confidence_domain_candidate` and `behavior_summary` are **disabled pending a
   trust-model redesign**, so nothing derived from your own observed queries is shared today.
4. **Signs and uploads** a gzip batch with HMAC-SHA256 auth headers, exponential backoff,
   a bounded on-disk spool, and 4xx poison-pill handling. A **dry-run mode**
   (`VEDETTA_TELEMETRY_DRYRUN=true`) runs the whole pipeline to the spool with **zero
   egress** so you can inspect exactly what would be sent.

A leak-scan runs over every serialized batch as a backstop, and the whole thing is pure
Go standard library (no third-party deps).

### Component 2 — Threat-network server (`threat-network/`, spec 003)

A single Go binary with a service-local SQLite DB. It:

- **Registers reporters** pseudonymously (`POST /api/v1/reporters/register`) — it stores an
  id and a hash of a secret, never an account, email, or operator identity.
- **Ingests signed batches** (`POST /api/v1/ingest`): verifies the HMAC signature, rejects
  timestamps outside ±300 s and reused nonces, treats a duplicate `batch_id` as an
  idempotent replay, **re-applies the privacy gate server-side** (any batch containing a
  private/special-use/single-label name, a raw IP literal, or an asset identifier is
  rejected whole), and dedups.
- **Builds consensus**: an indicator is promoted only when **multiple distinct matured
  reporter credentials** corroborate it — a single credential (or a burst of
  freshly-registered credentials that have not aged past the maturation delay) can never
  cause promotion. This raises the cost of manufacturing agreement but does not by itself
  prove reporter independence, which is why the feed is mechanically advisory-only. It
  stores **no PII at rest**.
- **Serves an advisory-only feed** (`GET /api/v1/feed/community`, public read like an
  abuse.ch list): every item carries `advisory: true` / `recommended_action: "advise"`.
  Consumers must never auto-block on feed membership — it may only add context or nudge
  the score of *locally observed* activity. A per-IP rate limiter and per-reporter
  influence caps bound abuse.

---

## Privacy guarantees (what leaves your network)

| Never leaves | What can leave (aggregate only) |
| --- | --- |
| Raw internal/WAN IPs, MACs, hostnames, SSIDs | Domain indicators for the 3 signal kinds (exact domain only for known-bad; eTLD+1 for candidates) |
| Your device inventory or per-device identifiers | Counts (`distinct_asset_count`, observation counts) — never a host list |
| Query history, internal domain names | A hash of your reporter secret (pseudonymous identity) |
| Operator identity, account, email | Coarse behavior summaries with no domain |

> **Beta:** only `known_bad_domain_hit` (the matched block-list indicator + its eTLD+1) is
> exported today. The candidate-eTLD+1 and behavior-summary rows above are **disabled for
> beta** pending a trust-model redesign; the kinds remain in the frozen contract for when
> they re-enable.

Two independent gates enforce this: structural stripping on the client (spec 002) **and**
a server-side privacy re-check on ingest (spec 003). A batch that violates either is
rejected whole.

---

## Hosting / infrastructure

**The server is off-node.** Per spec 003 NFR-1 it does *not* run on your Pi — it is shared
community infrastructure that many deployments report to and poll. You have two hosting
paths; the frozen wire contract means you can start with one and switch later.

### Option A — the Go + SQLite service I built (recommended to start)

A single CGO binary + a SQLite file, already containerized (`threat-network/Dockerfile`,
exposes `9090`, persists to a `/data` volume). Run it on anything that hosts a container
or a binary:

- a small VPS ($5/mo tier is a reasonable public-beta starting point),
- a free-tier VM / container host (Fly.io, Railway, Render, etc.),
- any box you already run — but **not** the Pi that runs Core.

Put it behind a reverse proxy with TLS for anything beyond local testing (the feed is
public HTTP; ingest is authenticated but should still be TLS in production). SQLite is
single-writer, which is fine for the public beta's low-thousands-node target; it is the scaling
ceiling to watch.

### Option B — the Cloudflare shape from the original brief

[docs/threat-intel-mvp.md](threat-intel-mvp.md) sketches a Cloudflare-first production
shape: a **Worker** for the API surface, **D1** for storage, optional **R2**. That was the
original intended production hosting and is still viable — the ingest wire format and feed
contract are frozen and identical, so a Worker+D1 implementation is a drop-in replacement
for Option A's endpoints. It has not been built; Option A is what exists in the repo today.
Choose it if you want managed, edge-hosted, free-tier-first infrastructure and are willing
to port the Go handlers to a Worker.

> **This is a decision for you.** The code is deliberately infra-agnostic so you're not
> locked in. The public-beta recommendation is Option A on a cheap VPS behind Caddy/Cloudflare
> Tunnel for TLS, validate it, and only consider porting to Workers+D1 if/when volume or
> ops preferences justify it.

---

## What *you* need to configure

Three independent roles — pick what applies. **You can do none of these and lose nothing
locally.**

### Role 1 — Consume the community feed (most operators)

Nothing to host. Once a threat-network server is running somewhere, Core polls its public
feed like any abuse.ch list and uses it to *add context / adjust scores* on locally
observed activity.

Core refreshes `GET /api/v1/feed/community` every 15 minutes using
`VEDETTA_THREAT_NETWORK_URL` (default `https://feed.vedettas.com`). The request carries no
Core credential. The response must be a complete, bounded schema-v1 snapshot; a malformed
or partial response is rejected atomically. Community matches remain advisory/corroborating
evidence and cannot independently create or raise the priority of a finding. Set
`VEDETTA_COMMUNITY_FEED_ENABLED=false` for an installation that should not make this
credential-free outbound request.

### Role 2 — Contribute (telemetry, on by default)

The telemetry container ships in the default stack and contributes to `https://feed.vedettas.com`
**out of the box**. You do not need to turn anything on. Use these env vars to disable it, point
it at a different server, or dry-run it. In `docker-compose.yml` (or the telemetry container's env):

| Variable | Set to | Purpose |
| --- | --- | --- |
| `VEDETTA_TELEMETRY_OPTIN` | `false` to disable (default `true`) | **The switch.** Only the exact value `false` turns the daemon off; you can also toggle it from the dashboard. |
| `VEDETTA_CORE_URL` | e.g. `http://backend:8080` | Where to read your events from |
| `VEDETTA_CORE_TOKEN` | a **read-only** Core API token | Auth for the events read (mint one in Core) |
| `VEDETTA_THREAT_NETWORK_URL` | defaults to `https://feed.vedettas.com` | Shared base URL for signed uploads and Core's credential-free feed download |
| `VEDETTA_COMMUNITY_FEED_ENABLED` | `false` to disable (default `true`) | Controls Core feed consumption independently from telemetry contribution |
| `VEDETTA_TELEMETRY_DRYRUN` | `true` (optional) | Run the full pipeline to spool with **zero egress** so you can inspect what would be sent before real upload |
| `VEDETTA_TELEMETRY_STATE_DIR` | a persisted path | Holds the cursor, reporter secret (0600), and HMAC salt |

If you want to inspect exactly what would be shared before any real egress, set
`DRYRUN=true` (telemetry is already on by default), let it run ~72 h, inspect the spooled
batches, then drop dry-run. (This is the owner-side "operational validation" that VED-014
tracks.) Registration is automatic and pseudonymous; the reporter secret is stored `0600`
in the state dir.

### Role 3 — Host the community server (only if you want to run the backend for others)

Deploy the `threat-network` container off-node:

| Variable | Default | Purpose |
| --- | --- | --- |
| `THREAT_NETWORK_PORT` | `9090` | Listen port (put TLS/reverse proxy in front) |
| `THREAT_NETWORK_DB` | `/data/threat-network.db` | SQLite file — **mount `/data` as a persistent volume** |

Then: give it a hostname + TLS, point contributors' `VEDETTA_THREAT_NETWORK_URL` at it, and
publish the feed URL for consumers. There is no admin dashboard in the MVP (excluded by
spec 003) — operations are the container + its DB + logs.

---

## Current status & honest limits

- **Implemented and tested** (unit + cross-service contract tests, adversarial review):
  telemetry pipeline, server ingest/consensus/feed, privacy gates, abuse controls.
- **Implemented:** the Core-side feed consumer (Role 1 wiring) and Cloudflare Tunnel
  deployment path. A sustained operational/SNR validation on an owner's real
  environment remains tracked as VED-014; fixtures and CI use only synthetic data.
- **On by default (opt-out), advisory-only, no PII at rest** — the shared feed is advisory
  only and is never a production dependency. Deployments that disable telemetry lose nothing
  locally.

## Decisions this doc is asking you to make

1. **Do you want to keep contributing telemetry?** It is on by default; if not, set
   `VEDETTA_TELEMETRY_OPTIN=false` or flip the dashboard toggle and it stops.
2. **If yes, who hosts the server?** Option A (Go+SQLite on a small VPS, recommended) vs
   Option B (build the Cloudflare Worker+D1 version).
3. **A domain + TLS** for the server (e.g. `feed.vedetta.<you>` behind Caddy or a
   Cloudflare Tunnel).
4. **Keep contributing, or just consume?** Contributing is on by default (opt-out via
   `VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle); a dry-run soak first is optional.
   Consuming a feed still needs the Core feed-poller finished.
