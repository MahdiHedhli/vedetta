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
| `THREAT_NETWORK_ADMIN_ENABLED` | `false` | Exact `true` starts the separate corpus-management listener |
| `THREAT_NETWORK_ADMIN_ADDR` | `127.0.0.1:9091` | Management bind; keep it on loopback for native deployments |
| `THREAT_NETWORK_ADMIN_TOKEN_FILE` | none | Owner-only (`0400`/`0600`) regular non-symlink file containing at least 32 random printable ASCII bytes (for example, hex or base64url; not raw binary) |
| `THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK` | `false` | Required second opt-in for an isolated container or authenticated TLS upstream |

The token-file check is deliberately strict: after trimming surrounding
whitespace, the token must contain at least 32 printable ASCII bytes with no
embedded whitespace or control characters. Generate an encoded value such as
hex or base64url rather than writing raw random bytes. The configured path must
be a readable **regular, non-symlink file** with no group or other permission
bits. Use `0400` or `0600`, owned by the account that runs `threat-network`, and
verify the path from inside the container or service namespace before startup.

- For a native install or a Docker/Compose bind mount, create the source under
  `umask 077`, `chmod 0600` it on the host, and mount it read-only. File-backed
  Compose secrets use a bind mount and silently ignore service-level `uid`,
  `gid`, and `mode`, so the host source mode is load-bearing; see Docker's
  [Compose secrets reference](https://docs.docker.com/reference/compose-file/services/#secrets).
- Docker/Swarm and environment-backed Compose secrets default to `0444`, which
  Vedetta rejects. Use long syntax with `mode: 0400` (or copy the secret into a
  private file before starting the service), then verify the effective mode.
- Kubernetes Secret volumes default to `0644`; set `defaultMode: 0400` in YAML.
  A projected Secret key path may be a symlink, which Vedetta also rejects, so
  expose a single regular file with a `subPath` mount or copy it from the Secret
  volume into a protected `emptyDir` in an init container. Ensure the service
  user can read the result and verify both
  `test -f "$THREAT_NETWORK_ADMIN_TOKEN_FILE"` and
  `test ! -L "$THREAT_NETWORK_ADMIN_TOKEN_FILE"`. See Kubernetes' [Secret-volume permission
  guidance](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/#set-posix-permissions-for-secret-keys).

Broad permissions fail closed with:

```text
threat-network stopped: management API enabled but token file is invalid: management token file must not be accessible by group or other users
```

A symlink or non-regular mount fails with `management token file must be a
regular non-symlink file`. Do not weaken these checks to accommodate a platform
default; fix the effective file type and permissions instead.

Then: give the public listener a hostname + TLS, point contributors'
`VEDETTA_THREAT_NETWORK_URL` at it, and publish the feed URL for consumers. Keep the
management listener out of the Cloudflare Tunnel and public reverse proxy.
The service refuses wildcard and non-loopback management addresses unless
`THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK=true` is also set. That escape hatch is
for an explicitly isolated container network only; the host mapping must still
bind to loopback and the port must remain outside every public tunnel. If a
management hop must cross a host or network boundary instead, put an
authenticated TLS reverse proxy in front of it and restrict the plaintext
upstream to that private path. Never expose port `9091` directly to a LAN,
tailnet, or the public internet.

### Curated device corpus operations (standalone branch)

The operations branch adds a centrally curated, versioned device-fingerprint corpus.
Its contract permits product-class facts only; observed household devices, IPs, full
MACs, hostnames, serial numbers, sensors, reporters, sites, and events are forbidden.
The deterministic shape hash is a content address, **not** anonymization. Privacy rests
on the fixed schema, leak-oriented validation, a trusted human curator, and review of
the exact proposed release before publication. Since useful product tokens are still
bounded human-authored strings, the validators prevent common accidental leaks but are
not a proof against a malicious curator intentionally encoding private data.

Public, credential-free reads remain on port 9090:

- `GET /api/v1/device-corpus/manifest`
- `GET /api/v1/device-corpus/snapshot`

Manual curation uses a separate authenticated listener. Create the secret without
placing it in an environment variable or command line:

```sh
# From the repository root, build and install the native service binary once.
(cd threat-network && go build -o ./threat-network ./cmd/threat-network)
sudo install -m 0755 threat-network/threat-network /usr/local/bin/threat-network

id -u vedetta >/dev/null 2>&1 || \
  sudo useradd --system --user-group --home-dir /var/lib/vedetta --shell /usr/sbin/nologin vedetta
sudo install -d -m 0700 -o vedetta -g vedetta /var/lib/vedetta
sudo -u vedetta sh -c \
  'umask 077; openssl rand -hex 32 > /var/lib/vedetta/threat-network-admin.token'
sudo chmod 600 /var/lib/vedetta/threat-network-admin.token

sudo -u vedetta env \
  THREAT_NETWORK_DB=/var/lib/vedetta/threat-network.db \
  THREAT_NETWORK_ADMIN_ENABLED=true \
  THREAT_NETWORK_ADMIN_ADDR=127.0.0.1:9091 \
  THREAT_NETWORK_ADMIN_TOKEN_FILE=/var/lib/vedetta/threat-network-admin.token \
    /usr/local/bin/threat-network
```

For the repository's Compose deployment, use the tracked opt-in overlay. It
handles the otherwise easy-to-miss Docker distinction: the listener binds all
interfaces **inside** the container, while Docker publishes it only on host
loopback. The second non-loopback guard remains explicit. The Threat Network
container is attached to its own `threat-network-isolated` bridge rather than
the ordinary Vedetta application bridge, so Core, telemetry, collector, and
frontend siblings cannot connect directly to the management port.

```sh
export THREAT_NETWORK_ADMIN_TOKEN_FILE=/var/lib/vedetta/threat-network-admin.token
docker compose -f docker-compose.yml -f docker-compose.corpus-ops.yml \
  --profile community up -d --build threat-network
curl -fsS http://127.0.0.1:9090/api/v1/device-corpus/manifest
```

Do not substitute an untracked local override for this deployment contract.

The tailnet-only dashboard shim holds that token server-side and exposes only an exact
corpus route allowlist. The browser never receives it. Deployment, Tailscale identity
authorization, and proxy-hardening instructions live in
[`threat-network/web/README.md`](../threat-network/web/README.md). The dashboard and
corpus implementation remain on their standalone operations branch and are not part of
the product's `main` release.

Profile labels, fingerprint variants, curator corrections, real firmware evolution,
audit events, and complete public releases are versioned independently. Drafts never
appear publicly. Old release bytes remain immutable and can be inspected through the
management API; recovery to an older release is an explicit SQLite backup/manual
operation rather than a one-click browser mutation.

Every publish, profile retirement, and full variant withdrawal is authorized against
both the target profile ETag and the public corpus revision displayed to the curator.
An intervening release anywhere in the corpus rejects the action atomically with
`CORPUS_ADVANCED`; the dashboard reloads the current snapshot before a retry. Discarding
only an unpublished draft does not create a release and retains its ETag-only contract.

Evidence entered as an `import` must include a curator-reviewed redistributable
`license_code`; imports without it are rejected. This prevents an unresolved
third-party corpus from being admitted merely because it fits the technical schema.

The corpus tables and releases live in the same persisted
`/data/threat-network.db`. Back up that file with SQLite's online `.backup` command
before deploying schema or curator-workflow changes. Corpus migrations 004–007 are
forward-only and additive, so a pre-corpus threat-network binary ignores the new
tables; restoring the matching binary and pre-change database remains the clean
rollback path.

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
   Feed consumption is independently enabled by default and can be disabled with
   `VEDETTA_COMMUNITY_FEED_ENABLED=false`.
