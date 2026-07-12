# Vedetta Telemetry Service (on by default / opt-out, privacy-reduced export)

> Implements `specs/002-telemetry-service/`. Frozen wire contract:
> `specs/002-telemetry-service/contracts/telemetry-export.md`.

The telemetry daemon lets a Vedetta Core deployment contribute a small set of
privacy-reduced, domain-level threat observations to the community threat
network. It is **ON by default (opt-out)**, **advisory-only** downstream,
**pseudonymous (not anonymous)** — see PRIVACY.md — and disable-able at any time
with zero impact on local monitoring.

## ON by default (opt-out)

The daemon contributes unless it is explicitly disabled. Only the exact string
`VEDETTA_TELEMETRY_OPTIN=false` (or flipping the dashboard toggle off) disables
it; when disabled it does nothing: no Core reads, no network egress, no reporter
registration, no state writes beyond a single log line — it blocks until a
signal, exactly like the prior stub.

## What leaves the node

Only three aggregate signal kinds, all counts-and-domains-only. The exhaustive,
one-page trust boundary is the contract file. In short:

| Kind | Domain material | Notes |
| --- | --- | --- |
| `known_bad_domain_hit` | matched block-list indicator | only when already matched a trusted local threat source |
| `high_confidence_domain_candidate` | eTLD+1 only | **DISABLED for beta** (see note) |
| `behavior_summary` | none | **DISABLED for beta** (see note) |

> **Beta:** telemetry currently exports **only `known_bad_domain_hit`** — the
> Core-confirmed block-list indicator, which cannot carry a caller-supplied
> identifier. The `high_confidence_domain_candidate` and `behavior_summary` kinds
> derive from observed queries and depend on Core-side verdicts a compromised
> writer could forge (GHSA-hx86), so they are temporarily disabled pending a
> trust-model redesign. The kinds remain in the contract for when they re-enable.

**Never exported:** raw source IPs, resolved/server IPs, MAC addresses,
hostnames, device inventories/vendors/models, network segments, SSIDs, exact
per-event timestamps (hour buckets only), raw query history, free-form metadata,
geo, or any per-asset identifier. `source_hash` is an HMAC used *inside* the node
to compute `distinct_asset_count` and is discarded before egress — it is never
serialized.

This is enforced **structurally**: the `ExportCandidate` type
(`internal/export/candidate.go`) has no field capable of holding a forbidden
value, so forbidden data is dropped by construction, not by a blocklist. A
`LeakScan` helper (`internal/export/leakscan.go`) runs over every serialized
batch in the test suite as a privacy regression gate.

## Configuration

Telemetry is on by default, so no env var is needed to enable it. Set these on
the `telemetry` container to point it at Core and the threat network (and set
`VEDETTA_TELEMETRY_OPTIN=false` only if you want to disable contribution):

```sh
VEDETTA_CORE_TOKEN=<least-privilege read token>   # required while enabled
VEDETTA_CORE_URL=http://backend:8080              # default
VEDETTA_THREAT_NETWORK_URL=http://threat-network:9090  # default
```

Optional tuning (defaults shown):

```sh
VEDETTA_TELEMETRY_TICK_INTERVAL=15m
VEDETTA_TELEMETRY_STATE_DIR=/var/lib/vedetta-telemetry
VEDETTA_TELEMETRY_STATUS_ADDR=127.0.0.1:9091
VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE=0.85
VEDETTA_TELEMETRY_BEHAVIOR_MIN_SCORE=0.70
```

## Dry-run audit procedure (recommended before first real egress)

```sh
VEDETTA_TELEMETRY_DRYRUN=true
```

Dry-run runs the **full pipeline** — read, gate, strip, aggregate, sign, gzip —
but performs **zero egress**. Batches are written to the on-disk spool and
summarized on `/status`. Inspect the spooled `*.json.gz` files (gunzip them) and
confirm every would-be exported record is domain-level and leak-free. Only then
remove `VEDETTA_TELEMETRY_DRYRUN` to enable real egress. Keep any real captures
in gitignored `analysis-notes/` — never in tracked files.

## Status surface

`GET http://127.0.0.1:9091/healthz` → `200` while the loop is alive.
`GET http://127.0.0.1:9091/status` → JSON with **counts and states only**:
telemetry-enabled state, dry-run, reporter-registered, cursor position, last tick, last batch
`{time, signal_count, result}`, spool depth, malformed-events skipped, last
error. No exported payload (no domains) ever appears here.

The persisted cursor uses an inclusive timestamp plus the exact bounded set of
event IDs already consumed at that timestamp. This prevents equal-timestamp
events from alternating on every tick, while still accepting a late event at
the same timestamp regardless of how its ID sorts. Legacy cursor files containing
only `last_event_id` are upgraded in place on their next successful save.

## How to disable

Set `VEDETTA_TELEMETRY_OPTIN=false` (exact string — any other value leaves it on)
or flip the dashboard telemetry toggle off, then restart the container. The daemon
returns to fully inert on next start. To sever the local half of the pseudonymous
reporter identity, also delete `reporter.json` and `salt` from the state dir.
Note the **community-side linkage does not yet age out**: retention/expiry is
incomplete today, so the server-side `reporter_id`↔indicator/hour linkage is
**retained**, not aged out (see PRIVACY.md).

## Failure behavior (best-effort by design)

- Core unreachable / `401`: tick skipped, cursor unchanged, error on `/status`;
  retried next tick. No local data loss.
- An extraordinary cohort above 50,000 events at one exact Core timestamp:
  tick fails visibly and holds the prior cursor; the bounded cursor is never
  truncated into silent loss or partial replay.
- Threat network `5xx`/network: exponential backoff (1s→5min) then spool
  (bounded: 50 batches / 24h, oldest dropped).
- Threat network `4xx`: poison-pill — not retried; moved to `spool/rejected/`
  (capped) for inspection.
