# Vedetta Telemetry Service (opt-in, privacy-reduced export)

> Implements `specs/002-telemetry-service/`. Frozen wire contract:
> `specs/002-telemetry-service/contracts/telemetry-export.md`.

The telemetry daemon lets an **explicitly opted-in** Vedetta Core deployment
contribute a small set of privacy-reduced, domain-level threat observations to
the community threat network. It is **OFF by default**, **advisory-only**
downstream, and revocable at any time with zero impact on local monitoring.

## OFF by default

Unless `VEDETTA_TELEMETRY_OPTIN=true` (exact string), the daemon does nothing:
no Core reads, no network egress, no reporter registration, no state writes
beyond a single log line. It blocks until a signal, exactly like the prior stub.

## What leaves the node

Only three aggregate signal kinds, all counts-and-domains-only. The exhaustive,
one-page trust boundary is the contract file. In short:

| Kind | Domain material | Notes |
| --- | --- | --- |
| `known_bad_domain_hit` | exact FQDN | only when already matched a trusted local threat source |
| `high_confidence_domain_candidate` | eTLD+1 only | exact domain withheld |
| `behavior_summary` | none | e.g. `dns_beaconing_candidate` |

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

## How to opt in

Set environment variables on the `telemetry` container:

```sh
VEDETTA_TELEMETRY_OPTIN=true
VEDETTA_CORE_TOKEN=<least-privilege read token>   # required when opted in
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
opt-in, dry-run, reporter-registered, cursor position, last tick, last batch
`{time, signal_count, result}`, spool depth, malformed-events skipped, last
error. No exported payload (no domains) ever appears here.

## How to revoke

Unset `VEDETTA_TELEMETRY_OPTIN` (or set it to anything other than `true`) and
restart the container. The daemon returns to fully inert on next start. To fully
sever the reporter identity, also delete `reporter.json` and `salt` from the
state dir; the community-side identity ages out server-side.

## Failure behavior (best-effort by design)

- Core unreachable / `401`: tick skipped, cursor unchanged, error on `/status`;
  retried next tick. No local data loss.
- Threat network `5xx`/network: exponential backoff (1s→5min) then spool
  (bounded: 50 batches / 24h, oldest dropped).
- Threat network `4xx`: poison-pill — not retried; moved to `spool/rejected/`
  (capped) for inspection.
