# Tasks: Telemetry Service (Opt-In Privacy-Reduced Export)

> Plan: `specs/002-telemetry-service/plan.md`
> Status: Not Started
> Created: 2026-07-03

Phases are sequential; tasks within a phase are parallelizable unless noted.
Every task states its verification. Mark done with date.
All test fixtures use synthetic values only: RFC 5737 IPs (192.0.2.x / 198.51.100.x /
203.0.113.x), MACs 00:00:5E:00:53:xx, RFC 2606 `.example` domains, placeholder hostnames.

## Phase 1: Skeleton, config, and opt-in gate

- [ ] T1.1 — Create package layout and config loader.
      Files: `telemetry/internal/config/config.go`, `config_test.go`
      Env vars (with defaults): `VEDETTA_TELEMETRY_OPTIN` (unset→off),
      `VEDETTA_THREAT_NETWORK_URL` (`http://threat-network:9090`),
      `VEDETTA_CORE_URL` (`http://backend:8080`), `VEDETTA_CORE_TOKEN` (required when
      opted in), `VEDETTA_TELEMETRY_STATE_DIR` (`/var/lib/vedetta-telemetry`),
      `VEDETTA_TELEMETRY_TICK_INTERVAL` (`15m`), `VEDETTA_TELEMETRY_STATUS_ADDR`
      (`127.0.0.1:9091`), `VEDETTA_TELEMETRY_DRYRUN` (`false`), gate thresholds
      (`VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE=0.85`,
      `VEDETTA_TELEMETRY_BEHAVIOR_MIN_SCORE=0.70`), read/batch caps.
      Verify: table-driven tests — defaults, overrides, opted-in-without-token error;
      `go test ./internal/config` green.
- [ ] T1.2 — Rewire `cmd/telemetry/main.go`: preserve exact OFF-by-default behavior
      (opt-in not `true` → log one line, no state-dir creation, no network, block on
      signal), else start tick loop + status server with graceful shutdown.
      Files: `telemetry/cmd/telemetry/main.go`
      Verify: run binary with no env → single log line, `lsof` shows no listeners, no
      files created; run with opt-in + dry-run → status server up; SIGTERM exits clean.
- [ ] T1.3 — Status server: `GET /healthz` (200 when loop alive) and `GET /status`
      (JSON: opt_in, dry_run, reporter_registered, cursor, last_tick, last_batch
      {time, signal_count, result}, spool_depth, events_skipped_malformed, last_error).
      Files: `telemetry/internal/status/status.go`, `status_test.go`
      Verify: unit tests via httptest; assert `/status` payload contains counts only —
      no domain/signal payload fields.
- [ ] T1.4 — State-dir helpers: versioned JSON state files, atomic write
      (tmp+rename), 0600 for secrets, regenerate-on-corrupt semantics.
      Files: `telemetry/internal/config/state.go`, `state_test.go`
      Verify: tests for round-trip, corrupt-file regeneration, permission bits.

## Phase 2: Batch reader (Core events API client)

- [ ] T2.1 — Core client: `GET /api/v1/events` with bearer token, `from` + `limit`
      paging (existing params), decode into a local mirror struct of `models.Event` JSON (keep in sync
      by contract, not by import — telemetry is a separate Go module).
      Files: `telemetry/internal/corereader/client.go`, `client_test.go`
      Verify: httptest fake Core serving synthetic fixtures; paging, 401 handling,
      malformed-event skip counting.
- [ ] T2.2 — Cursor persistence: RFC3339 timestamp + last event ID tie-breaker in
      `cursor.json`; advance only after a page is fully processed (at-least-once).
      Files: `telemetry/internal/corereader/cursor.go`, `cursor_test.go`
      Verify: crash-resume test — kill between pages, restart, assert no events lost
      and duplicates bounded to one page.
- [ ] T2.3 — Tick loop: per-tick read cap (default 5000), Core-unreachable → skip tick
      with cursor unchanged and error on `/status`.
      Files: `telemetry/internal/corereader/tick.go` (or in cmd wiring), tests
      Verify: unit test with failing fake Core — cursor unchanged, status error set.

## Phase 3: PII stripper + export gate (the privacy boundary)

- [ ] T3.1 — `ExportCandidate` type: struct whose fields are EXACTLY the plan.md
      allowlist (kind, domain, etld_plus_one, behavior, time_bucket,
      local_confidence, local_reasons, blocked, source_hash-internal). No metadata,
      no free-text passthrough fields.
      Files: `telemetry/internal/export/candidate.go`
      Verify: compile-time shape + reflection test asserting the struct's JSON keys
      are a subset of the contract's field set (source_hash tagged `json:"-"`).
- [ ] T3.2 — Eligibility gate `Eligible(ev) (kind, ok)`: event-type filter, ack/
      whitelist/suppression exclusion, private/special-use domain filter
      (`.local`, `.lan`, `.home`, `.internal`, `.corp`, `home.arpa`, `in-addr.arpa`/
      `ip6.arpa`, single-label, IP-literal, punycode tricks), threshold + tag rules
      for the three signal kinds.
      Files: `telemetry/internal/export/gate.go`, `gate_test.go`
      Verify: table-driven tests covering EVERY exclusion rule with synthetic events
      (e.g. domain `nas-placeholder-01.local` from 192.0.2.10 → withheld; acked
      `known_bad` event → withheld; score 0.84 dga_candidate → withheld; 0.86 →
      candidate kind).
- [ ] T3.3 — Stripper `Strip(ev, salt) ExportCandidate`: allowlist projection, hour
      bucketing (UTC), confidence clamp, reason-vocabulary intersection, HMAC-SHA256
      source_hash with telemetry-local salt, eTLD+1 via vendored PSL snapshot.
      Files: `telemetry/internal/export/strip.go`, `strip_test.go`,
      `telemetry/internal/export/psl_snapshot.go`
      Verify: **table-driven tests proving forbidden fields never pass** — input
      events fully populated with synthetic PII (source_ip 192.0.2.55, resolved_ip
      203.0.113.9, server_ip 198.51.100.1, MAC 00:00:5E:00:53:2A in metadata,
      hostname `laptop-placeholder`, device_vendor, network_segment, geo, threat_desc,
      free-text tags, exact timestamps) → assert output candidate AND its JSON
      serialization contain none of them; known HMAC vector test; PSL cases including
      multi-part suffixes.
- [ ] T3.4 — Leak-scan test helper: scans any serialized batch for IP literals (all
      ranges), MAC patterns, forbidden suffixes, URL syntax, non-contract JSON keys,
      and non-vocabulary reason strings; wired into all Phase 3–5 tests.
      Files: `telemetry/internal/export/leakscan_test.go` (helper importable by other
      package tests via `export/leakscantest` if needed)
      Verify: helper self-test — seeded violations for each rule are all caught.
- [ ] T3.5 — Aggregator `Aggregate([]ExportCandidate) []Signal`: group by (kind,
      indicator, time_bucket); collapse source_hash set → distinct_asset_count and
      DISCARD hashes; sum observation/blocked counts (with contract caps); max
      confidence; union reasons.
      Files: `telemetry/internal/export/aggregate.go`, `aggregate_test.go`
      Verify: table-driven math tests; reflection test that `Signal` JSON has no
      `source_hash` key; leak-scan on serialized output.

## Phase 4: Transmitter (registration, signing, retry, spool)

- [ ] T4.1 — Reporter registration client + persistence: register on first opted-in
      run, persist `reporter.json` (0600) with reporter_id/secret/server config;
      generate + persist telemetry-local HMAC `salt` (0600); re-register with a fresh
      install UUID if state is lost.
      Files: `telemetry/internal/transmit/register.go`, `register_test.go`
      Verify: httptest server; permission bits asserted; lost-state re-registration.
- [ ] T4.2 — Request signing per contract §1: canonical string
      `timestamp\nnonce\nsha256hex(body)`, HMAC-SHA256, headers set.
      Files: `telemetry/internal/transmit/sign.go`, `sign_test.go`
      Verify: fixed-vector test (fixed secret/timestamp/nonce/body → expected hex)
      shared as a fixture with specs/003-threat-network's validator tests.
- [ ] T4.3 — Batch builder + sender: envelope fields, `max_batch_items` split, gzip,
      POST; backoff 1s→2s→4s→8s… cap 5min within tick; 4xx → no retry, move to
      `spool/rejected/` (cap 5); 5xx/network → spool (cap 50 batches or 24h, oldest
      dropped); spool drain before new batch on next tick.
      Files: `telemetry/internal/transmit/send.go`, `spool.go`, `send_test.go`,
      `spool_test.go`
      Verify: httptest fault-injection tests for each path; spool rotation test;
      leak-scan every serialized batch produced in tests.
- [ ] T4.4 — Dry-run mode: full pipeline, batches written to spool + summarized on
      `/status`, zero egress.
      Files: touch `send.go`, `status.go`
      Verify: test asserts no HTTP calls occur in dry-run while spool receives batches.

## Phase 5: Integration, golden files, and docs

- [ ] T5.1 — Golden-file contract test: synthetic Core fixture events → full pipeline
      → assert byte-stable batch (modulo UUIDs/times, injected deterministically)
      matches `contracts/telemetry-export.md` §7 example shape; fixtures placed in
      `specs/002-telemetry-service/contracts/fixtures/` for reuse by
      specs/003-threat-network's validator tests.
      Files: `telemetry/internal/export/golden_test.go`, contract fixtures
      Verify: `go test ./...` green; fixture files contain only synthetic values
      (leak-scan run over fixtures themselves).
- [ ] T5.2 — End-to-end compose test: stub threat-network binary (httptest) +
      telemetry container. Assert: (a) opt-in off → zero outbound requests and no
      state files; (b) opt-in on → register, then valid signed batch accepted;
      (c) server down → spool grows, then drains on recovery.
      Files: `telemetry/integration_test.go` (build-tagged), stub under
      `telemetry/internal/transmit/testutil/`
      Verify: `go test -tags=integration ./...` green locally.
- [ ] T5.3 — Update `telemetry/Dockerfile` (state-dir volume, status port expose on
      localhost mapping guidance) and compose wiring docs; keep container healthy-idle
      when not opted in (unchanged default).
      Files: `telemetry/Dockerfile`, compose file, `docs/architecture.md` service
      table row (`telemetry`: scaffolded → shipped-alpha once merged)
      Verify: `docker build telemetry/` succeeds; compose up with no opt-in shows the
      single idle log line.
- [ ] T5.4 — Operator docs: what leaves the node (link the contract), how to opt in,
      dry-run audit procedure, how to revoke; update `docs/backlog.md` VED-008 to link
      `specs/002-telemetry-service/`.
      Files: `docs/threat-intel-mvp.md` (status note), `docs/backlog.md`, README
      status section
      Verify: docs state OFF-by-default, opt-in, advisory-only explicitly; honest
      alpha framing per constitution.

## Phase 6: Live validation (SNR/export-quality gate)

- [ ] T6.1 — 72h live dry-run on a real opted-in node: pipeline runs, batches spool
      locally, NO egress. Operator reviews every would-be exported record.
      Verify: review checklist recorded here (date + result): zero raw IPs/MACs/
      hostnames observed; zero private/special-use domains; signal volume within
      caps; thresholds adjusted if junk candidates appear. Real captures/notes stay
      in gitignored `analysis-notes/` only — this file records pass/fail + parameter
      changes with synthetic examples.
- [ ] T6.2 — First real egress against the deployed threat-network alpha
      (specs/003-threat-network) with a single node; confirm accept/dedup/reject
      behaviors match contract §7 responses on `/status`.
      Verify: threat-network receipt visible; replayed batch → `duplicate: true`;
      tampered signature → 401 surfaced on `/status`.

## Final Gate

- [ ] Builds/tests green: `go build ./... && go test ./... -short` in `backend/`,
      `sensor/`, and `telemetry/`; `npm run build` in `frontend/` (unchanged but
      verified)
- [ ] Fresh-install migration chain applies cleanly (no new migrations in this
      feature — regression check on the existing 17)
- [ ] SNR validation pass recorded (Phase 6 dry-run review — export-quality gate for
      the community corpus)
- [ ] Leak-scan suite green over all fixtures, golden files, and integration output
- [ ] Docs updated: README status, docs/roadmap.md, docs/backlog.md (VED-008 →
      specs/002-telemetry-service/), docs/architecture.md service table;
      docs/schema.md untouched (no schema change) — confirmed
- [ ] Constitution check re-confirmed on the implemented result (OFF by default
      re-tested on the shipped binary; opt-in revocation re-tested; contract file
      matches emitted bytes)
