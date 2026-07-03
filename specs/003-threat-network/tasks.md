# Tasks: Community Threat-Network Backend (Ingest, Consensus, Advisory Feed)

> Plan: `specs/003-threat-network/plan.md`
> Status: Not Started
> Created: 2026-07-03

Phases are sequential; tasks within a phase are parallelizable unless noted.
Every task states its verification. Mark done with date.
All test fixtures use synthetic data only (RFC 5737 IPs, `*.example` domains,
`00:00:5E:00:53:xx` MACs) per the constitution.

## Phase 1: Storage foundation (SQLite + migrations)

- [ ] T1.1 — Create `threat-network/internal/store` with SQLite open (mattn/go-sqlite3,
      WAL, busy_timeout) and a sequential migration runner mirroring Core's
      `schema_migrations` pattern (never edit committed migrations).
      Files: `threat-network/internal/store/db.go`, `threat-network/migrations/001_init.sql`
      Verify: `go test ./internal/store/` — fresh temp DB applies chain cleanly;
      re-running the runner is a no-op; all 9 tables from plan.md exist with expected
      columns and indexes.
- [ ] T1.2 — Implement store CRUD: reporters (create/lookup/denylist/touch last_seen),
      nonces (insert-if-absent, purge >24h), ingest_receipts (insert, exists),
      signals upsert on `(reporter_id, kind, indicator_key, time_bucket)` taking
      max(confidence) and summing counts, reporter_counters increment/read,
      allowlist lookup by eTLD+1.
      Files: `threat-network/internal/store/{reporters,signals,receipts,counters,allowlist}.go` + tests
      Verify: unit tests cover upsert-dedup semantics (same reporter+indicator+bucket
      twice → one row, merged counts) and nonce replay returns "already seen".
- [ ] T1.3 — Seed static allowlist snapshot (top eTLD+1 list, checked into repo as
      `threat-network/data/allowlist.txt`) loaded into `allowlist_domains` at startup.
      Files: `threat-network/data/allowlist.txt`, loader in `internal/store/allowlist.go`
      Verify: test asserts a known-popular placeholder entry loads and lookup hits;
      file contains only public well-known registered domains (no environment data).
- [ ] T1.4 — Retention purge routine: signals/receipts >30d, nonces >24h, revoked
      feed_items >90d; runs on a daily ticker.
      Files: `threat-network/internal/store/retention.go` + test
      Verify: unit test with backdated rows purges exactly the expired set.

## Phase 2: Reporter registration & request authentication

- [ ] T2.1 — `POST /api/v1/reporters/register`: validate request
      (`schema_version`, `install_id`, `capabilities` ⊆ the three known kinds),
      generate random `reporter_id` + secret, store SHA-256(secret) only, return
      secret once with config `{min_upload_interval_seconds:900, max_batch_items:250}`.
      Files: `threat-network/internal/auth/register.go`, `internal/api/handlers.go` + tests
      Verify: httptest round-trip matches the request/response shapes in
      `docs/threat-intel-mvp.md`; DB row contains hash, not the secret.
- [ ] T2.2 — HMAC signed-request verification middleware:
      `Authorization: VedettaReporter <id>`, `X-Vedetta-Timestamp` (±5 min),
      `X-Vedetta-Nonce` (single-use per reporter), `X-Vedetta-Signature =
      hex(HMAC-SHA256(secret, ts + "\n" + nonce + "\n" + sha256(body)))`;
      constant-time compare; denylisted reporters rejected.
      Files: `threat-network/internal/auth/hmac.go` + tests
      Verify: table-driven tests — valid request passes; wrong secret, skewed
      timestamp, reused nonce, tampered body, denylisted reporter each rejected with
      the plan.md error code (`INVALID_SIGNATURE`, `STALE_TIMESTAMP`, `NONCE_REUSED`,
      `REPORTER_DENYLISTED`).
- [ ] T2.3 — Per-IP in-memory token-bucket limiter for `/reporters/register` and
      `/ingest` and `/feed/community`; no IP ever persisted.
      Files: `threat-network/internal/api/ratelimit.go` + tests
      Verify: burst over limit → 429 with `retry_after_seconds`; grep confirms no IP
      value flows into any store call.

## Phase 3: Ingest pipeline (contract validation, privacy re-gate, dedup, caps)

- [ ] T3.1 — Batch envelope validation against
      `specs/002-telemetry-service/contracts/telemetry-export.md`: schema_version,
      batch_id uuid, window bounds, ≤250 signals; duplicate `batch_id` → idempotent
      replay: `200` with `duplicate: true`, no re-processing (002 contract §1).
      Files: `threat-network/internal/ingest/validate.go` + tests
      Verify: fixtures derived from the 002 contract examples pass; each envelope
      violation yields its specific error code; replaying a `batch_id` returns `200`
      with `duplicate: true` and does not re-process.
- [ ] T3.2 — Per-signal validation for the three kinds (required fields per kind,
      confidence ∈ [0,1], counts ≥ 0, hour-aligned `time_bucket` inside the batch
      window); invalid signals rejected individually and reflected in the `rejected`
      count of the `202` response body (per-signal detail logged server-side only —
      never added to the wire).
      Files: `threat-network/internal/ingest/validate.go` + tests
      Verify: mixed-validity batch returns `accepted`/`rejected` counts matching
      fixture expectations.
- [ ] T3.3 — Server-side privacy re-gate: if any signal's indicator is a
      private/special-use/single-label name (`.local`, `.lan`, `.home`, `.internal`,
      `.corp`, `home.arpa`, `in-addr.arpa`, `ip6.arpa`, bare label — the full
      002-contract §5 rule-4 list), an IP literal, or carries unexpected
      identifier-like fields → reject the WHOLE batch with `422` and body
      `{error, rule, detail, batch_id}` (002 contract §5).
      Files: `threat-network/internal/ingest/privacy.go` + tests
      Verify: table-driven test with every excluded class from
      `docs/threat-intel-mvp.md` rejecting the entire batch with `422` and the
      002 §5 error body; `sub.badhost.example` accepted.
- [ ] T3.4 — Dedup + persist: compute `indicator_key` per kind, upsert into `signals`,
      write `ingest_receipts`, enforce per-reporter caps (4 batches/h, 1,000 accepted
      signals/day, 200 distinct new indicators/day via `reporter_counters`) → 429
      over cap.
      Files: `threat-network/internal/ingest/ingest.go` + tests
      Verify: replaying the same batch returns `200` with `duplicate: true` and is
      not re-processed; same signal in two batches
      dedupes to one row; cap tests hit 429 while a second reporter is unaffected.
- [ ] T3.5 — Wire `POST /api/v1/ingest` handler replacing the stub TODO in
      `threat-network/cmd/threat-network/main.go`; success response `202` with body
      `{accepted, rejected, batch_id, duplicate}` (002 contract §7; any extra
      observability is logged server-side, never added as wire fields).
      Files: `threat-network/cmd/threat-network/main.go`, `internal/api/handlers.go` + httptest
      Verify: end-to-end httptest — register, sign, ingest a synthetic batch, rows in
      `signals`; unauthorized/unsigned request rejected.

## Phase 4: Consensus, promotion, decay

- [ ] T4.1 — Aggregation: recompute `signal_aggregates` per `(kind, indicator_key)`
      over trailing 7 days — per-reporter contribution = max(local_confidence)
      counted once per reporter (influence cap), `avg_conf`, `distinct_reporters`,
      `has_known_bad`, merged reasons.
      Files: `threat-network/internal/consensus/aggregate.go` + tests
      Verify: 100 signals from one reporter yield `distinct_reporters=1` and the same
      contribution as 1 signal; recomputation is idempotent.
- [ ] T4.2 — Promotion rules + confidence model from plan.md: rules 1/2/3 with
      allowlist guard first; `feed_confidence = min(0.99, avg_conf * (0.7 + 0.3 *
      min(1, distinct_reporters/5)))`; severity mapping; non-promoted aggregates
      remain in hold state; allowlisted-indicator reports increment reporter
      `allowlist_flags`.
      Files: `threat-network/internal/consensus/promote.go` + tests
      Verify: boundary tests — known_bad at 1 vs 2 reporters; exact domain at 2 vs 3
      reporters and avg_conf 0.89 vs 0.90; cluster at 3 vs 4 and 0.79 vs 0.80;
      allowlisted eTLD+1 never promotes regardless of reporters.
- [ ] T4.3 — Feed item lifecycle: upsert promoted items into `feed_items`
      (`sources_required`, `sources_observed`, timestamps), refresh
      `last_seen`/`confidence`/`expires_at` while corroborated (30d known-bad / 7d
      others), mark expired items revoked.
      Files: `threat-network/internal/consensus/lifecycle.go` + tests
      Verify: time-injected tests — item expires exactly at boundary; refreshed item
      extends; revoked item excluded from feed queries.
- [ ] T4.4 — 15-minute consensus ticker wired into service startup; run-once mode for
      tests/ops (`-consensus-once` flag or internal call).
      Files: `threat-network/cmd/threat-network/main.go` + integration test
      Verify: integration test runs consensus once after ingest and observes
      `feed_items`; crash-mid-run then re-run converges to identical state.

## Phase 5: Community feed publish API

- [ ] T5.1 — `GET /api/v1/feed/community`: cursor pagination on `(updated_at, feed_id)`,
      `limit`/`min_confidence`/`kind` filters, expiry filtering, 5,000-item cap,
      `ETag` + `If-None-Match` → 304, `Cache-Control: max-age=900`, advisory fields
      on every item.
      Files: `threat-network/internal/feed/feed.go`, `internal/api/handlers.go` + tests
      Verify: httptest paginates a seeded 12-item feed at limit=5 across 3 stable
      pages; unchanged feed returns 304; every item asserts `advisory==true` and
      `recommended_action=="advise"`.
- [ ] T5.2 — Contract conformance test: golden test validating the live response
      structure (fields, types, enums) against the examples and field reference in
      `specs/003-threat-network/contracts/community-feed-api.md`, including error
      bodies (`INVALID_CURSOR`, `RATE_LIMIT_EXCEEDED`).
      Files: `threat-network/internal/feed/contract_test.go` (+ testdata)
      Verify: `go test ./internal/feed/` green; intentionally removing a field fails
      the test.
- [ ] T5.3 — Deprecate stubs: `/api/v1/feed/top-domains` and `/api/v1/feed/anomalies`
      keep returning empty payloads with a `Deprecation` header for one release;
      `/api/v1/status` gains `feed_items` count.
      Files: `threat-network/cmd/threat-network/main.go` + test
      Verify: both paths still return 200 empty JSON (backward compat), header present.

## Phase 6: Abuse hardening, ops, docs

- [ ] T6.1 — Denylist workflow: store flag + admin path (config-file or CLI subcommand,
      no web UI) to denylist/reinstate a reporter; denylisted ingest → 403
      `REPORTER_DENYLISTED`; existing signals from a denylisted reporter excluded from
      the next consensus run.
      Files: `threat-network/internal/auth/denylist.go` + tests
      Verify: end-to-end test — denylist reporter, its indicator drops below threshold
      and is not promoted on recompute.
- [ ] T6.2 — PII-free logging audit: structured logs carry reporter_id, batch_id,
      counts, and error codes only — never request bodies, indicators at debug-off,
      or client IPs beyond the in-memory limiter.
      Files: logging call sites across `threat-network/internal/`
      Verify: test-mode log capture during full integration run greps clean for
      synthetic "client IP" and body markers planted by the test.
- [ ] T6.3 — Load smoke: script simulating 50 reporters × 250-signal batches on a
      15-minute cadence (compressed bursts) against a 1 vCPU / 512 MB container;
      record p95 ingest latency, consensus run time, DB size.
      Files: `threat-network/scripts/loadsmoke/` (synthetic generators only)
      Verify: no 5xx, consensus completes < 1 min, results noted in this file.
- [ ] T6.4 — Docs: update `docs/threat-intel-mvp.md` status (Phase 1–2 implemented
      server-side), `README.md` shipped-vs-planned honesty note, `docs/backlog.md`
      VED-008 → link `specs/003-threat-network/`; note that Core-side consumption is
      a follow-up spec (proposed `fetchVedettaCommunity()` in
      `backend/internal/threatintel/feeds.go` maps feed items to `Indicator`).
      Files: `docs/threat-intel-mvp.md`, `README.md`, `docs/backlog.md`
      Verify: links resolve; no environment-specific identifiers introduced.

## Final Gate

- [ ] Builds/tests green: `go build ./... && go test ./...` in `threat-network/`,
      plus backend, sensor (`-short`), and frontend build unaffected
- [ ] Fresh-install migration chain applies cleanly (`threat-network/migrations/`,
      empty temp DB, runner idempotent)
- [ ] SNR validation pass recorded: simulated multi-reporter suite from plan.md
      (no single-reporter promotion, threshold boundaries, allowlist guard, decay,
      flood isolation) all green; live-alpha dark-feed review checklist created
- [ ] Docs updated: README status, docs/roadmap.md, docs/backlog.md (VED-008),
      docs/threat-intel-mvp.md cross-links; schema.md untouched (no Core schema change)
      with a pointer added for the service-local schema
- [ ] Constitution check re-confirmed on the implemented result (privacy/opt-in table
      in spec.md; PII-free logging audit T6.2 passed; all fixtures synthetic)
- [ ] Rollout gate honored: feed endpoint stays dark until the Phase-1 style
      ingest-only alpha review from plan.md's SNR Tuning Plan is complete
