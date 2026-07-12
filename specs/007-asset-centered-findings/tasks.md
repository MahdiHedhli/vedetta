# Tasks: Asset-Centered Findings and Detection Fusion

## Phase 1 - Schema and identity foundation

- [x] Add migration 025 and inline fallback parity.
- [x] Add temporal address and many-to-many identity evidence stores.
- [x] Thread authenticated sensor/segment/timestamp through device observations.
- [x] Add event identity fields and deterministic timestamp resolver.
- [x] Convert destructive merges to audited soft redirects; add confirm/merge/split APIs.
- [x] Capture/hash DHCP 55/61, SSDP UUID/type, and selected mDNS stable evidence.
- [x] Add migration, DHCP churn, reused IP, conflict, merge/split audit tests.

## Phase 2 - Unified processing and evidence

- [x] Implement `IngressEnvelope`/Processor and per-event transaction result contract.
- [x] Extract every currently available typed observable, including all DNS answers.
- [x] Produce typed detector evidence without replacing source metadata.
- [x] Evaluate IOC/IPS before benign context; calculate priority once.
- [x] Evaluate legacy and finding suppression server-side without deleting evidence.
- [x] Route sensor DNS, `/ingest`, Pi-hole, AdGuard, and direct UniFi through Processor.
- [x] Add source-parity tests and direct-UniFi/DNS-answer IOC regression tests.

## Phase 3 - Durable findings and health

- [x] Implement finding key/generation/reopen policy and concurrent unique invariant.
- [x] Add evidence links, status history, admin lifecycle APIs, and suppression policy.
- [x] Add findings list/detail/stats APIs and detection health API.
- [x] Persist source/feed success, freshness, counts, and errors.
- [x] Test aggregation, unrelated detectors, max severity, resolution, recurrence,
      suppression, immutable events, and concurrent duplicate prevention.

## Phase 4 - Findings-first dashboard

- [x] Add Vitest/RTL/jsdom and component/API test harness.
- [x] Add findings state with explicit loading/healthy/stale/error/unauthorized states.
- [x] Replace browser grouping with server findings; keep Raw Events drill-down.
- [x] Add blocked/allowed/observed, reason, action, count/window, evidence, and device links.
- [x] Add Investigating/Resolved actions and identity confirm/merge/split workflow.
- [x] Replace lifetime dashboard threat counts with current finding/health metrics.
- [x] Test empty vs failure, lifecycle, device links, evidence, and DHCP-stable rendering.

## Phase 5 - Delivery

- [x] Update API/schema/operator docs and success-metric instrumentation.
- [x] Run all Go build/vet/race/migration tests and frontend test/build/audit gates.
- [x] Run sanitization/secret/diff checks and capture synthetic screenshots.
- [x] Document migration, backup, forward-only rollback, limitations, and deferred issues.
- [x] Open draft PR #58 from `feat/asset-centered-findings`; never merge it.
- [x] Request independent adversarial review and address release-relevant findings.

## Constitution check

Each phase remains passive-first, local-only, additive, Pi-hole-optional, deterministic,
and bounded for the Raspberry Pi 4 floor. Synthetic fixtures only.
