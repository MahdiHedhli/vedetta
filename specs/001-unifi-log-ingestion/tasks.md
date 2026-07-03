# Tasks: UniFi Log Ingestion (First Supportable Router/Firewall Path)

> Plan: `specs/001-unifi-log-ingestion/plan.md`
> Status: Not Started
> Created: 2026-07-03

Phases are sequential; tasks within a phase are parallelizable unless noted.
Every task states its verification. Mark done with date.

## Phase 1: Contract validation & sample corpus

- [ ] T1.1 — Build the synthetic test corpus from the contract: CEF firewall lines
      (allow/block/drop/reject, in/out, tcp/udp/icmp), iptables-style lines
      (`[RULESET-N-A]` accept/drop/reject, inbound/outbound/inter-VLAN), multicast
      blocks, malformed lines, and a 100k-line WAN-drop flood file. RFC 5737 IPs and
      `00:00:5E:00:53:xx` MACs only.
      Files: `collector/testdata/unifi/*.log`, small Go or shell generator in
      `collector/testdata/unifi/gen/`
      Verify: corpus files committed; `grep -rE '(^|[^0-9])(10|172\.16|192\.168)\.' collector/testdata/unifi/` returns nothing (no private/real IPs).
- [ ] T1.2 — Live capture validation (LOCAL-ONLY): enable UniFi SIEM/CEF export and
      legacy syslog export toward a scratch listener; capture real samples of every
      firewall/security message class; confirm/correct the CEF extension keys and
      iptables grammar in `contracts/unifi-syslog-cef.md`; note UniFi Network version
      tested. Raw captures go to gitignored `analysis-notes/` ONLY; the contract gets
      sanitized field-name updates, never real values.
      Files: `analysis-notes/unifi-capture-notes.md` (gitignored),
      `specs/001-unifi-log-ingestion/contracts/unifi-syslog-cef.md` (sanitized updates)
      Verify: every "(validate)" marker in the contract resolved or moved to Open
      Questions with rationale; `git diff` of the contract contains no RFC-1918/real
      WAN IPs, real MACs, or real hostnames.
- [ ] T1.3 — Decide and document the rollup window + throttle defaults from observed
      live volume (events/day raw, by category).
      Files: `specs/001-unifi-log-ingestion/plan.md` (update defaults if needed),
      `analysis-notes/` for raw numbers
      Verify: plan.md defaults either confirmed or updated with sanitized justification.

## Phase 2: Collector pipeline (Fluent Bit)

- [ ] T2.1 — Write `unifi_transform.lua`: dialect detection (CEF vs iptables vs drop),
      field extraction, action/protocol normalization, direction inference,
      tag assembly (`source:unifi`, `fw:*`, `dir:*`, `fw:multicast`), metadata JSON
      construction (incl. `raw_log` truncated to 1 KB, `dialect`), malformed-line
      drop counter with sampled logging.
      Files: `collector/config/unifi_transform.lua`
      Verify: golden-file test script replays `collector/testdata/unifi/*.log` through
      `fluent-bit -c` test config; output JSON matches expected fixtures exactly.
- [ ] T2.2 — Implement the WAN-inbound rollup in the Lua filter: per-window
      accumulation (default 15 min), emit one rollup event per window with
      count/unique_src/top_dst_ports metadata and `wan_scan_noise` tag; individual
      WAN-inbound drops suppressed.
      Files: `collector/config/unifi_transform.lua`
      Verify: golden test — 1,482 synthetic WAN drops in one window produce exactly 1
      rollup event with `count=1482`; outbound blocks in the same input still emit
      individually.
- [ ] T2.3 — Wire the pipeline in `fluent-bit.conf`: route `firewall.syslog` through
      the new Lua filter (replacing the current bare `modify` filter for UniFi lines),
      add `throttle` filter (default 2,000 events/min on `firewall.*`), set
      `mem_buf_limit` on the syslog input, keep the existing HTTP output. Preserve
      the Pi-hole path untouched.
      Files: `collector/config/fluent-bit.conf`, `collector/config/parsers.conf` (only
      if the rfc3164 parser needs hardening), `collector/Dockerfile` (copy new Lua)
      Verify: `docker compose up collector` clean start; Pi-hole golden test still
      passes; flood file replay shows throttle engagement in collector logs and
      bounded memory (`docker stats` < 100 MB for the collector).
- [ ] T2.4 — Add optional ingest-auth header support to the collector config
      (templated `Header Authorization Bearer ${VEDETTA_INGEST_TOKEN}`; omitted when
      unset) and document the env var in compose.
      Files: `collector/config/fluent-bit.conf`, `docker-compose.yml`
      Verify: with token set, requests carry the header (backend access log);
      without, config remains valid and requests succeed against an open Core.

## Phase 3: Backend — enrichment, auth, migration

- [ ] T3.1 — Enricher `firewall_log` branch: skip DNS heuristics; device cross-ref by
      `source_ip` (attach `device_vendor`, canonical segment, `risky_device_fw_block`
      tag/boost for `risk_category` devices); first-occurrence detection for
      (source_ip, dst_ip, rule) → `new_fw_block` tag + 0.4 base; recurring → 0.1;
      rollups stay 0.0; score cap 1.0.
      Files: `backend/internal/dnsintel/enricher.go`, tests in
      `backend/internal/dnsintel/enricher_test.go`
      Verify: `go test ./internal/dnsintel/ -run Firewall -v` covers the scoring
      matrix from plan.md (all rows) and asserts DNS events are unaffected.
- [ ] T3.2 — Ingest auth (scope `ingest`): extend the `auth` package with the new
      scope; enforce on `POST /api/v1/ingest` only when an ingest-scope token exists
      AND `VEDETTA_REQUIRE_INGEST_AUTH=1`; add the 5,000 events/request cap (413).
      Bootstrap/no-token behavior unchanged.
      Files: `backend/internal/auth/*.go`, `backend/internal/api/router.go`, tests
      Verify: `go test ./internal/api/ -run Ingest` — matrix: open mode 200; enforced
      mode 401 without / 200 with token; 5,001 events → 413; existing ingest tests
      still green.
- [ ] T3.3 — Migration `018_unifi_firewall_defaults.sql`: seed default whitelist rules
      (`wl-fw-wan-scan-rollup` tag_match=`wan_scan_noise`; `wl-fw-multicast-broadcast`
      tag_match=`fw:multicast`; `wl-fw-self-scan` disabled template), all
      `is_default=TRUE`, `category='firewall'`, `INSERT OR IGNORE`.
      Files: `siem/migrations/018_unifi_firewall_defaults.sql`
      Verify: T3.4 migration tests; re-applying the INSERT block manually is a no-op.
- [ ] T3.4 — Migration chain tests: fresh install (empty DB → 001..018, assert
      `schema_migrations` count and seeded rules present) and upgrade (DB at 017 →
      apply 018 only).
      Files: `backend/internal/store/db_test.go` (or existing migration test file)
      Verify: `go test ./internal/store/ -run Migration -v` green on both paths.
- [ ] T3.5 — Whitelist engine coverage for firewall events: ensure `tag_match` and
      `source_ip_pattern` rules apply to `firewall_log` events in the enricher branch
      (not just DNS), and that whitelisted events are score-zeroed/tagged per existing
      semantics.
      Files: `backend/internal/dnsintel/enricher.go`, `backend/internal/store/whitelist.go` (if needed), tests
      Verify: unit test — event tagged `wan_scan_noise` + seeded rule → suppressed;
      rule disabled → not suppressed.

## Phase 4: Optional REST connector (VED-002 closure)

- [ ] T4.1 — Finish `UniFiConnector` auth: `X-API-KEY` support (preferred) alongside
      the existing cookie login; TOFU note documented (cert pinning deferred — record
      as accepted limitation); keep `/proxy/network` autodetect.
      Files: `backend/internal/firewall/unifi.go`,
      `backend/internal/firewall/unifi_test.go` (httptest fixtures, synthetic data)
      Verify: `go test ./internal/firewall/ -v` — API-key path, cookie fallback, UDM
      prefix detection, IPS event parse against fixtures.
- [ ] T4.2 — Wire the connector into Core startup behind config: register with
      `firewall.Manager` only when `VEDETTA_UNIFI_HOST` + credentials are set; IPS
      events → `ToEvent()` (tags `source:unifi`, `ips`, severity→score map 1→0.4,
      2→0.7, 3→1.0; `metadata.dialect="rest"`) → `InsertEvents`; dedup high-water
      mark so REST-polled IPS events aren't re-inserted across restarts.
      Files: `backend/cmd/*/main.go` (Core entrypoint), `backend/internal/firewall/manager.go`, `backend/internal/firewall/connector.go`
      Verify: integration test with httptest controller — two polls insert each IPS
      event exactly once; connector absent from startup when env unset.
- [ ] T4.3 — Client inventory sync (enrichment only): `list clients` → device registry
      upsert (`discovery_method: "unifi_connector"`, hostname/vendor/segment
      metadata), never creating events; existing device merge rules respected.
      Files: `backend/internal/firewall/manager.go`, `backend/internal/store/devices.go` (only if an upsert variant is needed), tests
      Verify: unit test — synthetic client list upserts devices; re-poll updates
      `last_seen` without duplicates; devices view shows connector-sourced fields.
- [ ] T4.4 — Connector health surfacing: expose `ConnectorHealth` via an admin API
      route (e.g. `GET /api/v1/connectors`) for the setup guide's verification step.
      Files: `backend/internal/api/router.go`, `backend/internal/firewall/manager.go`
      Verify: curl against running Core returns connector name, connected state,
      last_poll, last_error, event_count; route requires admin scope.

## Phase 5: SNR validation loop (required for the "supported" label)

- [ ] T5.1 — Simulated pass: end-to-end docker-compose replay of the full synthetic
      corpus + flood file; record events stored vs lines sent, rollup counts, scores.
      Files: `tools/` or `scripts/` validation script (follow the existing SNR
      validation tooling pattern), results table in `docs/SNR-IMPROVEMENTS.md`
      Verify: acceptance numbers from plan.md hold — flood stores ≤ window rollups,
      no score>0.5 from routine corpus, risky-device injection scores ≥0.7.
- [ ] T5.2 — Live pass (≥72 h on a real UniFi gateway, LOCAL-ONLY raw data): measure
      events/day pre/post suppression, review every score>0.5 event, catalogue
      residual noise patterns; add/adjust default rules or scoring as needed.
      Files: `analysis-notes/` (raw, gitignored); sanitized summary in
      `docs/SNR-IMPROVEMENTS.md`; rule/scoring adjustments in their Phase 2/3 files
      Verify: post-suppression steady state ≤ ~500 stored firewall events/day;
      false-positive review documented; any tuning change re-runs T5.1 green.
- [ ] T5.3 — Post-tuning regression sweep: full test suites re-run after any Phase 5
      adjustments; confirm DNS-path SNR metrics unchanged (no cross-source
      regression).
      Files: n/a (execution)
      Verify: `go test ./... -short` (backend, sensor) green; existing SNR heartbeat/
      validation tooling shows no DNS-side deltas.

## Phase 6: UI & documentation

- [ ] T6.1 — Frontend: `firewall_log` + `source:unifi` filter chips in the events
      view; firewall metadata rendering (action/proto/src→dst:port/rule) in event
      detail; rollup events rendered as an aggregate row ("WAN scan noise: N drops").
      Files: `frontend/src/App.jsx` (and components it delegates to)
      Verify: `npm run build` green; manual check against seeded events — filters,
      detail fields, and rollup rendering correct.
- [ ] T6.2 — Setup guide `docs/connectors/unifi.md`: UniFi-side export configuration
      (SIEM/CEF and legacy syslog variants, with placeholder IPs), verification steps
      (`/api/v1/stats`, `/api/v1/connectors`), optional REST connector setup
      (read-only local account/API key), ingest-token setup, expected volumes,
      supported vs experimental statement (syslog events = supported; REST
      inventory/IPS = experimental). Closes VED-002.
      Files: `docs/connectors/unifi.md`, link from `docs/connector-guide.md`
      Verify: a clean-room follow-through of the guide (or peer review) reaches
      "events visible in UI" with no undocumented step; all example values synthetic.
- [ ] T6.3 — Tracker/docs updates: `docs/backlog.md` VED-002 + VED-005 → link this
      spec directory and mark resolved; `docs/roadmap.md` UniFi item → shipped
      status; `README.md` supported-inputs section; `docs/schema.md` note on
      firewall_log metadata keys and migration 018.
      Files: `docs/backlog.md`, `docs/roadmap.md`, `README.md`, `docs/schema.md`
      Verify: grep for VED-002/VED-005 shows spec links; docs state shipped vs
      planned honestly (alpha posture preserved).

## Final Gate

- [ ] Builds/tests green: backend, sensor, frontend
      (`go build ./... && go test ./... -short` in `backend/` and `sensor/`,
      `npm run build` in `frontend/`)
- [ ] Fresh-install migration chain applies cleanly (001 → 018, seeded defaults
      verified; upgrade-from-017 path verified)
- [ ] SNR validation pass recorded (simulated T5.1 + live T5.2 results in
      `docs/SNR-IMPROVEMENTS.md` with sanitized examples)
- [ ] Docs updated: README status, docs/roadmap.md, docs/backlog.md (VED-002,
      VED-005 → `specs/001-unifi-log-ingestion/`), docs/schema.md
- [ ] Environment-data scrub check: no RFC-1918/real WAN IPs, real MACs, hostnames,
      or credentials anywhere in the tracked diff (release blocker per constitution)
- [ ] Constitution check re-confirmed on the implemented result (spec table reviewed
      against what actually shipped; deviations documented as exceptions)
