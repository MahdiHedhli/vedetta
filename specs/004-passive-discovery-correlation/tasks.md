# Tasks: Passive Discovery Correlation, Labeling & Multi-Network Handling

> Plan: `specs/004-passive-discovery-correlation/plan.md`
> Status: Not Started
> Created: 2026-07-03

Phases are sequential; tasks within a phase are parallelizable unless noted.
Every task states its verification. Mark done with date.

## Phase 1: Sensor — mDNS record-graph correlation & PTR fix

- [ ] T1.1 — Write failing tests capturing the current defects: PTR service branch never fires (dead code via `trimDNSName` underscore-stripping) and TXT/PTR metadata attaches to the wrong host in multi-host mDNS packets.
      Files: `sensor/internal/passive/parse_test.go` (extend existing test file pattern from `capture_test.go`)
      Verify: `go test ./internal/passive/ -run TestMDNS -v` in `sensor/` shows the new cases failing for the documented reasons.
- [ ] T1.2 — Rework `hostsFromMDNS` into record-graph correlation: owner-name keyed maps for A/AAAA (host→IP), SRV (instance→target host+port), TXT (instance→kv), PTR (service type→instance, using the RAW owner name before underscore-stripping); attach model/vendor/services to the host resolved through the graph, never `hosts[len(hosts)-1]`. Cap records/TXT pairs/services per packet (flood guard).
      Files: `sensor/internal/passive/parse.go`
      Verify: T1.1 tests pass; existing passive tests stay green (`go test ./... -short` in `sensor/`).
- [ ] T1.3 — Friendly-name extraction: mDNS service-instance label (e.g. `Living Room TV._googlecast._tcp.local` → `Living Room TV`), TXT `fn=`/`n=` keys, SSDP-derived names; add `FriendlyName string \`json:"friendly_name,omitempty"\`` to `netscan.DiscoveredHost` and propagate through `dedupeHosts`.
      Files: `sensor/internal/netscan/scanner.go`, `sensor/internal/passive/parse.go`, `sensor/internal/passive/parse_test.go`
      Verify: table-driven tests cover instance-label, TXT `fn=`, SSDP, and absent-name cases; sensor builds.
- [ ] T1.4 — Malformed/hostile input hardening tests: empty names, PTR without matching SRV/A, TXT-before-A record ordering, >cap record counts — all degrade to today's behavior without panic.
      Files: `sensor/internal/passive/parse_test.go`
      Verify: `go test ./internal/passive/` green; no panics under `go test -run TestMDNSMalformed -count=100`.

## Phase 2: Schema — migration 019 + store plumbing

- [ ] T2.1 — Author `siem/migrations/019_device_correlation.sql` exactly per plan.md Schema Changes (devices.display_name, devices.friendly_name, device_signals, device_identities, device_networks + indexes). Do NOT edit committed migrations (018 is reserved by specs/001).
      Files: `siem/migrations/019_device_correlation.sql`
      Verify: fresh temp DB applies 001→019 cleanly via the sequential runner (extend `backend/internal/store/db_test.go` fresh-install test).
- [ ] T2.2 — Backfill logic: seed `device_identities` from existing `devices.mac_address`/`hostname`, `device_networks` from `devices(segment, ip_address)`, compute initial `display_name`; decide SQL-in-migration vs first-boot Go (record decision in plan.md if changed).
      Files: `siem/migrations/019_device_correlation.sql` and/or `backend/internal/store/db.go`
      Verify: upgrade test over a fixture DB containing pre-existing devices (incl. a duplicate pair) shows seeded rows, non-empty display_name, unchanged first_seen values.
- [ ] T2.3 — Store accessors for the new tables: signal upsert (batch, one tx per report), identity alias upsert, network-attachment upsert, provenance read for API.
      Files: `backend/internal/store/devices_correlate.go` (new), `backend/internal/models/device.go` (DisplayName, FriendlyName, Segments, Signals fields)
      Verify: unit tests for each accessor against temp DB; `go build ./... && go test ./... -short` in `backend/`.

## Phase 3: Core — identity resolution, confidence merge, dedup

- [ ] T3.1 — Generic-hostname stoplist + confidence table as reviewable constants (source→confidence per FR-6; stoplist seed per SNR Tuning Plan).
      Files: `backend/internal/store/devices_correlate.go`
      Verify: unit tests: stoplisted hostnames never match/label; confidence table covers every `discovery_source` value.
- [ ] T3.2 — Ordered identity resolver replacing the MAC-then-IP lookup in `UpsertDevice`: (1) MAC; (2) mDNS name+segment (7-day window); (3) unique non-stoplisted hostname+segment (7-day window); (4) IP+segment with MAC-conflict veto (never re-assign a record whose stored MAC differs; MAC-less both sides requires 24 h recency). Log the matching rule used.
      Files: `backend/internal/store/devices.go`, `backend/internal/store/devices_correlate.go`, `backend/internal/store/devices_correlate_test.go`
      Verify: table-driven resolver tests incl. DHCP churn (MAC 00:00:5E:00:53:0A across 192.0.2.20→.21→.22 stays one device), MAC-conflict veto creating a second device, stoplist and uniqueness rejections.
- [ ] T3.3 — Duplicate merge: when a MAC match and an alias/IP match resolve to different records, fold MAC-less record B into A (min first_seen; higher-confidence fields; move aliases, attachments, signals; delete B), emit structured audit log via `logInfo`.
      Files: `backend/internal/store/devices_correlate.go`, tests
      Verify: merge test — MAC-less mDNS record then ARP+MAC observation ends with ONE device carrying mDNS model + earliest first_seen; audit line asserted.
- [ ] T3.4 — Confidence-weighted field merging replacing last-writer-wins UPDATE paths: canonical vendor/model/hostname/friendly_name/os/device_type recomputed from device_signals; equal-or-higher-confidence overwrites only; same source refreshes itself; `user_corrected` (1.0) locks fields (generalizes `UpdateDeviceFingerprint`).
      Files: `backend/internal/store/devices.go`, `backend/internal/store/devices_correlate.go`, tests
      Verify: tests — OUI vendor (0.2) cannot overwrite mDNS TXT model (0.9); DHCP hostname (0.7) overwrites nothing user-corrected; refresh-same-source updates last_observed.
- [ ] T3.5 — Multi-network attachments: upsert `device_networks` on every report (device × segment); keep `devices.segment`/`ip_address` = most recent attachment.
      Files: `backend/internal/store/devices_correlate.go`, tests
      Verify: same MAC reported on segments `lan` and `iot` yields one device, two attachment rows; `devices.segment` reflects latest.
- [ ] T3.6 — Widen fingerprint engine inputs: pass services, TXT-derived model, friendly name into `Engine.Fingerprint` / `DetectEOLFromSignals`; risk-category behavior (apply-even-at-lower-confidence) preserved.
      Files: `backend/internal/fingerprint/engine.go`, `backend/internal/fingerprint/eol.go` (call sites), tests
      Verify: fingerprint tests — mDNS model string triggers the same risk category as an equivalent hostname signal; existing engine tests green.

## Phase 4: API, wire contract & UI surfacing

- [ ] T4.1 — Sensor payload: add optional `friendly_name` to the hosts struct in `handleSensorDevices` and to sensor report code; write `contracts/sensor-devices.md` documenting the full hosts contract + compatibility rules (additive-only).
      Files: `backend/internal/api/router.go`, `sensor/cmd/vedetta-sensor/main.go` (report path), `specs/004-passive-discovery-correlation/contracts/sensor-devices.md`
      Verify: integration tests: old payload (no friendly_name) accepted unchanged; new payload stores friendly_name.
- [ ] T4.2 — Label deriver + API exposure: display_name precedence (custom_name > friendly_name > model+vendor > cleaned hostname > vendor+MAC suffix > IP), recomputed on upsert; `GET /devices` & `/devices/new` return `display_name`, `friendly_name`, `segments`, `signals`.
      Files: `backend/internal/store/devices_correlate.go`, `backend/internal/store/devices.go`, `backend/internal/api/router.go`, tests
      Verify: precedence table test (each fallback level); API response asserted in handler test.
- [ ] T4.3 — Frontend: device inventory shows display_name (custom_name editing unchanged), provenance tooltip from `signals`, multi-segment badge; events context surfaces display_name where hostname/vendor shows today.
      Files: `frontend/src/App.jsx`
      Verify: `npm run build` green; manual check in dev UI.
- [ ] T4.4 — `new_device` tag description text updated to mention private-MAC rotation as a benign cause (SNR plan item 3); keep `GetMinFirstSeenForIP` for this release, add TODO with removal target next release.
      Files: `backend/internal/api/router.go`, `backend/internal/store/devices.go`
      Verify: tag description asserted in enrichment test; TODO comment present.

## Phase 5: SNR validation & docs

- [ ] T5.1 — Simulated validation suite per plan: multi-host mDNS fixture, DHCP churn sequence, MAC-less→MAC link-up, identical-generic-hostname non-merge, multi-segment roam — as one integration test package run in CI.
      Files: `backend/internal/store/devices_correlate_test.go` (integration section) or `backend/internal/api/router_test.go`
      Verify: suite green in `go test ./... -short`.
- [ ] T5.2 — Live soak ≥48 h on dev network: before/after device row count, duplicate rate, `new_device` events/day, wrong-merge count (target 0). Raw data → gitignored `analysis-notes/`; sanitized summary (RFC 5737 / 00:00:5E:00:53:xx only) → this spec directory.
      Files: `specs/004-passive-discovery-correlation/snr-validation.md` (sanitized), `analysis-notes/` (raw, gitignored)
      Verify: acceptance criteria from plan.md SNR section met and recorded; any stoplist additions folded back into T3.1 constants.
- [ ] T5.3 — Docs: README status line, `docs/roadmap.md` (move item from Planned to Shipped), `docs/backlog.md` (VED-012 entry → Done), `docs/schema.md` (019 tables), `docs/sensor-architecture.md` (mDNS correlation description).
      Files: as listed
      Verify: docs mention shipped-vs-planned honestly; no real environment identifiers in any tracked file (grep for non-RFC-5737 private IPs/MACs in the diff).

## Final Gate

- [ ] Builds/tests green: backend, sensor, frontend (`go build ./... && go test ./... -short` in `backend/` and `sensor/`; `npm run build` in `frontend/`)
- [ ] Fresh-install migration chain applies cleanly (001→019) + upgrade-with-data test passes
- [ ] SNR validation pass recorded (simulated suite + live soak summary in `snr-validation.md`)
- [ ] Docs updated: README status, docs/roadmap.md, docs/backlog.md (VED-012), schema.md
- [ ] Constitution check re-confirmed on the implemented result (passive-first: confirm no active requests added; env-data: confirm sanitized examples only)
