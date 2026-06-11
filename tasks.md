# UniFi Ingestion Tasks (phased, testable, thin-slice-first; planning only)

Map to backlog: VED-002 (firewall connectors / ingest), VED-005 (UniFi specific).

All work is planning artifacts only. No implementation in this branch.

## Phase 0: Setup & Research (done in this planning PR)
- [x] Run `specify integration list` (not native; claude present at ~/.local/bin/claude 2.1.144).
- [x] Gating research on CURRENT Ubiquiti docs (CEF confirmed for SIEM/syslog Security/Firewall/IPS; cite help.ui.com article).
- [x] constitution.md (this repo root).
- [x] spec.md (V1 passive syslog + collector Lua parse for raw_log → FirewallEvent fields).
- [x] plan.md (end-to-end, SNR first-class, NEW mig only, Pi-4).
- [x] tasks.md (this file).
- [ ] /speckit.analyze (cross-artifact; shell out to claude; report contradictions/scope/constitution).
- Commit artifacts, push, open PR, STOP. No code.

## Phase 1: Thin Slice — Collector + Happy Path (VED-002 / VED-005 entry)
- Add collector/config/unifi_transform.lua (modeled on pihole_transform.lua; parses CEF key fields action/protocol/src/dst/ports/interface into Event shape or metadata; preserves raw_log and source=unifi).
- Extend fluent-bit.conf: new INPUT for UniFi CEF syslog (distinct port or tag), Parser if needed, modify + Lua filter, OUTPUT to /ingest (reuse existing http output pattern).
- Update collector README / docs/connector-guide.md (UniFi section: config on gateway, Lua location of normalization per spec, note on pfSense CSV vs UniFi CEF, explicit "connector must parse so PIECE 3 filters work").
- Add minimal test payload (synthetic CEF sample) + roundtrip in backend internal/api/router_test.go or store (honest collector shape, like the faithful firewall test).
- Backend build + sensor (n/a) + any collector smoke green.
- Commit, push to branch (no main merge).

## Phase 2: Core Wiring + Filters Verification (no schema change)
- Verify /ingest already accepts the emitted shape (reuse map-lift if top-level non-Event).
- Exercise json_extract filters with source=unifi + action=blocked etc (extend existing events filter tests).
- Add source="unifi" handling in Enricher or simple tag for SNR (conservative, no broad suppression).
- Update docs/connector-guide.md with "where the normalization happens" decision (collector Lua, Pi-hole consistency).
- Full backend green (multi-module).
- Commit.

## Phase 3: SNR + Volume Guardrails (Pi-4 first-class)
- Add source=unifi to suppression rule examples / quick actions (UI or API, thin).
- Retention / health: ensure unifi events participate in EnforceRetention; add cardinality note in db-health or collection-health for high-volume sources.
- Backpressure: collector config comments + limits for chatty "block" categories.
- Test: seed high volume of synthetic unifi blocks + assert retention + no OOM / filter function.
- Backend green.
- Commit.

## Phase 4: Optional Additive Migration (only if justified after Phase 1-3 measurement)
- NEW file only: siem/migrations/017_....sql (guarded ALTERs for any first-class firewall columns if metadata perf is insufficient after real data).
- Runner already handles duplicates/ensures.
- Update store/events.go query comments if new columns.
- Tests + green.
- Docs update.
- Commit (still on feature branch; owner decides merge).

## Phase 5: Docs, Analyze, Polish
- Full connector-guide.md + sensor-architecture.md + snr-improvement-plan.md updates (additive).
- Run claude (or equivalent) for final /speckit.analyze on artifacts + code; address any flagged constitution/scope drift.
- Update research/deep-dive-firewall-connectors.md if needed (read-only grounding).
- End-to-end manual test note (synthetic + one real UniFi gateway if available).
- PR ready (unimplemented beyond planning artifacts).

## Test Strategy (thin-slice, always green gate)
- Unit: collector Lua (if testable) or synthetic payload roundtrips in Go tests (faithful shape).
- Integration: backend router_test + store filters test with unifi-shaped events.
- Build/test: backend + sensor only (collector is sidecar).
- No main merge until full green + owner review (detection tuning stays on snr-tuning branch).

## Out of Scope for V1
- UniFi device import / REST client.
- Active scanning via UniFi.
- Exploit verification.
- Editing old migrations.
- New auth mechanisms.

Owner review required before any implementation begins. This PR is the complete planning artifact set.
