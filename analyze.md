# /speckit.analyze — UniFi Ingestion Planning Artifacts

**Generated**: 2026-06-11 (planning-only branch plan/unifi-ingestion)
**Method**: specify CLI not present in PATH (not native Grok/xAI integration in this environment). Claude Code (2.1.144) present at ~/.local/bin/claude but non-interactive -p requires login in this context (attempted; fell back to direct cross-check per "shell out" instruction and report which). Analysis performed against the four artifacts + constitution + explicit Stage 1 in-scope + Vedetta HARD RULES + current main state (post-pipeline merge + L5/L6).

## Summary
All artifacts are internally consistent, stay strictly within planning scope (no implementation, no UniFi code, STOP before any), and correctly elevate the Stage 1 finding (raw_log parse responsibility) and constitution constraints. V1 path recommendation (passive syslog + collector Lua normalization) aligns with passive-first and reuse of shipped /ingest + filters. Gating research correctly used CURRENT official Ubiquiti docs (CEF for SIEM/syslog Security/Firewall/IPS categories) and cites them; no CEF assumption in the "do not assume" sense — it is the documented format. No scope drift into V1 exclusions (full LAN scan, exploit verification, REST invention, old mig edits). Pi-4 / SNR / NEW mig only are first-class.

## Contradictions
- None found between spec/plan/tasks/constitution.
- The "where normalization happens" decision (collector Lua, Pi-hole consistency) is uniform across spec + plan + tasks + connector-guide note (existing).
- No conflict with existing pipeline (ingest map-lift, metadata for firewall details until optional future mig, auth reuse).

## Scope Drift
- None. The EXPLICIT IN-SCOPE from Stage 1 is called out verbatim in spec.md, plan.md, tasks.md, and connector-guide.md (to be updated in impl phase): "the connector layer must PARSE the vendor firewall log into the FirewallEvent fields (action/protocol/src-dst/ports/interface) so the PIECE 3 json_extract filters actually function — they're currently inert because the collector leaves details inside raw_log. Note pfSense/filterlog = positional CSV in raw_log; UniFi = its own format (verify). Spec must define WHERE this normalization happens — collector-side Lua (like pihole_transform.lua) vs handler-side — favoring consistency with the Pi-hole approach."
- V1 path is the passive syslog via existing Fluent Bit (not hybrid or new REST client).
- All references to "NEW migration file only, never edit 001/016" are consistent.
- SNR impact (high-volume low-severity UniFi block noise) and source="unifi" suppression location are explicit.

## Constitution Compliance
- Native L2 sensor / Docker Core split: respected (UniFi is connector/ingest only; no sensor changes).
- Pi-hole optional: yes (this is parallel to Pi-hole collector path).
- Passive-first: yes (syslog ingest via collector, not active UniFi API polling as primary).
- V1 excludes full LAN scan + exploit verification: explicit in spec + plan.
- Pi-4 floor: volume/backpressure/retention/SNR called out with SD longevity considerations.
- SNR ongoing: first-class in every artifact; suppression and source tagging required in Phase 3.
- Local-first/opt-in telemetry: no new cloud paths.
- Primary-source grounding: everything traces to UniFi export (CEF) → collector parse → /ingest → store → query.
- No contradictions with "primary-source grounding" or other bullets.

## Recommendations
- In implementation phase: add a faithful synthetic CEF payload test (modeled on the pipeline's TestHandleIngest_FirewallFieldsRoundtrip_FaithfulCollectorShape) and rename/comment honestly if using synthetic vs live UniFi output.
- Measure real volume from one gateway before widening categories (Pi-4 risk).
- After thin slice, run real-data SNR heartbeat on snr-tuning branch before widening.
- Keep analyze artifact updated if spec drifts during owner review.
- For the PR: title/body must state "Planning artifacts + PR only. No UniFi code. Awaiting review. Implements the Stage 1 raw_log parse in-scope for filters."

## Citations (gating research)
- https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration (CEF for all SIEM/syslog exports, Security category includes Firewall + Intrusion Prevention).
- Related: Advanced Logging (suricata internal), Traffic Flows (NetFlow/CSV/SIEM alternatives), community notes on CEF vs plain syslog evolution.

**Artifacts reviewed**: constitution.md, spec.md, plan.md, tasks.md (and cross-ref to main's connector-guide.md, research/deep-dive-firewall-connectors.md, existing fluent-bit + pihole_transform.lua, models Event/Device, ingest handler, filter tests).

No blockers for planning PR. Ready for owner review. Do not merge or implement.
