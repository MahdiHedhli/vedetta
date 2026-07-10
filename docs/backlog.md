# Vedetta Backlog

> Last updated: 2026-05-19
> Purpose: day-to-day project management, task assignment, and working coordination

This document is the working task tracker for Vedetta. It is intentionally different from the product roadmap:

- [roadmap.md](roadmap.md) explains product direction and broad status
- `backlog.md` tracks actionable work, ownership, and movement

## How To Use This File

- Add new ideas and loose work to `Inbox`
- Move scoped, ready work to `Ready`
- Give each active task one clear owner
- Use `Blocked` when progress depends on a decision, dependency, or outside input
- Move finished work to `Done` with the completion date

## Status Values

| Status | Meaning |
| --- | --- |
| `Inbox` | Captured, but not yet shaped into ready work |
| `Ready` | Clear enough to pick up |
| `In Progress` | Actively being worked |
| `Blocked` | Waiting on something external or unresolved |
| `Done` | Completed and no longer active |

## Priority Values

| Priority | Meaning |
| --- | --- |
| `P0` | Security-critical or release-blocking |
| `P1` | Important near-term work |
| `P2` | Normal priority |
| `P3` | Nice to have / later |

## Active Backlog

| ID | Task | Area | Priority | Status | Owner | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| VED-003 | Write an alpha install and troubleshooting guide for Core + Sensor | Docs / DX | P1 | Ready | Unassigned | Keep install messaging aligned with the current Docker + native sensor reality |
| VED-004 | Decide whether to standardize repo and Go module naming | Repo / Build | P1 | Inbox | Unassigned | Public repo uses `MahdiHedhli/vedetta`, while code still uses `github.com/vedetta-network/...` imports |
| VED-015 | Fix broken fresh-install migration runner (was: fails at 009) | Schema / Bug | P0 | Done | — | **Resolved (commit `ac8a96b`).** `001_init.sql` now ships the final 19-column events schema and `009_event_type_encrypted_dns.sql` was reworked to recreate `events` with the explicit final schema and copy rows via an explicit shared column list (works from both the 14-column legacy and 19-column fresh shapes); migration 020 repairs correlation FKs. The fresh-install chain (001..023) now runs clean end-to-end and a real-runner regression test was added. Fresh production Docker Core installs are no longer affected. |
| VED-013 | Relax `devices.segment` / `events.network_segment` CHECK to allow arbitrary segment names | Schema / Bug | P1 | Ready | Unassigned | Migration 001 pins `CHECK (segment IN ('default','iot','guest'))`, but UniFi ingestion and multi-network correlation now write other segment names — real migrations would reject the write. Tests miss it (inline fallback has no CHECK). Add a migration to relax it + a real-migration-chain test |
| VED-014 | Live validation passes for the newly implemented sources | Validation | P1 | Ready (owner, local-only) | Unassigned | UniFi ≥72h SNR pass (spec 001 T5.2), telemetry 72h dry-run (spec 002), threat-network operational check (spec 003), correlation ≥48h soak (spec 004 T5.2) — all require the owner's real environment; raw data stays gitignored per constitution |

## Done

| ID | Task | Completed | Notes |
| --- | --- | --- | --- |
| VED-000 | Align public site and README messaging with current product state | 2026-04-20 | Clarified DNS-first wedge, optional integrations, current install shape, and future-facing threat-network positioning |
| VED-007 | Move dashboard-facing sensor management routes under admin auth | 2026-04 | `RequireAdmin` middleware protecting sensor mgmt, token, suppression, whitelist, scan-target, device-write, and log routes; frontend admin token creation + recovery flow |
| VED-002 | Document and validate the UniFi connector workflow | 2026-07-03 | Implemented per [specs/001](../specs/001-unifi-log-ingestion/): collector CEF/syslog parser, `firewall_log` enrichment/scoring, seeded noise suppression, optional REST connector, UI filters, [docs/connectors/unifi.md](connectors/unifi.md). Live ≥72h SNR validation → VED-014 |
| VED-005 | Define the first supportable router/firewall ingestion path | 2026-07-03 | Decided + implemented: UniFi syslog first (specs/001); broader connectors deferred to specs/005. Live validation → VED-014 |
| VED-008 | Opt-in threat-intel MVP contract | 2026-07-03 | Superseded and delivered via [specs/002](../specs/002-telemetry-service/) + [specs/003](../specs/003-threat-network/); privacy-reduced, advisory-only, off by default at delivery (default later flipped to on/opt-out via issue #37) |
| VED-010 | Implement the opt-in telemetry service (spec 002) | 2026-07-03 | Off unless `VEDETTA_TELEMETRY_OPTIN=true` at delivery (default later flipped to on/opt-out via issue #37), structural PII stripping, aggregate-only signed export, bounded spool + backoff, cross-service contract tests. Operational dry-run → VED-014 |
| VED-011 | Implement the community threat network (spec 003) | 2026-07-03 | Signed reporter ingest, idempotent per-reporter batches, whole-batch privacy/schema re-gate, consensus over distinct matured reporter credentials (advisory-only, not a proof of reporter independence), advisory-only feed, swept rate limiter. Operational check → VED-014 |
| VED-012 | Implement passive discovery correlation (spec 004) | 2026-07-03 | Multi-signal identity resolver surviving DHCP churn (MAC-conflict veto), confidence-weighted provenance (migration 018), mDNS record-graph parsing + PTR fix, display_name, multi-segment attachments. Live ≥48h soak → VED-014 |
| VED-001 | Finish end-to-end sensor authentication flow | 2026-04-21 | Sensor bootstrap now returns a one-time `auth_token`, the sensor persists it locally, and later device/DNS/work calls require bearer auth |
| VED-006 | Expand passive discovery beyond current DNS capture and nmap scanning | 2026-04-21 | Sensor now captures ARP, DHCP, mDNS, and SSDP/UPnP observations and batches them back to Core as device reports |
| VED-009 | Add EOL router & camera risk detection (IC3 2026-03-12 AVrecon models) | 2026-05 | Fingerprinting, device flagging (`eol_risk`), scoring boost, UI badges, and context-aware suppression for known high-risk EOL devices |
