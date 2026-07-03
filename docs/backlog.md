# Vedetta Backlog

> Last updated: 2026-07-03
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
| VED-002 | Document and validate the current UniFi connector workflow | Connectors | P1 | Ready | Unassigned | Spec exists: [specs/001-unifi-log-ingestion/](../specs/001-unifi-log-ingestion/spec.md). Decide what can honestly be called experimental support vs in-progress groundwork |
| VED-003 | Write an alpha install and troubleshooting guide for Core + Sensor | Docs / DX | P1 | Ready | Unassigned | Keep install messaging aligned with the current Docker + native sensor reality |
| VED-004 | Decide whether to standardize repo and Go module naming | Repo / Build | P1 | Inbox | Unassigned | Public repo uses `MahdiHedhli/vedetta`, while code still uses `github.com/vedetta-network/...` imports |
| VED-005 | Define the first supportable router/firewall ingestion path | Connectors / PM | P1 | Ready | Unassigned | Decided: UniFi syslog first. Spec exists: [specs/001-unifi-log-ingestion/](../specs/001-unifi-log-ingestion/spec.md); broader connectors deferred to specs/005 |
| VED-007 | Move dashboard-facing sensor management routes under admin auth | Security / UI | P0 | Done (2026-04) | Grok (autonomous) | Added `RequireAdmin` middleware + protected `/sensor/list`, `/sensor/*/primary`, token mgmt, suppression, whitelist, scan targets, device writes, logs, etc. Frontend now has full admin token creation + recovery flow via localStorage + authFetch wrapper. |
| VED-008 | Build the opt-in threat-intel MVP contract and Cloudflare PoC | Threat Network / Security | P1 | Ready | Unassigned | Superseded by specs: design now lives in [specs/002-telemetry-service/](../specs/002-telemetry-service/spec.md) + [specs/003-threat-network/](../specs/003-threat-network/spec.md); keep export privacy-reduced, advisory-only, and off by default |
| VED-010 | Implement the opt-in telemetry service per spec 002 | Telemetry | P1 | Ready | Unassigned | `telemetry/cmd/telemetry/main.go` is a stub with TODOs; implement per [specs/002-telemetry-service/](../specs/002-telemetry-service/) — off by default, opt-in only |
| VED-011 | Implement the community threat network per spec 003 | Threat Network / Security | P1 | Ready | Unassigned | `threat-network/cmd/threat-network/main.go` is a stub with TODOs; implement per [specs/003-threat-network/](../specs/003-threat-network/) — depends on VED-010 groundwork |
| VED-012 | Implement passive discovery correlation per spec 004 | Sensor / Discovery | P1 | Ready | Unassigned | Correlate ARP/DHCP/mDNS/SSDP/DNS observations into unified device identities per [specs/004-passive-discovery-correlation/](../specs/004-passive-discovery-correlation/) |

## Done

| ID | Task | Completed | Notes |
| --- | --- | --- | --- |
| VED-000 | Align public site and README messaging with current product state | 2026-04-20 | Clarified DNS-first wedge, optional integrations, current install shape, and future-facing threat-network positioning |
| VED-001 | Finish end-to-end sensor authentication flow | 2026-04-21 | Sensor bootstrap now returns a one-time `auth_token`, the sensor persists it locally, and later device/DNS/work calls require bearer auth |
| VED-006 | Expand passive discovery beyond current DNS capture and nmap scanning | 2026-04-21 | Sensor now captures ARP, DHCP, mDNS, and SSDP/UPnP observations and batches them back to Core as device reports |
| VED-009 | Add EOL router & camera risk detection (IC3 2026-03-12 AVrecon models) | 2026-05 | Fingerprinting, device flagging (`eol_risk`), scoring boost, UI badges, and context-aware suppression for known high-risk EOL devices |
| — | Ship the core log ingestion pipeline | 2026-03-30 | `POST /api/v1/ingest` (single / array / Fluent Bit pairs, enrichment, batch insert), events query API (`/events`, `/stats`, `/timeline`), sequential migration runner with `schema_migrations` tracking, daily 90-day retention enforcer; landed in commit `1386964`, hardened in later SNR work |
| — | Device risk categories + sensor actionability payloads | 2026-07-03 | `known_exploited` / `eol_eos` / `high_risk_iot` device classification (migration 016) plus richer sensor payloads (`dns_answers`, `server_ip`, `services`, `discovery_source`); commit `5756864` |
