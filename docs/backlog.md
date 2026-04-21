# Vedetta Backlog

> Last updated: 2026-04-21
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
| VED-002 | Document and validate the current UniFi connector workflow | Connectors | P1 | Ready | Unassigned | Decide what can honestly be called experimental support vs in-progress groundwork |
| VED-003 | Write an alpha install and troubleshooting guide for Core + Sensor | Docs / DX | P1 | Ready | Unassigned | Keep install messaging aligned with the current Docker + native sensor reality |
| VED-004 | Decide whether to standardize repo and Go module naming | Repo / Build | P1 | Inbox | Unassigned | Public repo uses `MahdiHedhli/vedetta`, while code still uses `github.com/vedetta-network/...` imports |
| VED-005 | Define the first supportable router/firewall ingestion path | Connectors / PM | P1 | Inbox | Unassigned | Likely starts with UniFi or pfSense/OPNsense before broader connector claims |
| VED-007 | Move dashboard-facing sensor management routes under admin auth | Security / UI | P0 | Ready | Unassigned | `/api/v1/sensor/list` and `PUT /api/v1/sensor/{id}/primary` still rely on the broader dashboard auth rollout |

## Done

| ID | Task | Completed | Notes |
| --- | --- | --- | --- |
| VED-000 | Align public site and README messaging with current product state | 2026-04-20 | Clarified DNS-first wedge, optional integrations, current install shape, and future-facing threat-network positioning |
| VED-001 | Finish end-to-end sensor authentication flow | 2026-04-21 | Sensor bootstrap now returns a one-time `auth_token`, the sensor persists it locally, and later device/DNS/work calls require bearer auth |
| VED-006 | Expand passive discovery beyond current DNS capture and nmap scanning | 2026-04-21 | Sensor now captures ARP, DHCP, mDNS, and SSDP/UPnP observations and batches them back to Core as device reports |
