# Vedetta Architecture

> Last updated: 2026-07-12
> Version: public beta

## Overview

Vedetta is a self-hosted security monitoring platform built around a simple split:

- **Core** runs in Docker and stores, scores, and presents data
- **Sensor** runs natively on the network you want to inspect

That split matters because the strongest current Vedetta workflows depend on local network access. Containers alone are not enough on macOS or Windows to see the network with the fidelity Vedetta needs.

Vedetta today is best described as:

- DNS-first security monitoring
- device discovery and local visibility
- optional DNS and network-source integrations
- privacy-respecting, self-hosted first

## Core + Sensor Model

```text
LAN / WLAN
   |
   |  passive DNS capture, device discovery
   v
vedetta-sensor (native, macOS/Linux/Windows)
   |
   |  HTTP API
   v
vedetta-core (Docker Compose)
   |- backend
   |- frontend
   |- collector
   |- telemetry (on by default; opt-out)
   |- public community-feed consumer (on by default; independently disableable)
   `- local SQLite events, assets, evidence, and findings
```

### Why the split exists

- Docker on macOS and Windows runs inside a VM and does not get true host-network visibility by default.
- Device discovery and packet capture are more reliable from a native process with direct interface access.
- Core can still run a built-in scanner on suitable Linux hosts, but the native sensor is the primary design.

## What Core Does Today

- receives device and DNS data from sensors
- normalizes every production event source through one processing pipeline
- resolves event-time stable device identity from temporal network evidence
- evaluates local and advisory threat intelligence plus deterministic detectors
- stores immutable raw events/evidence and durable actionable findings
- exposes the UI and API
- manages scan targets, suppression rules, and whitelist rules

### Core services

| Service | Purpose | Status |
| --- | --- | --- |
| `backend` | API, event enrichment, device/event storage | shipped |
| `frontend` | findings-first operator dashboard and raw-event drill-down | shipped |
| `collector` | syslog and normalized log ingestion path | shipped, limited public workflows today |
| `telemetry` | privacy-reduced community sharing | implemented, **on by default** (opt out: `VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle) |
| `threat-network` | community intelligence backend | implemented, advisory-only, runs off-node ([ops doc](threat-network-operations.md)) |

## What the Sensor Does Today

- runs active network discovery with `nmap`
- captures plaintext DNS traffic passively on a chosen interface
- pushes device and DNS events back to Core
- executes scan targets defined in Core

### Supported sensor reality today

- **Public install path:** macOS, Linux, and Windows (`install.sh` / `install.ps1`)
- **Current workflow:** native install, local network access, and elevated privileges for the strongest visibility
- **Windows:** a native, driver-free sensor — DNS via the `Microsoft-Windows-DNS-Client` ETW provider and discovery via native ICMP/ARP (no Npcap, no nmap), running as a LocalSystem service. v1 is host-scoped (this machine's DNS); segment-wide L2 capture via optional Npcap is a later, never-required tier. Core also runs under Docker (Desktop/WSL2).

## Data Sources

### Available now

- passive DNS capture from the native sensor
- Pi-hole polling
- AdGuard Home polling
- UniFi syslog/CEF ingestion and an optional direct REST connector (live SNR validation pending)
- curated local threat-intel feeds and the advisory Vedetta community snapshot

### Planned next

- OpenWRT connector
- pfSense / OPNsense ingestion
- MikroTik connector
- more passive discovery sources such as ARP, DHCP, mDNS, and SSDP
- additional local DNS collection modes for advanced users

## Detection Pipeline And Findings

Sensor DNS, Pi-hole, AdGuard, generic collector/syslog, and direct UniFi REST
events all converge on one server-side processor. It:

1. normalizes the event and extracts typed observables;
2. resolves a stable device using identity evidence valid at the event timestamp;
3. evaluates threat intelligence and deterministic detectors;
4. applies device/benign context and suppression without erasing evidence;
5. calculates priority once; and
6. atomically stores the raw event, exact typed evidence, and finding updates.

Missing source IDs are derived deterministically, so adapter retries do not inflate
raw-event or finding counts. Events preserve the source-reported enforcement
semantics as `blocked`, `allowed`, or `observed`; absent enforcement is not called
allowed.

The backend includes detectors for:

- DGA-like domain patterns
- beaconing behavior
- DNS tunneling patterns
- DNS rebinding
- DNS bypass and public-resolver use

High-confidence IOC/IPS evidence is evaluated before allowlist or device context.
The community snapshot is consumed every 15 minutes by default, but community
matches are advisory/corroborating only and cannot independently create or raise
a finding. Findings aggregate recurrence by stable device, explicit detector, and
normalized observable; Raw Events remains the immutable evidence surface.

Telemetry contribution and community-feed consumption are independent controls:
`VEDETTA_TELEMETRY_OPTIN=false` stops contributions, while
`VEDETTA_COMMUNITY_FEED_ENABLED=false` stops public snapshot downloads. Local
detection works without either. See
[threat-network-operations.md](threat-network-operations.md).

## Deployment Reality

Vedetta is public beta software. Public docs should reflect the real install shape:

- Core uses Docker Compose
- the sensor is a native install
- the sensor setup still assumes some networking comfort
- `sudo` or equivalent privileges are part of the current story for strong local visibility

That makes Vedetta a good fit today for homelabs, technical home users, consultants, MSPs, and small businesses that want practical visibility without standing up a full SOC stack.

## Privacy And Trust

- the local deployment is the primary product
- the local deployment should stay useful even with no cloud dependency
- telemetry is on by default and opt-out (`VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle, with a versioned, browser-origin-local first-run acknowledgement dialog), and the shared feed is advisory-only
- community sharing is **privacy-reduced and pseudonymous, not anonymous**: beta signals contain the matched public block-list domain/eTLD+1, hourly event bucket, observation/distinct-asset/blocked counts, local confidence/fixed reasons, random IDs, and batch/window timing; registration sends a random install UUID, version, and capability names. Internal/device IPs, MACs, hostnames, raw queries, and the local distinct-count HMAC are not serialized. The server does not retain the install UUID, but its stable `reporter_id` links signal rows and exact receipt/merge/last-seen timing; signal rows and receipts expire after 30 days, while reporter/counter/derived-record expiry is incomplete. Cloudflare sees the public connection source/timing, and the service transiently uses that public address as an in-memory rate-limit key until swept after 30 idle minutes (not SQLite/application logs). Query-derived candidate/behavior signals remain disabled for beta (see [PRIVACY.md](../PRIVACY.md) and [specs/003-threat-network/anonymization-proof.md](../specs/003-threat-network/anonymization-proof.md)); opting out is trivial

## Auth Model (Public Beta)

Vedetta uses scoped bearer tokens:

- `admin` — management and all reads
- `read` — dashboard/query reads only
- `sensor` — exact-scope native sensor work and ingest routes
- `ingest` — collector event submission

The first admin is created with a single-use setup code. Sensor registration is
admin-first and requires a short-lived enrollment code; existing identities require
a reset code bound to that sensor. There is no unauthenticated sensor-enrollment
bootstrap.

Read routes remain bootstrap-open only until an active admin exists. Sensor ingest
always requires an exact sensor token; management writes require admin; a read token
cannot write or submit collector events.

See `backend/internal/auth/middleware.go` (`RequireAdmin`, `RequireAuth`) and the implementation plan in `docs/auth-hardening-plan.md`.

## Security Status

Core binds to host loopback by default. Remote access should use the documented TLS
reverse proxy; changing the Compose binding to LAN-wide plaintext HTTP is an explicit
operator choice. The community feed is advisory because anonymous reporter consensus
cannot fully solve Sybil trust. Neither the feed nor telemetry is a dependency for
local detection.

## Public Positioning Notes

When describing Vedetta externally, keep these boundaries clear:

- Vedetta is **not** a Pi-hole companion product, though it can integrate with Pi-hole.
- Vedetta's community feed is **advisory**, not authoritative threat verdicting.
- Vedetta is **not** yet a consumer plug-and-play box.
- Vedetta **is** a practical self-hosted watchtower for DNS-first monitoring and network visibility.
