# Vedetta Architecture

> Last updated: 2026-07-03
> Version: 0.1.0-dev
>
> Reference document describing the system as implemented. Planned work is marked
> explicitly and cross-referenced to its spec under `specs/`. Governance:
> `.specify/memory/constitution.md`.

## Overview

Vedetta is a self-hosted, AGPLv3 security monitoring platform built around one
foundational split:

- **Core** runs in Docker Compose and stores, enriches, scores, and presents data.
- **Sensor** (`vedetta-sensor`) runs as a native binary on the host OS of the network
  being watched.

The split is a hard constraint, not a convenience: Docker cannot provide full host
network stack fidelity (raw sockets, ARP, passive sniffing) on macOS/Windows — only
Linux `--network=host` works reliably. Every L2-visibility feature (discovery,
passive DNS/ARP/DHCP/mDNS/SSDP) depends on the native sensor.

Design priorities (see constitution): passive-first (zero gateway cooperation
required), Pi-hole/AdGuard strictly optional inputs, local value first, Raspberry
Pi 4 hardware floor.

## Core + Sensor Model

```text
LAN / WLAN
   |
   |  passive DNS capture, passive ARP/DHCP/mDNS/SSDP, active nmap discovery
   v
vedetta-sensor (native binary; macOS/Linux today)
   |
   |  HTTP: POST /api/v1/sensor/devices, /sensor/dns  (sensor-scoped token)
   |        GET  /api/v1/sensor/work                  (scan job pickup)
   v
vedetta-core (Docker Compose)
   |- backend        API, enrichment, fingerprinting, SQLite storage
   |- frontend       dashboard UI
   |- collector      Fluent Bit: syslog UDP 5140 + Pi-hole tail -> /api/v1/ingest
   |- telemetry      STUB (spec: specs/002-telemetry-service/spec.md)
   `- threat-network STUB (spec: specs/003-threat-network/spec.md)
```

## Ingestion Pipeline (shipped)

The general-purpose log path, end to end:

1. **Inputs (collector, Fluent Bit)** — `collector/config/fluent-bit.conf`:
   - `syslog` input listening on **UDP 5140** (RFC 3164 parser) for router/firewall
     logs; a `modify` filter tags records `event_type=firewall_log` and maps
     `host`→`source_hash`, `message`→`raw_log`.
   - `tail` input on the Pi-hole log (optional source) transformed to the Vedetta
     Event schema by a Lua filter (`pihole_transform.lua`).
2. **HTTP output → Core** — Fluent Bit posts JSON to `POST /api/v1/ingest` on the
   backend.
3. **Ingest endpoint** — `backend/internal/api/router.go` (`handleIngest`):
   - Accepts a single event object, an array of events, or Fluent Bit's
     `[timestamp, record]` pair format. Body capped at 10 MB.
   - Validates `event_type` against an allowlist (`dns_query`, `dns_blocked`,
     `encrypted_dns_detected`, `nmap_discovery`, `firewall_log`, `anomaly`);
     rejected events are counted, not fatal.
   - Fills defaults: `event_id` (UUID), `timestamp` (now UTC), `source_hash`
     (`unknown`), `network_segment` (`default`); clamps `anomaly_score` to [0,1].
4. **Enrichment** — each accepted event runs through the DNS-intel enricher
   (`backend/internal/dnsintel/enricher.go`): local threat-intel matching plus the
   DNS detectors (DGA patterns, beaconing, tunneling, rebinding, bypass/public
   resolvers).
5. **Storage** — batch insert via `InsertEvents` (`backend/internal/store/events.go`)
   into SQLite.
6. **Retention** — `backend/internal/store/retention.go` runs a daily background
   enforcer (once at startup, then every 24 h) deleting events older than the
   configured window (**90 days default**, `retention_config` table).

Query side: `GET /api/v1/events`, `/events/stats`, and `/events/timeline` serve the
dashboard, plus a CSV export path that flattens metadata fields such as
`dns_answers` and `server_ip`.

## Sensor Data Paths (shipped)

Sensor pushes are authenticated with least-privilege sensor-scoped tokens
(`RequireStrictAuth` + `RequireExactScope(sensor)`); registration
(`POST /api/v1/sensor/register`) is IP rate-limited.

### Passive DNS capture (`sensor/internal/dnscap/`)

Captures plaintext DNS on a chosen interface and ships queries to
`POST /api/v1/sensor/dns` with actionability fields added in migration 017:

- `server_ip` — which DNS resolver was queried/answered (e.g. `192.0.2.53`).
- `answers` — resolved IPs/CNAME targets extracted from answer records. Core stores
  them as `dns_answers` in event metadata and promotes the first answer to
  `resolved_ip`, so an analyst can see the actual destination behind a query.

### Discovery (`sensor/internal/netscan/`, `sensor/internal/passive/`)

Device reports to `POST /api/v1/sensor/devices` carry:

- `services` — service names observed for the device (for actionability).
- `discovery_source` — how the device was seen: `nmap_active` (backend canonical)
  or `passive_arp`, `passive_dhcp`, `passive_mdns`, `passive_ssdp` from the passive
  parsers. Active nmap scanning is complementary to the passive paths, never a
  replacement.

The sensor also polls `GET /api/v1/sensor/work` to execute scan targets defined in
Core.

## Device Fingerprinting & Risk Categorization (shipped)

`backend/internal/fingerprint/` (engine.go, eol.go, oui.go, hostname.go) fingerprints
devices from OUI/hostname/service evidence and assigns a `risk_category`
(migration 016, `siem/migrations/016_device_risk_categories.sql`):

| Category | Meaning | Grounding |
| --- | --- | --- |
| `known_exploited` | Models named in an active-campaign advisory | IC3 FLASH 2026-03-12 AVrecon/SocksEscort model list (these are also EOL) |
| `eol_eos` | End-of-life / end-of-support, no active-campaign evidence | EOL router signatures (migration 015, `eol_risk`/`eol_model`) |
| `high_risk_iot` | Weak-default camera/IoT vendor lines, rarely patched firmware | Vendor-line signatures plus a fallback classification for unmatched cameras |

Categorization only upgrades a device's risk fields; it never overwrites an existing
category with a weaker one.

## Storage & Migrations

- SQLite, single local database owned by the backend.
- Sequential migration runner (`backend/internal/store/db.go`): applies
  `siem/migrations/NNN_*.sql` in order and records each in a `schema_migrations`
  table. **17 migrations** as of this writing (001_init through
  017_sensor_actionability).
- Rule (constitution): every schema change is a NEW sequential migration; committed
  migrations are never edited.
- Schema reference: `docs/schema.md`.

## Connectors (partial)

`backend/internal/firewall/` contains the connector framework (`connector.go`,
`manager.go`) and UniFi connector groundwork (`unifi.go`). The complete, SNR-tuned
UniFi log ingestion workflow is specified in `specs/001-unifi-log-ingestion/spec.md`
and lands as one full workflow before the next connector starts (one data source at
a time). Broader firewall connectors (OpenWRT, pfSense/OPNsense, MikroTik) are
planned: `specs/005-broader-firewall-connectors/spec.md`. Until then, generic
firewall syslog arrives via the collector's UDP 5140 path described above.

## Planned Services (stubs — do not describe as shipped)

| Service | Current state | Spec |
| --- | --- | --- |
| `telemetry` | `telemetry/cmd/telemetry/main.go` is a stub (TODO: batch reader, PII stripper, transmitter). Opt-in, off by default by design. | `specs/002-telemetry-service/spec.md` |
| `threat-network` | `threat-network/cmd/threat-network/main.go` is a stub (TODO: validate/deduplicate/store batches). Community intelligence backend. | `specs/003-threat-network/spec.md` |

Passive discovery correlation work is specified in
`specs/004-passive-discovery-correlation/spec.md`.

## Auth Model (Alpha)

Bearer tokens with two scopes:

- `admin` — human operators via the dashboard (`POST /api/v1/auth/tokens`).
- `sensor` — least-privilege machine tokens, auto-minted at sensor registration.

**Bootstrap mode:** while zero tokens exist, most routes are open for first-run
setup. Once the first admin token exists, `RequireAdmin` protects management routes
(device writes, ack/suppression, whitelist, scanning, token management, sensor
management). Sensor ingest paths always require a valid sensor-scoped token. See
`backend/internal/auth/middleware.go` and `docs/auth-hardening-plan.md`.

## Deployment Reality & Limits

- Alpha software. LAN-first; public internet exposure is not a supported operating
  model yet.
- Core: Docker Compose. Sensor: native install, elevated privileges for full
  visibility. Windows sensor is not a supported public install story yet.
- Hardware floor: Raspberry Pi 4; idle budget target <200 MB RAM, <5% CPU on core
  paths.
- Ingest hard limits: 10 MB request body, event-type allowlist; malformed entries in
  a batch are dropped individually rather than failing the batch.

## Signal-to-Noise Discipline

SNR tuning is ongoing, not a one-time gate: every new data source re-opens
suppression, whitelisting, and scoring work before that source is called supported.
Shipped controls: suppression rules, known-traffic whitelist (with seeding), event
acknowledgment, device risk context in the fingerprint engine. History and current
work: `docs/snr-improvement-plan.md`, `docs/SNR-IMPROVEMENTS.md`.

## Privacy & Trust

- Local deployment is the product; it must stay useful with no cloud dependency.
- Telemetry and community sharing are optional, opt-in, and privacy-conscious —
  and currently unimplemented stubs (see table above).
- All tracked docs use documentation-reserved values only (RFC 5737 IPs such as
  `192.0.2.x`, example MACs `00:00:5E:00:53:xx`); real environment data never enters
  the tracked tree.
