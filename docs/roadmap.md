# Vedetta Roadmap

> Last updated: 2026-07-03
> Status: Alpha / active development

## What Vedetta is today

Vedetta is an open-source, self-hosted security monitoring platform for homes and small businesses. The product is strongest today at two things:

- DNS-first visibility and detection
- device discovery and local network inventory

Vedetta is not a Pi-hole product, and it is not yet a plug-and-play consumer appliance. Core runs in Docker. A native sensor handles local network visibility. Pi-hole and AdGuard Home are optional integrations if you already run them.

## Current product shape

- **Vedetta Core** runs in Docker Compose and provides the API, dashboard, local storage, and ingestion pipeline.
- **Vedetta Sensor** runs natively on the network you want to watch. Today it supports macOS and Linux install paths and combines nmap-based discovery with passive DNS, ARP, DHCP, mDNS, and SSDP/UPnP visibility.
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** uses local abuse.ch-backed intelligence so the local product keeps value without cloud dependence.
- **EOL Router & Camera Risk Detection** — Detects specific end-of-life and vulnerable router and camera models listed in the [FBI IC3 FLASH 2026-03-12 advisory](https://www.ic3.gov/CSA/2026/260312.pdf) (AVrecon / SocksEscort) and applies elevated risk scoring when they exhibit suspicious behavior.
- **Device risk categories** classify inventory against primary sources: `known_exploited` (CISA KEV-listed gear), `eol_eos` (end-of-life/end-of-support), and `high_risk_iot`.
- **Optional DNS sources** include Pi-hole and AdGuard Home pollers.
- **Log ingestion pipeline** is live: `POST /api/v1/ingest` accepts single events, arrays, and Fluent Bit pair payloads, enriches them, and batch-inserts into local storage. Events are queryable via `GET /api/v1/events`, `/stats`, and `/timeline`. A Fluent Bit collector config with a UDP 5140 syslog input feeds the endpoint.
- **Router and firewall work** has started in code, with a connector framework and UniFi connector groundwork. Turning UniFi syslog into a complete, tuned workflow is specced ([specs/001-unifi-log-ingestion/](../specs/001-unifi-log-ingestion/spec.md)) but not yet claimed as supported.

## Spec-Driven Development

Vedetta has adopted the GitHub Spec Kit workflow: major features get a `spec.md` → `plan.md` → `tasks.md` under `specs/` before implementation, validated against the [project constitution](../.specify/memory/constitution.md). Current specs:

- [specs/001-unifi-log-ingestion/](../specs/001-unifi-log-ingestion/) — UniFi syslog as the first supported router/firewall source
- [specs/002-telemetry-service/](../specs/002-telemetry-service/) — opt-in, privacy-conscious telemetry service
- [specs/003-threat-network/](../specs/003-threat-network/) — optional community threat network
- [specs/004-passive-discovery-correlation/](../specs/004-passive-discovery-correlation/) — passive discovery correlation and labeling
- [specs/005-broader-firewall-connectors/](../specs/005-broader-firewall-connectors/) — OpenWRT, pfSense/OPNsense, MikroTik connectors

## Status Snapshot

### Available now

- Docker-based Core with local API, UI, and SQLite-backed storage
- Native sensor for active and passive device discovery plus passive DNS capture
- DNS-first threat scoring and local event enrichment
- Log ingestion pipeline: `POST /api/v1/ingest` (single / array / Fluent Bit pairs), events query API (`/api/v1/events`, `/stats`, `/timeline`), sequential migration runner with `schema_migrations` tracking, and a daily retention enforcer (90-day default)
- Device risk categories: `known_exploited`, `eol_eos`, and `high_risk_iot` classification on the device inventory
- Sensor actionability payloads: DNS events carry `dns_answers` and `server_ip`, device reports carry observed `services` and `discovery_source`, so alerts arrive with enough context to act on
- EOL Router & Camera Detection (FBI IC3 2026-03-12 advisory models)
- Optional Pi-hole integration
- Optional AdGuard Home integration
- Device inventory, scan targets, whitelist/suppression, and basic onboarding flow

### In progress

- Install and onboarding polish for alpha users
- Broader auth hardening, token rotation, and cleaner setup flow
- UniFi log ingestion as the first complete, tuned router/firewall workflow ([specs/001-unifi-log-ingestion/](../specs/001-unifi-log-ingestion/))
- Better public docs that separate shipped features from roadmap items

### Planned next

- Specced, not yet implemented (see [Spec-Driven Development](#spec-driven-development)):
  - Optional, privacy-conscious telemetry service (specs/002)
  - Optional community threat network (specs/003)
  - Passive discovery correlation, labeling, and multi-network handling (specs/004)
  - Broader router/firewall connectors: OpenWRT, pfSense/OPNsense, MikroTik (specs/005) — one source at a time, after UniFi is complete
- Better local DNS collection options for advanced deployments

## Required Vs Optional

### Required today

- Vedetta Core
- At least one native sensor on the network segment you want to inspect

### Optional today

- Pi-hole integration
- AdGuard Home integration
- UniFi connector experimentation
- Telemetry and community sharing

Pi-hole and AdGuard Home can add value if they are already part of your network. They are not required to make Vedetta useful, and they are not the product identity.

## Who Vedetta is for today

Vedetta currently fits best for:

- homelab users
- technical home users
- small businesses without a full SOC
- consultants, MSPs, and security practitioners helping very small environments

Vedetta is not yet positioned as a mass-market consumer appliance. The current install path still assumes comfort with Docker, a native sensor, local networking, and `sudo`.

## Privacy And Trust

- **Self-hosted first.** The local deployment should stand on its own.
- **Local value first.** Device discovery, DNS visibility, and local detections work without a cloud dependency.
- **Telemetry is optional.** The telemetry container is off by default and the current threat-network path is still future-facing.
- **Community sharing is not the core promise.** It is a roadmap direction, not the present-tense reason to adopt Vedetta.

## Known Product Limits

- The recommended Core path still uses Docker Compose.
- The sensor install path is currently oriented around macOS and Linux. Windows is not yet a supported public install path.
- Router and firewall coverage is not mature yet. The ingest pipeline and connector framework exist, and UniFi groundwork is in the repo, but no router/firewall source is a complete, tuned workflow yet (UniFi is specced in specs/001; broader connectors in specs/005).
- The threat-network and telemetry services are still stubs with TODOs. Their designs are specced (specs/002, specs/003) but they should be described as upcoming, not shipped.
- Sensor bearer auth is now in place for registration follow-up, device reports, DNS ingest, and work fetches. Broader dashboard/admin auth hardening is still incomplete, and public internet exposure remains unsupported.

## Near-Term Roadmap Themes

1. **Make the local product sharper on its own.**
   Better setup, better explanations, better device visibility, better DNS workflow coverage.
2. **Expand beyond DNS-only inputs.**
   Add router and firewall logs from gear people actually run.
3. **Harden the operating model.**
   Finish sensor authentication, improve trust boundaries, and make alpha deployment expectations explicit.
4. **Build the community layer carefully.**
   Keep it optional, privacy-conscious, and clearly secondary to local value.

## Near-Term Priorities

- tighten README and site messaging around the real product wedge
- document optional vs required integrations clearly
- improve alpha install guidance for Core plus native sensor
- move router/firewall work from "interesting code in repo" to honest experimental support
- finish the next round of dashboard/admin and sensor security hardening
