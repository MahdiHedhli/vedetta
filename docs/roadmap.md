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
- **Vedetta Sensor** runs natively on the network you want to watch, with install paths for macOS, Linux, and Windows. On macOS/Linux it combines nmap-based discovery with passive DNS, ARP, DHCP, mDNS, and SSDP/UPnP visibility; the Windows sensor is driver-free and host-scoped in v1 (DNS via ETW, native ICMP/ARP discovery, no Npcap/nmap).
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** uses local abuse.ch-backed intelligence so the local product keeps value without cloud dependence.
- **EOL Router & Camera Risk Detection** — Detects specific end-of-life and vulnerable router and camera models listed in the [FBI IC3 FLASH 2026-03-12 advisory](https://www.ic3.gov/CSA/2026/260312.pdf) (AVrecon / SocksEscort) and applies elevated risk scoring when they exhibit suspicious behavior.
- **Optional DNS sources** include Pi-hole and AdGuard Home pollers.
- **Router and firewall work** has started in code, with a connector framework and UniFi connector groundwork, but broader coverage is still roadmap work.

## Status Snapshot

Major features are now developed spec-first under [`specs/`](../specs/), validated
against the [project constitution](../.specify/memory/constitution.md).

### Available now

- Docker-based Core with local API, UI, and SQLite-backed storage
- Native sensor for active and passive device discovery plus passive DNS capture
- Log ingestion pipeline (`POST /api/v1/ingest` + events query API + retention enforcer)
- DNS-first threat scoring and local event enrichment
- EOL Router & Camera Detection (FBI IC3 2026-03-12 advisory models) plus device risk categories (`known_exploited` / `eol_eos` / `high_risk_iot`)
- **UniFi log ingestion** ([specs/001](../specs/001-unifi-log-ingestion/)): collector CEF/syslog parser → `firewall_log` events, firewall-aware scoring, seeded noise suppression, optional REST connector, UI filters — syslog path implemented, live SNR validation pending
- **Passive discovery correlation** ([specs/004](../specs/004-passive-discovery-correlation/)): multi-signal identity resolution surviving DHCP churn, confidence-weighted provenance, mDNS record-graph parsing, per-device display name, multi-segment attachments
- Passive sensor actionability payloads (`dns_answers`, `server_ip`, `services`, `discovery_source`)
- Optional Pi-hole integration
- Optional AdGuard Home integration
- Device inventory, scan targets, whitelist/suppression, and basic onboarding flow

### On by default (opt-out)

- **Telemetry service** ([specs/002](../specs/002-telemetry-service/)): **on by default, opt-out** (`VEDETTA_TELEMETRY_OPTIN=false`, or the dashboard telemetry toggle, disables it; a first-run banner discloses it); source IPs, MACs, and hostnames are stripped at the source, aggregate-only signed export.
- **Community threat network** ([specs/003](../specs/003-threat-network/)): implemented advisory-only community feed with reporter-consensus confidence and abuse resistance.

### In progress

- Install and onboarding polish for alpha users
- Broader auth hardening, token rotation, and cleaner setup flow
- Live SNR / operational validation of the newly implemented UniFi source on real deployments before it is labelled "supported"
- Better public docs that separate shipped features from roadmap items

### Planned next

- Broader router/firewall connectors: OpenWRT, pfSense/OPNsense, MikroTik ([specs/005](../specs/005-broader-firewall-connectors/)) — one source at a time, after UniFi is validated on real hardware
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
- **Telemetry is on by default and opt-out** (`VEDETTA_TELEMETRY_OPTIN=false` or the dashboard telemetry toggle); it strips source IPs, MACs, and hostnames at the source and exports only aggregate, advisory-only signals.
- **Community sharing is not the core promise.** The community threat network is implemented and advisory-only, but it is a secondary layer, not the present-tense reason to adopt Vedetta.

## Known Product Limits

- The recommended Core path still uses Docker Compose.
- The sensor has native install paths for macOS, Linux, and Windows (`install.sh` / `install.ps1`). The Windows sensor is host-scoped in v1 (DNS via ETW, native ICMP/ARP discovery, no Npcap/nmap); segment-wide L2 capture via optional Npcap remains a later, never-required tier.
- Router and firewall coverage is still maturing. UniFi log ingestion is implemented (specs/001) but has not completed the live ≥72h SNR validation on real hardware, so it is not yet labelled fully "supported"; broader connectors remain specced-only (specs/005).
- Telemetry and the community threat network are implemented (specs/002, specs/003) and on by default (opt-out via `VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle); the shared feed is advisory-only. The Core-side consumer that pulls community intel back into local scoring is specced but not yet wired.
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
