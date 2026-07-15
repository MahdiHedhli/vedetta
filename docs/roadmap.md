# Vedetta Roadmap

> Last updated: 2026-07-12
> Status: Public beta / active development

## What Vedetta is today

Vedetta is an open-source, self-hosted security monitoring platform for homes and small businesses. The product is strongest today at two things:

- DNS-first visibility and detection
- device discovery and local network inventory

Vedetta is not a Pi-hole product, and it is not yet a plug-and-play consumer appliance. Core runs in Docker. A native sensor handles local network visibility. Pi-hole and AdGuard Home are optional integrations if you already run them.

## Current product shape

- **Vedetta Core** runs in Docker Compose and provides the API, dashboard, local storage, and ingestion pipeline.
- **Vedetta Sensor** runs natively on the network you want to watch, with install paths for macOS, Linux, and Windows. On macOS/Linux it combines nmap-based discovery with passive DNS, ARP, DHCP, mDNS, and SSDP/UPnP visibility; the Windows sensor is driver-free and host-scoped in v1 (DNS via ETW, native ICMP/ARP discovery, no Npcap/nmap).
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** uses curated local intelligence plus an advisory community snapshot; either cloud-facing control can be disabled without losing local detection.
- **EOL Router & Camera Risk Detection** — Detects specific end-of-life and vulnerable router and camera models listed in the [FBI IC3 FLASH 2026-03-12 advisory](https://www.ic3.gov/CSA/2026/260312.pdf) (AVrecon / SocksEscort) and applies elevated risk scoring when they exhibit suspicious behavior.
- **Optional DNS sources** include Pi-hole and AdGuard Home pollers.
- **UniFi firewall ingestion** is implemented through syslog/CEF and an optional REST connector; live SNR validation and broader vendor coverage remain roadmap work.

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
- **Asset-centered findings** ([specs/007](../specs/007-asset-centered-findings/)): temporal device identity, one replay-safe processor across all production event sources, durable evidence-linked findings, lifecycle/suppression, collection/feed health, and a findings-first dashboard
- Passive sensor actionability payloads (`dns_answers`, `server_ip`, `services`, `discovery_source`)
- Optional Pi-hole integration
- Optional AdGuard Home integration
- Device inventory, scan targets, whitelist/suppression, and basic onboarding flow

### Community defaults (independent controls)

- **Telemetry service** ([specs/002](../specs/002-telemetry-service/)): **on by default, opt-out** (`VEDETTA_TELEMETRY_OPTIN=false`, or the dashboard telemetry toggle, disables it; a versioned first-run acknowledgement dialog discloses the effective state). Beta exports are allowlisted, pseudonymous records: matched public block-list domain/eTLD+1, hourly event bucket, counts, local confidence/fixed reasons, signal/batch IDs, timing/schema metadata, plus reporter registration/version/capabilities. Internal/device IPs, MACs, hostnames, raw queries, and per-asset hashes are not serialized; see [PRIVACY.md](../PRIVACY.md) for server linkage and retention.
- **Community threat network** ([specs/003](../specs/003-threat-network/)): implemented advisory-only community feed with reporter-consensus confidence and abuse resistance.
- **Core feed consumption** is on by default and independently disabled with `VEDETTA_COMMUNITY_FEED_ENABLED=false`; community evidence is corroborating only and cannot independently create or raise a finding.

### In progress

- Install and onboarding polish for public beta users
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
- Telemetry contribution and public community-feed consumption (independent opt-outs)

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
- **Telemetry is on by default and opt-out** (`VEDETTA_TELEMETRY_OPTIN=false` or the dashboard telemetry toggle); beta exports are allowlisted pseudonymous known-bad records with domain/eTLD+1, hourly event bucket, counts, confidence/fixed reasons, IDs, and timing/schema/registration metadata. Internal/device IPs, MACs, hostnames, raw queries, and per-asset hashes are not serialized; [PRIVACY.md](../PRIVACY.md) documents server linkage and retention.
- **Community sharing is not the core promise.** The community threat network is implemented and advisory-only, but it is a secondary layer, not the present-tense reason to adopt Vedetta.

## Known Product Limits

- The recommended Core path still uses Docker Compose.
- The sensor has native install paths for macOS, Linux, and Windows (`install.sh` / `install.ps1`). The Windows sensor is host-scoped in v1 (DNS via ETW, native ICMP/ARP discovery, no Npcap/nmap); segment-wide L2 capture via optional Npcap remains a later, never-required tier.
- Router and firewall coverage is still maturing. UniFi log ingestion is implemented (specs/001) but has not completed the live ≥72h SNR validation on real hardware, so it is not yet labelled fully "supported"; broader connectors remain specced-only (specs/005).
- Telemetry contribution is on by default (opt out via `VEDETTA_TELEMETRY_OPTIN=false` or the dashboard toggle). Core separately consumes the public snapshot every 15 minutes as advisory/corroborating evidence only; `VEDETTA_COMMUNITY_FEED_ENABLED=false` disables that download.
- Scoped bearer auth and admin-first sensor enrollment are in place. Core binds host loopback by default; remote access should use the documented TLS reverse proxy.

## Near-Term Roadmap Themes

1. **Make the local product sharper on its own.**
   Better setup, better explanations, better device visibility, better DNS workflow coverage.
2. **Expand beyond DNS-only inputs.**
   Add router and firewall logs from gear people actually run.
3. **Harden the operating model.**
   Improve token rotation, trust boundaries, and public-beta deployment operations.
4. **Build the community layer carefully.**
   Keep it optional, privacy-conscious, and clearly secondary to local value.

## Near-Term Priorities

- tighten README and site messaging around the real product wedge
- document optional vs required integrations clearly
- improve public-beta install guidance for Core plus native sensor
- complete sustained UniFi SNR validation before labelling the connector supported
- add broader router/firewall sources one proven adapter at a time
