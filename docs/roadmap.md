# Vedetta Roadmap

> Last updated: 2026-04-20
> Status: Alpha / active development

## What Vedetta is today

Vedetta is an open-source, self-hosted security monitoring platform for homes and small businesses. The product is strongest today at two things:

- DNS-first visibility and detection
- device discovery and local network inventory

Vedetta is not a Pi-hole product, and it is not yet a plug-and-play consumer appliance. Core runs in Docker. A native sensor handles local network visibility. Pi-hole and AdGuard Home are optional integrations if you already run them.

## Current product shape

- **Vedetta Core** runs in Docker Compose and provides the API, dashboard, local storage, and ingestion pipeline.
- **Vedetta Sensor** runs natively on the network you want to watch. Today it supports macOS and Linux install paths and performs nmap-based discovery plus passive DNS capture.
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** uses local abuse.ch-backed intelligence so the local product keeps value without cloud dependence.
- **Optional DNS sources** include Pi-hole and AdGuard Home pollers.
- **Router and firewall work** has started in code, with a connector framework and UniFi connector groundwork, but broader coverage is still roadmap work.

## Status Snapshot

### Available now

- Docker-based Core with local API, UI, and SQLite-backed storage
- Native sensor for device discovery and passive DNS capture
- DNS-first threat scoring and local event enrichment
- Optional Pi-hole integration
- Optional AdGuard Home integration
- Device inventory, scan targets, whitelist/suppression, and basic onboarding flow

### In progress

- Install and onboarding polish for alpha users
- Stronger sensor-to-Core hardening and cleaner setup flow
- Turning router and firewall ingestion into documented, testable workflows
- Better public docs that separate shipped features from roadmap items

### Planned next

- Router and firewall log aggregation for common platforms:
  UniFi, OpenWRT, pfSense/OPNsense, and MikroTik
- More passive discovery sources:
  ARP, DHCP, mDNS, and SSDP/UPnP
- Better local DNS collection options for advanced deployments
- An optional, privacy-conscious community threat network

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
- Router and firewall coverage is not mature yet. The connector framework exists, and UniFi groundwork is in the repo, but broader connector support is still ahead.
- The threat-network and telemetry services are still scaffolded. They should be described as upcoming, not shipped.
- Sensor-to-Core hardening is only partially complete. Core can mint sensor tokens during registration, but the full sensor flow is not yet using that path end to end. Treat public internet exposure as unsupported for now.

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
- finish the next round of sensor security hardening
