# Vedetta

[![Deploy Public Site](https://github.com/MahdiHedhli/vedetta/actions/workflows/pages.yml/badge.svg)](https://github.com/MahdiHedhli/vedetta/actions/workflows/pages.yml)

**Your network, under watch.** DNS-first security monitoring for homes and small businesses.

Vedetta is a lightweight, self-hosted security monitoring platform. Today it is strongest at DNS-first visibility and detection, active and passive device discovery, and local threat scoring. The current product stands on its own locally, can optionally pull value from existing DNS infrastructure such as Pi-hole or AdGuard Home, and is still best described as alpha software for homelabs, technical home users, small businesses, and hands-on operators.

## What Vedetta Is Today

- **Vedetta Core** runs in Docker Compose and provides the API, dashboard, local storage, and ingest pipeline.
- **Vedetta Sensor** runs natively on the network you want to inspect and handles active device discovery, passive ARP/DHCP/mDNS/SSDP visibility, and passive DNS capture.
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** is local-first and backed by downloaded threat intelligence feeds.
- **EOL Router & Camera Detection** — Detects specific end-of-life and vulnerable router and camera models listed in the [FBI IC3 FLASH 2026-03-12 advisory](https://www.ic3.gov/CSA/2026/260312.pdf) (AVrecon malware / SocksEscort) and applies elevated risk scoring when they exhibit suspicious behavior.
- **Optional DNS integrations** include Pi-hole and AdGuard Home if you already run them.
- **Router and firewall work** has started in code, but broader log aggregation and connector coverage still belong in the roadmap.

## Who It Is For Today

Vedetta currently fits best for:

- homelab users
- technical home users
- small businesses without a full SOC
- consultants, MSPs, and security practitioners helping very small environments

Vedetta is not yet a plug-and-play consumer appliance. The current install path assumes Docker, a native sensor, local network access, and some comfort with `sudo`.

## Required Vs Optional

### Required today

- Vedetta Core
- at least one sensor on the network segment you want to inspect

### Optional today

- Pi-hole integration
- AdGuard Home integration
- telemetry and future community sharing
- early router and firewall connector experimentation

Pi-hole and AdGuard Home are **optional integrations**, not the product identity. Vedetta is being built to ingest useful signals from multiple DNS and network sources over time.

## Status

Major features are developed spec-first under [`specs/`](specs/), validated against
the [project constitution](.specify/memory/constitution.md).

### Available now

- Docker-based Core with dashboard, API, and SQLite-backed storage
- native sensor for macOS and Linux install paths
- passive DNS capture plus active and passive device discovery
- log ingestion pipeline (`POST /api/v1/ingest` + events query API + retention enforcer)
- DNS-first threat scoring and local enrichment
- EOL Router & Camera Detection (FBI IC3 2026-03-12 advisory) plus device risk categories (`known_exploited` / `eol_eos` / `high_risk_iot`)
- **UniFi log ingestion** ([specs/001](specs/001-unifi-log-ingestion/), [setup guide](docs/connectors/unifi.md)): collector CEF/syslog parser → `firewall_log` events, firewall-aware scoring, seeded noise suppression, optional REST connector, UI filters — syslog path implemented, live SNR validation pending
- **passive discovery correlation** ([specs/004](specs/004-passive-discovery-correlation/)): multi-signal identity resolution surviving DHCP churn, confidence-weighted provenance, mDNS record-graph parsing, per-device display name, multi-segment attachments
- richer sensor payloads (`dns_answers`, `server_ip`, `services`, `discovery_source`)
- optional Pi-hole and AdGuard Home pollers
- device inventory, scan targets, whitelist, suppression, and activity logging

### Opt-in / off by default

- **Telemetry service** ([specs/002](specs/002-telemetry-service/)): implemented but does nothing unless `VEDETTA_TELEMETRY_OPTIN=true`; structural PII stripping (raw IPs/MACs/hostnames can never reach the wire), aggregate-only signed export. Needs an operational validation pass before real use.
- **Community threat network** ([specs/003](specs/003-threat-network/)): implemented advisory-only community feed with reporter-consensus confidence and abuse resistance. Alpha, not production-ready.

### In progress

- live SNR / operational validation of the newly implemented sources (UniFi, telemetry, threat network) on real deployments
- install and onboarding polish for alpha users
- broader dashboard/admin auth hardening plus sensor token rotation
- migration-runner hardening (fresh-install runner fails partway; tracked in the backlog)

### Planned next

- broader firewall log aggregation after UniFi is validated on real hardware:
  OpenWRT, pfSense/OPNsense, and MikroTik ([specs/005](specs/005-broader-firewall-connectors/), one source at a time)
- more local DNS collection options for advanced deployments

## Quick Start

### 1. Start Vedetta Core

```bash
git clone https://github.com/MahdiHedhli/vedetta.git
cd vedetta
docker compose up -d
```

Dashboard: [http://localhost:3107](http://localhost:3107)
API status: [http://localhost:8080/api/v1/status](http://localhost:8080/api/v1/status)

### 2. Deploy A Sensor

Review the installer, then run it against your Core instance:

```bash
curl -fsSL -o /tmp/vedetta-sensor-install.sh \
  https://raw.githubusercontent.com/MahdiHedhli/vedetta/main/sensor/deploy/install.sh

sudo bash /tmp/vedetta-sensor-install.sh --core http://<CORE_IP>:8080
```

Current public install path:

- macOS and Linux
- installs dependencies, builds the sensor from source, and can register a persistent service
- uses elevated privileges for the strongest local visibility
- prints a capture-interface recommendation during install and supports `--dns-iface` / `--passive-iface` if auto-selection needs to be pinned

If you prefer to build manually:

```bash
cd sensor
go build -o vedetta-sensor ./cmd/vedetta-sensor
sudo ./vedetta-sensor --core http://<CORE_IP>:8080
```

Useful sensor diagnostics:

```bash
./vedetta-sensor --core http://<CORE_IP>:8080 --cidr 10.0.0.0/24 --print-capture-plan
```

That command prints the recommended DNS and passive-discovery interfaces, explains why they were chosen, and shows the override flags if you need to pin a different interface on a laptop, VPN client, or multi-homed host.

### 3. Update Vedetta

```bash
./scripts/update-all.sh
./scripts/update-core.sh
./scripts/update-sensor.sh
```

## Architecture

Vedetta uses a **Core + Sensor** model:

- **Core** is the Docker-based control plane: API, UI, storage, enrichment, and ingestion
- **Sensor** is the native network-side component: active and passive discovery, passive DNS capture, and scan execution

This split is deliberate. The local network is the strongest source of truth Vedetta has today, and native sensor access is more reliable than relying on containers alone for that visibility.

## Services

| Service | Port | Purpose |
| --- | --- | --- |
| Backend | 8080 | API, device/event storage, enrichment, scan coordination |
| Frontend | 3107 | Dashboard UI |
| Collector | 5140/udp | Syslog and normalized log ingestion path |
| Telemetry | - | Opt-in outbound sharing, off unless `VEDETTA_TELEMETRY_OPTIN=true` |
| Threat Network | 9090 | Optional community backend (advisory-only feed) |

## Hardware And Platform Notes

- **Core:** Raspberry Pi 4 (4 GB RAM) or a small x86 box is a reasonable target for alpha deployments.
- **Sensor:** macOS or Linux host with `nmap` on the network segment you want to inspect.
- **Windows:** not yet a supported public install path.

## Router And Firewall Integrations

Vedetta is not just a Pi-hole companion. DNS is the current wedge, but the product is being expanded to pull value from multiple visibility layers.

Current state:

- UniFi log ingestion is implemented: the collector normalizes UniFi CEF/legacy-syslog on UDP 5140 into `firewall_log` events through `POST /api/v1/ingest`, with firewall-aware scoring and seeded noise suppression; setup guide at [docs/connectors/unifi.md](docs/connectors/unifi.md)
- an optional off-by-default REST connector (`backend/internal/firewall/`) adds UniFi client-inventory enrichment
- syslog is the working path; a live ≥72h SNR validation on real UniFi hardware is pending before it is called fully "supported"

Planned next (deliberately one source at a time, after UniFi is validated):

1. OpenWRT
2. pfSense / OPNsense
3. MikroTik

These should be described honestly as early or planned until they are documented and proven in the public workflow.

## Privacy And Trust

- **Self-hosted first.** The local deployment is the product.
- **Local value first.** Device discovery, DNS visibility, and local detections should remain useful without cloud dependency.
- **Telemetry is optional.** It is off unless `VEDETTA_TELEMETRY_OPTIN=true`, strips PII structurally, and exports only aggregate signals.
- **Community threat sharing is opt-in and advisory-only.** It is not the main present-tense promise and remains privacy-conscious by design.

## Known Alpha Limits

- Core plus native sensor is still the real deployment model.
- Install still assumes Docker, a native sensor, and some comfort with local networking and `sudo`.
- Sensor bearer auth is in place, but broader dashboard/admin auth hardening is still in progress.
- The telemetry and threat-network services are implemented but off-by-default / advisory-only and have not completed an operational validation pass — treat them as opt-in alpha, not production-ready.
- UniFi log ingestion is implemented (syslog path) but has not completed its live ≥72h SNR validation on real hardware, so it is not yet labelled fully "supported".
- The fresh-install migration runner currently fails partway on a clean DB (tracked in the backlog); production Docker Core fresh installs are affected until it is hardened.

## Documentation

- [Working Backlog](docs/backlog.md)
- [Architecture Reference](docs/architecture.md)
- [Project Roadmap](docs/roadmap.md)
- [Sensor Architecture](docs/sensor-architecture.md)
- [UniFi Connector Setup](docs/connectors/unifi.md)
- [Threat Network — Implementation, Hosting & Configuration](docs/threat-network-operations.md)
- [Project Constitution](.specify/memory/constitution.md)
- [Security Policy](SECURITY.md)

## Community

- [Discord](https://discord.gg/aubRTSWRyc)
- [Community Guide](COMMUNITY.md)

## License

AGPLv3 - see [LICENSE](LICENSE) for details.
