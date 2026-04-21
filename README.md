# Vedetta

**Your network, under watch.** DNS-first security monitoring for homes and small businesses.

Vedetta is a lightweight, self-hosted security monitoring platform. Today it is strongest at DNS-first visibility and detection, active and passive device discovery, and local threat scoring. The current product stands on its own locally, can optionally pull value from existing DNS infrastructure such as Pi-hole or AdGuard Home, and is still best described as alpha software for homelabs, technical home users, small businesses, and hands-on operators.

## What Vedetta Is Today

- **Vedetta Core** runs in Docker Compose and provides the API, dashboard, local storage, and ingest pipeline.
- **Vedetta Sensor** runs natively on the network you want to inspect and handles active device discovery, passive ARP/DHCP/mDNS/SSDP visibility, and passive DNS capture.
- **DNS detections** include DGA, beaconing, tunneling, rebinding, and DNS bypass scoring.
- **Threat enrichment** is local-first and backed by downloaded threat intelligence feeds.
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

### Available now

- Docker-based Core with dashboard, API, and SQLite-backed storage
- native sensor for macOS and Linux install paths
- passive DNS capture plus active and passive device discovery
- DNS-first threat scoring and local enrichment
- optional Pi-hole and AdGuard Home pollers
- device inventory, scan targets, whitelist, suppression, and activity logging

### In progress

- install and onboarding polish for alpha users
- broader dashboard/admin auth hardening plus sensor token rotation
- turning early router and firewall groundwork into documented workflows
- better public docs that separate shipped functionality from roadmap direction

### Planned next

- router and firewall log aggregation for common platforms:
  UniFi, OpenWRT, pfSense/OPNsense, and MikroTik
- better correlation and labeling across the new passive discovery sources
- more local DNS collection options for advanced deployments
- an optional, privacy-conscious community threat network

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
| Telemetry | - | Optional outbound sharing path, still scaffolded |
| Threat Network | 9090 | Future-facing community backend, still scaffolded |

## Hardware And Platform Notes

- **Core:** Raspberry Pi 4 (4 GB RAM) or a small x86 box is a reasonable target for alpha deployments.
- **Sensor:** macOS or Linux host with `nmap` on the network segment you want to inspect.
- **Windows:** not yet a supported public install path.

## Router And Firewall Integrations

Vedetta is not just a Pi-hole companion. DNS is the current wedge, but the product is being expanded to pull value from multiple visibility layers.

Current state:

- connector framework exists in `backend/internal/firewall/`
- early UniFi connector code exists
- collector exposes a syslog path on UDP 5140

Planned next:

1. UniFi hardening and documentation
2. OpenWRT
3. pfSense / OPNsense
4. MikroTik

These should be described honestly as early or planned until they are documented and proven in the public workflow.

## Privacy And Trust

- **Self-hosted first.** The local deployment is the product.
- **Local value first.** Device discovery, DNS visibility, and local detections should remain useful without cloud dependency.
- **Telemetry is optional.** It is off by default.
- **Community threat sharing is future-facing.** It is not the main present-tense promise and should remain opt-in and privacy-conscious.

## Known Alpha Limits

- Core plus native sensor is still the real deployment model.
- Install still assumes Docker, a native sensor, and some comfort with local networking and `sudo`.
- Sensor bearer auth is in place, but broader dashboard/admin auth hardening is still in progress.
- Threat-network and telemetry services are still scaffolded and should not be marketed as production-ready today.

## Documentation

- [Working Backlog](docs/backlog.md)
- [Architecture Reference](docs/architecture.md)
- [Project Roadmap](docs/roadmap.md)
- [Sensor Architecture](docs/sensor-architecture.md)
- [Security Policy](SECURITY.md)

## Community

- [Discord](https://discord.gg/aubRTSWRyc)
- [Community Guide](COMMUNITY.md)

## License

AGPLv3 - see [LICENSE](LICENSE) for details.
