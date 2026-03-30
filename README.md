# Vedetta

**Your network watchtower.** A free and open-source security monitoring platform for home users and small businesses.

Vedetta acts as a lightweight SIEM and network visibility tool that installs in a single Docker command, runs on a Raspberry Pi 4, and requires zero security expertise to operate. Users who opt in contribute anonymized telemetry to a community-powered threat intelligence network — the first such corpus built specifically from home and SMB network data.

## Quick Start

### 1. Start Vedetta Core

```bash
git clone https://github.com/vedetta-network/vedetta.git
cd vedetta
docker compose up -d
```

Dashboard: [http://localhost:3107](http://localhost:3107)
API: [http://localhost:8080/api/v1/status](http://localhost:8080/api/v1/status)

### 2. Deploy a Sensor

Sensors are lightweight native binaries that run on your LAN hosts and push device discovery data back to Core. You need at least one sensor to start discovering devices.

```bash
cd sensor
go build -o vedetta-sensor ./cmd/vedetta-sensor
sudo ./vedetta-sensor --core http://<CORE_IP>:8080
```

The sensor auto-detects the local subnet, registers with Core, and begins scanning on a 5-minute cycle. Use `sudo` for ARP-based MAC address and vendor discovery.

See [Deploying Sensors](#deploying-sensors) for remote deployment, systemd setup, and multi-NIC configurations.

## Architecture

Vedetta uses a **Core + Sensor** architecture. Core runs as a set of Docker containers (API, database, dashboard, log collector). Sensors run as native binaries on host machines with direct LAN access for network scanning.

```
vedetta/
├── backend/          Go API server (Core)
├── frontend/         React + Tailwind dashboard
├── sensor/           Native network sensor binary
│   └── deploy/       systemd service file
├── collector/        Fluent Bit log collection & normalization
├── telemetry/        Opt-in anonymized telemetry daemon
├── siem/             SIEM storage layer, schema, migrations
├── threat-network/   Central threat intelligence backend
├── docs/             Architecture & schema documentation
└── docker-compose.yml
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 8080 | Go API — device storage, scan coordination, event ingest |
| Frontend | 3107 | React dashboard (configurable via `VEDETTA_FRONTEND_PORT`) |
| Sensor | — | Native binary — nmap-based device discovery, pushes to Core |
| Collector | 5140/udp | Fluent Bit — ingests Pi-hole DNS logs and firewall syslog |
| Telemetry | — | Opt-in daemon — PII-stripped event batching to threat network |
| Threat Network | 9090 | Central threat intel backend |

## Deploying Sensors

### Prerequisites

The sensor host needs `nmap` and a Go toolchain (to build from source), or you can cross-compile and copy the binary.

- **macOS:** `brew install nmap`
- **Debian/Ubuntu:** `sudo apt install nmap`
- **Alpine:** `sudo apk add nmap`

### Build

```bash
cd sensor
go build -o vedetta-sensor ./cmd/vedetta-sensor
```

Or cross-compile for a remote Linux host:

```bash
GOOS=linux GOARCH=amd64 go build -o vedetta-sensor ./cmd/vedetta-sensor
# then scp vedetta-sensor to the target machine
```

### Run

```bash
sudo ./vedetta-sensor --core http://<CORE_IP>:8080
```

#### Sensor flags

| Flag | Default | Description |
|------|---------|-------------|
| `--core` | `http://localhost:8080` | Vedetta Core API URL |
| `--cidr` | `auto` | CIDR to scan (`auto` detects the local subnet) |
| `--interval` | `5m` | Scan cycle interval |
| `--ports` | `false` | Include top-100 port scan |
| `--primary` | `false` | Register as the primary sensor |
| `--once` | `false` | Run a single scan cycle and exit |

### Run as a systemd Service

For persistent deployment, install the sensor as a systemd service:

```bash
# Copy the binary
sudo cp vedetta-sensor /usr/local/bin/

# Install the service file
sudo cp sensor/deploy/vedetta-sensor.service /etc/systemd/system/

# Edit the service to set your Core IP
sudo systemctl edit vedetta-sensor
# Override the ExecStart line with your Core IP:
#   [Service]
#   ExecStart=
#   ExecStart=/usr/local/bin/vedetta-sensor --core http://<CORE_IP>:8080

# Enable and start
sudo systemctl enable --now vedetta-sensor

# Check status
sudo systemctl status vedetta-sensor
journalctl -u vedetta-sensor -f
```

A template service file is provided at `sensor/deploy/vedetta-sensor.service`.

### Multi-NIC / Multi-Segment Hosts

If the sensor host has NICs on multiple network segments (e.g. both your primary LAN and an IoT VLAN), a single sensor instance handles all of them. The sensor polls Core for enabled scan targets each cycle and uses the OS routing table to send traffic through the correct interface per subnet. No special configuration is needed — just add each network as a Scan Target in the Vedetta dashboard and the sensor will scan them all.

### Network Discovery Limitations

Device fingerprinting (MAC address, vendor, hostname) relies on ARP, which is a Layer 2 protocol and only works on the local subnet. If a sensor scans a remote subnet it is not directly connected to, devices will be discovered by IP but without MAC addresses or vendor identification.

For full fingerprinting on every segment, deploy a sensor on each network — or use a host with NICs on all segments you want to monitor.

## Hardware Requirements

- **Core:** Raspberry Pi 4 (4 GB RAM, 32 GB storage) or better, with Docker and Docker Compose
- **Sensor:** Any Linux/macOS host on the target network segment, with nmap installed

## License

AGPLv3 — see [LICENSE](LICENSE) for details.
