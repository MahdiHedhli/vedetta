# Vedetta

**Your network, under watch.** Open-source security monitoring for homes and small businesses.

Vedetta is the watchtower on your network — it sees everything and explains it simply. Install in one command, run on a Raspberry Pi, and get enterprise-grade network visibility without the enterprise learning curve. Vedetta monitors your network with device discovery, passive DNS analysis, and community-powered threat intelligence. Users who opt in contribute anonymized telemetry to a shared threat network — every Vedetta instance makes every other instance smarter.

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

**One-liner install** (macOS and Linux — installs nmap, Go, builds the sensor, and sets up a persistent service):

```bash
curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --core http://<CORE_IP>:8080
```

Or install manually:

```bash
cd sensor
go build -o vedetta-sensor ./cmd/vedetta-sensor
sudo ./vedetta-sensor --core http://<CORE_IP>:8080
```

The sensor auto-detects the local subnet, registers with Core, and begins scanning on a 5-minute cycle. Use `sudo` for ARP-based MAC address and vendor discovery.

See [Deploying Sensors](#deploying-sensors) for remote deployment, service management, and multi-NIC configurations.

## Architecture

Vedetta uses a **Core + Sensor** architecture. Core is the watchtower — it runs as a set of Docker containers (API, database, dashboard, log collector) and gives you a single pane of glass across your entire network. Sensors are lightweight native binaries that run on host machines with direct LAN access, scanning for devices and reporting back to Core.

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

### Automated Install (Recommended)

The install script detects your OS, installs dependencies (nmap, Go), builds the sensor from source, and registers it as a persistent service — launchd on macOS, systemd on Linux.

```bash
curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --core http://<CORE_IP>:8080
```

#### Install script options

| Option | Description |
|--------|-------------|
| `--core <url>` | **(Required)** Vedetta Core API URL |
| `--cidr <cidr>` | Override auto-detected subnet |
| `--interval <dur>` | Scan interval (default: 5m) |
| `--ports` | Enable top-100 port scanning |
| `--primary` | Register as the primary sensor |
| `--no-service` | Install binary only, skip service setup |
| `--uninstall` | Remove sensor binary and service |

#### Supported platforms

- **macOS** (Intel and Apple Silicon) — installs via Homebrew, service via launchd
- **Debian / Ubuntu / Pop!_OS / Linux Mint** — installs via apt
- **Fedora / RHEL / Rocky / AlmaLinux** — installs via dnf/yum
- **Alpine** — installs via apk
- **Arch / Manjaro** — installs via pacman

### Manual Install

#### Prerequisites

The sensor host needs `nmap` and a Go toolchain (to build from source), or you can cross-compile and copy the binary.

- **macOS:** `brew install nmap`
- **Debian/Ubuntu:** `sudo apt install nmap`
- **Alpine:** `sudo apk add nmap`

#### Build

```bash
cd sensor
go build -o vedetta-sensor ./cmd/vedetta-sensor
```

Or cross-compile for a remote Linux host:

```bash
GOOS=linux GOARCH=amd64 go build -o vedetta-sensor ./cmd/vedetta-sensor
# then scp vedetta-sensor to the target machine
```

#### Run

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

### Service Management

#### macOS (launchd)

```bash
# Status
sudo launchctl list | grep vedetta

# Logs
tail -f /usr/local/var/log/vedetta-sensor.log

# Stop
sudo launchctl bootout system/com.vedetta.sensor

# Start
sudo launchctl bootstrap system /Library/LaunchDaemons/com.vedetta.sensor.plist

# Uninstall
curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --uninstall
```

#### Linux (systemd)

```bash
# Status
sudo systemctl status vedetta-sensor

# Logs
journalctl -u vedetta-sensor -f

# Restart
sudo systemctl restart vedetta-sensor

# Uninstall
curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --uninstall
```

Template service files are provided in `sensor/deploy/`.

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
