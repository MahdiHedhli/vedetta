# Vedetta

**Your network, under watch.** Open-source security monitoring for homes and small businesses.

Vedetta is the watchtower on your network — it sees everything and explains it simply. Install in one command, run on a Raspberry Pi, and get enterprise-grade network visibility without the enterprise learning curve.

### What's included

- **DNS threat hunting** with 5 detection engines: DGA detection (Shannon entropy), beaconing detection (callback patterns), DNS tunneling, DNS rebinding, and DNS bypass detection
- **Passive DNS capture** via libpcap — zero-config, no DNS proxy needed
- **Pi-hole integration** for DNS event enrichment
- **Device discovery** via nmap + OUI lookup and hostname fingerprinting
- **Community threat intelligence** (planned) — shared, anonymized threat feeds
- **Known-traffic whitelist** with 20 default rules (Apple, mDNS, cloud services, OS updates, etc.)
- **Event management** — acknowledge, suppress, bulk manage, and deduplicate threats

## Quick Start

### 1. Start Vedetta Core

```bash
git clone https://github.com/vedetta-network/vedetta.git
cd vedetta
docker compose up -d
```

Dashboard: [http://localhost:3107](http://localhost:3107)
API: [http://localhost:8080/api/v1/status](http://localhost:8080/api/v1/status)

### 2. Update Vedetta

```bash
# Update all services (pull latest code + rebuild)
./scripts/update-all.sh

# Or update individual components
./scripts/update-core.sh     # Core services only
./scripts/update-sensor.sh   # Sensor binary only
```

### 3. Deploy a Sensor

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

## Features

### DNS Threat Detection

Five detection engines analyze DNS traffic in real-time:

- **DGA Detection** — Shannon entropy scoring to identify algorithmically generated domains
- **Beaconing Detection** — Recognizes regular callback patterns indicating command & control
- **DNS Tunnel Detection** — Detects subdomain exfiltration and data tunneling attempts
- **DNS Rebinding Detection** — Identifies public→private IP transitions that could bypass firewalls
- **DNS Bypass Detection** — Catches hardcoded resolver queries and DNS-over-HTTPS tunnels

### Multi-Source DNS Capture

- **Tier 1:** Passive libpcap sniffing via gopacket (zero-config, enabled by default)
- **Tier 2:** Pi-hole REST API polling (60-second intervals)
- **Tier 3:** Embedded DNS resolver (planned)
- **Tier 4:** iptables DNAT intercept (planned, Linux router mode)

### Device Discovery & Fingerprinting

Active nmap scanning with OUI lookup, hostname pattern matching, and multi-signal fusion scoring (confidence 0.2–0.95).

### Threat Intelligence

abuse.ch feeds (URLhaus, Feodo Tracker, SSLBL) with Bloom filter for O(1) lookups. All detection works offline — no external API calls required for threat matching.

### Event Management

- Acknowledge or suppress individual events or in bulk
- Suppression rules — auto-hide matching future events
- Known-traffic whitelist with 20 default rules
- Event grouping and deduplication

### Dashboard

React + Tailwind dark-theme UI featuring device inventory, threat events with severity filtering, sensor management, scan target configuration, and activity logging.

## Architecture

Vedetta uses a **Core + Sensor** architecture. Core is the watchtower — it runs as a set of Docker containers (API, database, dashboard, log collector) and gives you a single pane of glass across your entire network. Sensors are lightweight native binaries that run on host machines with direct LAN access, scanning for devices, capturing DNS traffic passively, and reporting back to Core.

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
| Sensor | — | Native binary — nmap-based device discovery, passive DNS capture, pushes to Core |
| Collector | 5140/udp | Fluent Bit — ingests firewall syslog (DNS now captured directly by sensor) |
| Telemetry | — | Opt-in daemon — PII-stripped event batching to threat network |
| Threat Network | 9090 | Central threat intel backend |

## Hardware Requirements

- **Core:** Raspberry Pi 4 (4GB RAM) or better. Docker + Docker Compose required.
- **Sensor:** Any Linux, macOS, or Windows (planned) host on the target network segment. Requires nmap.

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
- **Windows** (planned)

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
| `--dns` | `true` | Enable DNS capture via packet sniffing |
| `--dns-iface` | `auto` | Network interface for DNS capture (auto-detect if not specified) |

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

## Firewall Integration

### Planned Integrations

Firewall log ingestion is coming in a future release. Planned targets (in priority order):

1. UniFi (REST API)
2. OpenWRT (ubus JSON-RPC)
3. pfSense / OPNsense (syslog + REST API)
4. MikroTik (RouterOS API)

Fluent Bit syslog input is already configured on UDP port 5140.

## Documentation Links

- [Architecture Reference](docs/architecture.md)
- [Project Roadmap](docs/roadmap.md)
- [Event Schema](docs/schema.md)
- [Sensor Architecture](docs/sensor-architecture.md)

## License

AGPLv3 — see [LICENSE](LICENSE) for details.
