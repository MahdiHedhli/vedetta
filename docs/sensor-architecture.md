# Vedetta — Sensor Architecture

> Version: 1.0.0
> Last updated: 2026-03-30

---

## Why Core and Sensor are separate

Vedetta runs as two cooperating components: **Core** (containerized) and **Sensor** (native binary). Understanding why this split exists is essential for contributors and users.

Docker on macOS and Windows runs containers inside a Linux VM. The VM creates virtual network interfaces that are invisible to the real LAN. This means containers cannot see ARP broadcasts, DHCP traffic, mDNS announcements, or accurately detect devices on the local network. Only Linux with `--network=host` provides real access to the host's Layer 2 network.

The solution: the Sensor runs as a native binary directly on the host OS, where it has full access to the physical network. It discovers devices and pushes results to Core via HTTP.

```
┌─────────────────────────────────────────────────────────────────┐
│  Host OS (Linux, macOS, or Windows)                             │
│                                                                 │
│  ┌──────────────────────┐                                       │
│  │  vedetta-sensor       │  Native binary, runs with sudo       │
│  │  - nmap scanning      │  or CAP_NET_RAW                      │
│  │  - DNS capture        │  Pushes discovered devices to Core   │
│  │  - ARP/DHCP passive   │  via POST /api/v1/sensor/devices     │
│  │    (planned)          │  Pushes DNS events to Core           │
│  └──────────┬─────┬──────┘  via POST /api/v1/sensor/dns        │
│             │ HTTP │                                             │
│             │      └──────────────────────┐                      │
│  ┌──────────▼───────────────────────────┐ │                     │
│  │  Docker Compose                       │ │                     │
│  │                                       │ │                     │
│  │  ┌────────────┐  ┌────────────┐  ┌───▼─┬──────────┐  │     │
│  │  │  backend    │  │  frontend  │  │  collector   │  │     │
│  │  │  (Go API)   │  │  (React)   │  │  (Fluent Bit)│  │     │
│  │  │  Port 8080  │  │  via nginx │  │  Syslog UDP  │  │     │
│  │  └──────┬─────┘  └────────────┘  └──────────────┘  │     │
│  │         │                                           │     │
│  │  ┌──────▼─────┐                                     │     │
│  │  │  SQLite DB  │  /data/vedetta.db                  │     │
│  │  └────────────┘                                     │     │
│  └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**On Linux with `--network=host`**, the Core backend can optionally run its own built-in scanner (using nmap if available). This is a convenience fallback — the Sensor remains the recommended and more capable discovery path.

---

## Sensor capabilities

### Current (M1)

The sensor is an nmap-based network scanner that runs on the host OS.

**Discovery method:** Active scanning with nmap. The sensor runs `nmap -sn` (ping scan) at a configurable interval to find live hosts, then optionally runs port scans on discovered hosts.

**Subnet detection:** On startup, the sensor auto-detects the local LAN subnet from the host's network interfaces. On Linux/macOS this uses the `ip` or `ifconfig` output; on Windows it uses `ipconfig`. The `--cidr` flag overrides auto-detection.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--core` | `http://localhost:8080` | URL of the Vedetta Core API |
| `--cidr` | auto-detected | Subnet to scan (e.g., `192.168.1.0/24`) |
| `--interval` | `5m` | Time between scan cycles |
| `--ports` | `false` | Enable TCP port scanning |
| `--once` | `false` | Run a single scan and exit |
| `--dns` | `true` | Enable DNS capture via packet sniffing |
| `--dns-iface` | `auto` | Network interface for DNS capture (auto-detect if not specified) |

### DNS Capture (M2)

The sensor now captures DNS traffic passively via packet sniffing, enabling real-time visibility into network DNS activity without relying on external DNS services.

**Passive DNS sniffing via gopacket** — The sensor listens on the configured network interface and captures DNS queries and responses in real-time. This is a Tier 1 (zero-configuration) capability that requires no setup and runs by default. Combined with nmap active scanning, this provides continuous DNS visibility without polling external DNS providers.

**Encrypted DNS detection** — The sensor detects encrypted DNS traffic (DoH/DoT) by fingerprinting destination IPs known to host major DNS providers (Cloudflare, Quad9, OpenDNS, etc.). When encrypted DNS is detected, an `encrypted_dns_detected` event is recorded with the destination IP and port, allowing you to track which devices are using encrypted DNS resolvers.

**Sensor flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--dns` | `true` | Enable DNS capture via packet sniffing |
| `--dns-iface` | `auto` | Network interface for DNS capture (auto-detect if not specified) |

Captured DNS queries are pushed to Core via `POST /api/v1/sensor/dns` with the following payload:

```json
{
  "sensor_id": "a1b2c3d4-...",
  "dns_events": [
    {
      "timestamp": "2026-03-30T14:30:00Z",
      "domain": "example.com",
      "query_type": "A",
      "resolved_ip": "93.184.216.34",
      "source_ip_hash": "sha256:...",
      "dns_source": "passive_capture"
    }
  ]
}
```

**Four-tier DNS architecture:**

1. **Tier 1 (Sensor):** Passive packet capture on the local network. No configuration, runs by default.
2. **Tier 2 (Core):** Threat intelligence enrichment (domain reputation, geolocation, anomaly scoring) performed on ingested events.
3. **Tier 3 (Community):** Optional opt-in sharing of anonymized DNS events to the Vedetta threat network for community threat intelligence.
4. **Tier 4 (Global Intel):** Integration with external threat feeds (OSINT, abuse databases) for historical threat data.

### Planned (M4 — Passive Discovery)

The sensor will expand to include continuous passive listeners that require no active network probing:

**ARP watcher** — Captures ARP announcements and replies via raw sockets. Detects new devices the moment they communicate on the LAN, without waiting for the next scan interval. Sub-1% CPU on Pi 4 using BPF-filtered `afpacket`.

**DHCP sniffer** — Parses DHCP option 12 (hostname), option 60 (vendor class), and option 55 (parameter request list) for device fingerprinting. Uses `insomniacslk/dhcp` for option parsing.

**mDNS listener** — Listens for mDNS service announcements (`_airplay._tcp`, `_googlecast._tcp`, `_ipp._tcp`, etc.) and extracts model names from TXT records. Uses `hashicorp/mdns`.

**SSDP/UPnP listener** — Monitors for SSDP NOTIFY multicast announcements and fetches UPnP device description XML for manufacturer/model identification. Uses `koron/go-ssdp` and `huin/goupnp`.

All passive listeners are designed for ARM64 (Raspberry Pi 4) with combined overhead of <2% CPU and <15MB RAM.

---

## How the sensor communicates with Core

### Registration

On first startup, the sensor generates a persistent UUID stored in `~/.vedetta-sensor-id` and registers itself:

```
POST /api/v1/sensor/register
Content-Type: application/json

{
  "sensor_id": "a1b2c3d4-...",
  "hostname": "pi4-living-room",
  "os": "linux",
  "arch": "arm64",
  "cidr": "192.168.1.0/24",
  "version": "0.1.0"
}
```

Core upserts the sensor record and tracks `first_seen`, `last_seen`, and `status`.

### Device push

After each scan cycle, the sensor pushes discovered hosts:

```
POST /api/v1/sensor/devices
Content-Type: application/json
X-Sensor-ID: a1b2c3d4-...

{
  "sensor_id": "a1b2c3d4-...",
  "cidr": "192.168.1.0/24",
  "segment": "default",
  "hosts": [
    {
      "ip_address": "192.168.1.42",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "hostname": "living-room-tv",
      "vendor": "Samsung Electronics",
      "open_ports": [8080, 9090],
      "status": "up"
    }
  ]
}
```

Core responds with:
```json
{
  "accepted": 12,
  "new_devices": 1
}
```

### Heartbeat

Every device push also updates the sensor's `last_seen` timestamp. If a sensor hasn't reported in 3x its configured interval, it's marked as `offline` in the dashboard.

---

## Authentication

**Current state:** None. The sensor communicates with Core over plain HTTP with no authentication.

**Security note for contributors:** This is a known gap tracked for pre-V1 hardening. The planned approach is a shared secret (generated during first Core startup, displayed in the setup wizard) that the sensor provides via `Authorization: Bearer <token>` header. For LAN-only deployments the risk is low, but any public-facing Core instance must have authentication before accepting sensor or ingest data.

---

## Installing the sensor

### Linux (recommended for Pi 4)

```bash
# Download the binary
curl -L https://github.com/vedetta-network/vedetta/releases/latest/download/vedetta-sensor-linux-arm64 -o vedetta-sensor
chmod +x vedetta-sensor

# Run (requires sudo for ARP discovery)
sudo ./vedetta-sensor --core http://<core-ip>:8080

# Or install as a systemd service
sudo cp vedetta-sensor /usr/local/bin/
sudo cat > /etc/systemd/system/vedetta-sensor.service << 'EOF'
[Unit]
Description=Vedetta Network Sensor
After=network.target

[Service]
ExecStart=/usr/local/bin/vedetta-sensor --core http://<core-ip>:8080
Restart=always
RestartSec=10
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now vedetta-sensor
```

### macOS

```bash
curl -L https://github.com/vedetta-network/vedetta/releases/latest/download/vedetta-sensor-darwin-arm64 -o vedetta-sensor
chmod +x vedetta-sensor
sudo ./vedetta-sensor --core http://<core-ip>:8080
```

**Note:** nmap must be installed separately on macOS: `brew install nmap`.

### Windows

Download `vedetta-sensor-windows-amd64.exe` from releases. Run from an Administrator command prompt:

```
vedetta-sensor.exe --core http://<core-ip>:8080
```

**Note:** nmap must be installed separately. Download from https://nmap.org/download.html and ensure it's on the system PATH.

---

## How Core handles containerized environments

When Core starts inside Docker, it runs `discovery.IsInsideDocker()` which checks for `/.dockerenv` or `/proc/1/cgroup` containing `docker`. If detected, subnet auto-detection returns empty, and the frontend's `SensorSetupDialog` appears, prompting the user to install the native sensor.

On Linux with `--network=host` in Docker Compose, `IsInsideDocker()` still returns true but subnet auto-detection works correctly (real interfaces are visible). In this case, Core can run its built-in scanner as a convenience fallback, though the native sensor is still recommended for passive discovery capabilities.

---

## Multiple sensors

Vedetta supports multiple sensors reporting to a single Core instance. Each sensor registers with its own UUID and can scan different subnets. Common deployment:

- **Sensor 1** on a Pi 4 scanning `192.168.1.0/24` (main LAN) with segment `default`
- **Sensor 2** on the same Pi scanning `10.0.50.0/24` (IoT VLAN) with segment `iot`
- **Sensor 3** on a different machine scanning `192.168.10.0/24` (guest network) with segment `guest`

The dashboard shows which sensor discovered each device and tracks sensor health independently.

---

*See also: [Roadmap](roadmap.md) — M1 (Network Discovery), M4 (Passive Discovery & Fingerprinting)*
