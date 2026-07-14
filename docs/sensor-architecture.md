# Vedetta Sensor Architecture

> Last updated: 2026-07-11
> Status: Beta (native sensor: macOS, Linux, Windows)

## Why Vedetta Has A Native Sensor

Vedetta uses a Core + Sensor model because the local network is the product's strongest source of truth.

Core runs comfortably in Docker, but accurate network visibility often needs access that containers do not reliably get on every platform. The native sensor exists so Vedetta can:

- discover devices on the local segment
- capture DNS traffic directly from a real interface
- push clean, local observations back to Core

This is especially important on macOS and Windows, where Docker commonly runs inside a VM and does not expose the host network in the same way a native process can.

## What The Sensor Does Today

The current sensor is strongest at:

- active device discovery with `nmap`
- passive device discovery from ARP, DHCP, mDNS, and SSDP/UPnP traffic
- passive DNS capture on a selected interface
- scan-target execution driven by Core
- reporting devices and DNS events back to Core

### Current install reality

- **Public install path:** macOS, Linux, and Windows
- **Current installer:** `install.sh` (macOS/Linux) or `install.ps1` (Windows) downloads a
  checksum-verified prebuilt binary (or builds an exact published tag on Unix), stages and
  preflights it, and registers a persistent service (launchd / systemd / Windows service)
- **Privileges:** best visibility assumes elevated local access — a LocalSystem service on
  Windows, `sudo`/root on Unix
- **Capture preflight:** on Unix the installer prints a recommended DNS/passive capture
  interface and the sensor supports explicit `--dns-iface` / `--passive-iface` overrides; on
  Windows, DNS capture is host-scoped ETW and needs no interface selection

### Windows sensor (host-scoped, driver-free)

The Windows sensor needs **no Npcap, no nmap, and no cgo** — it is a single pure-Go binary.

- **DNS:** captured from the `Microsoft-Windows-DNS-Client` ETW provider — the OS resolver's
  own queries (event 3006) and responses (3008). This is **host-scoped**: it sees this
  machine's DNS, not other devices' traffic. A real-time ETW session needs an elevated token,
  which the LocalSystem service has. Every query is attributed to this host's primary IP.
- **Discovery:** native `IcmpSendEcho` sweep + `arp -a`, unioned with the ARP neighbor table so
  firewalled hosts that drop ICMP but still answer ARP are found.
- **Service:** runs under the Windows Service Control Manager (installed by `install.ps1`); the
  token lives at `%ProgramData%\Vedetta\sensor-token`, ACL-locked to SYSTEM + Administrators
  (NTFS ACLs, since `chmod` is a no-op there).
- **Limits (v1):** DoH/DoT from apps that bypass the OS resolver is not visible, and capture is
  this-host-only. Network-wide L2 capture (optional Npcap) and deep `nmap` scans are an opt-in
  Phase-3 tier — never required.

## What Is Required Vs Optional

### Required today

- Vedetta Core
- at least one sensor on the network segment you want to inspect

### Optional today

- Pi-hole or AdGuard Home integrations
- multiple sensors across multiple segments
- future telemetry and community sharing

## Data Flow

```text
vedetta-sensor
  |- first bootstrap:
  |    POST /api/v1/sensor/register
  |    receives one-time auth_token
  |    stores token in a root-only service path (0600)
  |
  |- ongoing device discovery
  |- ongoing passive DNS capture
  `- ongoing scan target execution
          |
          v
Authorization: Bearer <sensor token>
POST /api/v1/sensor/devices
POST /api/v1/sensor/dns
GET  /api/v1/sensor/work
          |
          v
vedetta-core
  |- stores devices and events
  |- enriches DNS activity
  `- serves the dashboard and API
```

## What The Sensor Is Not Yet

The current sensor is not yet the final shape of the product. Public copy should not imply that it already includes:

- network-wide capture on Windows (v1 is host-scoped ETW; segment-wide L2 capture is an opt-in Npcap tier)
- full passive discovery coverage beyond the current DNS capture and active scanning path
- turnkey zero-touch onboarding for non-technical users
- fully hardened internet-facing operation

## Planned Sensor Expansion

The next sensor milestones are meant to broaden local visibility without changing Vedetta's current identity:

- better passive correlation across the new ARP, DHCP, mDNS, and SSDP signals
- better multi-network and connector-aware workflows
- token rotation and deeper sensor-to-Core trust hardening
- cleaner installation and upgrade paths for alpha users

## Capture Interface Selection

Vedetta now chooses packet-capture interfaces at runtime instead of relying on a one-time install guess.

- explicit `--dns-iface` and `--passive-iface` overrides always win
- if no override is set, the sensor prefers the interface whose IP matches the scan CIDR
- route-to-Core is used as a secondary hint, not the only signal
- tunnel, VPN, loopback, and side-channel interfaces such as `utun*`, `awdl*`, `llw*`, and `ap*` are strongly de-prioritized in auto mode

This matters most on laptops and developer machines where Wi-Fi, Ethernet, Docker, and VPN interfaces can all coexist.

For diagnostics:

```bash
./vedetta-sensor --core http://<CORE_IP>:8080 --cidr 10.0.0.0/24 --print-capture-plan
sudo ./vedetta-sensor --check --require-token --core https://vedetta.example.com
```

`--print-capture-plan` prints the chosen DNS and passive interfaces, the reasons they won, and the next-best candidates.

The Unix installer keeps the long-running root service on a system-only `PATH`. It passes
an absolute `VEDETTA_NMAP_PATH` separately. Port probes, DNS-free connect discovery, and
all custom-path Nmap children drop to an unprivileged account. The sole exception is a
fixed-argument, no-port/no-DNS ARP discovery on Linux when Nmap is the root-owned system
binary and the IPv4 target is directly attached on a broadcast-capable interface. macOS
and custom Nmap paths use connect discovery; existing neighbor-cache entries enrich hosts
that Nmap confirms live, but quiet devices may require passive discovery. Active scanning
is IPv4-only in this beta; IPv6/hostname scan targets fail explicitly. The
installed sensor defaults to `/Library/Vedetta/bin/vedetta-sensor` on macOS and
`/usr/local/libexec/vedetta/vedetta-sensor` on Linux. Failed upgrades restore the prior
binary and service definition instead of leaving a new crash loop active.

Enrollment codes enter the Unix installer only through `--enroll-code-file` (a
mode-0600, non-symlink regular file) or `--enroll-code-stdin`. The installer pipes
the secret into its one-shot enrollment child, so it is absent from installer,
sudo, and sensor argument vectors and is never serialized into launchd/systemd.
The legacy `--enroll-code CODE` installer form is disabled unless an operator
explicitly enables the deprecated compatibility escape hatch.

## Security Note

The sensor auth loop is now closed for the machine-to-machine path:

- the first registration call can bootstrap a new sensor and returns a one-time `auth_token`
- the sensor persists that token locally with user-only permissions
- every later `devices`, `dns`, and `work` call uses `Authorization: Bearer <sensor token>`
- once a sensor already has an active token, registration updates must present that token instead of silently minting a second one
- initial registration is rate-limited per source IP to reduce unauthenticated abuse on local networks

Threat-model note:

- this hardening is designed for self-hosted, LAN-first alpha deployments, not exposed internet infrastructure
- local value does not depend on any cloud service
- there is still broader admin/dashboard auth work to finish around human-facing management routes

If you are documenting or deploying Vedetta publicly, do not position the current sensor path as fully hardened remote infrastructure. The right framing today is self-hosted, local-first, and still under active hardening.

## Richer Sensor Payloads for Actionability (L6 additive note)

Core + sensor now carry additional fields (populated by passive discovery and DNS ingest, stored, queryable, and surfaced in UI):

- On events (dns_query primarily): `server_ip` (the DNS server observed), plus `dns_answers` (resolved IPs from responses) and `process` (local process hint when available) — carried in metadata for the current collector shape.
- On devices: `model`, `services` (list from mDNS/SSDP/DHCP/etc.), `discovery_source` (json "discovery_source", db "discovery_method"; values e.g. passive, mdns, dhcp, arp, nmap_active), plus generalized `risk_category` / `risk_model` / `risk_reasons` (and legacy `eol_risk`/`eol_model` for compat per migration 016).

These enable operator actionability (L5) and are the target for future connectors (e.g. UniFi). The /ingest path and /events filters (json_extract on metadata) exist; normalization of vendor raw logs into structured FirewallEvent fields remains connector-layer responsibility (see connector-guide.md). All additions were made while preserving prior sensor architecture and data flows.
