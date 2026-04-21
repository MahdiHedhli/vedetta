# Vedetta Sensor Architecture

> Last updated: 2026-04-21
> Status: Alpha

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

- **Public install path:** macOS and Linux
- **Current installer:** builds from source, installs dependencies, and can register a persistent service
- **Privileges:** current best visibility still assumes elevated local access
- **Capture preflight:** installer prints a recommended DNS/passive capture interface and the sensor supports explicit `--dns-iface` / `--passive-iface` overrides
- **Windows:** not yet a supported public install path

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
  |    stores token in ~/.vedetta/sensor-token (0600)
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

- mature Windows support
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
```

That command prints the chosen DNS and passive interfaces, the reasons they won, and the next-best candidates.

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
