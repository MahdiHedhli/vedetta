# Vedetta Sensor Architecture

> Last updated: 2026-04-20
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
- passive DNS capture on a selected interface
- scan-target execution driven by Core
- reporting devices and DNS events back to Core

### Current install reality

- **Public install path:** macOS and Linux
- **Current installer:** builds from source, installs dependencies, and can register a persistent service
- **Privileges:** current best visibility still assumes elevated local access
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
  |- device discovery
  |- passive DNS capture
  `- scan target execution
          |
          v
POST /api/v1/sensor/register
POST /api/v1/sensor/devices
POST /api/v1/sensor/dns
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

- ARP, DHCP, mDNS, and SSDP passive discovery
- better multi-network and connector-aware workflows
- tighter sensor-to-Core authentication and request hardening
- cleaner installation and upgrade paths for alpha users

## Security Note

This is the most important operational caveat today:

- Core can mint sensor tokens during registration
- the current sensor flow does not yet use that token path end to end
- the deployment should still be treated as LAN-first alpha software

If you are documenting or deploying Vedetta publicly, do not position the current sensor path as fully hardened remote infrastructure. The right framing today is self-hosted, local-first, and still under active hardening.
