# Vedetta Architecture

> Last updated: 2026-04-20
> Version: 0.1.0-dev

## Overview

Vedetta is a self-hosted security monitoring platform built around a simple split:

- **Core** runs in Docker and stores, scores, and presents data
- **Sensor** runs natively on the network you want to inspect

That split matters because the strongest current Vedetta workflows depend on local network access. Containers alone are not enough on macOS or Windows to see the network with the fidelity Vedetta needs.

Vedetta today is best described as:

- DNS-first security monitoring
- device discovery and local visibility
- optional DNS and network-source integrations
- privacy-respecting, self-hosted first

## Core + Sensor Model

```text
LAN / WLAN
   |
   |  passive DNS capture, device discovery
   v
vedetta-sensor (native, macOS/Linux today)
   |
   |  HTTP API
   v
vedetta-core (Docker Compose)
   |- backend
   |- frontend
   |- collector
   |- telemetry (idle unless opted in)
   `- local SQLite data
```

### Why the split exists

- Docker on macOS and Windows runs inside a VM and does not get true host-network visibility by default.
- Device discovery and packet capture are more reliable from a native process with direct interface access.
- Core can still run a built-in scanner on suitable Linux hosts, but the native sensor is the primary design.

## What Core Does Today

- receives device and DNS data from sensors
- runs local DNS scoring and enrichment
- stores events and device inventory
- exposes the UI and API
- manages scan targets, suppression rules, and whitelist rules

### Core services

| Service | Purpose | Status |
| --- | --- | --- |
| `backend` | API, event enrichment, device/event storage | shipped |
| `frontend` | dashboard UI | shipped |
| `collector` | syslog and normalized log ingestion path | shipped, limited public workflows today |
| `telemetry` | optional outbound sharing path | scaffolded |
| `threat-network` | community intelligence backend | scaffolded |

## What the Sensor Does Today

- runs active network discovery with `nmap`
- captures plaintext DNS traffic passively on a chosen interface
- pushes device and DNS events back to Core
- executes scan targets defined in Core

### Supported sensor reality today

- **Public install path:** macOS and Linux
- **Current workflow:** native install, local network access, and elevated privileges for the strongest visibility
- **Windows:** not yet a supported public install story

## Data Sources

### Available now

- passive DNS capture from the native sensor
- Pi-hole polling
- AdGuard Home polling
- local threat-intel feeds for enrichment

### Early or partial

- router and firewall ingestion through the collector path
- UniFi connector code in the backend

### Planned next

- OpenWRT connector
- pfSense / OPNsense ingestion
- MikroTik connector
- more passive discovery sources such as ARP, DHCP, mDNS, and SSDP
- additional local DNS collection modes for advanced users

## Detection Pipeline

Vedetta currently focuses on DNS-first security signals. The backend includes detectors for:

- DGA-like domain patterns
- beaconing behavior
- DNS tunneling patterns
- DNS rebinding
- DNS bypass and public-resolver use

Threat-intelligence enrichment is local-first. The current community threat network should be treated as future work, not as a production dependency.

## Deployment Reality

Vedetta is still alpha software. Public docs should reflect the real install shape:

- Core uses Docker Compose
- the sensor is a native install
- the sensor setup still assumes some networking comfort
- `sudo` or equivalent privileges are part of the current story for strong local visibility

That makes Vedetta a good fit today for homelabs, technical home users, consultants, MSPs, and small businesses that want practical visibility without standing up a full SOC stack.

## Privacy And Trust

- the local deployment is the primary product
- the local deployment should stay useful even with no cloud dependency
- telemetry is optional and off by default
- future community sharing should remain opt-in and privacy-conscious

## Security Status

The most important current security note is around sensor-to-Core trust:

- Core can generate sensor tokens during registration
- the end-to-end sensor flow is not fully hardened yet
- the current deployment should be treated as LAN-first alpha software
- public internet exposure is not the intended operating model today

## Public Positioning Notes

When describing Vedetta externally, keep these boundaries clear:

- Vedetta is **not** a Pi-hole companion product, though it can integrate with Pi-hole.
- Vedetta is **not** yet a mature community threat network product.
- Vedetta is **not** yet a consumer plug-and-play box.
- Vedetta **is** a practical self-hosted watchtower for DNS-first monitoring and network visibility.
