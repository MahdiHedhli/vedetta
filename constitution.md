# Vedetta Constitution (Non-Negotiables)

This document encodes the core constraints and principles that all Vedetta development, planning, and implementation must respect. It is the highest-priority reference for scope, architecture, and trade-off decisions.

## Core Architecture
- Native L2 sensor (vedetta-sensor) + Docker Core split is fundamental. The sensor provides privileged local-network visibility (passive + limited active) that containers cannot reliably achieve on all platforms (especially macOS/Windows Docker VM scenarios).
- Pi-hole / AdGuard are optional pollers/integrations only. Not required. Core must remain useful with the native sensor alone.
- Passive-first philosophy: prioritize passive capture (DNS, mDNS, DHCP, ARP, SSDP) and existing collector paths over active scanning or exploit verification.

## V1 Scope Exclusions (Hard)
- V1 explicitly excludes full LAN scan / exhaustive active discovery as a primary path.
- V1 excludes exploit verification / active payload testing / offensive actions.
- Pi-4 (or equivalent low-power ARM single-board with SD storage) is the floor for target deployment. All volume, backpressure, and retention design must consider SD card longevity (WAL, incremental_vacuum, controlled VACUUM, retention enforcement).

## Ongoing Priorities
- SNR (signal-to-noise) improvement is continuous and first-class. New data sources (e.g. firewall) must not degrade the existing 80/20 target without explicit, measured mitigation. High-volume low-severity noise (e.g. UniFi block logs) requires source-specific suppression and normalization discipline.
- Local-first / opt-in telemetry only. No cloud dependency for core functionality. User data stays on their hardware.
- Primary-source grounding: all detections, device attributes, and events must be traceable to observed data from the local network or explicitly configured connectors. No fabricated or inferred fields without clear provenance and confidence.

## Connector & Ingestion Layer
- The /ingest endpoint and firewall filter extensions (json_extract on metadata for action/protocol/src-dst/ports/interface etc.) now exist.
- Connector layer (normalization before or at ingest) is responsible for parsing vendor-specific raw_log formats into the structured FirewallEvent fields so that PIECE 3 filters are not inert.
- pfSense/filterlog example: positional CSV embedded in raw_log.
- UniFi: its own format (CEF for SIEM/syslog export per current official docs; also internal suricata/iptables). Normalization location must favor consistency with the existing Pi-hole approach (collector-side Lua transform like pihole_transform.lua emitting clean Event-shaped JSON with top-level fields or properly lifted metadata).
- NEW migrations only (never edit 001 or 016). Additive columns with guarded ensures in runner.

## Other
- All changes must pass full backend/ + sensor/ `go build ./... && go test ./...` (multi-module) before any main merge.
- .env secrets (GITHUB_PAT etc.) are runtime-only; pushes use inline URL + -c credential.helper= only after live curl verification of "login":"MahdiHedhli".
- Spec Kit artifacts (this constitution, spec, plan, tasks, analyze) for future work (e.g. UniFi) must explicitly call out the above constraints and the Stage 1 raw_log parsing in-scope item.

Violations of this constitution are scope drift and must be flagged in /speckit.analyze and PR descriptions.
