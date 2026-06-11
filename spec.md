# UniFi Ingestion Spec (V1 path, planning artifact only)

**Status**: Planning only. Do not implement. See plan.md and tasks.md for phased execution. This spec is the output of /speckit.specify after gating research.

## Gating Research Summary (CURRENT official Ubiquiti docs as of 2026-06)
- Primary reference: https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration (and related Traffic Flows article).
- Export mechanism for SIEM/syslog: UniFi Network / UniFi OS supports **SIEM Server** destination under Integration > System Logging / SIEM (or Settings > CyberSecure > Traffic Logging in some views).
- Format: **All logs exported using Common Event Format (CEF)**. "Logs are all exported using the Common Event Format (CEF)."
- Categories relevant: Security (Firewall, Honeypot, Intrusion Prevention) — "Threat Detected and Blocked, Honeypot Triggered, Blocked by Firewall".
- Additional paths: Suricata raw logs on gateway (/var/log/suricata/suricata.log) for IPS/IDS details; internal iptables/policy engine logs; NetFlow/IPFIX for sampled flows; CSV export from Insights > Flows (UI only).
- Not pure RFC5424 JSON by default for the SIEM path; CEF over syslog is the documented standardized export.
- Older gateways (pre ~v8.5) had plain syslog; modern (v9.3+) emphasize CEF for SIEM.
- No assumption of direct REST "export" API for logs in V1 scope (REST groundwork exists elsewhere but passive syslog collector path is preferred).

Citations: official help.ui.com articles linked above; community threads confirm CEF-wrapped syslog for firewall/IPS events.

## V1 Recommendation (passive-first)
Choose the **passive syslog via existing Fluent Bit collector** path (extend current firewall INPUT + syslog-rfc3164 + modify + Lua normalizer, POST to existing /api/v1/ingest).

Rationale favoring passive-first + existing infra:
- Aligns with Vedetta constitution (passive-first, Pi-hole optional, no new active/REST invention for V1).
- Reuses the collector already wired for pfSense-style firewall (syslog input, raw_log embedding, /ingest 202 path, auth reuse).
- /ingest + PIECE 3 json_extract filters now exist on main — target them directly.
- UniFi CEF is structured enough for a thin Lua parser (or grok + modify) to lift key fields (action, protocol, src/dst, ports, interface) out of the CEF message into the Event shape or metadata so filters function.
- SNR impact is first-class: UniFi "block" logs are high-volume, low-severity noise by default. Source="unifi" suppression and volume backpressure (Pi-4 SD) must be designed in from the start.
- Alternative (existing REST connector groundwork) or hybrid deferred; passive syslog is the thin-slice V1 that exercises the already-shipped ingest pipeline.

## Explicit In-Scope (from Stage 1 finding — non-negotiable)
The collector/connector layer **must parse the vendor firewall log into the FirewallEvent fields** (action, protocol, src/dst IP, ports, interface/segment) so that the PIECE 3 json_extract filters on /events (and any future UI) actually function.

Current state (documented in connector-guide.md): the collector leaves details inside `raw_log`; pfSense/filterlog is positional CSV in raw_log; UniFi is its own format (CEF per official docs above). Without normalization, the filters are inert.

**Where normalization happens (spec decision favoring consistency)**: collector-side Lua transform (modeled exactly on pihole_transform.lua + the existing firewall modify filter in fluent-bit.conf). This keeps the "dumb collector → structured Event JSON" contract, reuses the HTTP output to /ingest, and avoids handler-side special cases. Handler can still do final lift of any top-level non-Event keys into metadata for safety (as done for the pipeline).

The spec must define:
- Input: syslog (CEF) from UniFi gateway/OS (configure SIEM destination to the Fluent Bit listener).
- Parsing: CEF header + extension fields (or message body) → map to event_type=firewall_log, source=unifi, raw_log (verbatim for audit), plus top-level or metadata-lifted action/protocol/src_ip/dst_ip/src_port/dst_port/interface.
- Output to /ingest: same shape the Pi-hole path produces (or the honest synthetic firewall shape used in tests).
- SNR: explicit source="unifi" tag or metadata; retention / suppression hooks; volume throttling note for Pi-4.

Out of scope for V1 spec/plan: full bidirectional REST sync, exploit verification, LAN-wide active mapping from UniFi, or changing the Event schema (use metadata + new migration only if additive columns required later).

## Non-Functional
- Pi-4 floor: backpressure, batching, retention (daily EnforceRetention + VACUUM) must accommodate high-volume low-severity UniFi blocks without SD wear or OOM.
- Idempotency / duplicate handling already in ingest path.
- Auth: reuse existing sensor/ingest token protection (RequireAuth + X-Sensor-ID or admin).
- No change to 001/016 migrations.

## Mapping to Backlog
- VED-002 (connectors / firewall)
- VED-005 (UniFi integration)

See tasks.md for thin-slice phasing.
