# Spec: UniFi Log Ingestion (First Supportable Router/Firewall Path)

> Feature directory: `specs/001-unifi-log-ingestion/`
> Status: Draft
> Backlog: VED-002 (document/validate the UniFi connector workflow), VED-005 (define the first supportable router/firewall ingestion path — resolved: UniFi via hybrid syslog + optional REST)
> Created: 2026-07-03

## Summary

Make UniFi gateways the first router/firewall data source Vedetta can honestly call
"supported." Users point their UniFi Network application's SIEM/syslog export at the
Vedetta collector (UDP 5140, already listening); firewall events arrive as normalized
`firewall_log` events in the existing events pipeline, tagged `source:unifi`, tuned so
the new source adds signal without flooding the dashboard. The existing REST connector
groundwork in `backend/internal/firewall/` is finished as an **optional, off-by-default**
enrichment path (client inventory + IPS events that UniFi does not reliably export via
syslog). The user-visible outcome: a UniFi owner follows a one-page setup guide, and
within minutes sees firewall blocks correlated with their device inventory — without a
noisy wall of WAN scan drops.

## Motivation & Evidence

- `docs/roadmap.md` "Planned next" names router/firewall log aggregation with UniFi
  first; `research/09-implementation-roadmap.md` calls UniFi "high-value because UniFi
  is the most common prosumer/SMB network stack."
- `docs/backlog.md` VED-005 asks for the first supportable ingestion path and VED-002
  asks to validate/document the existing UniFi connector groundwork. This spec resolves
  both with one decision: **hybrid — syslog/CEF push is the supported event path; the
  REST connector is optional inventory enrichment.**
- `research/deep-dive-firewall-connectors.md` (primary research): UniFi exports CEF via
  its SIEM integration but does **not** reliably forward IPS/IDS detections to syslog;
  those are only available via the controller REST API. It also documents the connector
  interface already present in `backend/internal/firewall/`.
- `research/02-log-aggregation.md`: Fluent Bit is the right collector (450 KB binary,
  ~2 MB RAM, fits the Pi 4 budget); the UDP 5140 syslog input and the HTTP output to
  `/api/v1/ingest` already exist in `collector/config/fluent-bit.conf`.
- The historical blocker is gone: `POST /api/v1/ingest` is implemented and working
  (single object, array, and Fluent Bit `[timestamp, record]` pairs; validation;
  enrichment; batch `InsertEvents`). `GET /api/v1/events`, `/stats`, `/timeline`, the
  sequential migration runner (17 migrations), and the daily retention enforcer all
  exist. The pipeline is ready for its first external log source.
- Local analysis (`analysis-notes/03-unifi-ingestion.md`, gitignored) confirms the
  sequencing: pipeline unblock is done, UniFi is the natural next data source, and SNR
  re-tuning is the main new work.

## User Stories

- As a **homelab user with a UniFi gateway**, I want to forward my gateway's syslog to
  Vedetta so that firewall blocks and client events show up alongside DNS events
  without installing anything on the gateway.
- As a **small business operator**, I want Vedetta to tell me when a device on my IoT
  VLAN has outbound traffic *blocked* by the firewall so that I can spot compromised or
  misconfigured devices — and I don't want thousands of routine WAN scan drops burying
  that signal.
- As a **UniFi owner who also wants inventory context**, I want to optionally connect
  Vedetta to my controller with a read-only API key so that firewall events are
  enriched with client names, connection type, and network/VLAN — while Vedetta stays
  fully functional if I never do this.
- As a **Vedetta contributor**, I want the UniFi path documented end to end (what is
  supported, what is experimental) so that the next connector (pfSense/OPNsense,
  OpenWrt) can follow the same shape.

## Requirements

### Functional

- FR-1: Vedetta MUST ingest UniFi syslog output on the existing collector UDP 5140
  input, in both formats UniFi produces: CEF (modern UniFi OS "SIEM Server" export) and
  legacy iptables-style kernel log lines (USG/EdgeOS-style `[RULESET-N-A]` messages).
- FR-2: Firewall messages MUST be normalized to the existing `FirewallEvent` shape
  (action, protocol, src/dst IP and port, interface, direction, rule) and stored as
  `event_type = "firewall_log"` events via `POST /api/v1/ingest` — structured fields in
  the event `metadata` JSON and `tags`, no new `events` columns (see plan.md).
- FR-3: Every UniFi-derived event MUST carry the tag `source:unifi` so queries,
  suppression rules, and the UI can filter by origin. Action tags (`fw:block`,
  `fw:allow`, etc.) and direction/interface context MUST be queryable via tags or
  metadata.
- FR-4: Non-firewall UniFi syslog lines (AP chatter, DHCP renewals, stp/kernel noise)
  MUST be dropped or aggregated at the collector — they never reach the events table as
  individual rows.
- FR-5: SNR tuning MUST ship with the feature: default suppression/whitelist rules for
  WAN inbound scan drops and known-benign block patterns (seeded via a new migration,
  `is_default = TRUE`, user-disableable), plus scoring context that boosts blocked
  *outbound* traffic from LAN/IoT devices (see plan.md SNR section).
- FR-6: The REST connector (`backend/internal/firewall/unifi.go`) MUST be completed to
  the point of "documented experimental": configurable off-by-default, API-key auth
  (`X-API-KEY`) in addition to the existing username/password login, client inventory
  sync into the device registry, and IPS event polling. It is enrichment, not the
  primary event path.
- FR-7: A setup guide (`docs/connectors/unifi.md`) MUST document: enabling UniFi
  SIEM/syslog export toward the collector, which log categories to enable, expected
  event volume, the optional REST connector setup, and what is supported vs
  experimental. This closes VED-002.
- FR-8: `POST /api/v1/ingest` MUST support optional bearer-token authentication
  (ingest scope) so a syslog source on the LAN cannot trivially inject forged events;
  default behavior stays backward compatible with the existing collector deployment
  (see plan.md "Auth" and Constitution note below).
- FR-9: Malformed or unparseable syslog lines MUST NOT create events; they are counted
  (collector-side metric/log) and a sample is logged for parser improvement.

### Non-Functional

- NFR-1: Pi 4 hardware floor — the added collector parsing (Lua CEF/iptables transform)
  and ingest volume MUST fit the idle budget (<200 MB RAM, <5% CPU core paths). A
  collector-side throttle caps sustained firewall event throughput (default
  2,000 events/min) so a WAN scan flood degrades to sampling, not to OOM or SD-card
  thrash.
- NFR-2: Works with Core + native sensor only — UniFi ingestion is additive. No new
  required dependency: without a UniFi device, nothing changes; with one, only syslog
  export configuration on the UniFi side is needed (no agent on the gateway).
- NFR-3: Storage: at ~1,000–10,000 firewall events/day post-suppression (per
  `research/02-log-aggregation.md` volume estimates) the 90-day retention window stays
  within the existing SQLite sizing envelope (~≤1 GB total).
- NFR-4: Backward compatibility: no changes to existing event fields or tags; new tags
  are additive; sensors and the collector upgrade independently of Core.

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | Yes (peripherally) | No change to the sensor. UniFi ingestion flows through the Docker-side collector + Core only; L2 visibility still comes from the native sensor. No Docker-collapse proposals. |
| Pi-hole optional | Yes | UniFi is another *optional* input beside Pi-hole/AdGuard/native capture. Vedetta delivers full value with neither; the collector's Pi-hole tail input is untouched. |
| Passive-first | Yes | Syslog push is passive receipt of logs the gateway already emits — zero gateway cooperation beyond one settings toggle, no active scanning. The REST poll is optional, read-only, and off by default. |
| V1 scope (no LAN scan/exploit) | Yes | Log ingestion only. No active vulnerability assessment, no exploit verification, no full LAN scanning. Scope cuts listed below. |
| SNR re-tune for new sources | Yes | Core of this spec: default suppression rules, WAN-scan-noise aggregation, context scoring, and a recorded SNR validation pass are REQUIRED before UniFi is labeled "supported" (FR-5, plan.md SNR Tuning Plan). |
| Privacy / opt-in telemetry | Yes | All data stays local. Firewall events follow the existing PII posture (source_hash HMAC, local-only raw IPs). Nothing UniFi-derived feeds telemetry/threat-network (both still stubs). |
| Environment data handling | Yes | All examples in this spec directory use RFC 5737 IPs, `00:00:5E:00:53:xx` MACs, and placeholder hostnames. Live captures used to validate the parser are written to gitignored `analysis-notes/` only (tasks.md T1.2). |
| One data source at a time | Yes | UniFi lands as a complete, tuned workflow (ingest → normalize → suppress → document → validate) before pfSense/OPNsense or OpenWrt start. |
| New sequential migration only | Yes | One new migration `018_unifi_firewall_defaults.sql`; no committed migration is edited. |

## Signal-to-Noise Impact

This is the first source since DNS that can emit thousands of events/day, and most of
them are noise by default. New noise patterns and the tuning work they demand:

| Noise pattern | Volume risk | Tuning shipped with this feature |
| --- | --- | --- |
| WAN inbound default-drop (internet background radiation, scanners hitting 203.0.113.x WAN IP) | Very high (can be 10k+/day) | Collector-side aggregation: individual WAN-inbound drops are not stored as rows; a periodic rollup event (`tags: ["source:unifi","wan_scan_noise"]`, counts in metadata) is stored instead. Default whitelist rule keeps rollups at score 0. |
| Legitimate blocked IoT outbound (cameras/TVs phoning home to disallowed destinations, expected on segmented networks) | Medium | Default suppression by (device, dst, rule) recurrence: first occurrence scores as signal (`new_fw_block` tag); repeats within a window are deduplicated/score-decayed. User can whitelist per device+destination. |
| Broadcast/multicast and inter-VLAN chatter blocks (mDNS, SSDP across segments) | Medium | Default whitelist rules for well-known multicast/broadcast destination patterns (`category: firewall`), seeded `is_default = TRUE` in migration 018. |
| Client connect/disconnect and AP/system CEF categories | Medium | Not stored as firewall events. Dropped at the collector in V1 (out of scope below) — only firewall/security categories pass. |
| Admin/self-inflicted noise (Vedetta's own nmap discovery tripping gateway rules) | Low | Default whitelist rule matching the Core/sensor host source IP pattern for `firewall_log` events, documented in the setup guide. |

Signal this source adds: blocked outbound from risk-flagged devices (correlates with
`risk_category` from migration 016), first-seen firewall blocks per device, IPS events
(via optional REST path), port-forward-related exposure context, and cross-source
correlation (DNS query → firewall block for the same device).

The source is NOT called "supported" until the SNR validation loop in plan.md runs on
simulated + live traffic and the results are recorded (tasks.md Phase 5 + Final Gate).

## Out of Scope

- **pfSense/OPNsense, OpenWrt, MikroTik connectors** — one data source at a time; the
  filterlog research is done but lands in a later spec.
- **UniFi client connect/disconnect and AP event ingestion** — different noise class
  and different value proposition (presence tracking); revisit after firewall events
  are tuned.
- **DPI/application stats and network-health polling** — dashboard/metrics work, not
  security events; the REST connector's `GetFirewallState`/health surface beyond basic
  connectivity checks stays experimental.
- **Firewall rule/config drift detection** — needs stored rule-state history; deferred
  until the connector path matures.
- **Acting on the firewall (blocking clients via UniFi API)** — Vedetta is
  watch-only in V1; write access to the gateway is a hard scope cut.
- **TCP/TLS syslog transport** — UDP 5140 only in V1 (matches existing collector
  input); TLS syslog needs cert management UX that isn't justified yet.
- **Multi-site / multi-controller UniFi** — single controller/gateway assumed;
  multi-site tagging is a follow-up.
- **CEF ingestion from non-UniFi vendors** — the Lua transform is written for UniFi's
  dialect; generic CEF support is not claimed.

## Open Questions

- [ ] Exact CEF device-event IDs and extension keys per UniFi Network version — the
      contract (`contracts/unifi-syslog-cef.md`) documents the expected mapping from
      vendor docs/research; T1.2 validates against a live capture (sanitized before
      anything lands in tracked files) and updates the contract.
- [ ] Whether modern UniFi OS gateways still emit the legacy iptables-style lines when
      "syslog" (non-SIEM) export is enabled — determines how much weight the fallback
      parser needs.
- [ ] Rollup window for WAN scan noise (initial: 15 min) — validate against live volume
      in Phase 5 before freezing the default.
- [ ] Should ingest-token enforcement become the default in the next release once the
      collector ships with token support? (Tracked in `docs/auth-hardening-plan.md`.)
