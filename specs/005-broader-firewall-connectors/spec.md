# Spec: Broader Firewall Connectors (OpenWRT, pfSense/OPNsense, MikroTik)

> Feature directory: `specs/005-broader-firewall-connectors/`
> Status: Draft
> Backlog: VED-005 (broader connectors deferred here per its notes; no implementation backlog item until specs/001 ships)
> Created: 2026-07-03

## Summary

Extend firewall log aggregation beyond UniFi (specs/001-unifi-log-ingestion/spec.md)
to the remaining "Planned next" platforms: OpenWRT, pfSense/OPNsense, and MikroTik.
Each platform lands as a syslog-first ingestion path through the existing collector
(UDP 5140 → Fluent Bit → `POST /api/v1/ingest`), following the pattern UniFi
establishes. This is a roadmap-direction spec, not an implementation commitment:
it fixes the sequencing, the per-platform ingestion approach, and the bar a
platform must clear before Vedetta may call it supported.

## Motivation & Evidence

- README and `docs/roadmap.md` ("Planned next") name UniFi, OpenWRT,
  pfSense/OPNsense, and MikroTik as the connector expansion order, with the
  explicit caveat that platforms are described honestly as early or planned until
  documented and proven.
- `research/deep-dive-firewall-connectors.md` (M5 deep dive) documents the
  pfSense/OPNsense `filterlog` CSV format field-by-field, both platforms' REST
  APIs, and a Fluent Bit parser + Lua design that plugs into the existing
  collector syslog input.
- `docs/connector-guide.md` documents the `firewall.Connector` interface already
  present in `backend/internal/firewall/` (connector.go, manager.go, unifi.go),
  which polling-based connectors implement.
- Ingest infrastructure is live today: `POST /api/v1/ingest` (single/array/
  Fluent-Bit pairs), batch `InsertEvents`, the collector's UDP 5140 syslog input,
  sequential migrations, and daily retention enforcement. The plumbing for
  syslog-based connectors exists; what each platform needs is a parser,
  normalization, documentation, and an SNR pass.

## User Stories

- As a homelab user running OpenWRT, I want my router's firewall log lines to
  appear as normalized Vedetta events so that blocked inbound traffic and unusual
  outbound connections are visible next to my DNS data.
- As a small business operator on pfSense or OPNsense, I want to point remote
  syslog at Vedetta and get parsed block/pass events so that I do not need a
  separate SIEM to see what my firewall is doing.
- As a MikroTik user, I want a documented logging recipe (which topics, which
  rule prefixes) so that Vedetta receives parseable events instead of free-text
  noise.
- As an MSP evaluating Vedetta, I want the docs to state plainly which platforms
  are supported vs experimental so that I can set customer expectations honestly.

## Per-Platform Syslog Capabilities Matrix

All examples are synthetic (RFC 5737 IPs, documentation MACs). Formats below are
from the M5 research doc (pfSense/OPNsense) and vendor documentation; each row
must be re-validated against a live or virtualized device before its
implementation spec is written.

| | OpenWRT | pfSense | OPNsense | MikroTik (RouterOS) |
| --- | --- | --- | --- | --- |
| Remote syslog | Built-in (`/etc/config/system`: `log_ip`, `log_port`, `log_proto`) | Built-in (Status → System Logs → Settings) | Built-in (System → Settings → Logging) | Built-in (`/system logging action` type=remote) |
| Syslog RFC | ~RFC 3164 | RFC 3164 default | RFC 5424 default | Non-standard/BSD-style; no structured framing |
| Firewall log format | Kernel netfilter LOG/nflog lines via fw4 (nftables, 22.03+) or fw3 (iptables) | `filterlog` CSV (fully field-documented) | `filterlog` CSV (pf-based, minor field/interface-name differences vs pfSense) | Free-text, topic-based (`firewall` topic); rule `log-prefix` is the only structure hook |
| Logging default | Off per rule (`option log '1'` required; zone-level `log` option) | On for default-deny; per-rule toggle | On for default-deny; per-rule toggle | Off per rule (`log=yes` + `log-prefix` required) |
| Parse difficulty | Medium — stable `IN=… OUT=… SRC=… DST=… PROTO=… SPT=… DPT=…` key-value grammar | Low — CSV positions documented by Netgate | Low — same grammar as pfSense | High — free text; requires a Vedetta-prescribed `log-prefix` convention to be reliable |
| IDS/IPS in syslog | No (not built in) | No (Suricata/Snort log separately) | Yes (Suricata alerts included in syslog; also via built-in REST API) | No |
| Supplementary API | ubus/LuCI RPC (out of scope here) | REST API package (pfrest, 200+ endpoints, not installed by default) | Built-in REST API (key+secret) | RouterOS API / REST API in v7 (out of scope here) |

Synthetic example lines:

```
# OpenWRT (fw4 default-deny, kernel netfilter log)
<4>Jul  3 08:12:41 openwrt kernel: [91203.112] REJECT wan in: IN=eth1 OUT= MAC=00:00:5e:00:53:0a SRC=203.0.113.50 DST=198.51.100.20 PROTO=TCP SPT=54021 DPT=23 SYN

# pfSense (filterlog CSV, RFC 3164)
<134>Jul  3 08:12:41 fw01 filterlog[12345]: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.50,198.51.100.20,54021,23,0,S,914512,,64240,,mss

# OPNsense (filterlog CSV, RFC 5424)
<134>1 2026-07-03T08:12:41+00:00 fw02 filterlog 77 - - 5,,,fae559338f65e11c53669fc3642c93c2,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.50,198.51.100.20,54021,23,0,S,914512,,64240,,mss

# MikroTik (firewall topic, Vedetta-prescribed log-prefix "vedetta-drop")
Jul  3 08:12:41 gw-lab firewall,info vedetta-drop input: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.50:54021->198.51.100.20:23, len 60
```

## What "Honest Experimental Support" Requires

Per the constitution (SNR as ongoing discipline; alpha honesty), a platform moves
through three labels, and the label in README/roadmap must match reality:

1. **Planned** — named in the roadmap, no working path.
2. **Experimental** — requires ALL of:
   - a documented public workflow: exact firewall-side configuration steps
     (remote syslog target, which rules/topics to log, prescribed prefixes) plus
     Vedetta-side setup, in `docs/connectors/<platform>.md`, using synthetic
     examples only;
   - a Fluent Bit parser (and Lua normalization where the format demands it)
     with unit tests against recorded/synthetic log fixtures — no live firewall
     required to run tests;
   - events normalized to the existing `firewall_log` event shape with
     backward-compatible tags.
3. **Supported** — experimental, plus a recorded SNR validation pass: the
   suppression/whitelist/scoring tuning for that platform's noise patterns
   shipped and validated against both simulated traffic and a real deployment,
   with the result written down (as done for the UniFi post-closure monitoring
   pass). No SNR pass, no "supported" label — a connector that parses but floods
   is worse than no connector.

## One-Source-at-a-Time Sequencing Rule

The constitution mandates one data source at a time for major expansions: each
connector lands as a complete, tuned workflow before the next starts. Applied
here:

1. **UniFi** (specs/001-unifi-log-ingestion/) ships and passes SNR validation
   first. Nothing in this spec starts before that.
2. **OpenWRT** — largest FOSS-aligned user overlap; syslog built-in; moderate
   parse effort.
3. **pfSense/OPNsense** — treated as one workstream (shared `filterlog` parser)
   but two SNR passes; OPNsense's RFC 5424 default and Suricata-in-syslog are
   platform-specific tuning work, not a shared checkbox.
4. **MikroTik** — last, because reliable parsing depends on a prescribed
   `log-prefix` convention that must be designed and documented before any
   parser is worth writing.

Each platform gets its own implementation spec (or a scoped amendment to this
directory) when its turn arrives; this spec does not authorize starting any of
them.

## Requirements

### Functional

- FR-1: Each platform ingests via the existing collector syslog path (UDP 5140 →
  Fluent Bit parser → `POST /api/v1/ingest`) as the primary mechanism. REST-API
  polling (pfrest, OPNsense API, RouterOS API) is a per-platform later
  enhancement, not part of this scope.
- FR-2: Events normalize to the existing `firewall_log` event type with
  platform-identifying tags (e.g. `source:openwrt`), consistent with the
  UniFi mapping in specs/001.
- FR-3: Parsers must tolerate the format they don't expect: non-filterlog syslog
  arriving on 5140 is dropped or tagged unparsed, never crashes the pipeline or
  inserts garbage events.
- FR-4: Each platform's documentation prescribes the exact firewall-side logging
  configuration (rules to log, prefixes, syslog RFC) so incoming data is
  predictable.
- FR-5: OPNsense and pfSense share one parser; platform is distinguished by
  configuration/tag, and divergences (interface names, RFC 5424 framing,
  Suricata lines) are handled explicitly.

### Non-Functional

- NFR-1: Pi 4 hardware floor — a chatty firewall (default-deny logging on a busy
  WAN) can emit tens of events/second; parsing plus batch insert must stay
  within the idle budget (<200 MB RAM, <5% CPU core paths), with rate limiting
  or sampling defined per platform in its implementation plan.
- NFR-2: Works with Core + native sensor only. Firewall connectors are additive
  inputs; no platform becomes a prerequisite for any existing feature.
- NFR-3: 90-day retention applies unchanged; firewall log volume must not
  require schema or retention special-casing without a new migration and spec.

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | Yes | Connectors run in Core (Docker); they consume remote syslog/API data and never touch raw sockets, so no pressure on the native-sensor split. |
| Pi-hole optional | Yes | Firewall sources are additive inputs like Pi-hole; none is required, and the product retains value with sensor + Core only. |
| Passive-first | Yes | Syslog ingestion is fully passive from Vedetta's side (firewall pushes); no scanning of or active probing against the gateway is introduced. |
| V1 scope (no LAN scan/exploit) | Yes | Log aggregation only. No exploit verification, no active vulnerability assessment. REST-API polling deferred to per-platform follow-ups. |
| SNR re-tune for new sources | Yes | Core of this spec: each platform requires its own recorded SNR pass before the "supported" label (see honest-support section). |
| Privacy / opt-in telemetry | Yes | All ingested data stays local; nothing here feeds telemetry or the threat network (both remain opt-in and out of scope). |
| Environment data handling | Yes | This spec and all future connector docs use RFC 5737 IPs, 00:00:5E:00:53:xx MACs, and placeholder hostnames only; live validation captures go to gitignored paths. |

## Signal-to-Noise Impact

Firewall logs are the noisiest source class Vedetta will have ingested, and each
platform brings distinct patterns:

- **All platforms:** default-deny WAN logging produces constant internet
  background radiation (scanners, worms hitting 22/23/445/5900). Blocked-inbound
  is the firewall working, not an incident — it needs aggressive aggregation
  (e.g. per-source-per-day rollups) and near-zero default scoring, with scoring
  reserved for outbound blocks and hits on device-risk-flagged hosts
  (known_exploited/eol_eos/high_risk_iot categories).
- **OpenWRT:** log verbosity depends entirely on user rule configuration;
  docs must prescribe a minimal logging profile or users will flood themselves.
- **pfSense/OPNsense:** default-deny logging is on out of the box — highest
  expected volume; OPNsense adds Suricata alert lines needing separate scoring.
- **MikroTik:** without the prescribed log-prefix convention, lines are
  unparseable free text — the noise risk is garbage events, handled by FR-3.

The concrete suppression rules, rollup strategy, and scoring live in each
platform's implementation plan; this spec establishes that no platform ships as
"supported" without that work validated.

## Out of Scope

- Any implementation now — blocked behind specs/001 UniFi shipping + SNR
  validation (one source at a time).
- REST-API polling connectors for these platforms (pfrest, OPNsense API,
  RouterOS API) — syslog-first; API enrichment is a per-platform follow-up spec.
- Firewall control/write actions (blocking clients, editing rules) — read-only
  visibility only in V1.
- Other platforms (Firewalla, Sophos, Fortinet, commercial NGFW) — not on the
  roadmap; the connector guide covers community contributions.
- New event schema columns — reuse `firewall_log` + tags + existing metadata
  paths; any schema change needs its own migration and plan.

## Open Questions

- [ ] Should pfSense and OPNsense count as one roadmap slot or two for the
      one-source-at-a-time rule? (Current position: one parser workstream, two
      SNR passes.)
- [ ] OpenWRT fw4 (nftables) vs fw3 (iptables) log-line differences — does one
      parser cover both, or do we set a minimum OpenWRT version (22.03+)?
- [ ] MikroTik log-prefix convention: what prefix grammar gives us
      action/direction/rule identity without exceeding RouterOS prefix length
      limits, across v6 and v7?
- [ ] Blocked-inbound rollup: aggregate at the collector (Fluent Bit/Lua), at
      ingest, or at query time? Affects Pi 4 volume budget — decide in the first
      platform's plan and reuse.
- [ ] Does the UniFi SNR pass (specs/001) produce reusable suppression
      primitives (per-source rollups, port-based scoring) that these platforms
      inherit, or is tuning fully per-platform?
