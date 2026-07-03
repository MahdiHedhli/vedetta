# Plan: UniFi Log Ingestion (First Supportable Router/Firewall Path)

> Spec: `specs/001-unifi-log-ingestion/spec.md`
> Status: Draft
> Created: 2026-07-03

## Architecture Overview

### Decision 1 — Ingestion mode: syslog/CEF push vs REST poll vs hybrid → **Hybrid**

| Option | Pros | Cons | Verdict |
| --- | --- | --- | --- |
| Syslog/CEF push only (collector → `/api/v1/ingest`) | Zero polling load on gateway; passive; infra already exists (UDP 5140 input, HTTP output); no credentials stored | UniFi does not reliably export IPS/IDS detections via syslog; no client inventory | Primary path, but incomplete alone |
| REST connector poll only (`backend/internal/firewall/unifi.go`) | IPS events + client inventory + rules; groundwork exists | Requires stored credentials; polling load on embedded controller; misses raw firewall log volume (REST does not expose per-packet allow/block stream); more failure modes | Insufficient alone |
| **Hybrid (chosen)** | Syslog carries the event stream (firewall blocks/allows) passively; REST fills the two gaps syslog can't (IPS events, client inventory enrichment) | Two paths to document | **Chosen.** Syslog is required-for-support; REST is optional, off by default. |

This matches the constitution's passive-first principle: the supported path needs only
a one-time syslog-export toggle on the UniFi side. The REST connector never becomes a
prerequisite.

### Components touched (Core + Sensor + Collector model)

```
UniFi gateway/controller
  │  syslog UDP 5140 (CEF or legacy iptables-style)          [push, primary]
  ▼
Collector (Fluent Bit, Docker)
  ├─ [INPUT] syslog udp 5140 (exists)
  ├─ [FILTER] lua unifi_transform.lua  (NEW: CEF + iptables parse → Event JSON,
  │           category filtering, WAN-scan rollup, throttle)
  └─ [OUTPUT] http POST /api/v1/ingest (exists; NEW: optional bearer token header)
  ▼
Core backend (Go, Docker)
  ├─ api.handleIngest (exists: validate/defaults/enrich/insert)
  ├─ dnsintel.Enricher (MODIFIED: firewall_log-aware branch — skip DNS heuristics,
  │           apply firewall scoring + whitelist + device cross-ref)
  ├─ firewall.Manager + UniFiConnector (MODIFIED: API-key auth, inventory sync,
  │           IPS PollEvents wiring; registered only when configured)  [poll, optional]
  └─ store (exists: InsertEvents, UpsertDevice, whitelist_rules)
  ▼
SQLite events/devices tables → GET /api/v1/events|stats|timeline → frontend
```

The native L2 sensor is untouched.

## Data Flow

1. **Source:** UniFi Network app → Settings → System → Logging/SIEM export → collector
   host, UDP 5140, CEF format (preferred). Legacy gateways: remote syslog export
   (iptables-style lines).
2. **Collector normalization (`collector/config/unifi_transform.lua`, new):**
   - Detect line class: `CEF:0|Ubiquiti|...` header → CEF parse; `[NAME-N-A]IN=...`
     kernel line → iptables parse; anything else from the firewall tag → drop+count.
   - Map to the wire event (see `contracts/unifi-syslog-cef.md`): `event_type:
     "firewall_log"`, `source_ip` = LAN-side IP (for outbound; else empty),
     `tags: ["source:unifi", "fw:<action>", "dir:<in|out>"]`, structured fields in
     `metadata` JSON (action, protocol, src/dst IP+port, interface, direction, rule,
     raw_log).
   - WAN-inbound drops: not emitted individually; accumulated per 15-min window into
     one rollup event (`tags += ["wan_scan_noise"]`, metadata carries counts and top
     ports — synthetic example in the contract).
   - Throttle filter caps sustained `firewall.*` throughput (default 2,000 events/min).
3. **Ingest:** existing `POST /api/v1/ingest` — Fluent Bit pair format already
   handled; `firewall_log` already in `allowedEventTypes`; batch `InsertEvents`.
4. **Storage:** `events` table, no new columns (Decision 2 below).
5. **Enrichment:** `Enricher.Enrich` gains a `firewall_log` branch: device cross-ref by
   `source_ip` (vendor, segment, `risk_category`), scoring (below), whitelist
   application (existing engine keyed on tag/source-IP patterns).
6. **Optional REST poll:** `firewall.Manager` polls `UniFiConnector` (IPS events →
   `FirewallEvent.ToEvent()` → `InsertEvents`; client list → device registry upsert
   with `discovery_method: "unifi_connector"`). Interval defaults: events 60 s,
   inventory 300 s.
7. **UI:** events surface through the existing events view; new filter chip for
   `source:unifi` and event-type `firewall_log` (frontend `App.jsx` filter additions).

## Schema Changes

**Decision 2 — FirewallEvent → events mapping needs NO events-table migration.**
The `events` table already has everything required: `event_type` CHECK includes
`firewall_log` (001), `metadata` TEXT (011), `source_ip` (011), `tags`, `blocked`,
`network_segment`. Structured firewall fields ride in `metadata` JSON (per the
deep-dive recommendation: metadata column for V1 flexibility; dedicated columns only
if V2 query patterns demand them). `network_segment` keeps its CHECK
(`default|iot|guest`) — the raw UniFi interface name (`br0`, `eth8`, VLAN name) goes in
`metadata.interface`, and an optional interface→segment mapping in connector/collector
config translates to the canonical segment.

**One new migration is still required — seeded SNR defaults:**

`siem/migrations/018_unifi_firewall_defaults.sql` (new sequential file; no committed
migration edited):

- INSERT (idempotent, `INSERT OR IGNORE` by fixed `rule_id`) default
  `whitelist_rules` rows, `is_default = TRUE`, `category = 'firewall'`:
  - `wl-fw-wan-scan-rollup` — `tag_match = 'wan_scan_noise'` (keeps rollups score 0 /
    out of the anomaly feed).
  - `wl-fw-multicast-broadcast` — destination-pattern rules for well-known
    multicast/broadcast blocks (mDNS 224.0.0.251, SSDP 239.255.255.250, broadcast) —
    expressed via `tag_match = 'fw:multicast'` (tag applied by the collector transform).
  - `wl-fw-self-scan` — commented template (disabled row) for suppressing the Vedetta
    host's own discovery traffic; the setup guide tells users to fill in their Core IP.
- No new tables, no new indexes (existing `idx_events_type_time`, `idx_events_source`
  cover the firewall query patterns; re-evaluate after live volume in Phase 5).

Fresh-install migration test required (tasks.md T3.4, Final Gate).

## API & Wire Contracts

- **`POST /api/v1/ingest` (existing, behavior extended):**
  - Payload unchanged — `models.Event` JSON; contract for UniFi-derived events in
    `contracts/unifi-syslog-cef.md` (crosses the collector→Core service boundary).
  - **Decision 3 — Ingest auth:** add optional bearer-token auth with a new token
    scope `ingest` (extends `auth` package + `api_tokens` from migration 014 — scope is
    a TEXT value, so no schema change). Semantics:
    - No ingest-scope token exists (default/bootstrap): endpoint stays open, exactly
      as today — backward compatible with already-deployed collectors.
    - An ingest-scope token exists AND `VEDETTA_REQUIRE_INGEST_AUTH=1` (compose
      default for new installs): requests must present `Authorization: Bearer <token>`
      (Fluent Bit `[OUTPUT] http` `Header` line, wired by install tooling).
    - This mirrors the sensor-token bootstrap pattern already in `router.go`.
  - New per-request guardrail: max 5,000 events per request (on top of the existing
    10 MB body cap); overflow → 413 with count, collector retries with smaller flush.
- **Backward compatibility:** all new tags (`source:unifi`, `fw:*`, `dir:*`,
  `wan_scan_noise`, `new_fw_block`) are additive; no field or tag is renamed; a Core
  upgrade without a collector upgrade changes nothing; a collector upgrade against an
  old Core degrades gracefully (unknown tags are stored as-is; token header ignored).
- **UniFi REST connector (optional path):** config via backend env/JSON
  (`VEDETTA_UNIFI_HOST`, `VEDETTA_UNIFI_API_KEY`, `VEDETTA_UNIFI_TLS_SKIP_VERIFY`,
  poll intervals). Not registered unless host+credentials are set. Read-only endpoints
  only (`stat/sta`, `stat/event?type=EVT_IPS_`, `stat/alarm`, `stat/health`).
- **Contract file:** `contracts/unifi-syslog-cef.md` — CEF header/extension mapping,
  legacy iptables-style mapping, normalized event JSON, rollup event shape. All
  examples synthetic (RFC 5737 / `00:00:5E:00:53:xx`).

## Detection & Enrichment

- `dnsintel.Enricher.Enrich` currently assumes DNS-shaped events; add an early branch:
  `event_type == "firewall_log"` → skip domain/DGA/beaconing heuristics, run:
  - **Device cross-ref:** look up device by `source_ip` (outbound events); attach
    `device_vendor`, canonical `network_segment`; if the device has `risk_category`
    (`known_exploited` / `eol_eos` / `high_risk_iot`, migration 016), add tag
    `risky_device_fw_block` and boost score.
  - **Scoring (initial values, tuned in Phase 5):**
    - WAN-inbound rollup: 0.0.
    - Blocked outbound, known device, recurring pattern: 0.1 (visible, not alerting).
    - Blocked outbound, first occurrence for (device, dst, rule): 0.4 + tag
      `new_fw_block`.
    - Blocked outbound from `risk_category` device: +0.3 (cap 1.0).
    - IPS events (REST path): map UniFi severity 1→0.4, 2→0.7, 3→1.0, tag `ips`.
  - **Whitelist:** existing engine (migration 013 + `store/whitelist.go`) applies via
    `tag_match` / `source_ip_pattern`; new defaults from migration 018.
- Existing detectors unaffected: DNS scoring, EOL/risk fingerprinting, and sensor
  actionability paths do not change. New cross-source value: firewall blocks and DNS
  anomalies for the same `source_ip` become correlatable in the UI/timeline (no new
  correlation engine in this feature — deliberate cut).

## SNR Tuning Plan

Shipped WITH the feature (not follow-up):

1. **Collector-side classification** (`unifi_transform.lua`): category filter (only
   firewall/security classes become events), WAN-inbound rollup (15-min window),
   multicast/broadcast tagging (`fw:multicast`), malformed-line drop counters.
2. **Seeded defaults** (migration 018): whitelist rules above, `is_default = TRUE`,
   user-disableable in the existing whitelist UI.
3. **Scoring context** (enricher branch): table above; `source:unifi` tag on every
   event enables one-click suppression scoped to the source.
4. **Validation loop (required before "supported" label):**
   - *Simulated:* replay corpus of synthetic CEF + iptables lines (contract examples ×
     volume harness) through a local Fluent Bit → assert event counts, rollup
     behavior, tag/metadata correctness, throttle engagement (extends the existing
     validation tooling pattern from the SNR heartbeat work).
   - *Live:* run ≥72 h against a real UniFi gateway (owner's environment); record
     events/day pre- and post-suppression, top noise patterns, false-positive review —
     summarized with sanitized examples in `docs/SNR-IMPROVEMENTS.md`; raw captures
     stay in gitignored `analysis-notes/`.
   - *Acceptance:* post-suppression steady-state ≤ ~500 stored firewall events/day on
     a typical home network, zero score>0.5 events from routine traffic during the
     live window, and the "blocked outbound from risky device" injection test scores
     ≥0.7.

## Failure Modes & Limits

| Failure | Behavior |
| --- | --- |
| UniFi stops sending / wrong destination | UDP is fire-and-forget: collector simply receives nothing. Setup guide includes a verification step (`GET /api/v1/stats` shows `firewall_log` counts). Optional REST connector `Health()` surfaces controller reachability. |
| Malformed / unknown syslog dialect | Dropped at the Lua filter with a counter + one sampled line per interval in collector logs (FR-9). Never inserted as garbage events. |
| Flood (WAN scan storm, misconfigured export of all categories) | Layered: (1) rollup absorbs WAN-inbound volume; (2) Fluent Bit throttle filter caps sustained events/min — excess is sampled, not queued; (3) Fluent Bit `mem_buf_limit` on the syslog input prevents collector OOM; (4) backend 10 MB body + 5,000 events/request caps. Degradation is lossy sampling of noise — acceptable for UDP syslog by design. |
| Core down / ingest 5xx | Fluent Bit HTTP output retries with backoff within its memory buffer; beyond the buffer, oldest records drop (bounded loss, bounded memory — Pi 4 first). |
| REST connector auth failure / controller offline | Connector marks `ConnectorHealth.LastError`, manager backs off (existing pattern); syslog path unaffected — enrichment degrades, events keep flowing. |
| SQLite growth | Existing daily retention enforcer (90-day default) covers `firewall_log`; NFR-3 sizing keeps 90 days ≤ ~1 GB. Phase 5 records actual bytes/event. |
| Rate/volume expectation (Pi 4) | Design point: 10k raw lines/day typical, 100k/day storm. Post-filter target ≤ 500 stored/day. Lua transform budget: <1 ms/line; throttle guarantees a ceiling regardless. |

## Constitution Check

The spec's constitution table holds for this technical approach; verification notes:

- **Passive-first:** primary path is push-based syslog; REST poll optional/off by
  default — no tension.
- **L2 sensor split:** untouched; the collector remains the Docker-side log funnel.
- **V1 scoping:** no gateway write access, no active scanning, no new attack surface
  beyond the already-open UDP 5140 (now with documented flood protection and optional
  ingest auth — a net hardening).
- **SNR discipline:** tuning + validation are in-scope deliverables, gated in tasks.md.
- **Migrations:** one new sequential file (018); none edited. ⚠ Note: `016` and `017`
  ship in the same release window — tasks.md verifies the full chain on fresh install.
- **Environment data:** contract and tests use synthetic values; live validation
  captures confined to `analysis-notes/`. Release-blocker scrub check in Final Gate.
- **New tension:** none identified. Ingest auth default-off (backward compat) is the
  only judgment call; it follows the alpha posture ("public internet exposure not
  supported yet") and the sensor-token bootstrap precedent, and hardening-by-default is
  tracked in `docs/auth-hardening-plan.md`.

## Test Strategy

- **Unit (backend):** enricher `firewall_log` branch (scoring matrix, device
  cross-ref, whitelist application); ingest auth (no-token open, token-required 401/
   valid-token 200, per-request event cap); `FirewallEvent.ToEvent` metadata/tags;
  UniFi connector against `httptest` fixtures (API-key + cookie auth, UDM `/proxy/
  network` prefix detect, IPS event parse) — fixtures are synthetic/sanitized.
- **Unit (collector):** Lua transform tested via `fluent-bit -c test.conf` golden-file
  runs in CI-style script: synthetic CEF, iptables, malformed, and rollup-window cases
  from the contract → expected normalized JSON.
- **Integration:** docker-compose up (collector + backend) → `logger`-style UDP replay
  of the synthetic corpus → assert via `GET /api/v1/events?type=firewall_log` counts,
  tags, metadata; flood replay → assert throttle + no backend errors + memory ceiling.
- **Migration:** fresh-install test — empty DB, run full chain 001→018, verify
  `schema_migrations` rows and seeded whitelist defaults; upgrade test — DB at 017,
  apply 018 only, verify idempotent re-run.
- **Manual/live:** owner's UniFi gateway 72-h validation pass (Phase 5), REST
  connector smoke against a real controller; results summarized sanitized.
- **Green-before-commit:** `go build ./... && go test ./... -short` (backend, sensor),
  `npm run build` (frontend) — per constitution, enforced in Final Gate.
