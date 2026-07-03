# Plan: Passive Discovery Correlation, Labeling & Multi-Network Handling

> Spec: `specs/004-passive-discovery-correlation/spec.md`
> Status: Draft
> Created: 2026-07-03

## Architecture Overview

Two-sided change inside the existing Core + Sensor split; no new services, no Collector involvement.

```
┌────────────────────────── native sensor ──────────────────────────┐
│ passive capture (gopacket, existing BPF filters)                  │
│   parse.go — REWORKED mDNS record-graph correlation:              │
│     PTR (service→instance) ─┐                                     │
│     SRV (instance→host:port)├─ owner-name keyed maps ─→ per-host  │
│     TXT (instance→kv)       │   DiscoveredHost with correct        │
│     A/AAAA (host→IP) ───────┘   model / services / friendly_name  │
│   ARP / DHCP / SSDP parsers — unchanged shape, + friendly_name    │
└──────────────── POST /api/v1/sensor/devices (additive field) ─────┘
                                 │
┌────────────────────────────── Core ───────────────────────────────┐
│ router.go handleSensorDevices (payload gains friendly_name)       │
│   └→ store: NEW identity resolver (devices_correlate.go)          │
│        1. MAC  2. mDNS name+segment  3. hostname+segment          │
│        4. IP+segment (MAC-conflict veto)  + duplicate merge        │
│      NEW signal merger — per-field provenance (device_signals)    │
│      NEW label deriver — devices.display_name                     │
│      NEW attachment tracking — device_networks (multi-segment)    │
│   fingerprint.Engine — input widened (services, TXT model,        │
│      friendly name); risk categories unchanged                    │
│   GET /api/v1/devices — display_name + signals provenance         │
└───────────────────────────────────────────────────────────────────┘
```

## Data Flow

Source → normalization → ingest → storage → enrichment → UI:

1. **Capture (sensor):** ARP/DHCP/mDNS/SSDP packets → `sensor/internal/passive/parse.go`. mDNS packets are now parsed as a record graph per packet: build `instances` (from PTR data + SRV owners), `hosts` (from A/AAAA owners), link `instance → SRV target host`, attach TXT kv and PTR service type to the resolved host. Example (synthetic): packet carrying `_googlecast._tcp.local PTR Living Room TV._googlecast._tcp.local`, `Living Room TV._googlecast._tcp.local SRV → chromecast-1.local:8009`, TXT `md=Chromecast Ultra fn=Living Room TV`, `chromecast-1.local A 192.0.2.57` yields one `DiscoveredHost{IP:192.0.2.57, Hostname:chromecast-1, Model:Chromecast Ultra, FriendlyName:Living Room TV, Services:[_googlecast._tcp]}`.
2. **Report (sensor→Core):** existing batched `POST /api/v1/sensor/devices` (bearer sensor auth), hosts array gains optional `friendly_name`.
3. **Identity resolution (Core, `backend/internal/store`):** per host, ordered resolver picks the target `device_id` (see below); may trigger a merge of a MAC-less duplicate row.
4. **Signal merge (Core):** each non-empty field becomes a signal `(device_id, field, value, source, confidence)`; canonical `devices` columns are recomputed from highest-confidence signals. Sources map to confidence per the spec's FR-6 table (`user_corrected`=1.0 locked … `oui`=0.2).
5. **Enrichment:** `fingerprint.Engine.Fingerprint` runs on the merged signal view (hostname + vendor + model + services + friendly name), producing device type / OS / risk category exactly as today but with better inputs. Event enrichment (`new_device`, risk-category tags in router.go SNR-11 block) reads the same device rows — no changes to its interface.
6. **Storage:** `devices` (canonical view) + new `device_signals`, `device_identities`, `device_networks` tables (migration 019).
7. **UI/API:** `GET /api/v1/devices` adds `display_name`, `friendly_name`, `identity` (aliases) and `signals` (per-field provenance) fields; frontend device inventory shows display_name with provenance tooltip; events context uses display_name where it currently shows hostname/vendor.

Endpoints/tables touched: `POST /api/v1/sensor/devices`, `GET /api/v1/devices`, `GET /api/v1/devices/new`, `PUT /api/v1/devices/{deviceID}`; tables `devices`, new `device_signals`/`device_identities`/`device_networks`; services `backend/internal/store`, `backend/internal/fingerprint`, `sensor/internal/passive`.

## Schema Changes

New sequential migration `siem/migrations/019_device_correlation.sql` (nothing edited in earlier migrations; `018` is reserved by `specs/001-unifi-log-ingestion/` which ships first — renumber at implementation time if sequencing changes):

```sql
-- Canonical display label + friendly name on the device row (cheap list queries).
ALTER TABLE devices ADD COLUMN display_name TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN friendly_name TEXT DEFAULT '';

-- Per-field provenance: which source last set each canonical field, at what confidence.
CREATE TABLE device_signals (
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    field          TEXT NOT NULL,   -- vendor|model|hostname|friendly_name|os_family|device_type
    value          TEXT NOT NULL,
    source         TEXT NOT NULL,   -- user_corrected|mdns_txt|mdns_ptr|ssdp|dhcp_hostname|dhcp_vendor_class|hostname_pattern|oui|nmap
    confidence     REAL NOT NULL DEFAULT 0.0,
    first_observed TIMESTAMP NOT NULL,
    last_observed  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, field, source)
);
CREATE INDEX idx_device_signals_device ON device_signals(device_id);

-- Identity aliases used by the resolver (survives DHCP churn).
CREATE TABLE device_identities (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    id_type    TEXT NOT NULL,       -- mac|hostname|mdns_name
    id_value   TEXT NOT NULL,
    segment    TEXT NOT NULL DEFAULT 'default',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (id_type, id_value, segment)
);
CREATE INDEX idx_device_identities_device ON device_identities(device_id);

-- Multi-network attachments: one device on N segments.
CREATE TABLE device_networks (
    device_id  TEXT NOT NULL REFERENCES devices(device_id),
    segment    TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    sensor_id  TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, segment)
);
CREATE INDEX idx_device_networks_segment ON device_networks(segment);
```

Backfill (in the same migration or first-boot code, decided in tasks): seed `device_identities` from existing `devices.mac_address`/`hostname`, `device_networks` from `devices(segment, ip_address)`, and compute initial `display_name` from existing columns. `devices.segment`/`ip_address` remain "most recent attachment" for backward compatibility. Retention: `device_signals`/`device_identities`/`device_networks` rows are deleted with their device; no time-based growth (bounded by fields × sources per device), so the 90-day event retention enforcer is unaffected.

## API & Wire Contracts

- **Sensor → Core (`POST /api/v1/sensor/devices`)**: hosts gain optional `friendly_name` (string). Additive-only: old sensors omit it (Core treats as empty); old Cores ignore unknown fields (JSON decode into struct drops them). `discovery_source` values unchanged (`passive_arp|passive_dhcp|passive_mdns|passive_ssdp|nmap_active`). No renames, so no alias window needed; still, the contract is recorded in `contracts/sensor-devices.md` since it crosses the sensor/Core boundary.
- **Core API (`GET /api/v1/devices`, `/devices/new`)**: response device objects gain `display_name`, `friendly_name`, `segments` (array from device_networks), and `signals` (array of `{field, value, source, confidence, last_observed}`). All additive; existing fields keep semantics.
- **`PUT /api/v1/devices/{deviceID}`** (existing user-correction path): unchanged shape; internally now writes a `user_corrected` signal at confidence 1.0 per corrected field, which locks those fields against automatic overwrite (today's `discovery_method='user_corrected'` behavior generalized per-field).
- **Backward compat test matrix**: new sensor + old Core, old sensor + new Core — both exercised in integration tests (NFR-3).

## Detection & Enrichment

- **`new_device` / `very_new_device` tagging (router.go SNR-11)**: unchanged code path, but now fed by merged records — merges take `MIN(first_seen)`, structurally removing the duplicate-record false positives that `GetMinFirstSeenForIP` papers over. That helper is kept for one release (belt-and-braces), then removed.
- **Risk categories (`known_exploited`/`eol_eos`/`high_risk_iot`)**: `fingerprint.Engine` gains a signal-aware entry point (services list, TXT-derived model, friendly name in addition to hostname/vendor/MAC). `DetectEOLFromSignals` signatures unchanged in semantics; better model strings raise match precision (e.g. exact camera model from mDNS TXT vs OUI-only vendor guess). Risk flags keep their "apply even at lower confidence" safety behavior.
- **Suppression/whitelist**: no rule-format changes. Device-scoped context (segment, device_type) becomes more reliable; existing whitelist rules keyed by IP/hostname continue to match because canonical `devices.ip_address`/`hostname` semantics are preserved.
- **Merge audit**: merges emit a structured log line (`logInfo("device", ...)`) with surviving/absorbed device IDs and the matching rule; no new event type (avoids new alert noise).

## SNR Tuning Plan

Shipped WITH the feature (not after):

1. **Generic-hostname stoplist** (Core, config-backed constant list; seed): `localhost`, `unknown`, `android`, `android-*` (random suffix), `espressif`, `esp-*`, `esp32-*`, `wlan0`, `raspberrypi`, `ubuntu`, `pc`, `desktop`, `laptop`, `printer`, `nas`, `camera`, `iphone`, `ipad` (bare, no owner prefix). Hostnames on the list never participate in identity matching or display_name derivation beyond last resort.
2. **Conservative merge guards**: MAC-conflict veto (two records with different known MACs never merge); hostname match requires uniqueness within segment + last_seen within 7 days; mDNS-name match requires exact instance name + segment + 7-day window; MAC-less IP+segment fallback requires 24 h recency.
3. **Churn handling for randomized MACs**: `new_device` tag description text updated to mention private-MAC rotation as a benign cause; devices re-linked by hostname/mDNS continuity do not re-alert.
4. **One-time upgrade churn**: backfill computes display_name and seeds identities without touching `first_seen`, so no alert wave on upgrade.

Validation loop before "supported":
- **Simulated**: table-driven fixtures — multi-host mDNS packet (two devices + TXT for each), PTR/SRV/TXT chains, DHCP churn sequence (same MAC, three IPs), MAC-less mDNS followed by ARP with MAC (must link, not duplicate), two devices with identical generic hostnames (must NOT merge), same MAC on two segments (one device, two attachments).
- **Live soak** (dev network, results to gitignored `analysis-notes/`, sanitized summary committed): ≥48 h before/after comparison of device row count, duplicate rate, `new_device` event count, and zero observed wrong-merges. Acceptance: duplicate device rows reduced to ~0 for MAC-bearing devices; no wrong-merge; `new_device` events per day not increased (excluding genuinely new devices).

## Failure Modes & Limits

- **mDNS floods / hostile packets**: record-graph maps are per-packet and size-capped (cap records processed per packet, e.g. 64; cap TXT pairs; cap services per host — consistent with existing dedupe guard). Oversized/malformed packets degrade to today's behavior (host without metadata), never crash the capture loop.
- **Identity resolver DB cost**: worst case 3 extra indexed point lookups per reported host; sensor reports are already batched. On Pi 4 with a few hundred devices this is negligible; signals written in one transaction per report batch.
- **Merge gone wrong**: audit log line enables manual diagnosis; user correction (custom_name / fingerprint edit) always wins; un-merge tooling explicitly out of scope for alpha.
- **Sensor offline / Core-only installs**: no passive signals → resolver degrades to MAC/IP matching exactly as today; nothing new required.
- **Old sensor versions**: missing `friendly_name` simply yields lower-quality labels; no errors.
- **Randomized MACs (iOS/Android private addresses)**: documented limitation; hostname/mDNS continuity is best-effort. Never merge on OUI-randomized MAC heuristics.
- **SQLite contention**: all new writes ride the existing single-writer connection; batch per report keeps transaction count unchanged.

## Constitution Check

The spec's constitution table holds for this technical approach; re-verified per constraint:

- **L2 native sensor split**: packet parsing changes live in `sensor/internal/passive` (native binary); Core changes are DB/API only. No Docker-collapse pressure.
- **Passive-first**: zero new probes. Explicitly rejected during design: fetching SSDP `LOCATION` XML (active HTTP) — out of scope; active mDNS queries — out of scope.
- **Pi-hole optional**: untouched.
- **V1 scoping**: no scanning/exploit surface; complexity bounded by conservative merge rules and additive schema. No new tension identified.
- **Migrations**: one new sequential file (019); no edits to committed migrations.
- **Backward compatibility**: additive wire fields only; alias window not needed but contract documented in `contracts/`.
- **Environment data**: all examples here use RFC 5737 / `00:00:5E:00:53:xx` / placeholder names; live soak data stays in gitignored analysis-notes.

## Test Strategy

- **Unit (sensor)**: `sensor/internal/passive/parse_test.go` — table-driven mDNS record-graph cases (PTR service extraction now emits `_googlecast._tcp` etc.; TXT attaches to correct host in multi-host packets; friendly-name extraction from instance labels and TXT `fn=`); regression test proving the old dead branch now fires (packet with only PTR records yields services on the SRV-target host); fuzz-ish malformed-record cases (empty names, missing SRV target, TXT before A record ordering).
- **Unit (Core)**: `backend/internal/store/devices_correlate_test.go` — resolver order; MAC-conflict veto; stoplist behavior; uniqueness requirement; recency windows; merge folding (min first_seen, higher-confidence field wins, aliases moved, absorbed row deleted); confidence-weighted field updates (lower-confidence source cannot overwrite; same source refreshes; user_corrected locks). `fingerprint` tests extended for signal-aware inputs.
- **Integration**: end-to-end `POST /api/v1/sensor/devices` sequences against a temp DB — DHCP churn (192.0.2.20 → 192.0.2.21 → 192.0.2.22, MAC 00:00:5E:00:53:0A stays one device with updated attachment); MAC-less mDNS then ARP link-up; multi-segment roaming (segments `lan` + `iot`, one device, two `device_networks` rows); old-payload (no friendly_name) compatibility.
- **Migration**: fresh-install test applying 001→019 on an empty DB (required), plus upgrade test applying 019 over a fixture DB with pre-existing duplicate devices to verify backfill + no data loss.
- **Manual verification**: run Core + sensor locally, confirm device inventory shows display_name + provenance, confirm merge log lines, and run the live soak described in the SNR plan.
- **Gates**: `go build ./... && go test ./... -short` in `backend/` and `sensor/`; `npm run build` in `frontend/` (constitution build gate).
