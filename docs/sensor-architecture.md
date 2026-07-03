# Vedetta Sensor Architecture

> Last updated: 2026-06-04 (S:N services indicator + 161st cycle)
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

## Richer Sensor Payloads for Actionability (2026-06)

User request: "Seeing a threat or risk is great but not useful if we don't get actionable data from it. Source, timestamp, anything that helps identify the process, host, destination, etc."

The sensor now supplies concrete identification data end-to-end (wire → ingest → store → UI) while remaining conservative and additive (no scoring impact).

### DNS / Query payloads (sensor/internal/dnscap/capture.go)
- Parses both queries (QR=0) and responses (QR=1).
- On responses: `Answers []string` is populated from RDATA (A/AAAA IPs and CNAMEs/names from answers + additionals). These are the resolved "destinations".
- `ClientIP` attributed from the dst IP of the response packet (original querier).
- `ServerIP` set to the responding resolver (src of response) or the target for queries.
- Timestamps use `packet.Metadata().Timestamp` (millisecond precision path; ingest handles legacy seconds compat).
- `Process` field is a stub (empty for pure network-tap pcap; intended for future co-located host-local agent mode for full process attribution).

Ingest (`backend/internal/api/router.go` handleSensorDNS) stores:
- `dns_answers` array inside event `metadata` JSON.
- `resolved_ip` from the first answer when present.
- `server_ip` passthrough where available.

### Device / host discovery (sensor/internal/netscan, passive/parse.go + backend/internal/discovery/nmap.go)
`DiscoveredHost` now carries richer fields for host identification:
- `Model string`
- `Services []string` (advertised services, e.g. from mDNS PTRs)
- `DiscoverySource string` (e.g. "passive_mdns", "passive_dhcp", "passive_ssdp", "passive_arp", "active_nmap")

Passive mDNS parser extracts additional actionable keys from TXT records:
- model / modelName / mn
- manufacturer / mf / vendor
- service pointers appended to Services

Backend store (`backend/internal/store/devices.go`):
- `UpsertDevice` accepts the new fields.
- `model` and `discovery_method` columns (pre-existing from EOL work).
- `services` stored as JSON TEXT column (added via `ALTER TABLE ... IF NOT EXISTS` in Upsert + COALESCE + unmarshal + notes-JSON fallback for compat on load in ListDevices/GetDeviceByIP).
- Services may also be merged into Notes for older rows.

Frontend (`frontend/src/App.jsx`):
- DeviceTable includes Model (after Vendor), Discovery Source (friendly labels: "mDNS (passive)", "Active (nmap)", "DHCP", etc.), and Services (truncated display in list; full list on hover title; full via CSV export with ; separator).
- Per-event host details render model, services (joined), discovery_source.
- Dedicated "Answers / Destinations (from sensor)" block + Server IP row + "Process (from sensor)" row in the details grid (pulls meta.dns_answers and meta.process).
- Main Events table (list view) includes narrow Server column (server_ip), Ans column (count of dns_answers with hover for full joined destinations), and Proc column (short preview of meta.process with full value on hover; for future host-local sensor process attribution).
- Events CSV export includes server_ip, dns_answers, and process columns (extracted from metadata JSON).
- Device CSV export includes Model, Discovery Source, and full Services.
- In details: services rendered as small subtle pill badges for scannability when passive mDNS data is present; Process row in the grid.

### Activating richer payloads on a live instance (redeploy)
The code changes for actionable data (Answers, ServerIP, Process, Model, Services[], DiscoverySource, precise timestamps) are in the tree and persisted/UI surfaced. However, the running sensor binary (often the docker one or previously installed native) predates these edits.

To see real values from your network:
1. Rebuild/install the updated sensor with elevated permissions:
   `sudo ./scripts/update-all.sh`
   (or the sensor-specific path if present, e.g. `./scripts/update-sensor.sh`)
2. Restart the backend (so ingest paths are current):
   `docker compose restart backend` (or equivalent).
3. Let the sensor run for a while (it does periodic passive + active scans + DNS capture).
4. Re-observe:
   - `make collection-health` (overall volumes + 0-FP confirmation)
   - Targeted queries:
     `docker compose exec -T backend sqlite3 /data/vedetta.db "SELECT COUNT(*), SUM(CASE WHEN COALESCE(server_ip,'')!='' THEN 1 ELSE 0 END) FROM events;"`
     `docker compose exec -T backend sqlite3 /data/vedetta.db "SELECT discovery_method, COUNT(*) c, SUM(CASE WHEN model != '' THEN 1 ELSE 0 END) m, SUM(CASE WHEN json_array_length(COALESCE(services,'[]'))>0 THEN 1 ELSE 0 END) s FROM devices GROUP BY discovery_method;"`
     `docker compose exec -T backend sqlite3 /data/vedetta.db "SELECT substr(metadata,1,120) FROM events WHERE metadata LIKE '%dns_answers%' OR metadata LIKE '%process%' ORDER BY timestamp DESC LIMIT 3;"`
5. In http://localhost:3107:
   - Devices table: look for non-"—" Model, "mDNS (passive)" or similar Discovery, Services list (hover for full).
   - Events/Threats list: Server and Ans columns start showing values + hovers.
   - Event details: Answers block, Server IP, Process row populated for some rows.
   - Exports (devices + events CSVs) contain the new columns with data.

### Live re-observation (as of 161st cycle)
- `make collection-health`: 74,265 real passive DNS events, 42 devices, 0/0/0 high-scores on primary hotspot (192.0.2.198) — **one hundred and sixty-first consecutive cycle at 0**.
- server_ip column present (0 populated); services JSON column + model + discovery_method present (all devices still discovery_method="nmap_active", model="", services="[]").
- Recent event samples: source_ip visible (e.g. 192.0.2.198), server_ip empty, metadata has DGA objects only (no dns_answers or process yet).
- UI: Proc column in Events list shows short truncated preview of process (e.g. first 12 chars + …) with full on hover; services in details rendered as small pills; Discovery Source column uses friendly labels (e.g. "mDNS (passive)"); table header "Discovery Source" with w-28 width; main events list "Source Device" cell now includes model (clean pill) and Discovery Source (pill for richer passive) with consistent ml-1.5 margins, plus services indicator ("S:N" pill with count e.g. S:2 if services present) when richer sensor data present (in addition to name/mac/segment/vendor).
- Expected until redeploy: the running sensor binary predates the richer payload changes. Passive (mDNS TXT for model/services, DiscoverySource tags) and response Answers will flow only after the redeploy steps above + fresh traffic.

### Limitations & future
- Full `Process` attribution requires host-local sensor/agent mode (not pure tap).
- Older devices discovered before richer passive will show nmap_active / empty until re-discovered via updated passive paths.
- All changes are additive, high-confidence from live review, user-suppressible via existing rules, and preserve the 0-FP normalization on the primary hotspot.

Update the "Last updated" date at the top of this file when editing.

## Security Note
