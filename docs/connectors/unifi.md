# UniFi Connector Setup Guide

> Spec: [specs/001-unifi-log-ingestion/](../../specs/001-unifi-log-ingestion/spec.md)
> Backlog: [VED-002](../backlog.md), [VED-005](../backlog.md)
>
> **All examples below use synthetic, documentation-reserved values only** —
> RFC 5737 IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), example MACs
> (`00:00:5E:00:53:xx`), and placeholder hostnames. Substitute your own addresses.

UniFi gateways are the first router/firewall data source Vedetta ingests. You point
your UniFi Network application's log export at the Vedetta collector, and firewall
events show up in the events view tagged `source:unifi`, tuned so the new source adds
signal without flooding the dashboard.

There are two paths:

| Path | What it carries | Status |
| --- | --- | --- |
| **Syslog / CEF push** (required for support) | The firewall event stream — blocks, allows, drops | **Supported** (see status ladder below) |
| **REST connector poll** (optional enrichment) | Client inventory + IPS/IDS detections that syslog does not carry | **Experimental** |

You only need the syslog path to get value. The REST connector is additive and
off by default.

---

## 1. Prerequisites

- A running Vedetta Core + collector deployment (`docker compose up -d`).
- The collector's syslog input is already listening on **UDP port 5140** (see
  `collector/config/fluent-bit.conf` and the `5140:5140/udp` mapping in
  `docker-compose.yml`).
- The IP or hostname of the machine running the Vedetta collector. In the examples
  below this is `198.51.100.10` — replace it with your collector's address.
- A UniFi gateway/console running UniFi Network. Modern UniFi OS consoles
  (Network 8.x+) support the CEF "SIEM Server" export; older USG/EdgeOS-style gateways
  use legacy remote syslog. Both are supported.

---

## 2. Configure the UniFi side (syslog export)

Vedetta accepts both dialects UniFi produces. Enable whichever your gateway offers;
CEF is preferred where available.

### Option A — CEF / SIEM export (modern UniFi OS, preferred)

1. Open the UniFi Network application.
2. Go to **Settings → System → Logging** (on some versions: **Settings → System →
   Advanced → Activity/Syslog**, or a dedicated **SIEM Server** panel).
3. Enable the remote syslog / SIEM export and set:
   - **Host:** your collector IP, e.g. `198.51.100.10`
   - **Port:** `5140`
   - **Protocol:** UDP
   - **Format:** CEF (where the version offers a format choice)
4. Enable the **firewall / security** log categories. Leave debug and verbose
   client/AP categories **off** — Vedetta drops non-firewall categories at the
   collector, and turning them on only wastes bandwidth.
5. Save.

A CEF firewall line looks like this (synthetic):

```
<134>Jul  3 10:16:05 gateway-placeholder CEF:0|Ubiquiti|UniFi Network|9.0.108|fwrule|Firewall Block|3|src=192.0.2.45 spt=51234 smac=00:00:5E:00:53:0A dst=203.0.113.10 dpt=8443 proto=TCP act=block deviceInboundInterface=br5 deviceOutboundInterface=eth8 cs1=IoT_Restrict egress deny
```

### Option B — Legacy remote syslog (USG / EdgeOS-style)

1. Go to **Settings → System → Logging → Remote Syslog Server** (naming varies by
   version).
2. Set **Host** = your collector IP (`198.51.100.10`), **Port** = `5140`.
3. Enable firewall logging on your firewall rules (the "Log" toggle per rule / ruleset)
   so the kernel emits `[RULESET-N-A]` lines.

A legacy iptables-style firewall line looks like this (synthetic):

```
<4>Jul  3 10:17:44 gateway-placeholder kernel: [LAN_IN-3001-D]IN=br5 OUT=br0 MAC=00:00:5E:00:53:0B SRC=192.0.2.45 DST=192.0.2.10 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=18321 DF PROTO=TCP SPT=49230 DPT=445 WINDOW=64240 RES=0x00 SYN URGP=0
```

The full field mapping for both dialects is documented in the wire contract:
[specs/001-unifi-log-ingestion/contracts/unifi-syslog-cef.md](../../specs/001-unifi-log-ingestion/contracts/unifi-syslog-cef.md).

---

## 3. What arrives in Vedetta

Firewall messages are normalized to `event_type = "firewall_log"` events and stored
through the existing `POST /api/v1/ingest` pipeline. Every UniFi-derived event carries:

- Tag `source:unifi` — filterable in the events view.
- An action tag: `fw:block`, `fw:drop`, `fw:reject`, or `fw:allow`.
- A direction tag: `dir:in`, `dir:out`, or `dir:local`.
- Structured fields in `metadata` JSON: `action`, `protocol`, `src_ip`/`src_port`,
  `dst_ip`/`dst_port`, `interface`, `direction`, `rule`, `gateway`, `dialect`, and a
  truncated `raw_log`.

In the dashboard, open **Threats** and use the **Type → Firewall** and
**Source → source:unifi** filter chips to isolate firewall events. Firewall rows show
a `FW` badge and a `PROTO src → dst:port` summary in place of the DNS domain; expanding
a row shows the full firewall detail (action, protocol, direction, interface, rule,
source MAC, raw log).

### Noise handling (why you will not drown)

The single largest noise source — internet background radiation hitting your WAN IP —
is aggregated at the collector. Individual WAN-inbound drops are **not** stored as rows;
instead one rollup event per window is stored, tagged `wan_scan_noise`, e.g.:

> WAN scan noise: 1482 drops in 15m

Rollups are kept out of the anomaly feed by a default whitelist rule (seeded by
migration `018_unifi_firewall_defaults.sql`) but remain queryable for "is my WAN being
probed" trend views. Well-known multicast/broadcast blocks are similarly tagged
`fw:multicast` and whitelisted by default. Blocked **outbound** traffic from your LAN/IoT
devices is treated as signal — a first-seen block for a `(device, destination, rule)`
tuple is tagged `new_fw_block` and scored higher.

---

## 4. Verify it is working

1. **Check ingest counts:**

   ```
   curl http://198.51.100.10:8080/api/v1/events/stats
   ```

   You should see the total event count climb after enabling export. (Replace the host
   and port with your Core address.)

2. **Query firewall events directly:**

   ```
   curl 'http://198.51.100.10:8080/api/v1/events?type=firewall_log&limit=20'
   ```

3. **In the UI:** open **Threats**, select the **Firewall** type chip and the
   **source:unifi** source chip, and confirm events appear.

4. **(Optional REST connector)** if configured, check connector health:

   ```
   curl http://198.51.100.10:8080/api/v1/connectors
   ```

If nothing arrives: UDP syslog is fire-and-forget, so a wrong host/port fails silently.
Re-check the export host/port on the UniFi side, confirm UDP 5140 is reachable from the
gateway to the collector, and confirm firewall logging is enabled on the rules.

---

## 5. Optional: ingest authentication

The ingest endpoint uses the same bootstrap-bypass auth as the rest of Core: it is open
**only while Core has no tokens at all**, and requires a valid ingest (or admin) token as
soon as any token exists (for example, the moment a sensor registers). So on any real
deployment the collector needs a credential — otherwise UniFi/firewall ingestion silently
stops with `401` once the first token is created.

To provision it:

1. Set `VEDETTA_INGEST_TOKEN` in `.env` to a strong secret (e.g. `openssl rand -hex 32`).
2. `docker compose` passes that value to **both** Core and the collector. Core provisions
   it as an ingest-scope token on startup (idempotent), and the collector sends
   `Authorization: Bearer ${VEDETTA_INGEST_TOKEN}` on its HTTP output.

There is no separate `VEDETTA_REQUIRE_INGEST_AUTH` flag — that toggle was removed. A rogue
host on the LAN without the token is rejected with `401`.

---

## 6. Optional: REST connector (experimental)

The REST connector polls the UniFi controller for the two things syslog does **not**
reliably carry: **client inventory** (to enrich firewall events with device names,
vendor, and network/VLAN) and **IPS/IDS detections**. It is read-only, off by default,
and never a prerequisite.

Configure it via backend environment variables (none set = connector not registered):

| Variable | Meaning |
| --- | --- |
| `VEDETTA_UNIFI_HOST` | Controller host, e.g. `198.51.100.20` |
| `VEDETTA_UNIFI_API_KEY` | Read-only API key (`X-API-KEY` auth, preferred) |
| `VEDETTA_UNIFI_TLS_SKIP_VERIFY` | `1` to accept the controller's self-signed cert (trust-on-first-use; cert pinning is a documented, accepted limitation) |

Create a **read-only** local account or API key on the controller — Vedetta only reads
(`stat/sta`, `stat/event`, `stat/alarm`, `stat/health`). It never writes to the gateway;
acting on the firewall (blocking clients) is a hard scope cut in V1.

IPS events polled via REST are stored with `metadata.dialect = "rest"` and tags
`source:unifi`, `ips`, with vendor severity mapped to score (1 → 0.4, 2 → 0.7, 3 → 1.0).
Client inventory syncs into the device registry with
`discovery_method: "unifi_connector"` and never creates events.

---

## 7. Support status ladder

Following the constitution's "document shipped vs planned honestly" alpha posture, and
the signal-to-noise discipline that re-opens with every new data source:

| Capability | Status | Meaning |
| --- | --- | --- |
| Syslog/CEF firewall event ingestion (UDP 5140) | **Supported** | Complete, tuned workflow: ingest → normalize → suppress → document. Default SNR suppression ships with the feature. |
| WAN-scan rollup + default whitelist tuning | **Supported** | Seeded via migration 018; user-disableable. |
| Optional ingest bearer-token auth | **Supported** | Off by default for backward compatibility. |
| REST connector — client inventory enrichment | **Experimental** | Off by default; API surface may change. |
| REST connector — IPS/IDS event polling | **Experimental** | Off by default; depends on controller version behavior. |
| pfSense/OPNsense, OpenWrt, MikroTik | **Planned** | Deferred to [specs/005-broader-firewall-connectors/](../../specs/005-broader-firewall-connectors/); one source at a time. |
| Firewall rule/config drift, acting on the firewall, multi-site | **Out of scope (V1)** | See the spec's Out of Scope section. |

> **Live SNR validation is the remaining gate before "supported" is claimed on a real
> network.** The synthetic-corpus validation ships with the feature; the ≥72h live pass
> against a real UniFi gateway (per the spec's Phase 5 / tasks.md T5.2) is a local-only
> owner task and its results are recorded in [SNR-IMPROVEMENTS.md](../SNR-IMPROVEMENTS.md).

## Related documents

- [Firewall Connector Guide](../connector-guide.md) — the connector interface for adding
  new firewall platforms.
- [specs/001-unifi-log-ingestion/](../../specs/001-unifi-log-ingestion/spec.md) — spec,
  plan, tasks, and the syslog/CEF wire contract.
- [schema.md](../schema.md) — event schema and `firewall_log` metadata keys.
