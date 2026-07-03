# Contract: UniFi Syslog/CEF → Vedetta Event Wire Format

> Feature: `specs/001-unifi-log-ingestion/`
> Boundary: UniFi gateway → Collector (Fluent Bit) → `POST /api/v1/ingest` (Core)
> Status: Draft — expected mapping from vendor docs/research; field names marked
> "(validate)" must be confirmed against a live capture (tasks.md T1.2) before the
> parser is frozen.
>
> **All examples in this file are SYNTHETIC** — RFC 5737 documentation IPs
> (192.0.2.x, 198.51.100.x, 203.0.113.x), example MACs (`00:00:5E:00:53:xx`), and
> placeholder hostnames. No real network artifacts, per the constitution.

## 1. Transport

| Property | Value |
| --- | --- |
| Protocol | Syslog over UDP, port **5140** (existing collector input) |
| Syslog framing | RFC 3164 (UniFi default); parser tolerates RFC 5424 prefixes |
| Payload dialects | **A.** CEF (UniFi Network "SIEM Server" export, UniFi OS 3.x+/Network 8.x+) — preferred. **B.** Legacy iptables-style kernel lines (USG/EdgeOS, and UniFi OS "syslog" non-SIEM export) — fallback. |
| Encoding | UTF-8, one message per datagram |

UniFi-side configuration (documented for users in `docs/connectors/unifi.md`):
UniFi Network → Settings → System → Logging → SIEM Server / Remote Syslog → host =
Vedetta collector IP, port = 5140, format = CEF where available. Enable
firewall/security categories; leave debug categories off.

## 2. Dialect A — CEF messages

### 2.1 Structure

```
<PRI>TIMESTAMP HOSTNAME CEF:0|Ubiquiti|UniFi Network|VERSION|DeviceEventClassID|Name|Severity|ext-key=value ...
```

- CEF header fields are pipe-delimited; the extension is space-separated
  `key=value` pairs with `\` escaping for `=`, `|`, `\`.
- `DeviceEventClassID` values observed in vendor docs/research (validate): firewall
  rule matches, threat/IPS notifications, admin activity, client events. Only
  firewall/security classes are ingested; others are dropped at the collector.

### 2.2 Expected CEF extension keys → normalized fields

| CEF key | Meaning | Normalized target | Notes |
| --- | --- | --- | --- |
| `src` | Source IP | `metadata.src_ip`; `source_ip` if LAN-side | (validate) |
| `spt` | Source port | `metadata.src_port` | int |
| `dst` | Destination IP | `metadata.dst_ip` | |
| `dpt` | Destination port | `metadata.dst_port` | int |
| `proto` | Protocol | `metadata.protocol` | lowercased: `tcp`/`udp`/`icmp` |
| `act` | Action | `metadata.action` + tag `fw:<action>` | normalized: `accept|allow`→`allow`, `drop|deny`→`drop`, `reject`→`reject`, `block`→`block` |
| `deviceInboundInterface` / `in` | Ingress interface | `metadata.interface` (+ direction inference) | (validate key name) |
| `deviceOutboundInterface` / `out` | Egress interface | `metadata.interface_out` | (validate) |
| `smac` | Source MAC | `metadata.src_mac` | e.g. `00:00:5E:00:53:0A` |
| `cs1` / `msg` / rule label | Matched rule name/ID | `metadata.rule` | (validate which key carries the ruleset name) |
| CEF header `Name` | Human event name | `threat_desc` seed | |
| CEF header `Severity` (0–10) | Vendor severity | scoring input only (not stored raw) | |
| syslog `TIMESTAMP`/`HOSTNAME` | Event time / gateway | `timestamp` (UTC) / `metadata.gateway` | year inferred for RFC 3164 |

### 2.3 Synthetic CEF examples

Blocked inbound on WAN (contributes to the WAN-scan rollup, not stored individually):

```
<134>Jul  3 10:15:22 gateway-placeholder CEF:0|Ubiquiti|UniFi Network|9.0.108|fwrule|Firewall Block|3|src=203.0.113.77 spt=54321 dst=198.51.100.2 dpt=22 proto=TCP act=block deviceInboundInterface=eth8 cs1=WAN_IN default drop
```

Blocked outbound from an IoT device (stored as an individual event):

```
<134>Jul  3 10:16:05 gateway-placeholder CEF:0|Ubiquiti|UniFi Network|9.0.108|fwrule|Firewall Block|3|src=192.0.2.45 spt=51234 smac=00:00:5E:00:53:0A dst=203.0.113.10 dpt=8443 proto=TCP act=block deviceInboundInterface=br5 deviceOutboundInterface=eth8 cs1=IoT_Restrict egress deny
```

## 3. Dialect B — legacy iptables-style messages

### 3.1 Structure

```
<PRI>TIMESTAMP HOSTNAME kernel: [RULESET-RULENUM-A]IN=<if> OUT=<if> MAC=<mac> SRC=<ip> DST=<ip> LEN=.. TTL=.. PROTO=<p> SPT=<port> DPT=<port> ...
```

- The bracket prefix encodes `ruleset-name`-`rule-number`-`action-letter`:
  `A` = accept, `D` = drop, `R` = reject → `metadata.rule` =
  `"RULESET-RULENUM"`, `metadata.action` from the letter.
- `IN=` non-empty + `OUT=` empty → inbound to gateway; `IN=` LAN bridge + `OUT=` WAN
  interface → outbound; both non-empty LAN → inter-VLAN. Sets `metadata.direction`
  and the `dir:` tag.
- Field grammar is `KEY=VALUE` space-separated; unknown keys are ignored (kept in
  `metadata.raw_log`).

### 3.2 Synthetic iptables-style examples

WAN inbound drop (rollup input):

```
<4>Jul  3 10:15:22 gateway-placeholder kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= MAC=00:00:5E:00:53:01 SRC=203.0.113.77 DST=198.51.100.2 LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=0 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
```

Inter-VLAN block, IoT device → LAN (stored individually):

```
<4>Jul  3 10:17:44 gateway-placeholder kernel: [LAN_IN-3001-D]IN=br5 OUT=br0 MAC=00:00:5E:00:53:0B SRC=192.0.2.45 DST=192.0.2.10 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=18321 DF PROTO=TCP SPT=49230 DPT=445 WINDOW=64240 RES=0x00 SYN URGP=0
```

## 4. Normalized event (collector → `POST /api/v1/ingest`)

The collector emits Fluent Bit HTTP JSON (`[timestamp, record]` pairs or an array of
records — both already accepted by `handleIngest`). Each record is a `models.Event`:

```json
{
  "event_type": "firewall_log",
  "timestamp": "2026-07-03T10:16:05Z",
  "source_ip": "192.0.2.45",
  "source_hash": "",
  "blocked": true,
  "anomaly_score": 0.0,
  "network_segment": "default",
  "tags": ["source:unifi", "fw:block", "dir:out"],
  "threat_desc": "block tcp :8443 (rule: IoT_Restrict egress deny)",
  "metadata": "{\"action\":\"block\",\"protocol\":\"tcp\",\"src_ip\":\"192.0.2.45\",\"src_port\":51234,\"src_mac\":\"00:00:5E:00:53:0A\",\"dst_ip\":\"203.0.113.10\",\"dst_port\":8443,\"interface\":\"br5\",\"interface_out\":\"eth8\",\"direction\":\"out\",\"rule\":\"IoT_Restrict egress deny\",\"gateway\":\"gateway-placeholder\",\"dialect\":\"cef\",\"raw_log\":\"CEF:0|Ubiquiti|UniFi Network|9.0.108|fwrule|...\"}"
}
```

Field rules:

| Field | Rule |
| --- | --- |
| `event_type` | Always `firewall_log` (already in the ingest allow-list and the 001 CHECK constraint) |
| `timestamp` | UTC ISO 8601; syslog time parsed, year inferred; falls back to receipt time |
| `source_ip` | The LAN-side/private IP when determinable (enables device cross-ref); empty for pure WAN-inbound |
| `source_hash` | Left empty by the collector; Core applies its existing default/HMAC handling |
| `blocked` | `true` for `block|drop|reject` |
| `anomaly_score` | Always `0.0` from the collector; scoring is Core-side (enricher) |
| `network_segment` | One of `default|iot|guest` (schema CHECK). Collector emits `default` unless an interface→segment mapping is configured; raw interface stays in metadata |
| `tags` | Required: `source:unifi`, `fw:<action>`, `dir:<in|out|local>`. Conditional: `fw:multicast` (well-known multicast/broadcast dst), `wan_scan_noise` (rollups only) |
| `metadata` | JSON string; keys as shown; `raw_log` always present (truncated to 1 KB); `dialect` = `cef` or `iptables` |

Core-added on ingest/enrichment (not the collector's job): `event_id`, defaulted
`source_hash`, `device_vendor`, canonical segment correction, score, extra tags
(`new_fw_block`, `risky_device_fw_block`, `ips`).

## 5. WAN-scan rollup event

Individual WAN-inbound drops are aggregated per 15-minute window (configurable):

```json
{
  "event_type": "firewall_log",
  "timestamp": "2026-07-03T10:30:00Z",
  "blocked": true,
  "anomaly_score": 0.0,
  "network_segment": "default",
  "tags": ["source:unifi", "fw:drop", "dir:in", "wan_scan_noise"],
  "threat_desc": "WAN inbound scan noise: 1482 drops in 15m",
  "metadata": "{\"rollup\":true,\"window_seconds\":900,\"count\":1482,\"unique_src\":312,\"top_dst_ports\":[{\"port\":22,\"count\":410},{\"port\":23,\"count\":287},{\"port\":445,\"count\":190}],\"interface\":\"eth8\",\"dialect\":\"iptables\"}"
}
```

Rollup events are matched by the seeded default whitelist rule
(`tag_match = 'wan_scan_noise'`, migration 018) and stay out of the anomaly feed while
remaining queryable for trend/"is my WAN being probed" views.

## 6. Ingest authentication (optional)

When ingest auth is enforced (see plan.md Decision 3), the collector adds:

```
Authorization: Bearer <ingest-scope-token>
```

via Fluent Bit `[OUTPUT] http` → `Header Authorization Bearer ...`. Responses:
`401` missing/invalid token (when enforced), `413` over the 5,000-events/request or
10 MB caps, `200` with `{"accepted": N, "rejected": M}` otherwise (existing shape).

## 7. Compatibility guarantees

- Tags and metadata keys in this contract are **additive**; none replace existing
  vocabulary. Renames, if ever needed, keep the old tag as an accepted alias for at
  least one release (constitution: wire-format backward compatibility).
- A Core older than this feature accepts these events unchanged (they are plain
  `firewall_log` events); a newer Core accepts pre-feature collector traffic
  unchanged. Collector and Core upgrade independently.
- Unknown CEF keys / iptables keys: preserved only inside `metadata.raw_log`; the
  parser must not fail on them.
- IPS events from the optional REST connector use the same normalized shape with
  `tags += ["ips", "<unifi-category>"]` and `metadata.dialect = "rest"`.

## 8. Validation status

| Item | Status |
| --- | --- |
| Syslog framing on UDP 5140 | Confirmed against existing collector config |
| CEF header structure & vendor fields | From vendor docs/research — **validate live (T1.2)** |
| CEF extension key names (`deviceInboundInterface`, `cs1`, …) | **Validate live (T1.2)**; update this file with confirmed keys |
| iptables-style `[RULESET-N-A]` grammar | From EdgeOS/USG documentation — **validate live (T1.2)** on a modern UniFi OS gateway |
| Normalized event acceptance by `handleIngest` | Confirmed against `backend/internal/api/router.go` (event_type allow-list, pair format, metadata passthrough) |
