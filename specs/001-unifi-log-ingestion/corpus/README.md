# UniFi Firewall Syslog — Synthetic Test Corpus

> Feature: `specs/001-unifi-log-ingestion/`
> Covers tasks T1.1 (corpus), T1.3 (rollup/throttle defaults), T2.1/T2.2 (Lua
> transform golden tests).
>
> **Every value here is SYNTHETIC** — RFC 5737 documentation IPs
> (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), example MACs
> (`00:00:5E:00:53:xx`), and placeholder hostnames. No real network artifacts,
> per the project constitution. A grep for RFC-1918 / real WAN IPs over this
> directory must return nothing.

## Layout

```
corpus/
├── README.md                 this file
├── inputs/                   raw syslog datagrams (one message per line)
│   ├── cef.log               Dialect A: UniFi CEF firewall lines
│   ├── iptables.log          Dialect B: legacy [RULESET-N-A] kernel lines
│   ├── noise.log             non-firewall lines that MUST be dropped
│   └── wan_drops.log         1,482 WAN-inbound drops in one 15-min window
├── expected/                 golden normalized output (one JSON event / line)
│   ├── cef.expected.json
│   ├── iptables.expected.json
│   └── noise.expected.json   (empty — every noise line is dropped)
└── gen/
    └── gen_wandrop.lua       generator for wan_drops.log and flood files
```

## Synthetic-IP convention

To exercise both traffic directions deterministically, the transform and this
corpus treat the RFC 5737 blocks as follows:

| Block | Role in the corpus |
| --- | --- |
| `192.0.2.x`, `198.51.100.x` | **LAN-side / private** (device source IPs, the gateway WAN address as a drop *target*) |
| `203.0.113.x` | **WAN-side / public** (internet scanners, allowed outbound destinations) |

`unifi_transform.lua` classifies `192.0.2.x` and `198.51.100.x` (plus real
RFC-1918 / CGNAT ranges) as private for `source_ip` selection and direction
inference; `203.0.113.x` is treated as public.

## What each input exercises

- **cef.log** — CEF block (WAN inbound → rollup), CEF block (IoT outbound →
  individual event), CEF allow, CEF reject (inter-VLAN → `dir:local`), CEF drop
  to a multicast destination (`fw:multicast`).
- **iptables.log** — the same five shapes in the legacy `[RULESET-N-A]` dialect
  (`A`=accept, `D`=drop, `R`=reject), covering inbound-to-gateway, LAN→WAN
  outbound, inter-VLAN, and broadcast/multicast destinations.
- **noise.log** — CEF `client`/`admin` categories, DHCP, hostapd, a bare kernel
  bridge line, raw garbage, and a **non-Ubiquiti** CEF line. All are dropped;
  none become events.
- **wan_drops.log** — a WAN scan burst. All 1,482 lines fall in one 15-minute
  window and collapse into **exactly one** `wan_scan_noise` rollup event.

## Rollup window + throttle defaults (T1.3)

These defaults are set in `collector/config/unifi_transform.lua` and
`collector/config/fluent-bit.conf`, and mirror `plan.md`:

| Setting | Default | Where | Rationale |
| --- | --- | --- | --- |
| WAN-inbound rollup window | **900 s (15 min)** | `ROLLUP_WINDOW_SECONDS` in `unifi_transform.lua` | Individual WAN-scan drops are internet background radiation; one rollup event per 15 min keeps the trend visible without flooding the events table. Initial value; Phase 5 live validation (T5.2, LOCAL-ONLY) may retune against observed volume. |
| Firewall event throttle | **2,000 events / 60 s** | `throttle` filter in `fluent-bit.conf` (`Rate 2000, Window 1, Interval 60s`) | Pi-4-first ceiling. Runs after the transform, so it caps emitted events (rollups + individuals). Excess is sampled/dropped, never queued — a storm degrades to sampling, not OOM/SD-card thrash. |
| Syslog input memory buffer | **16 MB** | `Mem_Buf_Limit` on the syslog `[INPUT]` | Bounds collector memory under flood before the throttle even engages. |
| `raw_log` truncation | **1 KB** | `RAW_LOG_MAX` in `unifi_transform.lua` | Keeps metadata bounded; full line context without unbounded rows. |

## Running the transform tests

Requires a Lua 5.x interpreter (developed/verified on Lua 5.5). No Fluent Bit
needed — the harness emulates the rfc3164 parser field split (including the
CEF `ident="CEF"` colon quirk) and runs `unifi_transform.normalize` directly.

```sh
# from the repo root
lua collector/test/run_tests.lua          # assert against committed fixtures
UPDATE=1 lua collector/test/run_tests.lua  # regenerate fixtures after a change
```

Regenerate the rollup input (deterministic, seed 42):

```sh
cd specs/001-unifi-log-ingestion/corpus
lua gen/gen_wandrop.lua 1482 > inputs/wan_drops.log
# a 100k-line flood file for throttle/perf checks (NOT committed — reproducible):
lua gen/gen_wandrop.lua 100000 > /tmp/flood.log
```

## Notes / limitations

- The Lua transform runs identically under bare Lua and Fluent Bit's embedded
  Lua (no external modules; a self-contained minimal JSON encoder).
- CEF extension keys marked "(validate)" in `contracts/unifi-syslog-cef.md`
  remain to be confirmed against a live capture (T1.2, LOCAL-ONLY). The parser
  already tolerates unknown keys (preserved only inside `raw_log`).
- End-to-end Fluent Bit + backend replay (T5.1) and the ≥72 h live pass (T5.2)
  are separate tasks; this corpus is the synthetic substrate they build on.
