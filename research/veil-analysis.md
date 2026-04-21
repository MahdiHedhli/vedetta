# VEIL 3.0 Analysis: Findings for Vedetta

## Executive Summary

VEIL 3.0 (neatlabs-ai/neatlabs-veil) is a desktop-focused, real-time network monitor that captures traffic directly from the host via a three-tier fallback (Scapy → raw sockets → psutil polling) and surfaces privacy and threat signals to an end-user UI. Vedetta, by contrast, is a passive, appliance-style SIEM running on a Raspberry Pi that ingests pre-parsed logs from Pi-hole, AdGuard, and firewall syslog through Fluent Bit and persists normalized events into SQLite (with an opt-in ClickHouse threat network). The two projects differ sharply in their capture layer — VEIL sniffs packets on a user's machine, while Vedetta consumes DNS and firewall logs from network infrastructure — so VEIL's process-to-connection mapping and packet-capture plumbing are largely **not** portable to Vedetta. What **is** directly portable, and what this document focuses on, is VEIL's detection and scoring layer: its ten-plus heuristic alert conditions (data exfiltration ratios, DNS tunneling via subdomain length, C2 indicators on non-standard ports, suspicious TLDs, beaconing intervals, phone-home patterns), its additive IP threat risk score (0–100, trivially normalized to Vedetta's `anomaly_score` 0.0–1.0), its Privacy Exposure Score weighting model, and its tracker-signature JSON database. Each of these maps cleanly onto Vedetta's existing `Event` struct, tag vocabulary (`c2_candidate`, `dga_candidate`, `known_bad`, `beaconing`, `high_volume`), and the currently-stubbed `anomaly_score` field — giving Vedetta a ready-made blueprint for turning its ingest pipeline from a passive log store into an actively scored detection engine without adopting VEIL's capture architecture.

---

## Detection & Scoring Reference

The four components below — heuristic alerts, IP threat risk score, Privacy Exposure Score, and the tracker-signature database — are the parts of VEIL 3.0 that port directly onto Vedetta's existing data model. Each is shown as a structured reference that a Vedetta developer can implement against the current `Event` struct (see `docs/schema.md`).

### 1. Heuristic Alert Conditions

VEIL ships a set of independent detection rules that each evaluate a single signal against a threshold and emit a typed alert. The pipeline is fan-out/fan-in: every new connection (or, in Vedetta's case, every ingested event) is passed through all rules in parallel, and any rule that fires contributes a tag and a score delta.

```
                     ┌──────────────────────────────────────────┐
   ingested event ──▶│         detection rule fan-out           │
   (dns_query,       │  each rule is stateless or window-scoped │
    firewall_log,    └──────────────────────────────────────────┘
    nmap_discovery)        │   │   │   │   │   │   │   │
                           ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼
                         R1  R2  R3  R4  R5  R6  R7  R8…
                           │   │   │   │   │   │   │   │
                           └───┴───┴───┴───┴───┴───┴───┴──▶ tags[] + score deltas
                                                                   │
                                                                   ▼
                                                     anomaly_score (0.0–1.0)
```

| # | VEIL Rule | Signal | Threshold / Heuristic | Vedetta Tag | Data Available? |
|---|-----------|--------|-----------------------|-------------|-----------------|
| R1 | Data exfiltration | outbound bytes vs. inbound bytes per source, windowed | outbound > 5× inbound over 10 min | `high_volume` | No (needs byte counters — not in DNS-only stream) |
| R2 | DNS tunneling | length of leftmost subdomain label | label length > 40 chars | `dga_candidate` | Yes (Pi-hole / AdGuard logs carry full query name) |
| R3 | DGA domain | Shannon entropy + n-gram rarity of SLD | entropy > 3.5 bits, or n-gram score < 0.2 | `dga_candidate` | Yes |
| R4 | Suspicious TLD | configurable TLD blocklist (`.xyz`, `.top`, `.tk`, `.click`, etc.) | suffix match | `known_bad` | Yes |
| R5 | C2 on non-standard port | destination IP is a datacenter/VPS ASN AND dst port ∉ {80, 443, 22, 53} | boolean AND | `c2_candidate` | Partial (firewall syslog provides ports; needs ASN enrichment) |
| R6 | Unencrypted HTTP | dst port 80 | boolean | *(new tag: `cleartext_http`)* | Yes (firewall syslog) |
| R7 | Geographic anomaly | dst country ∉ baseline set for this `source_hash` | set difference | *(new tag: `geo_anomaly`)* | Yes once `geo` is populated |
| R8 | Beaconing | stdev of inter-query intervals to same (source, domain) pair | stdev/mean < 0.1 over ≥ 10 queries | `beaconing` | Yes (time-series over Pi-hole logs) |
| R9 | Phone-home | silent periodic connection to same FQDN with no user-driven queries | periodic AND low query diversity | `c2_candidate` | Yes (partial — requires per-device session context) |
| R10 | Known attacker | resolved_ip matches abuse.ch / URLhaus / Spamhaus | list membership | `known_bad` | Yes (already a planned threat-intel feed) |
| R11 | Newly registered | RDAP / WHOIS age < 30 days | age comparison | `newly_registered` | Yes (requires RDAP lookup) |
| R12 | High query volume | queries per source per 5 min | > baseline × 3 | `high_volume` | Yes |

Each row maps 1:1 onto an existing tag in `docs/schema.md` except R6 and R7, which require adding `cleartext_http` and `geo_anomaly` to the tag vocabulary.

### 2. IP Threat Risk Score

VEIL computes a per-IP risk score as a flat additive model capped at 100. It is a pure function of the IP's enrichment metadata — there is no temporal state, so it is cheap to recompute on every event.

```
                    IP enrichment lookup (ip-api.com, cached)
                                  │
                                  ▼
        ┌────────────────────────────────────────────────┐
        │ known_attacker      ──▶ +50                    │
        │ tor_exit_node       ──▶ +40                    │
        │ open_proxy          ──▶ +30                    │
        │ suspicious_tld      ──▶ +25                    │
        │ vpn                 ──▶ +20                    │
        │ unknown_org         ──▶ +10                    │
        │ datacenter          ──▶ +5                     │
        │ no_reverse_dns      ──▶ +5                     │
        └────────────────────────────────────────────────┘
                                  │
                                  ▼
                        sum, clamp to [0, 100]
                                  │
                                  ▼
                    anomaly_score = sum / 100.0   (→ 0.0–1.0)
```

Notable properties:

- **Additive, not multiplicative** — two mild flags (e.g. datacenter + VPN = 25) do not exceed a single strong flag (known attacker = 50), which matches Vedetta's preference for explainable scores.
- **Saturating** — a single IP with all flags set caps at 100, so the mapping to `anomaly_score` is lossless at the ceiling.
- **Stateless** — no sliding windows or per-source counters required; a Go function `Score(meta IPMeta) float64` is sufficient.
- **RFC1918 exemption** — VEIL short-circuits to 0 for private IPs; Vedetta should do the same for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, and `169.254.0.0/16`.

### 3. Privacy Exposure Score Weighting Model

Distinct from the threat score, VEIL computes a per-device **privacy** score on a 0–100 scale. It is a weighted sum with a time-decay term, designed to answer "how much is this device leaking?" rather than "is this malicious?".

```
   privacy_score(device, t) =
       w_tracker    · Σ severity(tracker_i)        // tracker hits weighted by severity
     + w_volume     · log10(bytes_sent + 1)        // dampened data-volume term
     + w_geo        · distinct_countries           // geographic diversity
     + w_http       · fraction_unencrypted          // cleartext HTTP penalty
     − w_decay      · age_hours                     // older events count less

        clamp to [0, 100]

   default weights (from VEIL source):
       w_tracker = 2.0    severity ∈ {low=1, med=3, high=5, critical=8}
       w_volume  = 5.0
       w_geo     = 3.0    (per distinct country beyond the first)
       w_http    = 15.0   (applied to ratio, so max contribution = 15)
       w_decay   = 0.5    (points per hour since event)
```

The score is intentionally asymmetric: **tracker severity dominates** (a single `critical` tracker contributes 16 points), while bytes and geographic spread are dampened. For Vedetta, this maps cleanly onto aggregating per-`source_hash` over a rolling window and storing the result either as a derived column on the `Device` object or as a periodic `anomaly` event.

### 4. Tracker Signature JSON Database

VEIL ships a flat-file database of ~60 tracker signatures used both for the Privacy Exposure Score and for UI-level "who is this device talking to?" callouts.

```
data/trackers.json
│
├── { "domain": "doubleclick.net",
│     "company": "Google",
│     "category": "advertising",
│     "severity": "high",
│     "description": "Ad/retargeting network" }
│
├── { "domain": "graph.facebook.com",
│     "company": "Meta",
│     "category": "social",
│     "severity": "high",
│     "description": "Facebook Graph API" }
│
├── { "domain": "*.segment.io",     ← wildcard match
│     "company": "Twilio",
│     "category": "analytics",
│     "severity": "medium",
│     "description": "Product analytics SDK" }
│
└── …~60 entries across advertising, analytics, social,
     fingerprinting, crash-reporting, and telemetry
     categories, each tagged low/medium/high/critical.
```

Record schema:

| Field | Type | Notes |
|-------|------|-------|
| `domain` | string | Exact FQDN or leading-wildcard (`*.example.com`) |
| `company` | string | Display name of the operator |
| `category` | enum | `advertising`, `analytics`, `social`, `fingerprinting`, `crash`, `telemetry` |
| `severity` | enum | `low`, `medium`, `high`, `critical` — feeds the Privacy Exposure Score |
| `description` | string | One-line human-readable explanation |

Match semantics: exact FQDN first, then longest-suffix wildcard. VEIL loads the file once at startup into an in-memory map keyed by the registrable domain (eTLD+1) for O(1) lookups.

---

## Implementation Plan for Vedetta

The following phased plan ports the four components above into Vedetta's existing Go backend (`backend/internal/`) and Fluent Bit ingest pipeline. Phases are ordered by ROI-per-line-of-code: DNS-only heuristics first (zero new data sources), scoring second (small enrichment dependency), tracker database third (data-only change), behavioural detectors last (require time-series state).

### Phase 1 — DNS-only heuristics (no new data required)

Rules R2, R3, R4, R11 fire entirely off fields already in Pi-hole / AdGuard logs.

- New package: `backend/internal/detect/` with one file per rule (`dns_tunneling.go`, `dga.go`, `suspicious_tld.go`, `newly_registered.go`).
- Each rule exports `func Evaluate(e *models.Event) (tags []string, delta float64)`.
- Wire into `handleEvents` in `backend/internal/api/router.go` so that `/api/v1/ingest` runs the fan-out before persisting.
- Config: `configs/detect.yaml` with TLD list, DGA entropy threshold, and tunneling label-length threshold — all tunable without recompiling.
- R11 (newly registered) adds an RDAP client at `backend/internal/enrich/rdap/` with a 24h TTL cache; failures degrade to "unknown, skip rule".

### Phase 2 — Additive IP threat risk score

- New package: `backend/internal/scoring/ipthreat/` with a single `Score(meta IPMeta) float64` function implementing the +50/+40/+30/+25/+20/+10/+5/+5 additive table.
- `IPMeta` is populated by Phase 3 enrichment; until then, use a minimal stub that only checks known-bad lists and RFC1918 so Phase 2 can ship independently.
- Integration point: same `/api/v1/ingest` fan-out as Phase 1 — the score becomes `max(current anomaly_score, ipthreat.Score(...))` so heuristic tags and IP score compose cleanly.
- Unit tests cover the saturation, RFC1918 short-circuit, and the all-flags-set ceiling case.

### Phase 3 — IP intelligence enrichment

- New package: `backend/internal/enrich/ipintel/` wrapping ip-api.com (free tier, 45 req/min, no API key).
- TTL cache using `github.com/jellydator/ttlcache/v3` keyed by IP, 24h entries, bounded to ~10k entries to stay under Raspberry Pi memory budgets.
- Rate limiter: `golang.org/x/time/rate` at 40 req/min to leave headroom under the 45/min quota.
- Populates `geo` on every `Event` (already in the schema) and provides `IPMeta` to Phase 2 scoring.
- Enables rules R5 (C2 on non-standard port, needs ASN) and R7 (geographic anomaly, needs country) — these rules ship in this phase.

### Phase 4 — Tracker signature database

- New file: `data/trackers.json`, seeded by adapting VEIL's list (verify license compatibility — VEIL is under a permissive license; attribute in `NOTICE`).
- New package: `backend/internal/trackers/` with `Load(path string)` at startup and `Match(domain string) (*Tracker, bool)` using eTLD+1 keying plus wildcard fallback.
- Extends `Event` enrichment: when `domain` matches, add tag `tracker:<category>` and bump `anomaly_score` by `severity → {low:0.02, med:0.05, high:0.10, critical:0.15}`.
- Admin endpoint `GET /api/v1/trackers` for UI-side inspection.

### Phase 5 — Behavioural detectors (beaconing, exfiltration, phone-home)

These require time-series state and a rolling window, so they need a background worker rather than per-event evaluation.

- New package: `backend/internal/detect/behavioral/` with a single goroutine scheduled every 60s.
- Worker reads the last 1h of events from SQLite per `source_hash` and evaluates R8 (beaconing: interval regularity), R9 (phone-home: low diversity + periodicity), and R12 (high volume: threshold × baseline).
- R1 (data exfiltration) is **deferred** — Pi-hole logs do not carry byte counts. Revisit when firewall-syslog byte fields or a passive-capture sensor lands.
- Writes synthesized `event_type = "anomaly"` rows back to SQLite with the appropriate tags and scores, so downstream queries see behavioural findings alongside heuristic ones.

### Cross-cutting changes

- **Schema additions** (`docs/schema.md`): add tags `cleartext_http`, `geo_anomaly`, and the `tracker:*` family; bump schema version from 1 → 2.
- **Event model** (`backend/internal/models/event.go`): no struct changes needed — `tags []string` and `anomaly_score float64` already absorb all new signals.
- **Privacy Exposure Score** is implemented as a periodic aggregator (similar to Phase 5) that computes per-`source_hash` scores from the last 24h of events and exposes them via a new `GET /api/v1/devices/:id/privacy` endpoint.
- **Tests**: each rule and scorer ships with table-driven unit tests; the ingest handler gets an integration test that feeds synthetic events through the full fan-out.
- **Licensing**: VEIL's tracker list and scoring constants are copied with attribution in `NOTICE`; no VEIL Python code is ported verbatim — only the heuristics and thresholds.
