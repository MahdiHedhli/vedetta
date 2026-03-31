# Public Threat Intelligence Sources for SIEM Functions

> Priority: P0 — Transforms Vedetta from a visibility tool into a detection platform

## Current State in Vedetta

The event schema includes tags like `c2_candidate`, `known_bad`, and `newly_registered` that imply threat intelligence enrichment, but no threat intel integration exists. The threat network backend is stubbed. The telemetry daemon is a placeholder.

## Research Findings

### 1. Free Threat Intelligence Feeds

#### Tier 1: High-Value, Easy Integration (Implement First)

**abuse.ch Platform** — https://abuse.ch/
The most valuable free threat intel source for a home/SMB SIEM. Community-driven, operated in partnership with Spamhaus.

| Feed | Content | Format | Update Freq | API |
|------|---------|--------|-------------|-----|
| URLhaus | Malware distribution URLs & domains | CSV, JSON | Real-time | REST (free, no key) |
| Feodo Tracker | Emotet/Dridex/TrickBot C2 IPs | CSV, JSON | Real-time | REST (free, no key) |
| SSL Blacklist (SSLBL) | Malicious SSL certificates + JA3 fingerprints | CSV | Daily | REST (free, no key) |
| ThreatFox | IOCs (IPs, domains, hashes) | JSON, STIX | Real-time | REST (free, API key) |
| MalwareBazaar | Malware samples & hashes | JSON | Real-time | REST (free, API key) |
| YARAify | YARA rules for malware detection | JSON | Real-time | REST (free, API key) |

**Key API endpoints for Vedetta integration:**
```
# URLhaus - Lookup domain
POST https://urlhaus-api.abuse.ch/v1/host/
Body: host=suspicious-domain.xyz

# Feodo Tracker - Get C2 IP blocklist
GET https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json

# SSLBL - Get JA3 fingerprint blocklist
GET https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv

# ThreatFox - Lookup IOC
POST https://threatfox-api.abuse.ch/api/v1/
Body: {"query": "search_ioc", "search_term": "suspicious-domain.xyz"}
```

**GreyNoise** — https://www.greynoise.io/
Identifies IPs that are mass-scanning the internet (noise) vs. targeted attacks.

- Community API: Free, no key required for basic lookups
- `GET https://api.greynoise.io/v3/community/{ip}` — Returns classification (benign/malicious/unknown), whether it's a known scanner, and tags
- Use case: When Vedetta detects an external IP connecting to the user's network, check if it's known internet noise or a targeted probe
- Rate limit: 50 requests/day (community), sufficient for home use

**AlienVault OTX (LevelBlue OTX)** — https://otx.alienvault.com/
Largest open threat exchange with 200K+ users and 20M+ IOCs.

- Free account required for API key
- STIX/TAXII feed support
- REST API: `GET /api/v1/indicators/domain/{domain}/general`
- Pulse subscriptions: curated threat intelligence "pulses" from community researchers
- SDK available in Python; Go integration via REST API
- Rate limit: Generous for authenticated users

#### Tier 2: Supplementary Feeds (Add After Tier 1)

**SANS Internet Storm Center (ISC)**
- Daily top threat IPs: `https://isc.sans.edu/api/topips/`
- Suspicious domains: `https://isc.sans.edu/api/domains/`
- Free, no API key

**Spamhaus DROP/EDROP**
- IP ranges controlled by spammers/cybercriminals
- `https://www.spamhaus.org/drop/drop.txt`
- Free for non-commercial use

**PhishTank**
- Community-verified phishing URLs
- Free API with registration
- `https://checkurl.phishtank.com/checkurl/`

**Emerging Threats (Proofpoint)**
- ET Open ruleset: Free Suricata/Snort rules updated daily
- `https://rules.emergingthreats.net/open/suricata-5.0/rules/`
- If Vedetta integrates Suricata, these rules come free

**MISP Feeds (Public)**
- CIRCL OSINT feed: `https://www.circl.lu/doc/misp/feed-osint/`
- Botvrij.eu: `https://www.botvrij.eu/data/feed-osint/`
- Free STIX-formatted threat data

**Cisco Talos IP Blacklist**
- `https://www.talosintelligence.com/documents/ip-blacklist`
- Known bad IPs, updated regularly

### 2. Feed Integration Architecture

```
                                ┌─────────────────────┐
                                │   Feed Scheduler     │
                                │   (Go, cron-style)   │
                                └────────┬────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
            │ abuse.ch      │   │ GreyNoise    │   │ OTX          │
            │ Downloader    │   │ Poller       │   │ Subscriber   │
            └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
                   │                   │                   │
                   ▼                   ▼                   ▼
            ┌─────────────────────────────────────────────────┐
            │              Local Threat Intel DB               │
            │  (SQLite table: threat_indicators)               │
            │  Columns: indicator, type, source, confidence,   │
            │           tags, first_seen, last_seen, ttl       │
            └──────────────────────┬──────────────────────────┘
                                   │
                                   ▼
            ┌─────────────────────────────────────────────────┐
            │              Event Enrichment Layer              │
            │  On ingest: lookup domain/IP against local DB   │
            │  Add tags: known_bad, c2_candidate, etc.        │
            │  Adjust anomaly_score                           │
            └─────────────────────────────────────────────────┘
```

### 3. STIX/TAXII Considerations

STIX (Structured Threat Information Expression) and TAXII (Trusted Automated Exchange of Intelligence Information) are the industry standards for threat intel sharing. Many feeds support them, and the Vedetta threat network should eventually produce STIX-formatted data.

However, for v1, a simpler approach is better:
- Download CSV/JSON feeds on schedule
- Normalize to a simple `threat_indicators` table
- Add STIX export capability to the threat network API later
- STIX/TAXII client implementation in Go is non-trivial; defer to Phase 3

### 4. Offline Operation

Vedetta must work without internet access (air-gapped networks, ISP outages). Design:
- All threat intel is cached locally in SQLite
- Feeds are downloaded on schedule when internet is available
- TTL per indicator (default 7 days for IPs, 30 days for domains)
- Stale indicators are demoted in scoring but not deleted
- Local-only detection (DGA entropy, beaconing) works without any feeds

## Recommended Implementation

### Phase 1: abuse.ch Integration (Immediate, High ROI)

Build a `threat_intel` Go package:

```go
type ThreatIntelDB struct {
    db *sql.DB
}

type Indicator struct {
    Value      string    // domain, IP, JA3 hash
    Type       string    // domain, ipv4, ipv6, ja3
    Source     string    // urlhaus, feodotracker, sslbl, greynoise
    Confidence float64   // 0.0-1.0
    Tags       []string  // c2, malware_distribution, phishing
    FirstSeen  time.Time
    LastSeen   time.Time
    TTL        time.Duration
}

func (db *ThreatIntelDB) Lookup(indicator string) (*Indicator, error) { ... }
func (db *ThreatIntelDB) BulkImport(source string, indicators []Indicator) error { ... }
func (db *ThreatIntelDB) Refresh() error { ... }  // Download all feeds
```

**Feed download schedule:**
- URLhaus blocklist: Every 5 minutes (small, changes frequently)
- Feodo Tracker C2 IPs: Every hour
- SSLBL JA3 fingerprints: Every 6 hours
- GreyNoise top scanners: Daily

**Storage estimate:** ~10MB SQLite for all Tier 1 feeds, refreshed on schedule.

### Phase 2: Event Enrichment Hook (Short-term)

Wire the threat intel DB into the event ingest pipeline:
```go
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
    events := parseEvents(r)
    for _, event := range events {
        // Enrich from threat intel
        if indicator, err := s.threatDB.Lookup(event.Domain); err == nil {
            event.Tags = append(event.Tags, indicator.Tags...)
            event.AnomalyScore = math.Max(event.AnomalyScore, indicator.Confidence)
        }
        if indicator, err := s.threatDB.Lookup(event.ResolvedIP); err == nil {
            event.Tags = append(event.Tags, indicator.Tags...)
            event.AnomalyScore = math.Max(event.AnomalyScore, indicator.Confidence)
        }
        s.store.InsertEvent(event)
    }
}
```

### Phase 3: OTX + Community Feeds (Medium-term)

- Add OTX pulse subscription for curated intelligence
- Implement SANS ISC and Spamhaus feed downloaders
- Add dashboard "Threat Intel Status" card showing feed freshness and indicator counts

### Schema Addition

```sql
CREATE TABLE threat_indicators (
    indicator TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('domain', 'ipv4', 'ipv6', 'ja3', 'url', 'hash')),
    source TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    tags TEXT,  -- JSON array
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ttl_hours INTEGER NOT NULL DEFAULT 168,  -- 7 days
    PRIMARY KEY (indicator, source)
);
CREATE INDEX idx_ti_indicator ON threat_indicators(indicator);
CREATE INDEX idx_ti_source ON threat_indicators(source);
CREATE INDEX idx_ti_last_seen ON threat_indicators(last_seen);
```

## References

- abuse.ch: https://abuse.ch/
- URLhaus API: https://urlhaus.abuse.ch/api/
- Feodo Tracker: https://feodotracker.abuse.ch/
- SSLBL: https://sslbl.abuse.ch/
- ThreatFox: https://threatfox.abuse.ch/api/
- GreyNoise Community API: https://docs.greynoise.io/docs/using-the-greynoise-community-api
- AlienVault OTX: https://otx.alienvault.com/
- SANS ISC API: https://isc.sans.edu/api/
- Spamhaus DROP: https://www.spamhaus.org/drop/
- MISP Feeds: https://www.misp-project.org/feeds/
- SOCRadar free feeds list: https://socradar.io/blog/the-ultimate-list-of-free-and-open-source-threat-intelligence-feeds/
- Anomali open source feeds: https://www.anomali.com/blog/open-source-threat-intelligence-feeds
