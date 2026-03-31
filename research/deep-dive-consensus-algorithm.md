# Deep Dive: Consensus Algorithm & Domain Reputation System

> Research document for Vedetta's community threat network, informed by CrowdSec's IP reputation model and adapted for DNS domain reputation.

## 1. CrowdSec Architecture Analysis

### 1.1 System Overview

CrowdSec is an open-source, crowdsourced intrusion prevention system built around IP reputation. Its architecture has three tiers:

1. **Security Engine (Local Agent)** — A Go daemon that ingests logs, parses them through a multi-stage pipeline, and detects attacks using leaky-bucket scenarios.
2. **Local API (LAPI)** — A RESTful HTTP server (Gin framework) that stores alerts and decisions locally, authenticates agents and bouncers, and synchronizes with the Central API.
3. **Central API (CAPI)** — CrowdSec's cloud service that aggregates signals from 70,000+ active installations worldwide (~10M signals/day), runs consensus, and distributes the community blocklist back to subscribers.

**Bouncers** are remediation components (firewall rules, nginx modules, WAF plugins) that query LAPI for active decisions and enforce blocks.

### 1.2 Detection Pipeline

The agent processes logs through an asynchronous, channel-based pipeline with configurable concurrency at each stage:

```
Acquisition → Parsing (s00-raw → s01-parse → s02-enrich) → Scenarios → Alerts → LAPI
```

**Stage breakdown:**

| Stage | Purpose | Implementation |
|-------|---------|---------------|
| Acquisition | Read logs from files, journald, syslog, Docker, Kafka, etc. | `pkg/acquisition/` — pluggable data sources |
| s00-raw | Normalize diverse log formats into a predictable structure | GROK patterns + YAML parsers |
| s01-parse | Extract fields (IP, URI, user-agent, status code, etc.) | Parser chains distributed via Hub |
| s02-enrich | Add GeoIP, ASN, reverse DNS context | Enrichment plugins |
| Scenarios | Detect attack patterns using leaky bucket algorithm | YAML-defined, compiled to bucket processors at runtime |
| Output | Push alerts to LAPI | `cmd/crowdsec/output.go` |

**Key Go code paths:**
- `cmd/crowdsec/serve.go` — daemon lifecycle
- `cmd/crowdsec/parse.go` — parsing pipeline
- `cmd/crowdsec/pour.go` — scenario evaluation (pouring events into buckets)
- `pkg/leakybucket/` — leaky bucket implementation
- `pkg/parser/` — parser engine
- `pkg/apiserver/` — LAPI server

### 1.3 Signal Sharing: Agent → CAPI → Community Blocklist → Agents

```
┌──────────────────────────────────────────────────────────────────┐
│                        CrowdSec Data Flow                        │
│                                                                  │
│  ┌─────────┐    alerts    ┌──────┐   signals   ┌──────────┐    │
│  │  Agent   │────────────▶│ LAPI │─────────────▶│   CAPI   │    │
│  │(parse +  │             │      │              │(Central  │    │
│  │ detect)  │             │      │◀─────────────│  API)    │    │
│  └─────────┘             │      │  community   │          │    │
│       │                   │      │  blocklist   └────┬─────┘    │
│       │                   └──┬───┘                   │          │
│       │                      │                       │          │
│       │    decisions         │                       │          │
│       │                      ▼                       ▼          │
│  ┌─────────┐           ┌─────────┐          ┌────────────┐     │
│  │ Bouncer │◀──────────│Decision │          │ Consensus  │     │
│  │(enforce)│   query   │  DB     │          │ Calculator │     │
│  └─────────┘           └─────────┘          │ + Expert   │     │
│                                              │ System     │     │
│                                              └────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

**Flow details:**

1. **Agent detects attack** — Log events match a scenario (e.g., `crowdsecurity/ssh-bf` for SSH brute force). The leaky bucket overflows, generating an alert with the attacker IP + scenario metadata.

2. **Alert → LAPI** — The alert is stored locally. LAPI creates a local decision (ban the IP for N hours). LAPI also queues the signal for CAPI submission.

3. **LAPI → CAPI** — Signals are batched and pushed to the Central API on a configurable interval. Each signal includes: IP, scenario triggered, timestamp, and the agent's enrollment ID.

4. **CAPI Consensus** — The Consensus Calculator evaluates incoming signals through a multi-stage pipeline:
   - **Baseline filter**: Minimum number of reports + minimum reporter trust score
   - **Metric computation**: Diversity (unique ASNs, IP ranges, geolocations), volume, recency
   - **Expert System**: A purpose-built rule engine with many rules encoding why an IP is threatening
   - **Honeypot cross-validation**: CrowdSec operates honeypots across public clouds; honeypot reports are ground truth

5. **Community Blocklist generation** — IPs that pass the Expert System are added to the community blocklist. The blocklist blocks ~25 attacks for every 1 detected locally.

6. **CAPI → LAPI** — Agents pull the community blocklist on a schedule. New decisions are merged into the local decision DB. Bouncers query LAPI and enforce.

### 1.4 CTI Scoring System (Three-Layer Architecture)

CrowdSec scores every IP across three layers:

**Layer 1 — Base Scores** (internal, used for blocklist generation and ML models):
- Raw counts: total reports, unique reporters, unique ASNs, scenarios triggered
- Normalized against network size (an IP reported by 25 nodes means different things at 1K vs 100K network size)
- Trust-weighted: each signal is weighted by the reporter's trust score and the scenario's trust score

**Layer 2 — Analyst Scores** (0–5 scale, four axes):

| Score | What It Measures | Computation Basis |
|-------|-----------------|-------------------|
| **Aggressiveness** | Volume of attacks from this IP | Report count, attack frequency, target diversity |
| **Threat** | Severity of attack types | Scenario severity (ssh-bf < CVE exploit), attack sophistication |
| **Trust** | Confidence in the data | Reporter diversity, honeypot correlation, consistency across sources |
| **Anomaly** | How unusual the behavior is | Deviation from expected patterns for the IP's ASN/range |

**Layer 3 — Product Scores** (derived, use-case specific):
- **Background Noise Score**: Filters out Internet background radiation (mass scanners, script kiddies) from targeted attacks
- Used for alert prioritization and triage

### 1.5 Trust & Anti-Gaming Mechanisms

**User (Node) Trust Score:**
- **Longevity**: Longest uninterrupted period of consistent reporting. A daemon reporting for months at 100% accuracy reaches maximum trust rank.
- **Accuracy**: Cross-checked against honeypot ground truth and other trusted sources. Inconsistent reports lower trust.
- **Anti-Sybil**: Reports are checked against the reporter's own IP — if a reporting node has itself been reported as malicious by others, its trust score is diminished.
- **Diversity requirement**: An IP must be reported by multiple nodes across different ASNs to enter the community blocklist. Sybil nodes in the same ASN cannot self-reinforce.
- **Progressive trust**: New nodes start untrusted. Only the highest trust rank can publish to the database without needing validation from CrowdSec's honeypot network.

**Anti-Poisoning:**
- Honeypot network serves as ground truth — when an IP reported by a user is also seen by a honeypot for the same behavior, confidence is high
- Machine profiling detects anomalous reporting patterns
- Cross-checking data sources guarantees information consistency
- Whitelists for known-good infrastructure (CDN ranges, cloud provider NAT IPs)

**False Positive Management:**
- Automatic FP detection cleans IPs from blocklists
- IPs in known CDN/cloud/NAT ranges get higher consensus thresholds
- Reporter cross-checking: if reporter IP has been flagged, its reports are discounted
- ML-based clustering identifies coordinated poisoning attempts

---

## 2. Vedetta Domain Reputation System Design

### 2.1 Architectural Mapping: CrowdSec → Vedetta

| CrowdSec Concept | Vedetta Equivalent | Key Difference |
|------------------|--------------------|----------------|
| IP reputation | Domain reputation | DNS-centric vs. connection-centric |
| Scenario (leaky bucket) | Detection engine (DGA, beaconing, C2, anomaly) | Pattern types differ; domain signals vs. connection signals |
| Signal (IP + scenario) | Report (domain + detection_type + evidence) | Richer context: query patterns, device types, temporal signals |
| LAPI | Local Vedetta daemon | Already exists (SQLite-backed) |
| CAPI | Threat Network Backend | ClickHouse-backed, self-hostable |
| Community blocklist | Community feeds (4 feed types) | More nuanced output than a simple blocklist |
| Bouncer | DNS blocklist integration | Pi-hole/AdGuard blocklist format |
| User trust score | Node trust score | Same concept, adapted for DNS context |
| Honeypot ground truth | Canary domain network + known-malware feeds | Ground truth source differs |

### 2.2 Node Trust Scoring Algorithm

Every Vedetta node that opts into telemetry receives a trust score that determines how much weight its reports carry in the consensus.

**Trust Score Components (0.0 – 1.0 scale):**

```
NodeTrust = w_longevity * Longevity
          + w_accuracy  * Accuracy
          + w_diversity * Diversity
          + w_consistency * Consistency

where:
  w_longevity   = 0.25
  w_accuracy    = 0.35
  w_diversity   = 0.15
  w_consistency = 0.25
```

**Pseudocode:**

```python
def compute_node_trust(node_id: str, db: ClickHouseClient) -> float:
    """
    Compute trust score for a telemetry node.
    Returns float in [0.0, 1.0].
    """

    # --- Longevity (0.0 - 1.0) ---
    # Days of continuous reporting (at least 1 report per 48h window)
    first_seen = db.query(
        "SELECT min(received_at) FROM telemetry_events WHERE node_hash = {node_id}"
    )
    last_seen = db.query(
        "SELECT max(received_at) FROM telemetry_events WHERE node_hash = {node_id}"
    )
    # Count gaps > 48h as interruptions
    active_days = db.query("""
        SELECT count(DISTINCT toDate(received_at))
        FROM telemetry_events
        WHERE node_hash = {node_id}
          AND received_at >= now() - INTERVAL 90 DAY
    """)
    max_possible_days = min(90, (now() - first_seen).days)
    longevity = min(1.0, active_days / max(max_possible_days, 1))
    # Apply sigmoid to reward sustained participation
    longevity = sigmoid_scale(longevity, midpoint=0.5, steepness=6)

    # --- Accuracy (0.0 - 1.0) ---
    # What fraction of this node's flagged domains are corroborated?
    total_reports = db.query(
        "SELECT count(DISTINCT domain) FROM telemetry_events "
        "WHERE node_hash = {node_id} AND anomaly_score > 0.5"
    )
    corroborated = db.query("""
        SELECT count(DISTINCT te.domain)
        FROM telemetry_events te
        INNER JOIN ground_truth gt ON te.domain = gt.domain
        WHERE te.node_hash = {node_id} AND te.anomaly_score > 0.5
    """)
    # Also check: did this node report Tranco top-10k domains as malicious?
    false_positives = db.query("""
        SELECT count(DISTINCT te.domain)
        FROM telemetry_events te
        INNER JOIN tranco_top_domains td ON te.domain = td.domain
        WHERE te.node_hash = {node_id} AND te.anomaly_score > 0.7
    """)
    if total_reports == 0:
        accuracy = 0.0  # No reports = no trust earned
    else:
        corroboration_rate = corroborated / total_reports
        fp_penalty = min(1.0, false_positives / max(total_reports, 1) * 5)
        accuracy = max(0.0, corroboration_rate - fp_penalty)

    # --- Diversity (0.0 - 1.0) ---
    # How many distinct domains does this node report on?
    # Penalize nodes that only report on a narrow set (possible targeted poisoning)
    unique_domains = db.query(
        "SELECT count(DISTINCT domain) FROM telemetry_events "
        "WHERE node_hash = {node_id} AND received_at >= now() - INTERVAL 30 DAY"
    )
    # A healthy home network queries 500-5000 unique domains/month
    diversity = min(1.0, unique_domains / 500)

    # --- Consistency (0.0 - 1.0) ---
    # Does this node's reporting pattern match expected home/SMB behavior?
    # Check: daily report count variance (should be stable, not bursty)
    daily_counts = db.query("""
        SELECT toDate(received_at) as day, count(*) as cnt
        FROM telemetry_events
        WHERE node_hash = {node_id}
          AND received_at >= now() - INTERVAL 30 DAY
        GROUP BY day
    """)
    if len(daily_counts) < 7:
        consistency = 0.1  # Too little data
    else:
        cv = std(daily_counts.cnt) / mean(daily_counts.cnt)  # Coefficient of variation
        # CV < 0.5 is normal; CV > 2.0 is suspicious (bursty/bot-like)
        consistency = max(0.0, 1.0 - (cv - 0.5) / 1.5)

    # --- Composite Score ---
    trust = (0.25 * longevity + 0.35 * accuracy
             + 0.15 * diversity + 0.25 * consistency)

    # Clamp and apply minimum floor for active nodes
    return clamp(trust, 0.0, 1.0)


def sigmoid_scale(x: float, midpoint: float = 0.5, steepness: float = 6) -> float:
    """Map linear [0,1] to S-curve [0,1] — rewards sustained participation."""
    return 1.0 / (1.0 + math.exp(-steepness * (x - midpoint)))
```

**Trust tiers (for human-readable classification):**

| Trust Score | Tier | Meaning |
|-------------|------|---------|
| 0.0 – 0.2 | Untrusted | New node or flagged; reports accepted but carry minimal weight |
| 0.2 – 0.5 | Provisional | Building history; moderate weight |
| 0.5 – 0.8 | Trusted | Consistent reporter with good accuracy |
| 0.8 – 1.0 | Verified | Long-standing, highly accurate node; reports can fast-track consensus |

### 2.3 Domain Reputation Scoring Algorithm

Domain reputation is computed by aggregating reports from multiple nodes, weighted by node trust, and incorporating temporal and diversity signals.

**Score Components (0.0 – 1.0 scale, where 1.0 = most malicious):**

```
DomainReputation = w_consensus  * ConsensusScore
                 + w_temporal   * TemporalScore
                 + w_behavioral * BehavioralScore
                 + w_external   * ExternalScore

where:
  w_consensus  = 0.40
  w_temporal   = 0.20
  w_behavioral = 0.25
  w_external   = 0.15
```

**Pseudocode:**

```python
def compute_domain_reputation(domain: str, db: ClickHouseClient) -> DomainScore:
    """
    Compute reputation score for a domain.
    Returns DomainScore with overall score + component breakdown.
    """

    # =====================================================
    # CONSENSUS SCORE (0.0 - 1.0)
    # How many nodes report this domain, weighted by trust
    # =====================================================
    reports = db.query("""
        SELECT
            te.node_hash,
            nt.trust_score,
            te.anomaly_score,
            count(*) as report_count,
            min(te.received_at) as first_seen,
            max(te.received_at) as last_seen
        FROM telemetry_events te
        JOIN node_trust nt ON te.node_hash = nt.node_hash
        WHERE te.domain = {domain}
          AND te.anomaly_score > 0.3
          AND te.received_at >= now() - INTERVAL 7 DAY
        GROUP BY te.node_hash, nt.trust_score, te.anomaly_score
    """)

    if len(reports) == 0:
        return DomainScore(overall=0.0, consensus=0.0, ...)

    # Trust-weighted report strength
    weighted_reports = sum(r.trust_score * r.anomaly_score for r in reports)
    unique_nodes = len(set(r.node_hash for r in reports))

    # ASN diversity — reports from same ASN are partially deduplicated
    unique_asns = db.query("""
        SELECT count(DISTINCT geo_asn)
        FROM telemetry_events te
        WHERE te.domain = {domain}
          AND te.anomaly_score > 0.3
          AND te.received_at >= now() - INTERVAL 7 DAY
    """)

    # Minimum thresholds (anti-gaming)
    MIN_NODES = 3
    MIN_ASNS = 2
    if unique_nodes < MIN_NODES or unique_asns < MIN_ASNS:
        consensus_score = 0.0  # Not enough diversity for consensus
    else:
        # Normalize: 10+ trusted reports from 5+ ASNs = maximum score
        node_factor = min(1.0, unique_nodes / 10)
        asn_factor = min(1.0, unique_asns / 5)
        trust_factor = weighted_reports / unique_nodes  # Average trust-weighted signal
        consensus_score = node_factor * asn_factor * trust_factor

    # =====================================================
    # TEMPORAL SCORE (0.0 - 1.0)
    # Recency, persistence, and beaconing patterns
    # =====================================================

    # Recency: More recent reports score higher
    hours_since_last = (now() - max(r.last_seen for r in reports)).total_seconds() / 3600
    recency = max(0.0, 1.0 - hours_since_last / 168)  # Decay over 7 days

    # Persistence: How many consecutive days has this domain been reported?
    active_days = db.query("""
        SELECT count(DISTINCT toDate(received_at))
        FROM telemetry_events
        WHERE domain = {domain}
          AND anomaly_score > 0.3
          AND received_at >= now() - INTERVAL 30 DAY
    """)
    persistence = min(1.0, active_days / 7)

    # Beaconing: Is the query pattern periodic? (strong C2 indicator)
    beaconing_score = compute_beaconing_score(domain, db)

    temporal_score = 0.3 * recency + 0.3 * persistence + 0.4 * beaconing_score

    # =====================================================
    # BEHAVIORAL SCORE (0.0 - 1.0)
    # What detection types flagged this domain?
    # =====================================================
    detections = db.query("""
        SELECT
            detection_type,
            count(*) as cnt,
            avg(anomaly_score) as avg_score
        FROM telemetry_events
        WHERE domain = {domain}
          AND received_at >= now() - INTERVAL 7 DAY
        GROUP BY detection_type
    """)

    # Detection severity weights
    SEVERITY = {
        'dga': 0.9,          # Domain Generation Algorithm — very likely malicious
        'c2_beaconing': 0.95, # Command & Control — critical
        'newborn_domain': 0.4, # New domain — suspicious but not definitive
        'high_entropy': 0.5,   # Random-looking domain — moderate signal
        'dns_tunneling': 0.85, # Data exfiltration — very suspicious
        'blocked_upstream': 0.6, # Already blocked by known lists
        'anomalous_volume': 0.3, # Unusual query volume — weak signal alone
        'device_anomaly': 0.7,   # IoT device querying unusual domain
    }

    if not detections:
        behavioral_score = 0.0
    else:
        # Take highest severity detection, boosted by multiple detection types
        max_severity = max(SEVERITY.get(d.detection_type, 0.3) * d.avg_score
                          for d in detections)
        type_diversity = min(1.0, len(detections) / 3)  # Multiple detections = higher confidence
        behavioral_score = max_severity * (0.7 + 0.3 * type_diversity)

    # =====================================================
    # EXTERNAL SCORE (0.0 - 1.0)
    # Correlation with known threat intelligence
    # =====================================================

    # Check against ground truth sources
    in_known_malware_list = db.query(
        "SELECT count(*) FROM threat_intel_domains WHERE domain = {domain}"
    ) > 0
    in_tranco_top100k = db.query(
        "SELECT count(*) FROM tranco_top_domains WHERE domain = {domain} AND rank <= 100000"
    ) > 0

    domain_age_days = get_domain_age(domain)  # WHOIS or passive DNS

    if in_tranco_top100k:
        external_score = 0.0  # Override: popular domains are not malicious
    elif in_known_malware_list:
        external_score = 0.95  # Strong external confirmation
    elif domain_age_days is not None and domain_age_days < 7:
        external_score = 0.6  # Newborn domain — suspicious
    elif domain_age_days is not None and domain_age_days < 30:
        external_score = 0.3
    else:
        external_score = 0.1  # No external signal

    # =====================================================
    # COMPOSITE SCORE
    # =====================================================
    overall = (0.40 * consensus_score
             + 0.20 * temporal_score
             + 0.25 * behavioral_score
             + 0.15 * external_score)

    # Tranco whitelist override — never score popular domains above 0.1
    if in_tranco_top100k:
        overall = min(overall, 0.1)

    return DomainScore(
        domain=domain,
        overall=clamp(overall, 0.0, 1.0),
        consensus=consensus_score,
        temporal=temporal_score,
        behavioral=behavioral_score,
        external=external_score,
        unique_nodes=unique_nodes,
        unique_asns=unique_asns,
        detection_types=[d.detection_type for d in detections],
        first_seen=min(r.first_seen for r in reports),
        last_seen=max(r.last_seen for r in reports),
    )


def compute_beaconing_score(domain: str, db: ClickHouseClient) -> float:
    """
    Detect periodic query patterns (beaconing) using FFT-based analysis.
    Returns 0.0 (no pattern) to 1.0 (strong periodic signal).
    """
    # Get query timestamps for the last 48 hours, bucketed into 5-minute intervals
    buckets = db.query("""
        SELECT toStartOfFiveMinutes(received_at) as bucket, count(*) as cnt
        FROM telemetry_events
        WHERE domain = {domain}
          AND received_at >= now() - INTERVAL 48 HOUR
        GROUP BY bucket
        ORDER BY bucket
    """)

    if len(buckets) < 20:
        return 0.0  # Not enough data points

    # Fill gaps with zeros to create uniform time series
    time_series = fill_time_series(buckets, interval_minutes=5, span_hours=48)

    # FFT to detect periodicity
    freqs, magnitudes = fft(time_series)

    # Look for dominant frequency (excluding DC component)
    peak_magnitude = max(magnitudes[1:])
    mean_magnitude = mean(magnitudes[1:])

    if mean_magnitude == 0:
        return 0.0

    # Signal-to-noise ratio of the dominant frequency
    snr = peak_magnitude / mean_magnitude

    # SNR > 5 is strong beaconing; normalize to [0, 1]
    return min(1.0, max(0.0, (snr - 2) / 8))
```

### 2.4 Anti-Gaming Protections

#### 2.4.1 Sybil Resistance

**Problem:** An attacker creates many fake Vedetta nodes to inflate reports for a benign domain (poisoning) or suppress reports for a malicious domain.

**Defenses:**

```python
SYBIL_DEFENSES = {
    # 1. ASN Diversity Requirement
    # Reports from the same ASN are partially collapsed
    "min_unique_asns": 2,          # Minimum ASNs to enter any feed
    "asn_collapse_factor": 0.3,    # Additional reports from same ASN weighted at 30%

    # 2. Progressive Trust
    # New nodes cannot influence consensus for 7 days minimum
    "min_age_days": 7,             # Reports from nodes < 7 days old are discarded
    "min_trust_for_consensus": 0.2, # Minimum trust score to contribute to domain scoring

    # 3. Rate Limiting
    "max_reports_per_node_per_hour": 500,  # Anomaly if exceeded
    "max_unique_domains_flagged_per_day": 200,  # Normal home: ~5-20

    # 4. Report Consistency Check
    # If >80% of a node's flagged domains are unique to that node (not seen by others),
    # the node is likely poisoning
    "max_unique_flag_ratio": 0.8,

    # 5. Self-Report Detection
    # Check if the node's own IP has been reported by other nodes
    "self_report_penalty": 0.5,  # Multiply trust by 0.5 if node is itself suspicious
}
```

#### 2.4.2 Tranco Whitelist Protection

```python
def is_whitelisted(domain: str) -> bool:
    """
    Protect popular domains from false consensus.
    Uses the Tranco top-sites list (updated weekly).
    """
    # Direct match against top 100K
    if domain in TRANCO_TOP_100K:
        return True

    # Also protect base domains of top 10K
    # e.g., if "google.com" is top 10K, protect "*.google.com"
    base = extract_registered_domain(domain)  # publicsuffix2
    if base in TRANCO_TOP_10K:
        return True

    # CDN and infrastructure domains (manually curated)
    if domain in CDN_INFRASTRUCTURE_DOMAINS:
        return True

    return False
```

**Whitelist update schedule:** The Tranco list is refreshed weekly via a cron job. The infrastructure domain list is maintained in the Vedetta repository and updated with each release.

#### 2.4.3 Rate Limiting and Anomaly Detection on Reporters

```python
def validate_telemetry_batch(batch: TelemetryBatch, node: NodeRecord) -> ValidationResult:
    """
    Pre-consensus validation of incoming telemetry.
    Rejects or downgrades suspicious batches.
    """
    issues = []

    # Rate limit check
    recent_count = db.query("""
        SELECT count(*) FROM telemetry_events
        WHERE node_hash = {node.hash}
          AND received_at >= now() - INTERVAL 1 HOUR
    """)
    if recent_count + len(batch.events) > 500:
        issues.append("RATE_LIMIT_EXCEEDED")
        return ValidationResult(action="REJECT", issues=issues)

    # Check for domain stuffing (too many unique flagged domains)
    flagged_domains = [e for e in batch.events if e.anomaly_score > 0.5]
    if len(flagged_domains) > 100:
        issues.append("EXCESSIVE_FLAGS")
        # Don't reject — accept but flag for review and reduce trust
        node.trust_score *= 0.9

    # Check for Tranco domain poisoning attempts
    whitelisted_flags = [e for e in flagged_domains if is_whitelisted(e.domain)]
    if len(whitelisted_flags) > 5:
        issues.append("WHITELIST_POISONING_ATTEMPT")
        node.trust_score *= 0.7

    # Schema validation
    for event in batch.events:
        if not validate_event_schema(event):
            issues.append(f"INVALID_SCHEMA: {event.event_type}")

    valid_events = [e for e in batch.events if validate_event_schema(e)]

    return ValidationResult(
        action="ACCEPT",
        accepted_events=valid_events,
        rejected_count=len(batch.events) - len(valid_events),
        issues=issues
    )
```

### 2.5 Canary Domain Network (Ground Truth)

CrowdSec uses honeypots as ground truth. Vedetta's equivalent is a **canary domain network** — a set of domains controlled by the Vedetta project that mimic malicious patterns:

```python
CANARY_STRATEGY = {
    # 1. Known-bad canaries: Domains registered by Vedetta that exhibit
    #    DGA-like, beaconing, or tunneling patterns. Only Vedetta nodes
    #    should flag these — useful for measuring detection engine quality.
    "known_bad_canaries": [
        "xk7f9a2b.vedetta-canary.net",  # DGA-like
        "beacon.vedetta-canary.net",      # Beaconing pattern
    ],

    # 2. Known-good canaries: Domains that should NEVER be flagged.
    #    If a node flags these, it indicates a false-positive-prone engine.
    "known_good_canaries": [
        "safe.vedetta-canary.net",
        "control.vedetta-canary.net",
    ],

    # 3. External ground truth: Cross-reference with established feeds
    "ground_truth_feeds": [
        "URLhaus",          # abuse.ch malware URLs
        "PhishTank",        # Verified phishing domains
        "ThreatFox",        # abuse.ch IOCs
        "OpenPhish",        # Phishing intelligence
        "CertStream CT",    # Certificate Transparency for newborn detection
    ],
}
```

### 2.6 Feed Generation

The threat network produces four feeds, each generated by materialized views and scheduled queries in ClickHouse.

**Feed 1: Top Domains (domain reputation blocklist)**
```python
def generate_top_domains_feed(db: ClickHouseClient, limit: int = 10000) -> Feed:
    """
    Generate the primary domain reputation feed.
    Includes domains that have passed consensus and have score > threshold.
    Updated every 15 minutes.
    """
    domains = db.query("""
        SELECT
            domain,
            overall_score,
            consensus_score,
            temporal_score,
            behavioral_score,
            external_score,
            unique_nodes,
            unique_asns,
            detection_types,
            first_seen,
            last_seen,
            tags
        FROM domain_reputation_mv
        WHERE overall_score >= 0.6
          AND unique_nodes >= 3
          AND unique_asns >= 2
          AND NOT is_whitelisted
        ORDER BY overall_score DESC
        LIMIT {limit}
    """)

    return Feed(
        feed_type="top-domains",
        version=FEED_SCHEMA_VERSION,
        generated_at=now(),
        ttl_seconds=900,  # 15 minutes
        entries=[DomainEntry(**d) for d in domains]
    )
```

**Feed 2: Anomalies (sudden spikes and emerging patterns)**
```python
def generate_anomalies_feed(db: ClickHouseClient) -> Feed:
    """
    Domains with sudden volume spikes or novel behavioral patterns.
    Uses a sliding window comparison: last 6h vs. previous 7d average.
    """
    anomalies = db.query("""
        SELECT
            domain,
            recent_count,
            baseline_count,
            spike_ratio,
            detection_types,
            first_seen_network
        FROM (
            SELECT
                domain,
                countIf(received_at >= now() - INTERVAL 6 HOUR) as recent_count,
                countIf(received_at < now() - INTERVAL 6 HOUR
                    AND received_at >= now() - INTERVAL 7 DAY) / 28 as baseline_count,
                -- 28 = (7*24 - 6) / 6, approximate 6h windows in 7 days
                recent_count / greatest(baseline_count, 1) as spike_ratio,
                groupArrayDistinct(detection_type) as detection_types,
                min(received_at) as first_seen_network
            FROM telemetry_events
            WHERE received_at >= now() - INTERVAL 7 DAY
              AND anomaly_score > 0.3
            GROUP BY domain
        )
        WHERE spike_ratio > 5.0  -- 5x spike over baseline
          AND recent_count >= 10  -- Minimum absolute volume
        ORDER BY spike_ratio DESC
        LIMIT 500
    """)

    return Feed(
        feed_type="anomalies",
        version=FEED_SCHEMA_VERSION,
        generated_at=now(),
        ttl_seconds=900,
        entries=[AnomalyEntry(**a) for a in anomalies]
    )
```

**Feed 3: Emerging Threats (newborn + first-seen domains with suspicious signals)**
```python
def generate_emerging_threats_feed(db: ClickHouseClient) -> Feed:
    """
    Domains first seen in the network within the last 24h that already
    show suspicious characteristics. Early warning system.
    """
    emerging = db.query("""
        SELECT
            domain,
            first_seen_network,
            unique_nodes,
            avg_anomaly_score,
            detection_types,
            domain_age_days
        FROM domain_reputation_mv
        WHERE first_seen_network >= now() - INTERVAL 24 HOUR
          AND avg_anomaly_score > 0.5
          AND unique_nodes >= 2
          AND (domain_age_days < 7 OR domain_age_days IS NULL)
        ORDER BY avg_anomaly_score DESC
        LIMIT 200
    """)

    return Feed(
        feed_type="emerging-threats",
        version=FEED_SCHEMA_VERSION,
        generated_at=now(),
        ttl_seconds=900,
        entries=[EmergingEntry(**e) for e in emerging]
    )
```

**Feed 4: Network Health (anonymized per-node hygiene benchmark)**

This feed provides each subscribed node with anonymized percentile rankings so users can benchmark their network health against the community.

---

## 3. ClickHouse Schema Design

### 3.1 Core Tables

```sql
-- =============================================================
-- Telemetry Events: Raw ingested events from nodes
-- =============================================================
CREATE TABLE telemetry_events
(
    -- Event identity
    event_id          UUID DEFAULT generateUUIDv4(),
    node_hash         String,           -- HMAC of install ID (PII-safe)
    schema_version    UInt8,

    -- Event data
    event_type        LowCardinality(String),  -- 'dns_query', 'blocked', 'anomaly', etc.
    domain            String,
    query_type        LowCardinality(String),  -- 'A', 'AAAA', 'CNAME', 'TXT', etc.
    blocked           UInt8,                   -- 0 or 1
    anomaly_score     Float32,                 -- 0.0 - 1.0
    detection_type    LowCardinality(String),  -- 'dga', 'beaconing', 'c2', etc.
    tags              Array(LowCardinality(String)),

    -- Context (PII-stripped)
    geo_country       LowCardinality(String),  -- ISO country code
    geo_asn           UInt32,                  -- AS number
    device_type       LowCardinality(String),  -- 'iot', 'phone', 'desktop', etc.
    source_hash       String,                  -- HMAC of source IP

    -- Timestamps
    event_at          DateTime64(3),           -- When event occurred locally
    received_at       DateTime64(3) DEFAULT now64(3),  -- When backend received it

    -- Partition key
    event_date        Date DEFAULT toDate(received_at)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (domain, event_date, node_hash)
TTL event_date + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- Secondary index for node-based queries
ALTER TABLE telemetry_events ADD INDEX idx_node_hash node_hash TYPE bloom_filter(0.01) GRANULARITY 4;

-- Secondary index for anomaly queries
ALTER TABLE telemetry_events ADD INDEX idx_anomaly anomaly_score TYPE minmax GRANULARITY 4;


-- =============================================================
-- Node Trust: Precomputed trust scores per node
-- =============================================================
CREATE TABLE node_trust
(
    node_hash         String,
    trust_score       Float32,         -- 0.0 - 1.0
    trust_tier        LowCardinality(String),  -- 'untrusted', 'provisional', 'trusted', 'verified'

    -- Component scores
    longevity_score   Float32,
    accuracy_score    Float32,
    diversity_score   Float32,
    consistency_score Float32,

    -- Metadata
    first_seen        DateTime64(3),
    last_seen         DateTime64(3),
    total_reports     UInt64,
    total_domains     UInt64,
    geo_country       LowCardinality(String),
    geo_asn           UInt32,

    -- Anti-gaming flags
    is_flagged        UInt8 DEFAULT 0,
    flag_reason       Nullable(String),

    computed_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (node_hash)
SETTINGS index_granularity = 8192;


-- =============================================================
-- Domain Reputation: Precomputed domain scores
-- =============================================================
CREATE TABLE domain_reputation
(
    domain            String,

    -- Composite scores
    overall_score     Float32,
    consensus_score   Float32,
    temporal_score    Float32,
    behavioral_score  Float32,
    external_score    Float32,

    -- Consensus metadata
    unique_nodes      UInt32,
    unique_asns       UInt16,
    total_reports     UInt64,
    detection_types   Array(LowCardinality(String)),
    tags              Array(LowCardinality(String)),

    -- Temporal
    first_seen        DateTime64(3),
    last_seen         DateTime64(3),
    active_days_30d   UInt16,          -- Days with reports in last 30d

    -- Domain metadata
    domain_age_days   Nullable(UInt32),
    is_whitelisted    UInt8 DEFAULT 0,
    tranco_rank       Nullable(UInt32),

    -- Feed membership
    in_top_domains    UInt8 DEFAULT 0,
    in_anomalies      UInt8 DEFAULT 0,
    in_emerging       UInt8 DEFAULT 0,

    computed_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (domain)
SETTINGS index_granularity = 8192;

ALTER TABLE domain_reputation ADD INDEX idx_overall overall_score TYPE minmax GRANULARITY 4;
ALTER TABLE domain_reputation ADD INDEX idx_whitelisted is_whitelisted TYPE set(2) GRANULARITY 4;


-- =============================================================
-- Ground Truth: Known-malicious and known-good domains
-- =============================================================
CREATE TABLE ground_truth
(
    domain            String,
    source            LowCardinality(String),  -- 'urlhaus', 'phishtank', 'threatfox', 'canary', 'tranco'
    classification    LowCardinality(String),  -- 'malicious', 'benign', 'suspicious'
    confidence        Float32,                 -- 0.0 - 1.0
    added_at          DateTime64(3) DEFAULT now64(3),
    expires_at        Nullable(DateTime64(3)),
    metadata          String DEFAULT ''        -- JSON blob for source-specific data
)
ENGINE = ReplacingMergeTree(added_at)
ORDER BY (domain, source)
TTL expires_at DELETE
SETTINGS index_granularity = 8192;


-- =============================================================
-- Tranco Top Domains: Weekly-refreshed whitelist
-- =============================================================
CREATE TABLE tranco_top_domains
(
    domain            String,
    rank              UInt32,
    loaded_at         DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(loaded_at)
ORDER BY (domain)
SETTINGS index_granularity = 8192;
```

### 3.2 Materialized Views

```sql
-- =============================================================
-- MV: Domain report aggregation (15-minute windows)
-- Powers the consensus scoring pipeline
-- =============================================================
CREATE MATERIALIZED VIEW domain_report_agg_mv
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (domain, window_start)
AS SELECT
    domain,
    toStartOfFifteenMinutes(received_at) as window_start,

    uniqState(node_hash)          as unique_nodes_state,
    uniqState(geo_asn)            as unique_asns_state,
    countState()                  as total_reports_state,
    avgState(anomaly_score)       as avg_anomaly_state,
    maxState(anomaly_score)       as max_anomaly_state,
    groupUniqArrayState(detection_type) as detection_types_state,
    groupUniqArrayState(geo_country)    as countries_state,
    minState(received_at)         as first_seen_state,
    maxState(received_at)         as last_seen_state
FROM telemetry_events
WHERE anomaly_score > 0.1
GROUP BY domain, window_start;


-- =============================================================
-- MV: Node activity aggregation (daily)
-- Powers node trust computation
-- =============================================================
CREATE MATERIALIZED VIEW node_activity_daily_mv
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(activity_date)
ORDER BY (node_hash, activity_date)
AS SELECT
    node_hash,
    toDate(received_at) as activity_date,

    countState()                        as event_count_state,
    uniqState(domain)                   as unique_domains_state,
    countIfState(anomaly_score > 0.5)   as flagged_count_state,
    avgState(anomaly_score)             as avg_anomaly_state,
    uniqState(geo_asn)                  as asn_count_state
FROM telemetry_events
GROUP BY node_hash, activity_date;


-- =============================================================
-- MV: Domain volume spike detection (hourly)
-- Powers anomalies feed
-- =============================================================
CREATE MATERIALIZED VIEW domain_hourly_volume_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (domain, hour)
AS SELECT
    domain,
    toStartOfHour(received_at) as hour,
    count()                    as query_count,
    uniq(node_hash)            as node_count,
    avg(anomaly_score)         as avg_anomaly
FROM telemetry_events
GROUP BY domain, hour;
```

### 3.3 Scheduled Scoring Jobs

```sql
-- Run every 15 minutes via cron or ClickHouse scheduled task

-- Step 1: Recompute domain reputation scores
INSERT INTO domain_reputation
SELECT
    domain,
    -- Scores computed by the application layer (Go/Python service)
    -- This query provides the aggregated inputs
    0.0 as overall_score,       -- Placeholder: computed in application
    0.0 as consensus_score,
    0.0 as temporal_score,
    0.0 as behavioral_score,
    0.0 as external_score,
    uniqMerge(unique_nodes_state) as unique_nodes,
    uniqMerge(unique_asns_state)  as unique_asns,
    countMerge(total_reports_state) as total_reports,
    groupUniqArrayMerge(detection_types_state) as detection_types,
    [] as tags,
    minMerge(first_seen_state)  as first_seen,
    maxMerge(last_seen_state)   as last_seen,
    0 as active_days_30d,
    NULL as domain_age_days,
    0 as is_whitelisted,
    NULL as tranco_rank,
    0 as in_top_domains,
    0 as in_anomalies,
    0 as in_emerging,
    now64(3) as computed_at
FROM domain_report_agg_mv
WHERE window_start >= now() - INTERVAL 7 DAY
GROUP BY domain;

-- Note: The actual scoring (overall, consensus, temporal, behavioral, external)
-- is performed by the Vedetta scoring service (Go binary) which reads the
-- aggregated data, runs the algorithms from Section 2.3, and writes back
-- the computed scores. This keeps complex logic out of SQL.
```

---

## 4. API Contract: Telemetry Daemon ↔ Threat Network Backend

### 4.1 Authentication

All API calls require a node enrollment token, obtained during initial setup when the user opts into telemetry.

```
Authorization: Bearer <enrollment_jwt>

JWT Claims:
{
  "sub": "<node_hash>",       // HMAC of install ID
  "iss": "vedetta-daemon",
  "iat": 1711612800,
  "exp": 1743148800,          // 1 year validity
  "tier": "community"         // or "premium" for paid tiers
}
```

### 4.2 Telemetry Submission

**Endpoint:** `POST /api/v1/ingest`

**Request:**
```http
POST /api/v1/ingest HTTP/1.1
Content-Type: application/json
Content-Encoding: gzip
Authorization: Bearer <jwt>
X-Schema-Version: 1
X-Batch-ID: <uuid>
```

```json
{
  "schema_version": 1,
  "node_hash": "a1b2c3d4e5f6...",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "batch_timestamp": "2026-03-28T14:30:00Z",
  "events": [
    {
      "event_type": "dns_query",
      "domain": "suspicious-domain.xyz",
      "query_type": "A",
      "blocked": true,
      "anomaly_score": 0.87,
      "detection_type": "dga",
      "tags": ["high-entropy", "newborn"],
      "geo": "US",
      "geo_asn": 15169,
      "device_type": "iot",
      "source_hash": "f7e8d9c0b1a2...",
      "event_at": "2026-03-28T14:15:23.456Z"
    },
    {
      "event_type": "dns_query",
      "domain": "c2-beacon.example.com",
      "query_type": "TXT",
      "blocked": false,
      "anomaly_score": 0.92,
      "detection_type": "c2_beaconing",
      "tags": ["periodic", "txt-heavy"],
      "geo": "US",
      "geo_asn": 15169,
      "device_type": "desktop",
      "source_hash": "a3b4c5d6e7f8...",
      "event_at": "2026-03-28T14:16:01.789Z"
    }
  ]
}
```

**Response (Success):**
```json
{
  "status": "accepted",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "accepted": 2,
  "rejected": 0,
  "issues": [],
  "server_timestamp": "2026-03-28T14:30:01.123Z"
}
```

**Response (Partial Accept):**
```json
{
  "status": "partial",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "accepted": 1,
  "rejected": 1,
  "issues": [
    {
      "event_index": 1,
      "code": "INVALID_SCHEMA",
      "message": "Missing required field: domain"
    }
  ],
  "server_timestamp": "2026-03-28T14:30:01.123Z"
}
```

**Response (Rate Limited):**
```json
{
  "status": "rejected",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "accepted": 0,
  "rejected": 2,
  "issues": [
    {
      "code": "RATE_LIMIT_EXCEEDED",
      "message": "Node has exceeded 500 events/hour limit",
      "retry_after_seconds": 300
    }
  ],
  "server_timestamp": "2026-03-28T14:30:01.123Z"
}
```

**Error Codes:**

| HTTP Status | Code | Meaning |
|------------|------|---------|
| 200 | `accepted` | All events accepted |
| 200 | `partial` | Some events rejected (see issues array) |
| 400 | `INVALID_SCHEMA` | Event failed schema validation |
| 401 | `UNAUTHORIZED` | Invalid or expired JWT |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many events; back off |
| 503 | `SERVICE_UNAVAILABLE` | Backend overloaded; retry with backoff |

### 4.3 Feed Subscription

**Endpoint:** `GET /api/v1/feed/{feed_type}`

**Feed Types:** `top-domains`, `anomalies`, `emerging-threats`, `network-health`

**Request:**
```http
GET /api/v1/feed/top-domains?since=2026-03-28T14:00:00Z&limit=1000&format=json HTTP/1.1
Authorization: Bearer <jwt>
Accept: application/json
If-None-Match: "etag-abc123"
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | ISO 8601 | (none) | Only return entries updated after this timestamp |
| `limit` | int | 1000 | Max entries to return (max 10000) |
| `min_score` | float | 0.6 | Minimum overall score threshold |
| `format` | string | `json` | `json` or `csv` or `hostfile` (Pi-hole compatible) |
| `detection_type` | string | (none) | Filter by detection type (e.g., `dga`, `c2_beaconing`) |

**Response (JSON):**
```json
{
  "feed_type": "top-domains",
  "version": 1,
  "generated_at": "2026-03-28T14:30:00Z",
  "ttl_seconds": 900,
  "total_entries": 8472,
  "returned_entries": 1000,
  "etag": "etag-def456",
  "entries": [
    {
      "domain": "malware-c2.evil.xyz",
      "overall_score": 0.97,
      "consensus_score": 0.95,
      "temporal_score": 0.90,
      "behavioral_score": 0.98,
      "external_score": 0.95,
      "unique_nodes": 47,
      "unique_asns": 12,
      "detection_types": ["c2_beaconing", "dga"],
      "tags": ["critical", "active-c2"],
      "first_seen": "2026-03-25T08:12:00Z",
      "last_seen": "2026-03-28T14:28:00Z",
      "recommended_action": "block"
    },
    {
      "domain": "phish-login.example.com",
      "overall_score": 0.82,
      "consensus_score": 0.75,
      "temporal_score": 0.60,
      "behavioral_score": 0.70,
      "external_score": 0.95,
      "unique_nodes": 23,
      "unique_asns": 8,
      "detection_types": ["newborn_domain"],
      "tags": ["phishing", "credential-harvesting"],
      "first_seen": "2026-03-27T16:00:00Z",
      "last_seen": "2026-03-28T14:25:00Z",
      "recommended_action": "block"
    }
  ]
}
```

**Response (Hostfile format for Pi-hole/AdGuard):**
```
# Vedetta Community Threat Feed - Top Domains
# Generated: 2026-03-28T14:30:00Z
# Entries: 8472
# TTL: 900s
0.0.0.0 malware-c2.evil.xyz
0.0.0.0 phish-login.example.com
0.0.0.0 dga-domain-xk7f9.net
...
```

### 4.4 Node Status

**Endpoint:** `GET /api/v1/node/status`

**Response:**
```json
{
  "node_hash": "a1b2c3d4e5f6...",
  "trust_score": 0.72,
  "trust_tier": "trusted",
  "trust_components": {
    "longevity": 0.85,
    "accuracy": 0.68,
    "diversity": 0.70,
    "consistency": 0.78
  },
  "stats": {
    "total_events_submitted": 142857,
    "events_last_24h": 1823,
    "unique_domains_flagged": 47,
    "corroborated_flags": 31,
    "member_since": "2026-01-15T10:00:00Z"
  },
  "network_health_percentile": 72,
  "flags": []
}
```

### 4.5 Feed Diff (Incremental Updates)

For bandwidth efficiency, nodes can request only changes since their last sync.

**Endpoint:** `GET /api/v1/feed/{feed_type}/diff`

**Request:**
```http
GET /api/v1/feed/top-domains/diff?since_etag=etag-abc123 HTTP/1.1
Authorization: Bearer <jwt>
```

**Response:**
```json
{
  "feed_type": "top-domains",
  "diff_from_etag": "etag-abc123",
  "diff_to_etag": "etag-def456",
  "generated_at": "2026-03-28T14:30:00Z",
  "additions": [
    {
      "domain": "new-threat.xyz",
      "overall_score": 0.88,
      "detection_types": ["dga"],
      "recommended_action": "block"
    }
  ],
  "removals": [
    {
      "domain": "former-threat.example.com",
      "reason": "score_decayed"
    }
  ],
  "updates": [
    {
      "domain": "evolving-threat.net",
      "overall_score": 0.91,
      "previous_score": 0.75,
      "detection_types": ["c2_beaconing", "dns_tunneling"]
    }
  ]
}
```

---

## 5. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

1. **ClickHouse deployment** — Docker Compose with `telemetry_events` table and basic materialized views
2. **Ingest endpoint** — Implement `POST /api/v1/ingest` with schema validation and rate limiting
3. **Telemetry daemon completion** — Wire up the existing stub to batch, compress, and POST events
4. **Tranco whitelist loader** — Weekly cron to refresh `tranco_top_domains` table

### Phase 2: Scoring (Weeks 5-8)

1. **Node trust scoring** — Implement the algorithm from Section 2.2 as a Go service, run hourly
2. **Domain reputation scoring** — Implement Section 2.3 algorithm, run every 15 minutes
3. **Anti-gaming validation** — Implement Section 2.4 in the ingest pipeline
4. **Ground truth integration** — Ingest URLhaus, PhishTank, ThreatFox feeds into `ground_truth` table

### Phase 3: Feeds (Weeks 9-12)

1. **Feed generation** — Implement all four feed types with JSON and hostfile output
2. **Feed subscription** — Daemon pulls feeds and merges into local threat intel DB
3. **Diff endpoint** — Implement incremental feed updates for bandwidth efficiency
4. **Pi-hole/AdGuard integration** — Generate hostfile-format blocklists that users can subscribe to

### Phase 4: Hardening (Weeks 13-16)

1. **Canary domain network** — Deploy canary domains and integrate into trust scoring
2. **Beaconing detection (FFT)** — Implement the `compute_beaconing_score` function
3. **ML clustering** — Detect coordinated poisoning attempts across nodes
4. **Dashboard** — Expose network health metrics via Grafana dashboards
5. **Load testing** — Simulate 10K+ nodes submitting telemetry concurrently

---

## 6. Key Design Decisions and Rationale

### Why domains instead of IPs?

CrowdSec's model is IP-centric because it sits on server infrastructure where the attacker's IP is the primary identifier. Vedetta sits on home/SMB networks where DNS queries are the richest data source. Home users see thousands of DNS queries per day but rarely see direct IP-level attacks. Domain reputation is the natural unit for this context.

### Why not just forward to CrowdSec?

CrowdSec and Vedetta are complementary, not competitive. CrowdSec answers "which IPs are attacking servers?" while Vedetta answers "which domains are home networks talking to that they shouldn't be?" A future integration could cross-pollinate — Vedetta could flag IPs resolved from malicious domains back to CrowdSec, and CrowdSec's IP intel could enrich Vedetta's domain context.

### Why ClickHouse over TimescaleDB?

The threat network backend is a read-heavy analytical workload: billions of events, aggregated across many dimensions, with materialized views driving feed generation. ClickHouse excels at exactly this pattern with 10:1 compression and orders-of-magnitude faster analytical queries than PostgreSQL-based alternatives. The tradeoff is operational complexity, but Docker Compose makes single-node ClickHouse deployable.

### Why a 3-node / 2-ASN minimum for consensus?

This threshold balances two concerns: (1) a single compromised node cannot inject domains into feeds, and (2) the threshold isn't so high that real threats go unreported in the early network growth phase. As the network grows, these minimums can be raised. CrowdSec uses similar diversity requirements for their community blocklist.

### Why sigmoid scaling for longevity?

Linear trust growth rewards grinding (run a node for 1 day = small trust, 2 days = 2x trust). Sigmoid scaling creates a "proving period" where early days contribute little, a steep ramp in the middle where consistent behavior is rewarded, and a plateau where additional time adds diminishing trust. This mirrors CrowdSec's approach where "a daemon reporting for months at 100% accuracy eventually reaches maximum trust rank."

---

## References

- CrowdSec architecture: https://docs.crowdsec.net/docs/intro/
- CrowdSec consensus data: https://www.crowdsec.net/our-data
- CrowdSec CTI scoring: https://www.crowdsec.net/blog/crowdsec-cti-scoring-system
- CrowdSec IP range reputation: https://www.crowdsec.net/blog/introducing-the-ip-range-reputation-system
- CrowdSec GitHub: https://github.com/crowdsecurity/crowdsec
- CrowdSec detection pipeline (DeepWiki): https://deepwiki.com/crowdsecurity/crowdsec
- CrowdSec community blocklist: https://docs.crowdsec.net/docs/central_api/community_blocklist/
- Tranco top sites: https://tranco-list.eu/
- ClickHouse documentation: https://clickhouse.com/docs
- Previous Vedetta research: `06-event-aggregation-telemetry.md`, `07-competitor-analysis.md`
