# Network Scanning & Threat Hunting Methods

> Priority: P1 — Extends core discovery into active defense

## Current State in Vedetta

Vedetta performs periodic nmap scans (ping sweep or SYN scan of top 100 ports) on configurable intervals. The scanner detects hosts, open ports, and MAC/vendor data. There is no IDS/IPS capability, no traffic analysis, and no threat hunting logic.

## Research Findings

### 1. Scanning Techniques Beyond nmap

**ARP Scanning (arp-scan)**
- Faster than nmap `-sn` for local subnet discovery (pure Layer 2)
- No IP stack required on target — detects devices that block ICMP
- Go implementation: Send raw ARP requests via gopacket, collect responses
- Vedetta could use this as a fast "heartbeat" check between full nmap scans

**Masscan**
- Asynchronous TCP SYN scanner, can scan entire /24 in under a second
- Useful for rapid port-change detection between nmap intervals
- Downside: Less accurate than nmap for service/version detection
- Vedetta use case: Quick delta scan to detect port changes, trigger full nmap only on changed hosts

**Zmap**
- Internet-scale scanner, overkill for LAN but the architecture (stateless SYN probing) is instructive
- Vedetta could borrow the pattern for lightweight, targeted probes

### 2. Intrusion Detection Approaches

**Suricata (Recommended for Vedetta Integration)**
- Open-source IDS/IPS engine with signature-based and protocol-based detection
- Runs on Raspberry Pi 4 (tested, community projects exist like SuricataPi)
- Outputs structured JSON (`eve.json`) that maps directly to Vedetta's event model
- Supports 30,000+ community rules (ET Open Ruleset, free)
- Key capabilities: protocol anomaly detection, TLS inspection, file extraction, flow logging
- **Integration path**: Run Suricata alongside Vedetta, ingest `eve.json` via Fluent Bit

**Zeek (Complementary to Suricata)**
- Passive network traffic analyzer that produces rich, structured logs
- DNS, HTTP, TLS, SMTP, SSH, and 40+ protocol analyzers
- Outputs connection logs, DNS logs, SSL certificate info, file hashes
- Heavier than Suricata on Pi 4 (~500MB-1GB RAM) — recommend as optional add-on
- Key Vedetta use case: DNS anomaly detection (DGA, tunneling, beaconing)
- Zeek scripting language allows custom detection logic

**Comparison for Vedetta:**

| Feature | Suricata | Zeek |
|---------|----------|------|
| Pi 4 viable | Yes (2-4GB RAM) | Marginal (needs 4GB+) |
| Signature-based detection | Yes (ET rules) | No (behavioral) |
| Protocol analysis depth | Good | Excellent |
| DNS logging | Basic | Comprehensive |
| TLS/JA3 fingerprinting | Yes | Yes |
| Output format | EVE JSON | TSV/JSON logs |
| Resource usage | Moderate | Higher |

### 3. Threat Hunting Techniques for Home/SMB

**DNS-Based Hunting (Highest ROI for Vedetta)**
- DGA detection: Flag domains with high entropy, unusual length, or random-looking character distributions
- Beaconing detection: Identify periodic DNS queries at regular intervals (C2 callback pattern)
- Newly registered domain detection: Cross-reference query domains against WHOIS/threat intel for age
- DNS tunneling: Flag unusually long subdomain labels or high query volume to a single domain
- Implementation: All achievable with Pi-hole log analysis + lightweight Go scoring

**Port Change Detection (Already Partially Supported)**
- Track open ports per device over time
- Alert when a device opens new ports (potential compromise indicator)
- Alert when unexpected services appear (e.g., SSH on an IoT camera)
- Implementation: Compare current scan results against stored device profiles

**Lateral Movement Detection**
- Monitor for devices scanning other devices on the LAN (unusual ARP traffic spikes)
- Detect SMB enumeration patterns (series of failed connection attempts)
- Flag internal devices making connections to unusual numbers of internal hosts
- Implementation: Requires passive traffic capture (see doc 01)

**Behavioral Baselines**
- Build per-device behavioral profiles: typical query volume, connection patterns, active hours
- Alert on deviations: device active at unusual hours, sudden spike in DNS queries, new external connections
- Implementation: Rolling averages stored in SQLite, deviation scoring in Go

### 4. MITRE ATT&CK Mapping

Vedetta's detection capabilities should map to MITRE ATT&CK techniques relevant to home/SMB:

| ATT&CK Technique | Vedetta Detection Method |
|-------------------|--------------------------|
| T1046 - Network Service Discovery | Port scan detection (passive ARP traffic analysis) |
| T1071.004 - DNS C2 | Beaconing detection, DGA scoring |
| T1572 - Protocol Tunneling | DNS tunnel detection (long subdomains, high volume) |
| T1568.002 - Domain Generation | Entropy-based DGA detection |
| T1078 - Valid Accounts | New device detection (unauthorized device on network) |
| T1040 - Network Sniffing | ARP spoofing detection |
| T1498 - Network DoS | Traffic volume anomaly detection |

## Recommended Implementation

### Phase 1: Smart Scan Scheduling (Immediate)

Enhance the existing scanner:
- **Fast ARP heartbeat** every 60 seconds (lightweight, detects new devices immediately)
- **Full nmap scan** on configurable interval (default 5 min, existing)
- **Port delta scan** triggered when ARP heartbeat detects a known device with changed behavior
- **Alert generation** for: new device, port change, device disappearance

### Phase 2: DNS Threat Hunting Engine (Short-term)

Build a Go module in the backend that processes DNS events:

```go
type DNSThreatEngine struct {
    entropyThreshold  float64  // DGA detection (default: 3.5)
    beaconWindow      time.Duration
    beaconThreshold   int      // queries in window
    newDomainAgeDays  int      // flag domains < N days old
}

func (e *DNSThreatEngine) ScoreEvent(event *Event) float64 {
    score := 0.0
    if event.EventType == "dns_query" {
        score += e.entropyScore(event.Domain)
        score += e.beaconScore(event.SourceHash, event.Domain)
        score += e.reputationScore(event.Domain)
    }
    return math.Min(score, 1.0)
}
```

### Phase 3: Optional Suricata Integration (Medium-term)

- Provide a `docker-compose.suricata.yml` override file
- Suricata container with ET Open rules, outputting `eve.json`
- Fluent Bit input for `eve.json` → normalize to Vedetta events with `event_type: "ids_alert"`
- New event type in schema: `ids_alert` (extends the enum)
- Dashboard card for IDS alerts with severity levels

### Phase 4: Behavioral Baseline Engine (Long-term)

- Per-device rolling statistics stored in a `device_baselines` table
- Deviation scoring using standard deviation from baseline
- Automatic anomaly_score enrichment on all events

## References

- Suricata documentation: https://docs.suricata.io/
- SuricataPi: https://github.com/beep-projects/SuricataPi
- Zeek documentation: https://docs.zeek.org/
- ET Open Ruleset: https://rules.emergingthreats.net/open/
- MITRE ATT&CK: https://attack.mitre.org/
- DGA Detection techniques: https://www.splunk.com/en_us/blog/security/detecting-dga-domains.html
- Beaconing detection: https://www.activecountermeasures.com/blog/
