# DNS Query Capture & Intelligence

> Priority: P0 — DNS is the single richest data source for home/SMB threat detection

## Current State in Vedetta

Vedetta's Fluent Bit collector is configured to tail Pi-hole DNS logs and parse them with a custom regex. The event schema supports `dns_query` events with fields for domain, query_type, resolved_ip, blocked status, and tags including `dga_candidate`, `newly_registered`, `c2_candidate`, and `beaconing`.

**Gaps:**
- The ingest pipeline is not implemented (events are discarded)
- No DNS analysis or scoring logic exists
- Pi-hole is the only supported DNS source
- No support for AdGuard Home, dnsmasq standalone, or Unbound
- No passive DNS capture (only log-based)
- No threat intelligence enrichment of DNS queries

## Research Findings

### 1. DNS Data Sources

**Pi-hole (Current — Extend)**
- Logs to `/var/log/pihole/pihole.log` in dnsmasq format
- Pi-hole FTL (Faster Than Light) engine provides a richer API and database
- FTL API (`http://pi.hole/admin/api.php`) returns structured JSON with query type, status, reply type, and response time
- FTL database (`/etc/pihole/pihole-FTL.db`) contains full query history in SQLite
- **Recommendation**: In addition to log tailing, consider polling the FTL API or reading FTL.db directly for richer data

**AdGuard Home**
- Increasingly popular Pi-hole alternative with DNS-over-HTTPS/DoT built in
- Query log API: `GET /control/querylog` returns JSON with client, domain, answer, upstream, elapsed time
- Filtering rules API: `GET /control/filtering/status`
- **Recommendation**: Add AdGuard Home as an alternative DNS source with a Fluent Bit HTTP input or Go poller

**Unbound / dnsmasq (Standalone)**
- Unbound logs to syslog with query and response details
- dnsmasq (used by Pi-hole) logs queries with client IP, domain, and type
- Both can be captured via Fluent Bit syslog input (already configured for port 5140)

**Passive DNS Capture (Advanced)**
- Sniff DNS traffic (UDP 53, TCP 53, DoH on 443, DoT on 853) from the network tap
- Captures queries from devices that bypass the local DNS resolver
- Detects DNS exfiltration attempts (queries sent directly to external resolvers)
- Go implementation: gopacket with BPF filter `udp port 53`
- **Key insight**: Devices bypassing Pi-hole/AdGuard (e.g., hardcoded 8.8.8.8) are often IoT devices or potentially compromised hosts. Detecting this is a high-value signal.

### 2. DNS Threat Detection Techniques

**DGA Detection (Domain Generation Algorithm)**

DGA-generated domains have distinctive characteristics:
- High Shannon entropy (random-looking character distribution)
- Unusual character bigram/trigram frequencies
- No recognizable words or brand names
- Often use cheap TLDs (.xyz, .tk, .top, .club)

Implementation approach:
```go
func shannonEntropy(domain string) float64 {
    freq := make(map[rune]float64)
    for _, c := range domain {
        freq[c]++
    }
    entropy := 0.0
    length := float64(len(domain))
    for _, count := range freq {
        p := count / length
        entropy -= p * math.Log2(p)
    }
    return entropy
}
// Threshold: legitimate domains typically score 2.0-3.5
// DGA domains typically score 3.5-4.5+
```

More advanced: Use character bigram frequency analysis compared to English/common language distributions. This catches DGA domains that artificially lower entropy.

**Beaconing Detection**

C2 callbacks often exhibit regular, periodic DNS queries:
- Same domain queried at consistent intervals (e.g., every 60s, 300s, 3600s)
- Often with small jitter (±5-10% of interval)
- Detection: Track per-source, per-domain query timestamps, compute interval statistics
- Flag when standard deviation of inter-query intervals is low relative to mean

```go
type BeaconTracker struct {
    queries map[string][]time.Time  // key: source_hash:domain
}

func (bt *BeaconTracker) IsBeaconing(source, domain string, threshold float64) bool {
    key := source + ":" + domain
    timestamps := bt.queries[key]
    if len(timestamps) < 5 { return false }
    intervals := computeIntervals(timestamps)
    mean, stddev := stats(intervals)
    // Low coefficient of variation = regular beaconing
    return (stddev / mean) < threshold  // threshold ~0.15
}
```

**Newly Registered Domain Detection**
- Domains registered within the last 30 days are disproportionately used for phishing and malware
- Data sources: WHOIS (expensive/rate-limited), or pre-compiled NRD feeds
- Free NRD feeds: WhoisDS (daily CSV), CertStream (real-time CT log monitoring)
- **Recommendation**: Download daily NRD list, load into a Bloom filter for O(1) lookup. ~500KB for 100K domains.

**DNS Tunneling Detection**
- Exfiltration via DNS encodes data in subdomain labels: `aGVsbG8gd29ybGQ.evil.com`
- Indicators: unusually long subdomain labels (>30 chars), base64/hex-like character patterns, high query volume to single domain, TXT record queries
- Detection: Flag queries where the subdomain portion exceeds an entropy + length threshold

**DNS Rebinding Detection**
- A DNS rebinding attack returns an external IP initially, then a private IP on subsequent queries
- Detection: Flag when a domain's resolved_ip transitions from public to private (RFC 1918) address space

### 3. DNS Blocklist Integration

Beyond Pi-hole's built-in blocklists, Vedetta can add intelligence layers:

| List | Focus | Update Freq | Format |
|------|-------|-------------|--------|
| abuse.ch URLhaus | Malware distribution URLs | Real-time | CSV/JSON API |
| Phishing.Database | Phishing domains | Daily | Text |
| CertStream suspicious | Newly issued certs for suspicious domains | Real-time | WebSocket |
| SANS ISC suspicious domains | Active threat domains | Daily | Text |
| Bambenek C2 feeds | Known C2 domains | Hourly | Text |
| DGA Feeds (Bambenek) | Known DGA families | Daily | Text |

### 4. DNS-over-HTTPS/DoT Visibility Challenge

Modern devices increasingly use encrypted DNS (DoH/DoT), bypassing local resolvers:
- iOS 14+ and Android 9+ support private DNS (DoT)
- Chrome/Firefox can use DoH by default
- This creates a blind spot for Pi-hole/AdGuard-based monitoring

**Mitigation strategies:**
1. **Firewall rules**: Block outbound DNS (UDP/TCP 53) except to the local resolver. Force devices to use Pi-hole.
2. **DoH/DoT interception**: Run a local DoH/DoT resolver (AdGuard Home supports this natively). Redirect common DoH providers (dns.google, cloudflare-dns.com) to the local resolver.
3. **TLS SNI monitoring**: Even with DoH, the TLS ClientHello SNI field reveals the destination. Passive capture of SNI gives partial visibility.
4. **Detection alert**: Flag devices that are making direct DNS queries to external resolvers (traffic to port 53 not addressed to the local resolver).

## Recommended Implementation

### Phase 1: Complete the DNS Pipeline (Immediate)

1. Implement `/api/v1/ingest` to accept and store DNS events
2. Add Shannon entropy calculation as an inline enrichment during ingest
3. Tag events with `dga_candidate` when entropy exceeds threshold (configurable, default 3.5)
4. Implement the `/api/v1/events` query API with DNS-specific filters
5. Add DNS query count to the dashboard status card (currently hardcoded as "—")

### Phase 2: DNS Threat Scoring Engine (Short-term)

Build a `dns_intel` Go package:
- DGA scorer (entropy + bigram analysis)
- Beaconing detector (interval statistics)
- DNS tunnel detector (subdomain length + encoding detection)
- Integrate with event ingest: compute `anomaly_score` before storage

### Phase 3: Multi-DNS-Source Support (Short-term)

- Add AdGuard Home API poller as alternative to Pi-hole log tailing
- Add passive DNS capture in the sensor for bypass detection
- Add a Fluent Bit input for Unbound query logs

### Phase 4: Threat Intel Enrichment (Medium-term)

- Implement daily NRD list download + Bloom filter lookup
- Integrate abuse.ch URLhaus domain lookup
- Add `newly_registered` and `known_bad` tags during ingest enrichment
- Cache lookups in SQLite for offline operation

## References

- Pi-hole FTL API: https://docs.pi-hole.net/ftldns/
- AdGuard Home API: https://github.com/AdguardTeam/AdGuardHome/wiki/API
- Shannon entropy for DGA detection: https://www.splunk.com/en_us/blog/security/detecting-dga-domains.html
- CertStream: https://certstream.calidog.io/
- Bambenek C2 feeds: https://osint.bambenekconsulting.com/feeds/
- DNS Rebinding attacks: https://en.wikipedia.org/wiki/DNS_rebinding
- Pi-hole DNS logs in Sentinel: https://www.hanley.cloud/2025-03-30-Watching-the-DNS-Watcher-Pihole-Logs-in-Sentinel/
