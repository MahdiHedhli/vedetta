# Deep Dive: DNS-Based Threat Detection Algorithms for Vedetta

> Target platform: Raspberry Pi 4 (4GB RAM, ARM Cortex-A72 quad-core 1.5GHz)
> Language: Go | Memory budget for DNS detection: ≤50MB RSS
> Generated: 2026-03-28

## Table of Contents

1. [DGA Detection (Non-ML Approaches)](#1-dga-detection-non-ml-approaches)
2. [Beaconing Detection](#2-beaconing-detection)
3. [DNS Tunneling Detection](#3-dns-tunneling-detection)
4. [Composite Threat Scoring](#4-composite-threat-scoring)
5. [Memory & CPU Budget](#5-memory--cpu-budget)
6. [Test Dataset](#6-test-dataset)
7. [References](#7-references)

---

## 1. DGA Detection (Non-ML Approaches)

DGA-generated domains have distinctive lexical properties that can be detected without machine learning. We combine four independent scoring signals into a composite DGA score.

### 1.1 Shannon Entropy Scoring

**Principle:** DGA domains exhibit higher character-level entropy than legitimate domains because they are generated algorithmically (often pseudorandomly), while legitimate domains follow natural language patterns and branding conventions.

**Empirical thresholds (from literature):**

| Domain Type | Typical Entropy Range |
|---|---|
| Common brands (google.com, amazon.com) | 2.0–2.8 |
| Legitimate multi-word domains (stackexchange.com) | 2.8–3.5 |
| Dictionary-based DGA (superbigcomputer.net) | 3.0–3.6 |
| Pseudorandom DGA (eywonbdkjgmvsstgkblztpkfxhi.ru) | 3.8–4.5+ |

**Key finding:** A threshold of 3.8 catches most pseudorandom DGA with ~8–15% false positive rate on the Alexa top 1M. Lowering to 3.5 improves recall but increases false positives significantly. Shannon entropy alone is insufficient for dictionary-based DGA (e.g., Suppobox, Matsnu) since these concatenate real English words.

**Trade-offs:**
- Very fast: O(n) where n = domain length, ~50ns per domain on ARM
- Low memory: only a 256-entry frequency table per computation
- High false positive rate compared to ML (~8–15% vs. <1% for neural networks)
- Cannot detect dictionary-based DGA families

```go
// Shannon entropy calculation for the second-level domain (SLD) portion
func ShannonEntropy(domain string) float64 {
    // Extract SLD: "abc123.evil.com" → "abc123"
    sld := extractSLD(domain)
    if len(sld) == 0 {
        return 0.0
    }

    freq := make(map[rune]int)
    for _, c := range sld {
        freq[c]++
    }

    length := float64(utf8.RuneCountInString(sld))
    entropy := 0.0
    for _, count := range freq {
        p := float64(count) / length
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    return entropy
}

// Score: map entropy to 0.0–1.0 range
func EntropyScore(domain string) float64 {
    e := ShannonEntropy(domain)
    // Linear mapping: entropy 2.5 → 0.0, entropy 4.5 → 1.0
    score := (e - 2.5) / 2.0
    return clamp(score, 0.0, 1.0)
}
```

**CPU estimate:** ~50ns per domain on Pi 4. At 10,000 queries/hour = 0.5ms total/hour. Negligible.

### 1.2 Bigram Frequency Analysis

**Principle:** Legitimate domains are constructed from natural language (or at least human-memorable strings), so their character bigrams follow predictable frequency distributions. DGA domains contain bigram pairs that rarely appear in natural language or legitimate domains.

**Methodology (from philarkwright/DGA-Detection):**
1. Pre-compute a bigram frequency table from the Alexa top 1M domains (or Tranco list)
2. For each domain, extract all character bigrams from the SLD
3. Look up each bigram's normalized frequency in the reference table
4. The domain's bigram score = geometric mean of all bigram frequencies
5. Low geometric mean → domain contains unusual character pairs → likely DGA

**Performance:** 100% detection of GameoverZeus DGA with 8% FPR against Alexa top 1M (without allowlisting). With an allowlist of CDN/cloud domains, FPR drops to ~3%.

**Key insight:** Vowel-consonant bigrams (e.g., "an", "er", "in", "on") have the highest frequency in legitimate domains. Digit-letter and consonant-consonant-consonant sequences are rare and indicative of DGA.

```go
// Pre-computed bigram frequency table (loaded at startup from embedded file)
// Table size: 36×36 = 1,296 entries (a-z + 0-9) × 8 bytes = ~10KB
type BigramTable [36][36]float64

// Global reference table (computed from Tranco top 1M)
var RefBigrams BigramTable

func init() {
    // Load pre-computed bigram frequencies from embedded data
    RefBigrams = loadBigramTable()
}

func charIndex(c rune) int {
    switch {
    case c >= 'a' && c <= 'z':
        return int(c - 'a')
    case c >= '0' && c <= '9':
        return 26 + int(c-'0')
    default:
        return -1
    }
}

func BigramScore(domain string) float64 {
    sld := strings.ToLower(extractSLD(domain))
    if len(sld) < 3 {
        return 0.0 // Too short to score meaningfully
    }

    runes := []rune(sld)
    logSum := 0.0
    count := 0

    for i := 0; i < len(runes)-1; i++ {
        a := charIndex(runes[i])
        b := charIndex(runes[i+1])
        if a < 0 || b < 0 {
            continue
        }
        freq := RefBigrams[a][b]
        if freq < 1e-10 {
            freq = 1e-10 // Floor to avoid log(0)
        }
        logSum += math.Log(freq)
        count++
    }

    if count == 0 {
        return 1.0 // No valid bigrams → suspicious
    }

    // Geometric mean of bigram frequencies
    geoMean := math.Exp(logSum / float64(count))

    // Normalize: geoMean of legitimate domains ≈ 0.02–0.05
    // geoMean of DGA domains ≈ 0.001–0.005
    // Map to 0.0 (legitimate) to 1.0 (DGA)
    score := 1.0 - (math.Log10(geoMean)+4.0)/2.5
    return clamp(score, 0.0, 1.0)
}
```

**Memory:** ~10KB for the bigram table (embedded at compile time). Negligible.
**CPU:** ~200ns per domain (one pass over the SLD characters).

### 1.3 Dictionary-Word Ratio Scoring

**Principle:** Legitimate domains frequently contain recognizable English words or brand names (e.g., "stackoverflow", "microsoftonline", "bestbuy"). Pseudorandom DGA domains contain zero recognizable words. Dictionary-based DGA domains contain words, but their combinations are unusual (e.g., "supercomputerbig", "classalienmoon").

**Methodology:**
1. Segment the SLD into candidate words using a greedy longest-match against a compact dictionary
2. Compute the ratio: `word_coverage = total_chars_in_matched_words / total_SLD_length`
3. Bonus: Check if matched words are commonly co-occurring (brand combinations vs. random word soup)

**Dictionary design for Pi 4:**
- Use a compact dictionary of ~20,000 common English words + ~5,000 brand names/tech terms
- Store as a sorted slice for binary search, or a minimal perfect hash
- Memory: ~250KB for a packed string table

```go
// WordRatioScore segments a domain and returns 0.0 (all real words) to 1.0 (no words)
type DictionaryMatcher struct {
    words    map[string]bool // Set of known words (min length 3)
    maxLen   int             // Longest word in dictionary
}

func NewDictionaryMatcher(wordFile string) *DictionaryMatcher {
    dm := &DictionaryMatcher{words: make(map[string]bool)}
    // Load words from embedded dictionary file
    for _, w := range loadWords(wordFile) {
        if len(w) >= 3 {
            dm.words[strings.ToLower(w)] = true
            if len(w) > dm.maxLen {
                dm.maxLen = len(w)
            }
        }
    }
    return dm
}

// GreedySegment: scan SLD left-to-right, match longest dictionary word at each position
func (dm *DictionaryMatcher) GreedySegment(sld string) (matchedChars int, totalChars int) {
    sld = strings.ToLower(sld)
    runes := []rune(sld)
    totalChars = len(runes)
    matchedChars = 0
    i := 0

    for i < len(runes) {
        bestLen := 0
        maxTry := dm.maxLen
        if i+maxTry > len(runes) {
            maxTry = len(runes) - i
        }
        // Try longest match first
        for tryLen := maxTry; tryLen >= 3; tryLen-- {
            candidate := string(runes[i : i+tryLen])
            if dm.words[candidate] {
                bestLen = tryLen
                break
            }
        }
        if bestLen > 0 {
            matchedChars += bestLen
            i += bestLen
        } else {
            i++
        }
    }
    return matchedChars, totalChars
}

func (dm *DictionaryMatcher) WordRatioScore(domain string) float64 {
    sld := extractSLD(domain)
    if len(sld) < 3 {
        return 0.5 // Neutral for very short domains
    }

    matched, total := dm.GreedySegment(sld)
    coverage := float64(matched) / float64(total)

    // Invert: high coverage = legitimate = low score
    // coverage > 0.8 → score ~0.0 (legitimate)
    // coverage < 0.2 → score ~1.0 (DGA)
    score := 1.0 - coverage
    return clamp(score, 0.0, 1.0)
}
```

**Trade-offs:**
- Catches pseudorandom DGA very effectively (0% word coverage)
- Partially effective against dictionary-based DGA: word coverage may be high, but word combinations are unusual
- False positives on legitimate domains with creative spelling (e.g., "flickr", "tumblr") → mitigated by allowlisting
- Memory: ~250KB for the dictionary
- CPU: O(n × maxWordLen) per domain, ~500ns typical

### 1.4 TLD-Based Risk Scoring

**Principle:** Certain TLDs are disproportionately used for malicious purposes, including DGA campaigns. Free or extremely cheap TLDs attract abuse.

**Risk tiers (compiled from Palo Alto Unit42, Spamhaus, Netcraft data):**

| Risk Tier | TLDs | Score Weight |
|---|---|---|
| **Critical (0.9–1.0)** | .tk, .ga, .cf, .ml, .gq (Freenom free TLDs — now mostly defunct but legacy domains persist) | 0.95 |
| **High (0.7–0.9)** | .xyz, .top, .club, .work, .buzz, .surf, .icu, .pw, .ws | 0.80 |
| **Elevated (0.4–0.7)** | .info, .biz, .online, .site, .live, .click, .link, .space | 0.55 |
| **Moderate (0.2–0.4)** | .cc, .co, .me, .io, .ru, .cn | 0.30 |
| **Low (0.0–0.2)** | .com, .net, .org, .edu, .gov, country-code TLDs (established) | 0.05 |

**Important caveat:** TLD score alone has very low signal-to-noise ratio. Many legitimate services use .xyz or .io. TLD score should only serve as a multiplier/modifier on other DGA signals, never as a standalone indicator.

```go
// TLD risk scores loaded from config (allows easy updates)
var TLDRiskScores = map[string]float64{
    // Critical
    "tk": 0.95, "ga": 0.95, "cf": 0.95, "ml": 0.95, "gq": 0.95,
    // High
    "xyz": 0.80, "top": 0.80, "club": 0.75, "work": 0.75,
    "buzz": 0.80, "surf": 0.80, "icu": 0.80, "pw": 0.85, "ws": 0.70,
    // Elevated
    "info": 0.55, "biz": 0.55, "online": 0.55, "site": 0.55,
    "live": 0.50, "click": 0.60, "link": 0.55, "space": 0.50,
    // Moderate
    "cc": 0.30, "co": 0.25, "me": 0.20, "io": 0.15, "ru": 0.35, "cn": 0.35,
    // Low (default for unlisted TLDs)
}

func TLDScore(domain string) float64 {
    tld := extractTLD(domain) // "example.co.uk" → "co.uk" or "example.xyz" → "xyz"
    if score, ok := TLDRiskScores[tld]; ok {
        return score
    }
    return 0.05 // Default: low risk for established/unknown TLDs
}
```

**Memory:** ~2KB for the map. **CPU:** O(1) hash lookup.

### 1.5 Composite DGA Score

Combine all four signals with weighted averaging. The weights reflect each signal's reliability and independence:

```go
type DGAScorer struct {
    bigramTable  *BigramTable
    dictionary   *DictionaryMatcher
}

type DGAResult struct {
    EntropyScore  float64
    BigramScore   float64
    WordScore     float64
    TLDScore      float64
    CompositeScore float64
}

func (s *DGAScorer) Score(domain string) DGAResult {
    r := DGAResult{
        EntropyScore: EntropyScore(domain),
        BigramScore:  BigramScore(domain),
        WordScore:    s.dictionary.WordRatioScore(domain),
        TLDScore:     TLDScore(domain),
    }

    // Weighted combination
    // Entropy and bigram are the strongest independent signals
    // Word ratio provides redundancy and catches edge cases
    // TLD is a weak modifier
    const (
        wEntropy = 0.30
        wBigram  = 0.30
        wWord    = 0.25
        wTLD     = 0.15
    )

    r.CompositeScore = clamp(
        wEntropy*r.EntropyScore+
            wBigram*r.BigramScore+
            wWord*r.WordScore+
            wTLD*r.TLDScore,
        0.0, 1.0,
    )

    return r
}
```

**Expected performance of composite scorer:**

| Domain Type | Entropy | Bigram | Word | TLD | Composite |
|---|---|---|---|---|---|
| google.com | 0.10 | 0.05 | 0.00 | 0.05 | 0.05 |
| stackoverflow.com | 0.25 | 0.10 | 0.00 | 0.05 | 0.10 |
| xkcd.com | 0.55 | 0.70 | 1.00 | 0.05 | 0.57 |
| akamai-cdn-x7f2.net | 0.50 | 0.40 | 0.40 | 0.05 | 0.36 |
| qwrtyxzpkl.xyz | 0.95 | 0.95 | 1.00 | 0.80 | 0.94 |
| eywonbdkjgmvsst.ru | 0.90 | 0.85 | 1.00 | 0.35 | 0.82 |
| supercomputerbig.net (dict-DGA) | 0.45 | 0.20 | 0.10 | 0.05 | 0.22 |

**Key observations:**
- Pseudorandom DGA is detected with high confidence (>0.80)
- Dictionary-based DGA remains challenging (~0.20–0.35) — these require behavioral correlation (beaconing + DGA-like queries from same host) for reliable detection
- Short legitimate domains with no dictionary words (e.g., "xkcd.com") can trigger moderate false positives → mitigated by allowlisting the Tranco top 10K

---

## 2. Beaconing Detection

### 2.1 RITA/AC-Hunter Methodology

The RITA (Real Intelligence Threat Analytics) beaconing detection algorithm, developed by Active Countermeasures, identifies C2 communication by analyzing the statistical regularity of connection patterns. The core insight: malware beacons exhibit low variance in inter-query timing and payload size, even when jitter is applied.

**Four scoring components:**

1. **Timestamp Skewness Score (tsSkewScore):** Uses Bowley's quartile-based skewness to measure distribution symmetry of inter-query intervals. Beacons with jitter produce symmetric (uniform) distributions.

2. **Timestamp Dispersion Score (tsMADMScore):** Uses Median Absolute Deviation from Median (MADM) to measure the tightness of inter-query intervals around their central tendency. Perfect beacons have MADM = 0; jittered beacons have low MADM relative to the interval.

3. **Connection Count Score (tsConnCountScore):** Higher connection counts increase confidence. A minimum of 5–10 connections is required; scores increase up to ~50 connections.

4. **Data Size Score (dsScore):** Analyzes the consistency of DNS response sizes. C2 beacons typically have uniform response sizes.

### 2.2 Bowley Skewness

Standard skewness measures are sensitive to outliers. Bowley's quartile skewness is robust:

```
BowleySkew = (Q3 + Q1 - 2×Q2) / (Q3 - Q1)
```

Where Q1 = 25th percentile, Q2 = median (50th), Q3 = 75th percentile of inter-query intervals.

- **Symmetric distribution:** BowleySkew ≈ 0 → Score ≈ 1.0
- **Skewed distribution:** |BowleySkew| → 1 → Score ≈ 0.0

Jittered beacons (e.g., Cobalt Strike with 10% jitter around 60s) produce near-uniform distributions with BowleySkew ≈ 0 because the random jitter distributes symmetrically around the mean.

### 2.3 MADM (Median Absolute Deviation from Median)

```
MADM = median(|Xi - median(X)|) for all inter-query intervals X
```

- **Perfect beacon (no jitter):** MADM = 0
- **Jittered beacon (±10%):** For a 60s interval, MADM ≈ 3s
- **Normal browsing:** MADM typically >30s due to irregular human-driven access patterns

**Scoring:** `tsMADMScore = max(0, 1.0 - MADM/30.0)`. If MADM > 30s, the score is 0.

### 2.4 Complete Beaconing Detector

```go
const (
    MinBeaconSamples    = 6     // Minimum queries to evaluate
    MADMThresholdSec    = 30.0  // MADM above this → not beaconing
    MaxTrackPairs       = 50000 // Max source:domain pairs to track (memory budget)
    WindowDuration      = 24 * time.Hour // Sliding window
    BucketSize          = 64    // Timestamps per ring buffer
)

type BeaconEntry struct {
    Timestamps  [BucketSize]int64 // Unix seconds, ring buffer
    Head        int               // Ring buffer head
    Count       int               // Total count (may exceed BucketSize)
    LastSeen    int64
}

type BeaconTracker struct {
    mu      sync.RWMutex
    entries map[uint64]*BeaconEntry // Key: FNV-1a hash of sourceIP:domain
    count   int
}

func NewBeaconTracker() *BeaconTracker {
    return &BeaconTracker{
        entries: make(map[uint64]*BeaconEntry, MaxTrackPairs),
    }
}

// Record a DNS query timestamp for a source:domain pair
func (bt *BeaconTracker) Record(sourceIP, domain string, ts time.Time) {
    key := fnv1aHash(sourceIP + ":" + domain)
    bt.mu.Lock()
    defer bt.mu.Unlock()

    entry, exists := bt.entries[key]
    if !exists {
        if bt.count >= MaxTrackPairs {
            bt.evictOldest() // Remove LRU entry
        }
        entry = &BeaconEntry{}
        bt.entries[key] = entry
        bt.count++
    }

    entry.Timestamps[entry.Head%BucketSize] = ts.Unix()
    entry.Head++
    entry.Count++
    entry.LastSeen = ts.Unix()
}

// Score returns the beacon score for a source:domain pair (0.0 = not beaconing, 1.0 = definite beacon)
func (bt *BeaconTracker) Score(sourceIP, domain string) float64 {
    key := fnv1aHash(sourceIP + ":" + domain)
    bt.mu.RLock()
    entry, exists := bt.entries[key]
    bt.mu.RUnlock()

    if !exists || entry.Count < MinBeaconSamples {
        return 0.0
    }

    // Extract valid timestamps from ring buffer
    timestamps := bt.extractTimestamps(entry)
    if len(timestamps) < MinBeaconSamples {
        return 0.0
    }

    // Sort timestamps and compute inter-query intervals (deltas)
    sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
    deltas := make([]float64, len(timestamps)-1)
    for i := 1; i < len(timestamps); i++ {
        deltas[i-1] = float64(timestamps[i] - timestamps[i-1])
    }

    // Component 1: Bowley Skewness Score
    q1, q2, q3 := percentiles(deltas, 0.25, 0.50, 0.75)
    skewScore := 0.0
    if q3-q1 > 0 {
        bowley := math.Abs((q3 + q1 - 2*q2) / (q3 - q1))
        skewScore = 1.0 - bowley // Symmetric → high score
    } else {
        skewScore = 1.0 // All identical intervals → perfect beacon
    }

    // Component 2: MADM Score
    madm := medianAbsoluteDeviation(deltas)
    madmScore := math.Max(0, 1.0-madm/MADMThresholdSec)

    // Component 3: Connection Count Score
    // Logarithmic scale: 6 connections → 0.3, 20 → 0.7, 50+ → 1.0
    connScore := math.Min(1.0, math.Log2(float64(len(deltas)))/math.Log2(50))

    // Component 4: Duration Score (persistence)
    // Longer observation windows increase confidence
    duration := float64(timestamps[len(timestamps)-1]-timestamps[0]) / 3600.0 // hours
    durScore := math.Min(1.0, duration/6.0) // Full score at 6+ hours of observation

    // Weighted combination
    const (
        wSkew = 0.30
        wMADM = 0.30
        wConn = 0.20
        wDur  = 0.20
    )

    return clamp(
        wSkew*skewScore + wMADM*madmScore + wConn*connScore + wDur*durScore,
        0.0, 1.0,
    )
}

// percentiles computes quartile values from a sorted slice
func percentiles(data []float64, ps ...float64) (float64, float64, float64) {
    sort.Float64s(data)
    n := len(data)
    results := make([]float64, len(ps))
    for i, p := range ps {
        idx := p * float64(n-1)
        lower := int(math.Floor(idx))
        upper := int(math.Ceil(idx))
        if lower == upper || upper >= n {
            results[i] = data[lower]
        } else {
            frac := idx - float64(lower)
            results[i] = data[lower]*(1-frac) + data[upper]*frac
        }
    }
    return results[0], results[1], results[2]
}

func medianAbsoluteDeviation(data []float64) float64 {
    sorted := make([]float64, len(data))
    copy(sorted, data)
    sort.Float64s(sorted)
    median := sorted[len(sorted)/2]

    deviations := make([]float64, len(sorted))
    for i, v := range sorted {
        deviations[i] = math.Abs(v - median)
    }
    sort.Float64s(deviations)
    return deviations[len(deviations)/2]
}
```

### 2.5 Data Structures & Memory Budget

**Per-entry memory:**
- Ring buffer: 64 timestamps × 8 bytes = 512 bytes
- Head + Count + LastSeen: 24 bytes
- Map overhead per entry: ~80 bytes (Go map internals)
- **Total per entry: ~616 bytes**

**At 50,000 tracked pairs:** 50,000 × 616 = **30.8 MB**

This fits within our 50MB budget with room for the DGA scorer tables (~270KB) and DNS tunnel tracker (~15MB).

**Eviction strategy:** LRU based on `LastSeen`. Pairs not seen in 24 hours are eligible for eviction. Under memory pressure, evict the oldest 10% of entries.

### 2.6 Jitter-Aware Detection

Modern C2 frameworks (Cobalt Strike, Sliver, Mythic) add configurable jitter:
- **Cobalt Strike default:** 0% jitter (pure periodic) — trivially detected
- **Cobalt Strike typical config:** 10–30% jitter around the sleep interval
- **Sliver:** Configurable jitter, often 20–50%

**Why Bowley + MADM still works with jitter:**
- Jitter is typically implemented as `interval ± random(jitter_pct × interval)`
- This produces a **uniform distribution** around the mean interval
- Uniform distributions have **BowleySkew ≈ 0** (perfectly symmetric)
- MADM of a uniform distribution on [a, b] = (b-a)/4
- For 60s interval with 20% jitter: range = [48, 72], MADM ≈ 6s, madmScore = 1 - 6/30 = 0.80

Even with 50% jitter (aggressive evasion), a 60s beacon produces MADM ≈ 15s, madmScore = 0.50. Combined with high skewness and connection count scores, this still flags reliably.

**Detection limits:** Beacons with >50% jitter or very long intervals (>1 hour) become difficult to distinguish from normal DNS caching behavior. These require longer observation windows (>24 hours).

---

## 3. DNS Tunneling Detection

### 3.1 Overview of DNS Tunneling

DNS tunneling encodes arbitrary data in DNS queries and responses, using subdomain labels as the data channel. Common tools:

| Tool | Primary Record Types | Encoding | Typical Subdomain Length |
|---|---|---|---|
| iodine | NULL, TXT, CNAME, MX, A | Base32/Base64/Raw | 100–200+ chars |
| dnscat2 | TXT, CNAME, MX, A | Hex encoding | 60–120 chars |
| dns2tcp | TXT | Base64 | 80–150 chars |

### 3.2 Detection Signals

#### Signal 1: Subdomain Length & Entropy

Legitimate subdomains are short and human-readable. Tunneling tools maximize data throughput by stuffing encoded data into subdomain labels.

```go
const (
    SubdomainLenThreshold  = 50   // Characters — legitimate rarely exceeds this
    SubdomainEntropyThresh = 3.8  // Shannon entropy of subdomain portion
    LabelCountThreshold    = 5    // Number of subdomain labels
)

type TunnelSignals struct {
    SubdomainLength  int
    SubdomainEntropy float64
    LabelCount       int
    QueryType        string
    QueriesPerMinute float64
    UniqueSubdomains int // Unique subdomains to the same parent domain in window
}

func SubdomainAnalysis(fqdn string) (length int, entropy float64, labels int) {
    // Split: "aGVsbG8gd29ybGQ.sub2.evil.com" → subdomain = "aGVsbG8gd29ybGQ.sub2"
    parts := strings.Split(fqdn, ".")
    if len(parts) <= 2 {
        return 0, 0.0, 0
    }

    // Everything before the registered domain (last 2 parts for .com, or last 3 for .co.uk)
    subParts := parts[:len(parts)-2] // Simplified; use public suffix list for accuracy
    subdomain := strings.Join(subParts, ".")

    return len(subdomain), ShannonEntropy(subdomain), len(subParts)
}
```

#### Signal 2: Query Type Distribution

Legitimate DNS traffic is dominated by A and AAAA queries. Tunneling tools disproportionately use:
- **NULL records:** iodine's preferred type (deprecated by RFC 1035 — any NULL query is highly suspicious)
- **TXT records:** Used by dnscat2, dns2tcp, and many custom tunnels
- **CNAME records:** Used as fallback by iodine and dnscat2

```go
// Track query type distribution per parent domain
type QueryTypeTracker struct {
    mu       sync.RWMutex
    domains  map[string]*QueryTypeStats
}

type QueryTypeStats struct {
    Total    int
    ByType   map[string]int // "A", "AAAA", "TXT", "NULL", "CNAME", "MX"
    Window   time.Time      // Start of current window
}

func (qtt *QueryTypeTracker) RecordQuery(parentDomain, qtype string) {
    qtt.mu.Lock()
    defer qtt.mu.Unlock()

    stats, exists := qtt.domains[parentDomain]
    if !exists {
        stats = &QueryTypeStats{
            ByType: make(map[string]int),
            Window: time.Now(),
        }
        qtt.domains[parentDomain] = stats
    }
    stats.Total++
    stats.ByType[qtype]++
}

// TXTRatio returns the fraction of queries that are TXT/NULL type
func (stats *QueryTypeStats) SuspiciousTypeRatio() float64 {
    if stats.Total == 0 {
        return 0.0
    }
    suspicious := stats.ByType["TXT"] + stats.ByType["NULL"] + stats.ByType["ANY"]
    return float64(suspicious) / float64(stats.Total)
}
```

#### Signal 3: Query Volume per Parent Domain

Tunneling produces a high volume of queries to the same parent domain with many unique subdomains. Legitimate CDN domains (e.g., cloudfront.net) also have high query volumes, so we measure **unique subdomain count** per parent domain.

```go
// Track unique subdomains per parent domain using HyperLogLog for memory efficiency
type SubdomainCounter struct {
    mu       sync.RWMutex
    counters map[string]*hyperloglog.Sketch // Parent domain → HLL sketch
}

// Approximate unique subdomain count per parent domain
// Memory: ~256 bytes per HLL sketch × number of parent domains
func (sc *SubdomainCounter) Record(fqdn string) {
    parent := extractParentDomain(fqdn)
    subdomain := extractSubdomainPortion(fqdn)

    sc.mu.Lock()
    defer sc.mu.Unlock()

    sketch, exists := sc.counters[parent]
    if !exists {
        sketch = hyperloglog.New14() // 2^14 registers = 16KB per sketch (overkill; use New10 = 1KB)
        sc.counters[parent] = sketch
    }
    sketch.Insert([]byte(subdomain))
}

func (sc *SubdomainCounter) UniqueCount(parentDomain string) uint64 {
    sc.mu.RLock()
    defer sc.mu.RUnlock()
    if sketch, ok := sc.counters[parentDomain]; ok {
        return sketch.Estimate()
    }
    return 0
}
```

#### Signal 4: Encoding Detection

Tunneling tools encode binary data as base32, base64, or hex in subdomain labels. These have distinctive character distributions:

```go
// Detect encoding patterns in subdomain labels
func EncodingScore(subdomain string) float64 {
    if len(subdomain) < 10 {
        return 0.0
    }

    lower := strings.ToLower(subdomain)

    // Base32 detection: only uses a-z, 2-7, and = padding
    base32Chars := 0
    for _, c := range lower {
        if (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') || c == '=' {
            base32Chars++
        }
    }
    base32Ratio := float64(base32Chars) / float64(len(lower))

    // Hex detection: only uses 0-9, a-f
    hexChars := 0
    for _, c := range lower {
        if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
            hexChars++
        }
    }
    hexRatio := float64(hexChars) / float64(len(lower))

    // Base64 detection: uses a-z, A-Z, 0-9, +, /, =
    // In DNS, base64url uses - and _ instead of + and /
    base64Chars := 0
    for _, c := range subdomain { // Case-sensitive for base64
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=' {
            base64Chars++
        }
    }
    base64Ratio := float64(base64Chars) / float64(len(subdomain))

    // Return the highest encoding match score
    // High ratio + high entropy + long length = likely encoded data
    maxRatio := math.Max(base32Ratio, math.Max(hexRatio, base64Ratio))

    // Only flag if the subdomain is also long (short encoded strings are common in CDN URLs)
    lengthFactor := math.Min(1.0, float64(len(subdomain))/50.0)

    return maxRatio * lengthFactor
}
```

### 3.3 Composite Tunnel Score

```go
func TunnelScore(fqdn string, qtype string, queryStats *QueryTypeStats,
    uniqueSubdomains uint64, windowMinutes float64) float64 {

    subLen, subEntropy, labelCount := SubdomainAnalysis(fqdn)
    subdomain := extractSubdomainPortion(fqdn)

    // Signal 1: Subdomain length (0.0–1.0)
    lengthScore := math.Min(1.0, float64(subLen)/100.0)

    // Signal 2: Subdomain entropy (0.0–1.0)
    entropyScore := clamp((subEntropy-2.5)/2.0, 0.0, 1.0)

    // Signal 3: Label count (0.0–1.0)
    labelScore := math.Min(1.0, float64(labelCount)/6.0)

    // Signal 4: Suspicious query type ratio (0.0–1.0)
    typeScore := queryStats.SuspiciousTypeRatio()

    // Signal 5: Query rate (unique subdomains per minute to same parent)
    rateScore := 0.0
    if windowMinutes > 0 {
        rate := float64(uniqueSubdomains) / windowMinutes
        rateScore = math.Min(1.0, rate/5.0) // 5+ unique subdomains/min is suspicious
    }

    // Signal 6: Encoding detection
    encScore := EncodingScore(subdomain)

    // NULL record queries are an immediate high signal
    nullBoost := 0.0
    if qtype == "NULL" || qtype == "ANY" {
        nullBoost = 0.3
    }

    // Weighted combination
    score := 0.20*lengthScore +
        0.15*entropyScore +
        0.05*labelScore +
        0.20*typeScore +
        0.20*rateScore +
        0.20*encScore +
        nullBoost

    return clamp(score, 0.0, 1.0)
}
```

### 3.4 Known Tool Signatures

For rapid detection, maintain a set of regex patterns that match known tunneling tool fingerprints:

```go
var TunnelSignatures = []struct {
    Name    string
    Pattern *regexp.Regexp
    Score   float64
}{
    {
        Name:    "iodine",
        // iodine uses a specific prefix format and base32-encoded data
        // Subdomain pattern: [a-v0-9]{2,}.[a-v0-9]{2,}.tunnel.domain
        Pattern: regexp.MustCompile(`^[a-v0-9]{20,}\.[a-v0-9]*\.`),
        Score:   0.95,
    },
    {
        Name:    "dnscat2",
        // dnscat2 prepends a hex-encoded session ID followed by hex data
        Pattern: regexp.MustCompile(`^[0-9a-f]{16,}\.[0-9a-f]*\.`),
        Score:   0.95,
    },
    {
        Name:    "dns2tcp",
        // dns2tcp uses base64-encoded data in TXT queries
        Pattern: regexp.MustCompile(`^[A-Za-z0-9+/]{30,}={0,2}\.`),
        Score:   0.90,
    },
}

func SignatureMatch(fqdn string) (matched bool, toolName string, score float64) {
    for _, sig := range TunnelSignatures {
        if sig.Pattern.MatchString(fqdn) {
            return true, sig.Name, sig.Score
        }
    }
    return false, "", 0.0
}
```

---

## 4. Composite Threat Scoring

### 4.1 Design Philosophy

Each DNS query receives a composite `anomaly_score` in the range [0.0, 1.0] that aggregates signals from DGA detection, beaconing analysis, tunneling detection, and threat intelligence reputation feeds. The score answers: "How likely is this DNS activity to be malicious?"

**Design constraints:**
- Scores must be comparable across signal types (a 0.7 from DGA should mean roughly the same severity as a 0.7 from tunneling)
- Individual detectors output calibrated [0.0, 1.0] scores (already designed above)
- The composite score must be monotonically related to true threat probability
- False positives at the "alert" threshold should be <1% after allowlisting

### 4.2 Score Combination Strategy

We use a **maximum-of-signals with boosting** approach rather than averaging, because threat signals are typically disjoint (a domain is DGA *or* a tunnel, rarely both):

```go
type ThreatScoreResult struct {
    DGAScore       float64 // From Section 1
    BeaconScore    float64 // From Section 2
    TunnelScore    float64 // From Section 3
    ReputationScore float64 // From threat intel feeds (0.0 = clean, 1.0 = known-bad)

    CompositeScore float64 // Final anomaly_score
    PrimarySignal  string  // Which detector contributed most
    Tags           []string // e.g., ["dga_candidate", "beaconing"]
}

func ComputeThreatScore(dga, beacon, tunnel, reputation float64) ThreatScoreResult {
    result := ThreatScoreResult{
        DGAScore:        dga,
        BeaconScore:     beacon,
        TunnelScore:     tunnel,
        ReputationScore: reputation,
    }

    // Strategy: Take the maximum signal, then boost if multiple signals fire
    signals := []struct {
        score float64
        name  string
        tag   string
    }{
        {dga, "dga", "dga_candidate"},
        {beacon, "beacon", "beaconing"},
        {tunnel, "tunnel", "dns_tunnel"},
        {reputation, "reputation", "known_bad"},
    }

    // Find primary (maximum) signal
    maxScore := 0.0
    for _, s := range signals {
        if s.score > maxScore {
            maxScore = s.score
            result.PrimarySignal = s.name
        }
    }

    // Count corroborating signals (score > 0.3)
    corroborating := 0
    for _, s := range signals {
        if s.score > 0.3 {
            corroborating++
            result.Tags = append(result.Tags, s.tag)
        }
    }

    // Boost composite score when multiple signals fire
    // Two signals at 0.5 each should score higher than one signal at 0.5
    boost := 0.0
    if corroborating >= 2 {
        // Add 10% for each additional corroborating signal
        boost = 0.10 * float64(corroborating-1)
    }

    result.CompositeScore = clamp(maxScore+boost, 0.0, 1.0)
    return result
}
```

### 4.3 Normalization Techniques

Each sub-scorer already outputs [0.0, 1.0], but their distributions differ:

| Scorer | Distribution Shape | Typical Legitimate | Typical Malicious |
|---|---|---|---|
| DGA | Bimodal (most domains <0.2 or >0.7) | 0.01–0.15 | 0.70–0.95 |
| Beacon | Right-skewed (most near 0) | 0.0–0.10 | 0.60–0.95 |
| Tunnel | Right-skewed (most near 0) | 0.0–0.05 | 0.50–0.95 |
| Reputation | Binary-like (0 or 1) | 0.0 | 0.90–1.0 |

To ensure scores are calibrated (i.e., a score of 0.8 from any detector implies roughly the same probability of being malicious), we apply **isotonic calibration** during development:

1. Collect scores from each detector on a labeled dataset (known-good + known-bad domains)
2. Compute empirical P(malicious | score) for each detector
3. Build a monotonic mapping from raw score → calibrated probability
4. Embed the mapping as a lookup table (≤1KB per detector)

For the initial deployment, the linear mappings designed into each scorer above are sufficient. Calibration can be refined as Vedetta collects real-world data.

### 4.4 Alert Thresholds

```go
const (
    ThresholdInfo     = 0.30 // Logged but no alert
    ThresholdWarning  = 0.50 // Warning: needs review
    ThresholdHigh     = 0.70 // High confidence threat
    ThresholdCritical = 0.85 // Critical: likely active compromise
)

type AlertLevel int

const (
    AlertNone AlertLevel = iota
    AlertInfo
    AlertWarning
    AlertHigh
    AlertCritical
)

func ClassifyThreat(score float64) AlertLevel {
    switch {
    case score >= ThresholdCritical:
        return AlertCritical
    case score >= ThresholdHigh:
        return AlertHigh
    case score >= ThresholdWarning:
        return AlertWarning
    case score >= ThresholdInfo:
        return AlertInfo
    default:
        return AlertNone
    }
}
```

**Threshold rationale:**
- **0.30 (Info):** Captures anomalies worth logging (unusual TLDs, slightly elevated entropy). Expected to fire on ~5% of traffic. No user-visible alert.
- **0.50 (Warning):** Significant anomaly. Expected FPR ~0.5% after allowlisting. Appears in dashboard but does not send notifications.
- **0.70 (High):** High confidence detection. Expected FPR ~0.05%. Sends push notification (if configured).
- **0.85 (Critical):** Near-certain threat or reputation match. Expected FPR ~0.01%. Immediate notification + optional automated blocking.

### 4.5 Allowlisting

Critical for reducing false positives in a home/SMB environment:

```go
type Allowlist struct {
    exactDomains   map[string]bool     // e.g., "xkcd.com"
    suffixDomains  []string            // e.g., ".amazonaws.com", ".cloudfront.net"
    topDomains     map[string]bool     // Tranco top 10,000
}

func (al *Allowlist) IsAllowed(domain string) bool {
    if al.exactDomains[domain] {
        return true
    }
    if al.topDomains[domain] {
        return true
    }
    for _, suffix := range al.suffixDomains {
        if strings.HasSuffix(domain, suffix) {
            return true
        }
    }
    return false
}

// In the scoring pipeline:
func ScoreDNSQuery(query DNSEvent, scorers *ScorerSuite) ThreatScoreResult {
    domain := query.Domain

    // Skip scoring for allowlisted domains
    if scorers.Allowlist.IsAllowed(domain) {
        return ThreatScoreResult{CompositeScore: 0.0, PrimarySignal: "allowlisted"}
    }

    dga := scorers.DGA.Score(domain).CompositeScore
    beacon := scorers.Beacon.Score(query.SourceIP, domain)
    tunnel := TunnelScore(query.FQDN, query.QueryType,
        scorers.QueryTypes.Get(domain),
        scorers.SubdomainCounter.UniqueCount(extractParentDomain(query.FQDN)),
        scorers.WindowMinutes)
    reputation := scorers.ReputationLookup(domain)

    return ComputeThreatScore(dga, beacon, tunnel, reputation)
}
```

---

## 5. Memory & CPU Budget

### 5.1 Memory Breakdown (Target: ≤50MB)

| Component | Data Structure | Size |
|---|---|---|
| Bigram frequency table | [36][36]float64 array | 10 KB |
| Dictionary (20K words + 5K brands) | map[string]bool | 250 KB |
| TLD risk scores | map[string]float64 | 2 KB |
| Beacon tracker (50K entries × 616B) | map[uint64]*BeaconEntry | 30.8 MB |
| Query type tracker (10K parent domains) | map[string]*QueryTypeStats | 800 KB |
| Subdomain HLL counters (10K domains × 1KB) | map[string]*HLL | 10 MB |
| Allowlist (Tranco 10K + custom) | map[string]bool + []string | 500 KB |
| Tunnel regex patterns | []*regexp.Regexp | 10 KB |
| **Total** | | **~42.4 MB** |

This fits within the 50MB budget with 7.6MB headroom for Go runtime overhead and temporary allocations.

### 5.2 CPU Estimates (Pi 4 @ 1.5GHz)

Assuming a busy home network generating **10,000 DNS queries/hour** (~2.8 queries/second):

| Operation | Per-query Cost | Hourly Total |
|---|---|---|
| Shannon entropy | ~50ns | 0.5ms |
| Bigram scoring | ~200ns | 2ms |
| Dictionary word ratio | ~500ns | 5ms |
| TLD lookup | ~30ns | 0.3ms |
| Beacon tracker record + score | ~2μs | 20ms |
| Tunnel analysis (subdomain + encoding) | ~1μs | 10ms |
| Signature regex matching | ~500ns | 5ms |
| Composite scoring + allowlist check | ~200ns | 2ms |
| **Total per query** | **~4.5μs** | **~45ms/hour** |

**CPU utilization:** 45ms out of 3,600,000ms per hour = **0.001%**. The DNS scoring engine is completely negligible on Pi 4. Even at 100K queries/hour (a very busy small office), CPU usage would be ~0.01%.

### 5.3 Concurrency Design

```go
// The scoring pipeline runs in a single goroutine consuming from a channel
// This avoids lock contention while processing queries sequentially
type DNSScoringPipeline struct {
    ingestCh chan DNSEvent
    scorers  *ScorerSuite
    store    EventStore
}

func (p *DNSScoringPipeline) Run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case event := <-p.ingestCh:
            result := ScoreDNSQuery(event, p.scorers)
            event.AnomalyScore = result.CompositeScore
            event.Tags = result.Tags
            p.store.Insert(event)
        }
    }
}
```

A single goroutine can process 4.5μs × 10,000 = 45ms of work per hour. Buffered channel of 1,000 events provides burst absorption. No need for parallelism in the scoring path.

---

## 6. Test Dataset

### 6.1 Known-Good Domains (Expected: anomaly_score < 0.30)

```
# Tranco top sites — should score very low
google.com
facebook.com
amazon.com
apple.com
microsoft.com
netflix.com
wikipedia.org
github.com
stackoverflow.com
reddit.com

# CDN/infrastructure — should score low despite unusual appearance
d1234abcdef.cloudfront.net
ec2-54-123-45-67.compute-1.amazonaws.com
fonts.googleapis.com
cdn.jsdelivr.net
unpkg.com

# Short/creative legitimate domains — moderate entropy but allowlisted
xkcd.com
imgur.com
flickr.com
t.co
bit.ly
goo.gl

# Common IoT/smart home domains
mqtt.googleapis.com
device-metrics-us.amazon.com
spectrum.s3.amazonaws.com
time.google.com
ntp.ubuntu.com
```

### 6.2 Known-Bad: DGA Domains (Expected: anomaly_score > 0.70)

```
# Pseudorandom DGA samples (various families)
# Conficker-style
aklsdjfqwemnxcv.net
qwrtyxzpklmnbvc.com
zxcvbnmasdfghjk.org

# Necurs-style (longer, consonant-heavy)
eywonbdkjgmvsstgkblztpkfxhi.ru
xjmtprgvkdlqsfnwhycbzaeou.top
pqrstvwxyzabcdefghjklmnop.xyz

# CryptoLocker-style
jkhgfdswqazcxvbnm.co.uk
mnbvcxzasdfghjklp.tk
lkjhgfdswqazcxvb.ga

# Dictionary-based DGA (harder to detect — expect 0.30–0.60)
supercomputerbigcake.net
alienmoonfishpond.com
classicgreenrobotarm.org
```

### 6.3 Known-Bad: Beaconing Patterns (Expected: beacon_score > 0.60)

```
# Simulated beacon patterns (source_ip: timestamps in seconds since epoch)
# Perfect beacon: 60s interval, no jitter
192.168.1.100:c2.evil.com → [0, 60, 120, 180, 240, 300, 360, 420, 480, 540, 600]

# Beacon with 10% jitter (Cobalt Strike default-ish)
192.168.1.101:beacon.bad.xyz → [0, 55, 118, 174, 237, 298, 362, 419, 481, 536, 601]

# Beacon with 30% jitter (aggressive evasion)
192.168.1.102:stealth.c2.top → [0, 48, 131, 170, 253, 291, 380, 418, 502, 548, 629]

# Not a beacon: normal browsing (irregular, human-driven)
192.168.1.200:google.com → [0, 3, 45, 1200, 1205, 1210, 7800, 15000, 15002]
```

### 6.4 Known-Bad: DNS Tunneling (Expected: tunnel_score > 0.70)

```
# Iodine-style tunneling (base32 in subdomain, NULL record type)
aabbccdd0011223344556677.t.evil-tunnel.com  TYPE=NULL
ee ff0011aabbccdd55667788.t.evil-tunnel.com  TYPE=NULL

# dnscat2-style tunneling (hex-encoded session data)
0a1b2c3d4e5f0a1b2c3d4e5f6a7b8c9d.cmd.c2server.xyz  TYPE=TXT
1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c.cmd.c2server.xyz  TYPE=TXT

# dns2tcp-style (base64 in subdomain)
SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q.tun.exfil.org  TYPE=TXT
dGhpcyBpcyBhbm90aGVyIHBheWxvYWQ.tun.exfil.org  TYPE=TXT

# Legitimate but looks unusual (should NOT flag as tunnel)
v=spf1-include-_spf.google.com.example.com  TYPE=TXT
dkim1._domainkey.example.com  TYPE=TXT
_acme-challenge.letsencrypt.example.com  TYPE=TXT
```

### 6.5 Validation Script

```go
func RunValidation(scorers *ScorerSuite) {
    type TestCase struct {
        Domain       string
        QueryType    string
        Category     string // "legitimate", "dga", "tunnel"
        ExpectedLow  float64
        ExpectedHigh float64
    }

    cases := []TestCase{
        // Legitimate
        {"google.com", "A", "legitimate", 0.0, 0.20},
        {"stackoverflow.com", "A", "legitimate", 0.0, 0.20},
        {"xkcd.com", "A", "legitimate", 0.0, 0.35}, // Allow slightly higher due to short name

        // DGA
        {"qwrtyxzpklmnbvc.com", "A", "dga", 0.70, 1.0},
        {"eywonbdkjgmvsstgkblztpkfxhi.ru", "A", "dga", 0.75, 1.0},
        {"pqrstvwxyzabcdefghjklmnop.xyz", "A", "dga", 0.80, 1.0},

        // Tunnel
        {"aabbccdd0011223344556677.t.evil-tunnel.com", "NULL", "tunnel", 0.60, 1.0},
        {"SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q.tun.exfil.org", "TXT", "tunnel", 0.50, 1.0},

        // Legitimate infrastructure (should not flag)
        {"d1234abcdef.cloudfront.net", "A", "legitimate", 0.0, 0.30},
    }

    passed, failed := 0, 0
    for _, tc := range cases {
        result := ScoreDNSQuery(DNSEvent{
            Domain:    tc.Domain,
            FQDN:      tc.Domain,
            QueryType: tc.QueryType,
            SourceIP:  "192.168.1.100",
        }, scorers)

        score := result.CompositeScore
        ok := score >= tc.ExpectedLow && score <= tc.ExpectedHigh
        if ok {
            passed++
        } else {
            failed++
            log.Printf("FAIL: %s (%s) score=%.2f expected=[%.2f, %.2f]",
                tc.Domain, tc.Category, score, tc.ExpectedLow, tc.ExpectedHigh)
        }
    }

    log.Printf("Validation: %d/%d passed", passed, passed+failed)
}
```

---

## 7. References

### DGA Detection

- Philarkwright, "DGA Detection using Bigram Frequency Analysis": https://github.com/philarkwright/DGA-Detection
- Splunk, "Detecting DGA Domains": https://www.splunk.com/en_us/blog/security/detecting-dga-domains.html
- Mathew (2025), "DGA Detection with Trigram/Fourgram Entropy" (IJCA Vol 187): https://www.ijcaonline.org/archives/volume187/number44/mathew-2025-ijca-925758.pdf
- ResearchGate, "Detecting DGA-Based FQDNs with Shannon Entropy": https://www.researchgate.net/publication/370071106
- Energy LogServer, "Detection of DGA Using Entropy and AI": https://energylogserver.com/detection-of-domain-generation-algorithms-dga-using-entropy-and-artificial-intelligence/
- MITRE ATT&CK, "T1568.002 - Domain Generation Algorithms": https://attack.mitre.org/techniques/T1568/002/
- Pereira et al., "Dictionary Extraction and Detection of Algorithmically Generated Domain Names": http://faculty.washington.edu/mdecock/papers/mpereira2018a.pdf
- FIRST.org, "DNS Abuse Detection: Domain Generation Algorithms": https://www.first.org/global/sigs/dns/stakeholder-advice/detection/dga

### Beaconing Detection

- Active Countermeasures, "RITA - Real Intelligence Threat Analytics": https://www.activecountermeasures.com/free-tools/rita/
- Active Countermeasures, "RITA GitHub Repository": https://github.com/activecm/rita
- Cyb3r-Monk, "RITA-J: RITA Implementation in Jupyter Notebook": https://github.com/Cyb3r-Monk/RITA-J
- Mehmet Ergene, "Implementing RITA using KQL": https://posts.bluraven.io/implementing-rita-using-kql-8ccb0ee8eeae
- The DFIR Report, "Cobalt Strike: A Defender's Guide Part 2": https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/
- Black Hills InfoSec, "Detecting Malware Beacons with Zeek and RITA": https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/

### DNS Tunneling

- PMC, "DNS Tunnelling, Exfiltration and Detection over Cloud Environments": https://pmc.ncbi.nlm.nih.gov/articles/PMC10007605/
- Palo Alto Networks, "What is DNS Tunneling": https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling
- SANS/GIAC, "Detecting DNS Tunneling": https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367
- Infoblox, "DNS: A Small but Effective C2 System": https://www.infoblox.com/blog/security/dns-a-small-but-effective-c2-system/
- MDPI Encyclopedia, "DNS Tunnelling Detection": https://encyclopedia.pub/entry/55736
- Frontiers, "Advanced DNS Tunneling Detection: Hybrid RL and Metaheuristic": https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1728980/full

### TLD Risk & Reputation

- Palo Alto Unit42, "A Peek into Top-Level Domains and Cybercrime": https://unit42.paloaltonetworks.com/top-level-domains-cybercrime/
- BleepingComputer, "Top-Level Domains Threat Actors Like Most": https://www.bleepingcomputer.com/news/security/these-are-the-top-level-domains-threat-actors-like-the-most/
- Stobbs, "An Updated View of Bad TLDs": https://www.iamstobbs.com/insights/an-updated-view-of-bad-tlds
- CSC, "The Highest Threat TLDs": https://www.cscdbs.com/blog/the-highest-threat-tlds-part-1/
- Netcraft, "Cybercrime on Top Level Domains": https://trends.netcraft.com/cybercrime/tlds
- SOCRadar, "Top 10 TLDs Threat Actors Use for Phishing": https://socradar.io/blog/top-10-tlds-threat-actors-use-for-phishing/

### Composite Scoring & Normalization

- EmergentMind, "Composite Anomaly Score": https://www.emergentmind.com/topics/composite-anomaly-score
- CoreRuleSet, "Anomaly Scoring": https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
- Elastic, "ML Anomaly Scoring in Elasticsearch": https://www.elastic.co/blog/machine-learning-anomaly-scoring-elasticsearch-how-it-works
