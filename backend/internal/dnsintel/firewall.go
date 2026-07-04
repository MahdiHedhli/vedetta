package dnsintel

import (
	"encoding/json"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// firewallMeta captures the structured firewall fields parsed from an event's
// metadata JSON (produced by the collector transform, see the UniFi contract).
// Only the fields the enricher needs for scoring/cross-ref are decoded; unknown
// keys in the metadata are preserved untouched.
type firewallMeta struct {
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Interface string `json:"interface"`
	Direction string `json:"direction"`
	Rule      string `json:"rule"`
	Rollup    bool   `json:"rollup"`
}

// FirewallFirstSeen tracks the first occurrence of a (source_ip, dst_ip, rule)
// firewall-block tuple so that a first-seen block scores higher than a recurring
// one. It is an in-memory, thread-safe LRU-by-time map that mirrors the pattern
// used by the beaconing detector. State is bounded by periodic eviction.
type FirewallFirstSeen struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	maxKeys int
}

// NewFirewallFirstSeen creates a tracker. ttl controls how long a tuple is
// remembered (a repeat after ttl is treated as first-seen again).
func NewFirewallFirstSeen(ttl time.Duration) *FirewallFirstSeen {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &FirewallFirstSeen{
		seen:    make(map[string]time.Time),
		ttl:     ttl,
		maxKeys: 50000,
	}
}

// Observe records the tuple and reports whether it was first-seen (not present,
// or last seen longer ago than ttl).
func (f *FirewallFirstSeen) Observe(srcIP, dstIP, rule string, now time.Time) bool {
	key := srcIP + "|" + dstIP + "|" + rule
	f.mu.Lock()
	defer f.mu.Unlock()

	last, ok := f.seen[key]
	isFirst := !ok || now.Sub(last) > f.ttl
	f.seen[key] = now

	// Cheap bound: if we blow past the cap, drop the oldest entries.
	if len(f.seen) > f.maxKeys {
		cutoff := now.Add(-f.ttl)
		for k, ts := range f.seen {
			if ts.Before(cutoff) {
				delete(f.seen, k)
			}
		}
	}
	return isFirst
}

// EvictStale removes tuples older than ttl.
func (f *FirewallFirstSeen) EvictStale(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := now.Add(-f.ttl)
	for k, ts := range f.seen {
		if ts.Before(cutoff) {
			delete(f.seen, k)
		}
	}
}

// EntryCount returns the number of tracked tuples (observability).
func (f *FirewallFirstSeen) EntryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// enrichFirewall scores and tags a firewall_log event. It deliberately skips all
// DNS heuristics (DGA/tunnel/beaconing/rebinding/bypass) and applies the scoring
// model from specs/001 plan.md:
//
//   - WAN-scan rollup (tag wan_scan_noise):            0.0
//   - recurring blocked outbound:                      ~0.1
//   - first-seen blocked outbound (per src,dst,rule):  ~0.4 + tag new_fw_block
//   - referenced device has a risk_category:           +0.3 (cap 1.0) + risky_device_fw_block
//   - IPS event (dialect rest) severity 1/2/3:         0.4 / 0.7 / 1.0 + tag ips
//
// Whitelist suppression (tag_match / source_ip_pattern) zeroes the score and
// tags the event whitelisted, matching the DNS-path semantics.
func (e *Enricher) enrichFirewall(event *models.Event) {
	// Ensure required source tags exist even if the collector omitted them.
	event.Tags = appendUnique(event.Tags, "source:unifi")

	// Decode structured firewall fields from metadata (best-effort).
	var fm firewallMeta
	if event.Metadata != "" {
		_ = json.Unmarshal([]byte(event.Metadata), &fm)
	}

	// Prefer the explicit metadata source IP for cross-ref; fall back to the
	// event's SourceIP field.
	srcIP := event.SourceIP
	if srcIP == "" && fm.SrcIP != "" {
		srcIP = fm.SrcIP
	}

	// Action / direction tags (additive; collector normally sets these already).
	if fm.Action != "" {
		event.Tags = appendUnique(event.Tags, "fw:"+fm.Action)
	}
	if fm.Direction != "" {
		event.Tags = appendUnique(event.Tags, "dir:"+fm.Direction)
	}

	// Whitelist suppression: rollups and multicast/self-scan defaults live here.
	if e.FirewallWhitelisted != nil {
		if name, ok := e.FirewallWhitelisted(event.Tags, srcIP); ok {
			event.AnomalyScore = 0.0
			event.Tags = appendUnique(event.Tags, "whitelisted")
			if event.ThreatDesc == "" {
				event.ThreatDesc = "Suppressed by whitelist rule: " + name
			}
			return
		}
	}

	// WAN-scan rollup events stay at score 0 regardless (belt-and-suspenders in
	// case the whitelist rule is disabled by the user).
	if fm.Rollup || containsTag(event.Tags, "wan_scan_noise") {
		event.AnomalyScore = 0.0
		return
	}

	// IPS events (REST connector path) are scored by vendor severity, carried in
	// metadata.ips_severity (1/2/3). These are always security-relevant.
	if containsTag(event.Tags, "ips") {
		sev := ipsSeverity(event.Metadata)
		score := map[int]float64{1: 0.4, 2: 0.7, 3: 1.0}[sev]
		if score == 0 {
			score = 0.7 // unknown severity → medium
		}
		if score > event.AnomalyScore {
			event.AnomalyScore = score
		}
		e.applyFirewallDeviceContext(event, srcIP)
		return
	}

	// Only blocked traffic is scored as signal; explicit allows stay at 0.
	blocked := event.Blocked || fm.Action == "block" || fm.Action == "drop" || fm.Action == "reject"
	if !blocked {
		return
	}

	// First-seen vs recurring (source_ip, dst_ip, rule).
	base := 0.1
	if e.FirewallSeen != nil && srcIP != "" {
		if e.FirewallSeen.Observe(srcIP, fm.DstIP, fm.Rule, timeOrNow(event.Timestamp)) {
			base = 0.4
			event.Tags = appendUnique(event.Tags, "new_fw_block")
		}
	}
	if base > event.AnomalyScore {
		event.AnomalyScore = base
	}

	// Device cross-ref + risk boost.
	e.applyFirewallDeviceContext(event, srcIP)

	if event.ThreatDesc == "" && fm.Action != "" {
		desc := "Firewall " + fm.Action + " for " + fm.Protocol + " traffic"
		if fm.DstIP != "" {
			desc += " to " + fm.DstIP
		}
		if fm.Rule != "" {
			desc += " (rule: " + fm.Rule + ")"
		}
		event.ThreatDesc = desc
	}
}

// applyFirewallDeviceContext looks up the referenced device by source IP and,
// when the device carries a risk_category, boosts the score and tags the event.
func (e *Enricher) applyFirewallDeviceContext(event *models.Event, srcIP string) {
	if e.DeviceByIP == nil || srcIP == "" {
		return
	}
	dev := e.DeviceByIP(srcIP)
	if dev == nil {
		return
	}
	if dev.Vendor != "" && event.DeviceVendor == "" {
		event.DeviceVendor = dev.Vendor
	}
	if dev.Segment != "" && (event.NetworkSegment == "" || event.NetworkSegment == "default") {
		event.NetworkSegment = dev.Segment
	}

	hasRisk := dev.RiskCategory != "" || dev.EOLRisk
	if hasRisk {
		event.Tags = appendUnique(event.Tags, "risky_device_fw_block")
		event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.3)
		log.Printf("SNR: +0.30 firewall block from risk_category device (src=%s, vendor=%s, category=%s, score=%.2f)",
			srcIP, dev.Vendor, dev.RiskCategory, event.AnomalyScore)
	}
}

// ipsSeverity reads an integer ips_severity (1/2/3) from an event's metadata JSON.
func ipsSeverity(metadata string) int {
	if metadata == "" {
		return 0
	}
	var m map[string]any
	if json.Unmarshal([]byte(metadata), &m) != nil {
		return 0
	}
	switch v := m["ips_severity"].(type) {
	case float64:
		return int(v)
	case string:
		switch strings.TrimSpace(v) {
		case "1":
			return 1
		case "2":
			return 2
		case "3":
			return 3
		}
	}
	return 0
}

func timeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}
