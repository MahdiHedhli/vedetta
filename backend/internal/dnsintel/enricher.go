package dnsintel

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
	"golang.org/x/net/publicsuffix"
)

// Enricher wires all DNS threat detection algorithms into the event ingest
// pipeline. For each event, it runs applicable detectors and updates the
// event's anomaly_score and tags in place.
type Enricher struct {
	stateMu       sync.Mutex
	Beacon        *BeaconDetector
	ThreatDB      *threatintel.ThreatIntelDB
	Rebinding     *RebindingDetector
	Bypass        *BypassDetector
	IsWhitelisted func(domain string) bool // optional, for early noise suppression

	// SelfDomains are Vedetta's own hosts (community feed + telemetry, plus any
	// self-hosted mirror), derived from config in cmd/vedetta. Core polls its own feed
	// on a fixed timer, which would otherwise trip the beaconing/C2 detector on the
	// Core host's own DNS. Matched exact-or-suffix; nil = no-op.
	SelfDomains []string

	// Firewall (spec 001) — used only for event_type == "firewall_log".
	FirewallSeen        *FirewallFirstSeen                                  // first-seen (src,dst,rule) tracker
	FirewallWhitelisted func(tags []string, sourceIP string) (string, bool) // tag/source-IP whitelist check
	DeviceByIP          func(ip string) *models.Device                      // device inventory cross-ref
}

// knownGoodUpdateDomains contains domains that are known to produce
// regular "beaconing" or high-entropy subdomains as part of legitimate
// software update/telemetry mechanisms. These are excluded from DGA
// and Beaconing detection to reduce false positives.
var knownGoodUpdateDomains = []string{
	// Apple
	"apple.com", "icloud.com", "cdn-apple.com", "swcdn.apple.com", "mzstatic.com",
	// Google / Android
	"googleapis.com", "gstatic.com", "google.com", "googlevideo.com", "doubleclick.net",
	"android.com", "googleusercontent.com",
	// Microsoft / Windows
	"microsoft.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com",
	"azureedge.net", "microsoftonline.com",
	// CDNs and common infra
	"akamaiedge.net", "cloudfront.net", "fastly.net", "cloudflare.com", "akamaitechnologies.com",
	// Samsung
	"samsung.com", "samsungapps.com", "samsungcloud.com", "smartthings.com",
	// LG
	"lge.com", "lgtvsdp.com",
	// Other common IoT / Smart TV
	"roku.com", "netflix.com", "hulu.com", "disneyplus.com",
	"spotify.com", "sonos.com", "nest.com", "ring.com",
	// Amazon / Echo / AWS devices (very common in homes, high-entropy subdomains for updates/telemetry)
	"amazon.com", "amazonaws.com",
	// Philips Hue, TP-Link, Ubiquiti/Unifi (common smart home / SMB)
	"philips-hue.com", "meethue.com", "tplinkcloud.com", "ubnt.com", "ui.com", "ubiquiti.com",
	// Common telemetry / error reporting (high entropy but benign)
	"sentry.io", "segment.io", "mixpanel.com", "newrelic.com",
	// Additional common power and smart-home ecosystems
	"lifx.com", "koogeek.com", "cyberpower.com",
	// Tuya IoT cloud (common for Espressif/Realtek/Mediatek smart plugs, bulbs, and sensors;
	// these frequently produce high-entropy subdomains + regular telemetry that would otherwise trigger DGA/beacon false positives)
	"tuya.com", "tuyaus.com", "tuyacn.com", "tuya-cloud.com",
	// TP-Link / Kasa (common in home LANs with routers + IoT)
	"tplink.com", "kasa.com",
	// Other frequent IoT ecosystems (robotic mowers, cameras, and locks)
	"mammotion.com", "eufylife.com",
	// Netatmo security cameras and weather stations
	"netatmo.com", "netatmo.net",
	// PiKVM open-source IP-KVM devices
	"pikvm.org",
	// Ultra-common developer / consumer domains that frequently produce noisy single-signal "known_bad" hits
	// in abuse feeds (urlhaus etc.) during validation traffic. Pure feed matches on these
	// (especially from primary machines) is almost always FP. Real threats will still score via other signals
	// or high-risk device context (EOL, new, IoT).
	"github.com", "raw.githubusercontent.com",
	"discordapp.com", "discord.com", "cdn.discordapp.com",
	// Plex Media Server — plex.direct is Plex's dynamic DNS for direct secure
	// connections; the subdomain encodes the server's local IP + a per-server hash
	// (e.g. 10-37-129-2.<hash>.plex.direct), which trips DGA / tunneling / beacon FPs.
	"plex.tv", "plex.direct",
}

// isSelfDomain reports whether domain is one of Vedetta's own hosts (feed/telemetry
// or a self-hosted mirror). Exact-or-suffix on the registrable host, so a mirror at
// feed.mylab.example matches "feed.mylab.example" while "evilvedettas.com" does NOT
// match "vedettas.com". Case/trailing-dot normalized to match the ingest pipeline.
func (e *Enricher) isSelfDomain(domain string) bool {
	d := normalizeDNSName(domain)
	if d == "" {
		return false
	}
	for _, configured := range e.SelfDomains {
		self := normalizeDNSName(configured)
		if self == "" {
			continue
		}
		if d == self {
			return true
		}
		// Subdomain matching is useful for a configured feed host, but a bare
		// public suffix (for example "com") must never exempt every name below
		// that suffix. IP and single-label LAN hosts are exact-match only.
		if canMatchSelfSubdomains(self) && strings.HasSuffix(d, "."+self) {
			return true
		}
	}
	return false
}

func normalizeDNSName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func canMatchSelfSubdomains(host string) bool {
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(host)
	return err == nil
}

// SelfDomainsFromURLs extracts lowercased, deduped hostnames from the given URLs
// (Vedetta's community-feed / telemetry endpoints, including any operator override).
// Used to seed Enricher.SelfDomains so Core's own feed poll isn't flagged as C2
// beaconing. Blank/unparseable inputs are skipped.
func SelfDomainsFromURLs(raw ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			continue
		}
		h := normalizeDNSName(u.Hostname())
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// NewEnricher creates an Enricher with the default BeaconDetector,
// RebindingDetector, BypassDetector, and an optional ThreatIntelDB
// (can be nil if feeds haven't loaded yet).
func NewEnricher(threatDB *threatintel.ThreatIntelDB) *Enricher {
	return &Enricher{
		Beacon:       NewBeaconDetector(),
		ThreatDB:     threatDB,
		Rebinding:    NewRebindingDetector(24 * time.Hour),
		Bypass:       NewBypassDetector(nil, []string{}, 1*time.Hour),
		FirewallSeen: NewFirewallFirstSeen(24 * time.Hour),
	}
}

// EnsureDefaults fills optional detector dependencies for callers that build an
// Enricher struct directly (notably compatibility tests and embedders). Call it
// during single-threaded construction before the Enricher is shared.
func (e *Enricher) EnsureDefaults() {
	if e == nil {
		return
	}
	if e.Beacon == nil {
		e.Beacon = NewBeaconDetector()
	}
	if e.Rebinding == nil {
		e.Rebinding = NewRebindingDetector(24 * time.Hour)
	}
	if e.Bypass == nil {
		e.Bypass = NewBypassDetector(nil, []string{}, time.Hour)
	}
	if e.FirewallSeen == nil {
		e.FirewallSeen = NewFirewallFirstSeen(24 * time.Hour)
	}
}

// NewEnricherWithWhitelist is like NewEnricher but also accepts a whitelist
// checker function. This allows the Enricher to skip scoring on known-good
// domains early, dramatically improving signal-to-noise.
func NewEnricherWithWhitelist(threatDB *threatintel.ThreatIntelDB, isWhitelisted func(string) bool) *Enricher {
	e := NewEnricher(threatDB)
	e.IsWhitelisted = isWhitelisted
	return e
}

// detectionMeta captures structured output from each detection algorithm
// for storage as JSON in the event's metadata field.
type detectionMeta struct {
	DGA           *dgaMeta           `json:"dga,omitempty"`
	Tunnel        *tunnelMeta        `json:"tunnel,omitempty"`
	Beacon        *beaconMeta        `json:"beacon,omitempty"`
	Rebinding     *rebindingMeta     `json:"rebinding,omitempty"`
	Bypass        *bypassMeta        `json:"bypass,omitempty"`
	ThreatDB      *threatDBMeta      `json:"threat_db,omitempty"`
	DeviceContext *deviceContextMeta `json:"device_context,omitempty"`
}

type deviceContextMeta struct {
	Segment string   `json:"segment,omitempty"`
	Vendor  string   `json:"vendor,omitempty"`
	IsNew   bool     `json:"is_new,omitempty"`
	Boosts  []string `json:"boosts,omitempty"` // e.g., ["iot_segment", "new_device", "bypass"]
}

type dgaMeta struct {
	Entropy     float64 `json:"entropy"`
	BigramScore float64 `json:"bigram_score"`
	Score       float64 `json:"score"`
	Label       string  `json:"label"`
}

type tunnelMeta struct {
	Score   float64  `json:"score"`
	Signals []string `json:"signals"`
}

type beaconMeta struct {
	Score        float64 `json:"score"`
	CV           float64 `json:"cv"`
	MeanInterval float64 `json:"mean_interval_sec"`
	Samples      int     `json:"samples"`
}

type rebindingMeta struct {
	PublicIP  string `json:"public_ip"`
	PrivateIP string `json:"private_ip"`
}

type threatDBMeta struct {
	Confidence float64  `json:"confidence"`
	FeedTags   []string `json:"feed_tags"`
	Source     string   `json:"source"`    // which feed (urlhaus, feodotracker, etc)
	Indicator  string   `json:"indicator"` // the matching indicator value
}

type bypassMeta struct {
	Provider string  `json:"provider"`
	Method   string  `json:"method"` // "hardcoded_resolver" | "doh_dot_domain"
	Score    float64 `json:"score"`
}

// Enrich runs all applicable detection algorithms on the event and
// modifies it in place (tags, anomaly_score, threat_desc, metadata).
// This is called during ingest, before the event is written to the database.
func (e *Enricher) Enrich(event *models.Event) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.enrichEvent(event)
}

// enrichEvent runs with stateMu held, either by Enrich for direct callers or by
// BeginEventState for the processor's checkpoint-through-persistence window.
func (e *Enricher) enrichEvent(event *models.Event) {
	// GHSA-hx86: Core OWNS threat provenance and the verdict signals telemetry
	// trusts. /ingest deserializes caller-controlled fields directly onto the
	// Event, so a forged match_type / matched_indicator / known_bad tag (and, for
	// DNS, anomaly_score) could otherwise be re-exported to the community feed —
	// leaking an attacker-embedded identifier such as 192.0.2.55.badzone.example.
	// Reset them here so ONLY this enricher's own threat-intel analysis can set
	// them; no ingest, sensor, or admin token can pre-seed provenance.
	event.MatchType = ""
	event.MatchedIndicator = ""
	// Strip every verdict tag telemetry trusts (known_bad + the candidate/behavior
	// signal tags) so a caller cannot forge them; Core's own analysis re-adds them.
	event.Tags = removeTags(event.Tags, "known_bad", "c2_candidate", "dga_candidate", "tunneling_candidate", "beaconing_candidate", "newly_registered")
	if event.EventType == "dns_query" {
		event.AnomalyScore = 0 // recomputed below from analysis, never trusted from the caller
	}

	if event.EventType == "firewall_log" {
		e.enrichFirewall(event)
		return
	}
	if event.EventType != "dns_query" {
		e.enrichIP(event)
		return
	}

	// Benign context is evaluated before the heuristic work only to decide which
	// noisy behavioral detectors to skip. It MUST NOT return before threat-intel
	// evaluation: an operator allowlist or a normally-benign vendor domain can be
	// compromised, and strong IOC evidence must remain visible. The processor later
	// turns these tags into disposition/priority context without erasing evidence.
	operatorWhitelisted := e.IsWhitelisted != nil && e.IsWhitelisted(event.Domain)
	knownGoodContext := false
	for _, good := range knownGoodUpdateDomains {
		if event.Domain == good || strings.HasSuffix(event.Domain, "."+good) {
			knownGoodContext = true
			break
		}
	}
	if operatorWhitelisted {
		event.Tags = appendUnique(event.Tags, "whitelisted")
	}
	if knownGoodContext {
		event.Tags = appendUnique(event.Tags, "known_good_context")
	}
	selfDomain := e.isSelfDomain(event.Domain)
	if selfDomain {
		event.Tags = appendUnique(event.Tags, "vedetta_self")
	}
	// These exemptions are detector-specific. Known-good updater/Plex names can
	// legitimately look random and periodic, while Vedetta's own feed polling is
	// only a known beacon. Neither context is permission to suppress rebinding or
	// DNS-bypass evidence. An explicit operator whitelist retains that behavior.
	skipDGATunnel := operatorWhitelisted || knownGoodContext
	skipBeaconing := skipDGATunnel || selfDomain
	skipNetworkHeuristics := operatorWhitelisted

	var scores []float64
	var descriptions []string
	meta := &detectionMeta{}

	// Skip DGA, tunnel, and beaconing analysis for reverse DNS (PTR) lookups
	// of private IPs. macOS Bonjour/mDNS does periodic PTR sweeps of the local
	// subnet which triggers false alerts. Reversed IP octets also look like
	// random strings to the entropy/bigram scorers.
	isPrivatePTR := isPrivateReverseDNS(event.Domain)

	// 1. DGA detection on the domain
	if event.Domain != "" && !isPrivatePTR && !skipDGATunnel {
		dgaResult := ScoreDGA(event.Domain)
		if dgaResult.IsDGA {
			event.Tags = appendUnique(event.Tags, "dga_candidate")
			meta.DGA = &dgaMeta{
				Entropy:     dgaResult.Entropy,
				BigramScore: dgaResult.BigramScore,
				Score:       dgaResult.Score,
				Label:       dgaResult.Label,
			}
			descriptions = append(descriptions, fmt.Sprintf(
				"Domain looks machine-generated (DGA). The label \"%s\" has high entropy (%.1f bits) and unusual character patterns (bigram score %.0f%%), which is characteristic of malware that generates random domain names to contact command servers.",
				dgaResult.Label, dgaResult.Entropy, dgaResult.BigramScore*100,
			))
		}
		if dgaResult.IsDGA {
			scores = append(scores, dgaResult.Score)
		}
	}

	// 2. DNS tunnel detection
	if event.Domain != "" && !isPrivatePTR && !skipDGATunnel {
		tunnelResult := ScoreTunnel(event.Domain)
		if tunnelResult.IsTunnel {
			event.Tags = appendUnique(event.Tags, "dns_tunnel")
			meta.Tunnel = &tunnelMeta{
				Score:   tunnelResult.Score,
				Signals: tunnelResult.Signals,
			}
			descriptions = append(descriptions, fmt.Sprintf(
				"Possible DNS tunneling detected. Signals: %s. Attackers encode data inside DNS queries to bypass firewalls and exfiltrate information.",
				strings.Join(tunnelResult.Signals, ", "),
			))
		}
		if tunnelResult.IsTunnel {
			scores = append(scores, tunnelResult.Score)
		}

		// TXT query bonus for tunnel detection
		if IsTXTTunnelCandidate(event.QueryType) && tunnelResult.IsTunnel {
			scores = append(scores, 0.3)
		}
	}

	// 3. Beaconing detection
	if event.Domain != "" && event.SourceHash != "" && !isPrivatePTR && !skipBeaconing {
		beaconResult := e.Beacon.RecordAndScore(event.SourceHash, event.Domain, event.Timestamp)
		if beaconResult.IsBeaconing {
			event.Tags = appendUnique(event.Tags, "beaconing")
			meta.Beacon = &beaconMeta{
				Score:        beaconResult.Score,
				CV:           beaconResult.CV,
				MeanInterval: beaconResult.MeanInterval.Seconds(),
				Samples:      beaconResult.SampleCount,
			}
			descriptions = append(descriptions, fmt.Sprintf(
				"Regular beaconing pattern detected. This device queries this domain at very consistent intervals (every ~%.0fs, %d samples, variation %.1f%%). Malware and implants often 'phone home' on fixed schedules.",
				beaconResult.MeanInterval.Seconds(), beaconResult.SampleCount, beaconResult.CV*100,
			))
		}
		if beaconResult.IsBeaconing {
			scores = append(scores, beaconResult.Score)
		}
	}

	// 4. DNS rebinding detection
	if event.Domain != "" && event.ResolvedIP != "" && e.Rebinding != nil && !skipNetworkHeuristics {
		rebindResult := e.Rebinding.Check(event.Domain, event.ResolvedIP)
		if rebindResult != nil && rebindResult.IsRebinding {
			event.Tags = appendUnique(event.Tags, "dns_rebinding")
			meta.Rebinding = &rebindingMeta{
				PublicIP:  rebindResult.PublicIP,
				PrivateIP: rebindResult.PrivateIP,
			}
			descriptions = append(descriptions, fmt.Sprintf(
				"DNS rebinding attack detected. This domain previously resolved to a public IP (%s) and now resolves to a private IP (%s). This technique lets external attackers access devices on your local network.",
				rebindResult.PublicIP, rebindResult.PrivateIP,
			))
			scores = append(scores, 0.4)
		}

		// Extra boost for rebinding to high-risk devices (SNR-15)
		if rebindResult != nil && rebindResult.IsRebinding {
			isHighRiskDevice := containsTag(event.Tags, "new_device") || containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "eol_router")

			if event.DeviceVendor != "" {
				lowerVendor := strings.ToLower(event.DeviceVendor)
				if strings.Contains(lowerVendor, "espressif") || strings.Contains(lowerVendor, "realtek") || strings.Contains(lowerVendor, "mediatek") {
					isHighRiskDevice = true
				}
			}

			if isHighRiskDevice {
				scores = append(scores, 0.25) // Additional boost
				descriptions = append(descriptions, "This rebinding targets a high-risk device (new or IoT/embedded hardware), which is particularly dangerous.")
				log.Printf("SNR: +0.25 rebinding boost for high-risk device (domain=%s, vendor=%s, segment=%s)", event.Domain, event.DeviceVendor, event.NetworkSegment)
			}
		}
	}

	// 5. DNS bypass detection
	// Alert when a device is querying well-known public DNS resolvers directly,
	// bypassing the local network DNS (Pi-hole, router, etc.).
	// This is a strong signal of IoT devices with hardcoded resolvers, or
	// compromised devices trying to evade DNS-level security controls.
	if event.Domain != "" && e.Bypass != nil && !skipNetworkHeuristics {
		// Check for hardcoded public DNS resolver IPs
		if event.ResolvedIP != "" {
			resolverIP, provider := e.Bypass.DetectPublicResolverBypass(event.ResolvedIP)
			if resolverIP != "" {
				event.Tags = appendUnique(event.Tags, "dns_bypass")
				meta.Bypass = &bypassMeta{
					Provider: provider,
					Method:   "hardcoded_resolver",
					Score:    0.6,
				}
				descriptions = append(descriptions, fmt.Sprintf(
					"DNS bypass detected. This device queried a hardcoded public DNS resolver (%s, %s) instead of using the local DNS resolver (Pi-hole, router, or AdGuard). This is typical of IoT devices with embedded DNS settings or compromised devices trying to evade local DNS-level security controls.",
					resolverIP, provider,
				))
				scores = append(scores, 0.6)
			}
		}

		// Check for DoH/DoT domain queries if no hardcoded resolver was found
		if meta.Bypass == nil && event.Domain != "" {
			dohProvider := e.Bypass.DetectDoHDotBypass(event.Domain)
			if dohProvider != "" {
				event.Tags = appendUnique(event.Tags, "dns_bypass")
				meta.Bypass = &bypassMeta{
					Provider: dohProvider,
					Method:   "doh_dot_domain",
					Score:    0.5,
				}
				descriptions = append(descriptions, fmt.Sprintf(
					"DNS bypass via DoH/DoT detected. This device queried a DNS-over-HTTPS or DNS-over-TLS provider domain (%s via %s), which bypasses local DNS filtering. This suggests the device is intentionally trying to circumvent network-level DNS security controls.",
					event.Domain, dohProvider,
				))
				scores = append(scores, 0.5)
			}
		}
	}

	// 6. Threat intel domain lookup
	if event.Domain != "" && e.ThreatDB != nil {
		result := e.ThreatDB.Lookup(event.Domain)
		if result.Found {
			event.Tags = appendUnique(event.Tags, "known_bad")
			// Match provenance (GHSA-hx86): a DOMAIN-list hit. matched_indicator is the
			// matched list entry (== the observed FQDN today's exact-match logic).
			event.MatchType = "domain"
			event.MatchedIndicator = result.Indicator.Value
			for _, tag := range result.Indicator.Tags {
				event.Tags = appendUnique(event.Tags, tag)
			}
			meta.ThreatDB = &threatDBMeta{
				Confidence: result.Confidence,
				FeedTags:   result.Indicator.Tags,
				Source:     result.Indicator.Source,
				Indicator:  result.Indicator.Value,
			}

			// Build description with feed source reference URLs
			desc := fmt.Sprintf(
				"This domain appears in threat intelligence feeds (confidence %.0f%%, source: %s). It has been associated with: %s.",
				result.Confidence*100, result.Indicator.Source, strings.Join(result.Indicator.Tags, ", "),
			)

			// Add reference URLs based on feed source
			switch result.Indicator.Source {
			case "urlhaus":
				desc += fmt.Sprintf(" Verify: https://urlhaus.abuse.ch/browse.php?search=%s", event.Domain)
			case "feodotracker":
				desc += fmt.Sprintf(" Verify: https://feodotracker.abuse.ch/browse/host/%s/", result.Indicator.Value)
			}

			descriptions = append(descriptions, desc)
			scores = append(scores, result.Confidence)
		}
	}

	// 7. Threat intel IP lookup
	e.enrichIP(event)

	// === Device Context Scoring Adjustments (SNR-09) ===
	// Use passive discovery data (now attached to the event) to improve signal quality.
	// IoT/guest devices doing suspicious DNS are higher risk.
	// Known consumer devices on the main network are lower risk for the same signals.

	// Populate device context metadata for UI and analysis
	if containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "new_device_context") || containsTag(event.Tags, "dns_bypass") || containsTag(event.Tags, "eol_router") {
		if meta.DeviceContext == nil {
			meta.DeviceContext = &deviceContextMeta{}
		}
		meta.DeviceContext.Segment = event.NetworkSegment
		meta.DeviceContext.Vendor = event.DeviceVendor
		meta.DeviceContext.IsNew = containsTag(event.Tags, "new_device")

		boosts := []string{}
		if containsTag(event.Tags, "iot_context") {
			boosts = append(boosts, "iot_segment")
		}
		if containsTag(event.Tags, "new_device_context") {
			boosts = append(boosts, "new_device")
		}
		if containsTag(event.Tags, "eol_router") || containsTag(event.Tags, "eol_device_context") {
			boosts = append(boosts, "eol_router")
		}
		if containsTag(event.Tags, "dns_bypass") && (containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "new_device")) {
			boosts = append(boosts, "bypass_high_risk")
		}
		meta.DeviceContext.Boosts = boosts
	}
	if event.NetworkSegment == "iot" || event.NetworkSegment == "guest" {
		if event.AnomalyScore > 0.25 {
			event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.12)
			if !containsTag(event.Tags, "iot_context") {
				event.Tags = appendUnique(event.Tags, "iot_context")
			}
			log.Printf("SNR: +0.12 boost for iot/guest segment device (domain=%s, segment=%s, score=%.2f)", event.Domain, event.NetworkSegment, event.AnomalyScore)
		}
	}

	if event.DeviceVendor != "" {
		lowerVendor := strings.ToLower(event.DeviceVendor)
		iotLike := strings.Contains(lowerVendor, "espressif") ||
			strings.Contains(lowerVendor, "realtek") ||
			strings.Contains(lowerVendor, "mediatek") ||
			strings.Contains(lowerVendor, "broadcom")

		if iotLike && event.AnomalyScore > 0.2 {
			event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.10)
		}
	} else if event.AnomalyScore > 0.3 {
		// Unknown vendor + suspicious activity = slight boost (common for compromised or cheap IoT)
		event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.08)
	}

	// Conservative adjustment for known good consumer devices on the main network
	if event.NetworkSegment == "default" && event.DeviceVendor != "" {
		lowerVendor := strings.ToLower(event.DeviceVendor)
		knownGood := strings.Contains(lowerVendor, "apple") ||
			strings.Contains(lowerVendor, "samsung") ||
			strings.Contains(lowerVendor, "dell") ||
			strings.Contains(lowerVendor, "lenovo") ||
			strings.Contains(lowerVendor, "asus") ||
			strings.Contains(lowerVendor, "hp ") ||
			strings.Contains(lowerVendor, "intel") ||
			strings.Contains(lowerVendor, "microsoft") ||
			strings.Contains(lowerVendor, "ubiquiti") ||
			strings.Contains(lowerVendor, "ubnt") ||
			strings.Contains(lowerVendor, "sonos")

		if knownGood && event.AnomalyScore > 0.4 {
			// Slightly lower suspicion for known good vendors on the main LAN
			event.AnomalyScore = event.AnomalyScore * 0.9
		}
	}

	// New device boost (SNR-11): Brand new devices doing suspicious DNS are higher risk.
	// Skip for pure beaconing (common legitimate behavior from new IoT devices on real networks);
	// keep full boost for DGA/tunnel/rebind/bypass (high-risk signals).
	isPureBeaconing := containsTag(event.Tags, "beaconing") &&
		!containsTag(event.Tags, "dga") &&
		!containsTag(event.Tags, "dns_tunneling") &&
		!containsTag(event.Tags, "dns_rebinding") &&
		!containsTag(event.Tags, "dns_bypass")
	if containsTag(event.Tags, "new_device") && event.AnomalyScore > 0.25 && !isPureBeaconing {
		event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.15)
		if !containsTag(event.Tags, "new_device_context") {
			event.Tags = appendUnique(event.Tags, "new_device_context")
			descriptions = append(descriptions, "This activity originated from a device that was first discovered on the network very recently (within the last 48 hours), which significantly increases suspicion.")
		}
		log.Printf("SNR: +0.15 boost for new_device (domain=%s, vendor=%s, score=%.2f)", event.Domain, event.DeviceVendor, event.AnomalyScore)
	}

	// Very new device boost (< 1 hour): Even higher risk
	if containsTag(event.Tags, "very_new_device") && event.AnomalyScore > 0.2 {
		event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.10)
		log.Printf("SNR: +0.10 boost for very_new_device (<1h) (domain=%s, score=%.2f)", event.Domain, event.AnomalyScore)
	}

	// EOL Router / High-Risk Device boost (new feature for IC3 2026-03-12 AVrecon advisory)
	// Devices matching known EOL models (D-Link DIR-8xx, TP-Link WR8xx, Netgear R7000/DGN, Zyxel VMG etc.)
	// are frequently compromised and turned into residential proxies / C2 relays.
	// Any suspicious DNS activity (DGA/tunnel/rebind/bypass) from them is very high priority.
	if containsTag(event.Tags, "eol_router") && event.AnomalyScore > 0.15 {
		boost := 0.22
		event.AnomalyScore = math.Min(1.0, event.AnomalyScore+boost)
		if !containsTag(event.Tags, "eol_device_context") {
			event.Tags = appendUnique(event.Tags, "eol_device_context")
			descriptions = append(descriptions, "This activity originated from an End-of-Life (EOL) router or IoT device matching models known to be heavily exploited by AVrecon malware (FBI IC3 FLASH 2026-03-12). These devices rarely receive security updates and are commonly sold as residential proxies.")
		}
		log.Printf("SNR: +%.2f boost for EOL router/device (domain=%s, vendor=%s, score=%.2f)", boost, event.Domain, event.DeviceVendor, event.AnomalyScore)
	}

	// Extra boost for DNS bypass from high-risk devices (SNR-13)
	// A new or IoT device bypassing local DNS (public resolver or DoH) is a strong signal.
	if containsTag(event.Tags, "dns_bypass") {
		isHighRiskDevice := containsTag(event.Tags, "new_device") || containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "eol_router")

		if event.DeviceVendor != "" {
			lowerVendor := strings.ToLower(event.DeviceVendor)
			if strings.Contains(lowerVendor, "espressif") || strings.Contains(lowerVendor, "realtek") || strings.Contains(lowerVendor, "mediatek") {
				isHighRiskDevice = true
			}
		}

		if isHighRiskDevice && event.AnomalyScore > 0.2 {
			event.AnomalyScore = math.Min(1.0, event.AnomalyScore+0.12)
			log.Printf("SNR: +0.12 bypass boost for high-risk device (domain=%s, vendor=%s, segment=%s, score=%.2f)", event.Domain, event.DeviceVendor, event.NetworkSegment, event.AnomalyScore)
		}
	}

	// Consolidated device context explanation (cleaner threat descriptions)
	contextReasons := []string{}
	if containsTag(event.Tags, "iot_context") {
		contextReasons = append(contextReasons, fmt.Sprintf("on a %s network segment", event.NetworkSegment))
	}
	if containsTag(event.Tags, "new_device_context") {
		contextReasons = append(contextReasons, "from a device first seen in the last 48 hours")
	}
	if containsTag(event.Tags, "eol_device_context") || containsTag(event.Tags, "eol_router") {
		contextReasons = append(contextReasons, "from an EOL/vulnerable router (high exploitation risk per IC3 advisory)")
	}
	if event.DeviceVendor != "" && (containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "new_device_context") || containsTag(event.Tags, "eol_device_context")) {
		contextReasons = append(contextReasons, fmt.Sprintf("vendor: %s", event.DeviceVendor))
	}

	if len(contextReasons) > 0 {
		descriptions = append(descriptions, fmt.Sprintf("This activity came from a high-risk device (%s).", strings.Join(contextReasons, ", ")))
	}

	// Composite anomaly score - CONSERVATIVE VERSION for better signal-to-noise
	// Goal: Isolated weird domains (common source of false positives) should not
	// easily exceed ~0.65 unless they have corroborating signals.
	if len(scores) > 0 {
		maxScore := 0.0
		for _, s := range scores {
			if s > maxScore {
				maxScore = s
			}
		}

		signalCount := 0
		for _, s := range scores {
			if s > 0.3 {
				signalCount++
			}
		}

		// New conservative logic:
		// - Single signal (no corroboration): cap at 0.65
		// - Two signals: allow up to ~0.85
		// - Three+ signals or strong threat intel: allow up to 1.0
		var composite float64

		if meta.ThreatDB != nil {
			// A confirmed feed match is already strong, sourced evidence; do not
			// demote its confidence merely because it is the only detector firing.
			composite = maxScore
		} else if signalCount <= 1 {
			// Single signal — be conservative (biggest false positive reducer)
			composite = math.Min(0.65, maxScore)
		} else if signalCount == 2 {
			boost := 0.12
			composite = math.Min(0.88, maxScore+boost)
		} else {
			// 3+ signals — real threats usually look like this
			boost := 0.18
			composite = math.Min(1.0, maxScore+boost)
		}

		if composite > event.AnomalyScore {
			event.AnomalyScore = composite
		}
	}

	// Set human-readable threat description
	if len(descriptions) > 0 {
		event.ThreatDesc = strings.Join(descriptions, " ")
	}

	// Merge detection metadata into the source document instead of replacing it.
	// Sensor dns_answers/process fields and collector firewall/raw fields are evidence;
	// dropping them during enrichment made the result less actionable. Detector keys
	// remain at the root for one-release API compatibility and are also namespaced under
	// "detections" for the unified processor.
	if meta.DGA != nil || meta.Tunnel != nil || meta.Beacon != nil || meta.Rebinding != nil || meta.Bypass != nil || meta.ThreatDB != nil {
		event.Metadata = mergeDetectionMetadata(event.Metadata, meta)
	}
}

func mergeDetectionMetadata(existing string, detection *detectionMeta) string {
	merged := map[string]any{}
	if strings.TrimSpace(existing) != "" {
		_ = json.Unmarshal([]byte(existing), &merged)
	}
	if merged == nil {
		merged = map[string]any{}
	}
	detectionMap := map[string]any{}
	if raw, err := json.Marshal(detection); err == nil {
		_ = json.Unmarshal(raw, &detectionMap)
	}
	for key, value := range detectionMap {
		// Core-owned values replace any caller-supplied lookalike key.
		merged[key] = value
	}
	merged["detections"] = detectionMap
	if raw, err := json.Marshal(merged); err == nil {
		return string(raw)
	}
	return existing
}

// enrichIP checks the resolved IP against threat intel.
func (e *Enricher) enrichIP(event *models.Event) {
	if event.ResolvedIP == "" || e.ThreatDB == nil {
		return
	}

	result := e.ThreatDB.Lookup(event.ResolvedIP)
	if result.Found {
		event.Tags = appendUnique(event.Tags, "known_bad")
		// Match provenance (GHSA-hx86): a RESOLVED-IP hit. matched_indicator is the
		// matched IP — never the observed QNAME, which previously leaked downstream.
		// A domain match wins: don't overwrite provenance already set by the domain
		// path (which runs before enrichIP on the same event).
		if event.MatchType != "domain" {
			event.MatchType = "resolved_ip"
			event.MatchedIndicator = result.Indicator.Value
		}
		for _, tag := range result.Indicator.Tags {
			event.Tags = appendUnique(event.Tags, tag)
		}
		if result.Confidence > event.AnomalyScore {
			event.AnomalyScore = result.Confidence
		}
	}
}

// StartEviction starts a background goroutine that periodically evicts
// stale beacon entries. Returns a stop function.
func (e *Enricher) StartEviction() func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.stateMu.Lock()
				e.Beacon.EvictStale(time.Now())
				if e.FirewallSeen != nil {
					e.FirewallSeen.EvictStale(time.Now())
				}
				e.stateMu.Unlock()
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// BeaconEntryCount returns how many (source_hash, domain) pairs are currently
// being tracked by the beaconing detector. Useful for observability during
// long-running real traffic collection (helps tune MinSamples / understand
// state for FP analysis in the SNR project).
func (e *Enricher) BeaconEntryCount() int {
	if e == nil || e.Beacon == nil {
		return 0
	}
	return e.Beacon.EntryCount()
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// removeTags returns tags with every occurrence of the given values removed.
// Used to strip caller-supplied verdict tags on ingest so the enricher is the
// sole authority for them (GHSA-hx86).
func removeTags(tags []string, drop ...string) []string {
	if len(tags) == 0 {
		return tags
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		remove := false
		for _, d := range drop {
			if t == d {
				remove = true
				break
			}
		}
		if !remove {
			out = append(out, t)
		}
	}
	return out
}

// isPrivateReverseDNS returns true if the domain is a PTR lookup (in-addr.arpa)
// for an RFC 1918 private IP address. These are normal network housekeeping
// queries (Bonjour/mDNS, ARP cache maintenance, etc.) and should be exempt
// from beaconing, DGA, and tunnel detection.
//
// Covers: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (link-local)
func isPrivateReverseDNS(domain string) bool {
	if !strings.HasSuffix(strings.ToLower(domain), ".in-addr.arpa") {
		return false
	}
	// Reverse DNS format: D.C.B.A.in-addr.arpa → IP is A.B.C.D
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(domain), ".in-addr.arpa"), ".")
	if len(parts) != 4 {
		return false
	}
	// Reconstruct forward IP
	a, b := parts[3], parts[2]
	switch {
	case a == "10":
		return true // 10.0.0.0/8
	case a == "172":
		n := 0
		for _, c := range b {
			n = n*10 + int(c-'0')
		}
		return n >= 16 && n <= 31 // 172.16.0.0/12
	case a == "192" && b == "168":
		return true // 192.168.0.0/16
	case a == "169" && b == "254":
		return true // 169.254.0.0/16 (link-local)
	}
	return false
}
