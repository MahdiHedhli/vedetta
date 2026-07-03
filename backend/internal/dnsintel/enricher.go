package dnsintel

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

// Enricher wires all DNS threat detection algorithms into the event ingest
// pipeline. For each event, it runs applicable detectors and updates the
// event's anomaly_score and tags in place.
type Enricher struct {
	Beacon           *BeaconDetector
	ThreatDB         *threatintel.ThreatIntelDB
	Rebinding        *RebindingDetector
	Bypass           *BypassDetector
	IsWhitelisted    func(domain string) bool // optional, for early noise suppression
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
	// Additional from real network data (LIFX, Koogeek, CyberPower power devices)
	"lifx.com", "koogeek.com", "cyberpower.com",
	// Tuya IoT cloud (very common for cheap Espressif/Realtek/Mediatek smart plugs, bulbs, sensors on real home networks;
	// these frequently produce high-entropy subdomains + regular telemetry that would otherwise trigger DGA/beacon false positives)
	"tuya.com", "tuyaus.com", "tuyacn.com", "tuya-cloud.com",
	// TP-Link / Kasa (common in home LANs with routers + IoT)
	"tplink.com", "kasa.com",
	// Other frequent IoT ecosystems (robotic mowers, cameras, locks seen in real device scans)
	"mammotion.com", "eufylife.com",
	// Netatmo (security cameras like Welcome, weather stations - observed in real scans as Netatmo-Welcome-*)
	"netatmo.com", "netatmo.net",
	// PiKVM (open-source IP-KVM device - observed in 10h real device collection run)
	"pikvm.org",
	// Ultra-common developer / consumer domains that frequently produce noisy single-signal "known_bad" hits
	// in abuse feeds (urlhaus etc.) during live VALIDATE-REAL on real home traffic. Pure feed match on these
	// (especially from primary machines) is almost always FP. Real threats will still score via other signals
	// or high-risk device context (EOL, new, IoT).
	"github.com", "raw.githubusercontent.com",
	"discordapp.com", "discord.com", "cdn.discordapp.com",

	// abuse.ch services (FeodoTracker, URLhaus, MalwareBazaar, etc.)
	// Operated by a respected defensive security organization. Regular polling of these
	// public services is expected, legitimate behavior from researchers, SOC teams,
	// and defensive tooling. They should never trigger detections in isolation.
	"feodotracker.abuse.ch",
	"abuse.ch",
	"urlhaus.abuse.ch",
	"bazaar.abuse.ch",

	// Recurring Microsoft / Azure infrastructure that frequently produces high-entropy
	// subdomains and regular telemetry from the primary machines. These are internal
	// Microsoft services (OneDrive, Azure Front Door, etc.) and are safe to ignore.
	"onedriveclubproddm20037.blob.core.windows.net",
	"onedriveclubproddm20048.blob.core.windows.net",
	"onedriveclubproddm20049.blob.core.windows.net",
	"onedriveclubproddm20032.blob.core.windows.net",
	".azurefd.net",
	".cloudapp.azure.com",

	// Cloudflare public DNS (1.1.1.1). Commonly used for legitimate DNS bypass testing
	// and DoH/DoT. Regular queries are expected and benign.
	"one.one.one.one",

	// Internal application updater (antigravity). Observed as regular, low-risk
	// high-entropy polling from the primary development machine. Safe to suppress.
	"antigravity-auto-updater-974169037036.us-central1.run.app",

	// Additional recurring Microsoft infrastructure domains still generating
	// high-entropy DGA-like noise on the primary machines. These are internal
	// Microsoft services and are safe to ignore in this environment.
	"onedriveclubproddm20051.blob.core.windows.net",
	"onedriveclubproddm20032.blob.core.windows.net",
	"onedriveclubproddm20047.blob.core.windows.net",
	"194497-ipv4v6fdse.gr.global.aa-rt.sharepoint.com",

	// Specific Radware customer WAF subdomains that appear consistently as
	// high-entropy infrastructure noise from the primary Mac. These look like
	// legitimate customer WAF endpoints rather than malicious infrastructure.
	"c46f66d3abdc4ac1b41d0b76ec8fe974.v1.radwarecloud.net",
	"f4ee15e5e3904270bf96fe8c018be383.v1.radwarecloud.net",
}

// NewEnricher creates an Enricher with the default BeaconDetector,
// RebindingDetector, BypassDetector, and an optional ThreatIntelDB
// (can be nil if feeds haven't loaded yet).
func NewEnricher(threatDB *threatintel.ThreatIntelDB) *Enricher {
	return &Enricher{
		Beacon:    NewBeaconDetector(),
		ThreatDB:  threatDB,
		Rebinding: NewRebindingDetector(24 * time.Hour),
		Bypass:    NewBypassDetector(nil, []string{}, 1*time.Hour),
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
	DGA            *dgaMeta            `json:"dga,omitempty"`
	Tunnel         *tunnelMeta         `json:"tunnel,omitempty"`
	Beacon         *beaconMeta         `json:"beacon,omitempty"`
	Rebinding      *rebindingMeta      `json:"rebinding,omitempty"`
	Bypass         *bypassMeta         `json:"bypass,omitempty"`
	ThreatDB       *threatDBMeta       `json:"threat_db,omitempty"`
	DeviceContext  *deviceContextMeta  `json:"device_context,omitempty"`
}

type deviceContextMeta struct {
	Segment    string `json:"segment,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	IsNew      bool   `json:"is_new,omitempty"`
	Boosts     []string `json:"boosts,omitempty"` // e.g., ["iot_segment", "new_device", "bypass"]
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
	if event.EventType != "dns_query" {
		e.enrichIP(event)
		return
	}

	// Early exit for whitelisted domains — this is one of the highest-impact
	// changes for signal-to-noise. Known-good traffic should never generate
	// high anomaly scores.
	if e.IsWhitelisted != nil && e.IsWhitelisted(event.Domain) {
		return
	}

	// Early exit for known-good update/telemetry domains (SNR-20)
	// These produce regular beaconing, high-entropy subdomains, and sometimes
	// long subdomains that can look like tunneling, all legitimately.
	// Use proper domain suffix matching (dot + base) to preserve detection power
	// on lookalike domains while still excluding legitimate subdomains (e.g. foo.tuya.com).
	for _, good := range knownGoodUpdateDomains {
		if event.Domain == good || strings.HasSuffix(event.Domain, "."+good) {
			return
		}
	}

	var scores []float64
	var descriptions []string
	meta := &detectionMeta{}

	// Skip DGA, tunnel, and beaconing analysis for reverse DNS (PTR) lookups
	// of private IPs. macOS Bonjour/mDNS does periodic PTR sweeps of the local
	// subnet which triggers false alerts. Reversed IP octets also look like
	// random strings to the entropy/bigram scorers.
	isPrivatePTR := isPrivateReverseDNS(event.Domain)

	// 1. DGA detection on the domain
	if event.Domain != "" && !isPrivatePTR {
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
	if event.Domain != "" && !isPrivatePTR {
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
	if event.Domain != "" && event.SourceHash != "" && !isPrivatePTR {
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
	if event.Domain != "" && event.ResolvedIP != "" && e.Rebinding != nil {
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
			isHighRiskDevice := containsTag(event.Tags, "new_device") || containsTag(event.Tags, "iot_context") || containsAny(event.Tags, []string{"eol_router", "high_risk_iot", "known_exploited"})

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
	if event.Domain != "" && e.Bypass != nil {
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
			// Belt-and-suspenders protection: even if a domain somehow reaches here,
			// skip pure known_bad scoring for ultra-common legitimate infrastructure.
			// These domains frequently appear in abuse feeds with noisy tags but are
			// overwhelmingly used for benign purposes (updates, CDNs, dev, etc.).
			// Real threats using them will still be caught by other detectors + context.
			isKnownGood := false
			for _, good := range knownGoodUpdateDomains {
				if event.Domain == good || strings.HasSuffix(event.Domain, "."+good) {
					isKnownGood = true
					break
				}
			}
			if !isKnownGood {
				event.Tags = appendUnique(event.Tags, "known_bad")
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
	}

	// 7. Threat intel IP lookup
	e.enrichIP(event)

	// === Device Context Scoring Adjustments (SNR-09) ===
	// Use passive discovery data (now attached to the event) to improve signal quality.
	// IoT/guest devices doing suspicious DNS are higher risk.
	// Known consumer devices on the main network are lower risk for the same signals.

	// Populate device context metadata for UI and analysis
	highRiskRiskTags := []string{"eol_router", "eol_device_context", "high_risk_iot", "known_exploited"}
	if containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "new_device_context") || containsTag(event.Tags, "dns_bypass") || containsAny(event.Tags, highRiskRiskTags) {
		if meta.DeviceContext == nil {
			meta.DeviceContext = &deviceContextMeta{}
		}
		meta.DeviceContext.Segment = event.NetworkSegment
		meta.DeviceContext.Vendor = event.DeviceVendor
		meta.DeviceContext.IsNew = containsTag(event.Tags, "new_device")

		boosts := []string{}
		if containsTag(event.Tags, "iot_context") { boosts = append(boosts, "iot_segment") }
		if containsTag(event.Tags, "new_device_context") { boosts = append(boosts, "new_device") }
		if containsAny(event.Tags, highRiskRiskTags) { boosts = append(boosts, "high_risk_device") }
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

	// Risk device boost (generalized from IC3 2026-03-12 AVrecon work).
	// Devices in "known_exploited", "eol_eos" (tagged "eol_router"), or "high_risk_iot"
	// categories get elevated priority when exhibiting suspicious DNS behavior.
	// known_exploited is checked first so it wins when a device carries multiple risk tags.
	highRiskTags := []string{"known_exploited", "eol_router", "high_risk_iot"}
	for _, rt := range highRiskTags {
		if containsTag(event.Tags, rt) && event.AnomalyScore > 0.15 {
			boost := 0.22
			event.AnomalyScore = math.Min(1.0, event.AnomalyScore+boost)

			contextTag := "high_risk_device_context"
			if !containsTag(event.Tags, contextTag) {
				event.Tags = appendUnique(event.Tags, contextTag)
			}
			// Backward compatibility: EOL devices historically emitted "eol_device_context",
			// and user suppression/whitelist rules may still key on it. known_exploited devices
			// (the IC3 AVrecon models) are also EOL, so they keep the legacy tag too.
			// Deprecated — new rules should match "high_risk_device_context" instead.
			if rt == "eol_router" || rt == "known_exploited" {
				event.Tags = appendUnique(event.Tags, "eol_device_context")
			}

			// Category-specific description (kept conservative and factual).
			// The FBI IC3 AVrecon reference belongs ONLY to known_exploited (the advisory's
			// campaign models); eol_eos and high_risk_iot get generic category descriptions.
			desc := ""
			switch rt {
			case "known_exploited":
				desc = "This activity originated from a device model known to be actively exploited in the wild: it matches the FBI IC3 FLASH 2026-03-12 advisory on AVrecon malware and the SocksEscort residential proxy botnet, which target EOL SOHO routers and IP cameras."
			case "eol_router":
				desc = "This activity originated from an End-of-Life (EOL) router or IoT device. EOL devices no longer receive security updates, so known vulnerabilities remain exploitable indefinitely."
			case "high_risk_iot":
				desc = "This activity originated from a high-risk IoT or camera device from a product line commonly shipped with weak default credentials and rarely-updated firmware, making it a frequent botnet recruitment target."
			}
			if desc != "" {
				descriptions = append(descriptions, desc)
			}

			log.Printf("SNR: +%.2f boost for %s (domain=%s, vendor=%s, score=%.2f)", boost, rt, event.Domain, event.DeviceVendor, event.AnomalyScore)
			break // only apply once
		}
	}

	// Extra boost for DNS bypass from high-risk devices (SNR-13)
	// A new or IoT device bypassing local DNS (public resolver or DoH) is a strong signal.
	if containsTag(event.Tags, "dns_bypass") {
		isHighRiskDevice := containsTag(event.Tags, "new_device") || containsTag(event.Tags, "iot_context") || containsAny(event.Tags, []string{"eol_router", "high_risk_iot", "known_exploited"})

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
	if containsAny(event.Tags, []string{"eol_device_context", "eol_router", "high_risk_iot", "known_exploited"}) {
		contextReasons = append(contextReasons, "from a high-risk device (EOL, vulnerable IoT, or known exploited)")
	}
	if event.DeviceVendor != "" && (containsTag(event.Tags, "iot_context") || containsTag(event.Tags, "new_device_context") || containsAny(event.Tags, []string{"eol_device_context", "high_risk_device_context"})) {
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

		if signalCount <= 1 {
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

	// Serialize detection metadata as JSON
	if meta.DGA != nil || meta.Tunnel != nil || meta.Beacon != nil || meta.Rebinding != nil || meta.Bypass != nil || meta.ThreatDB != nil {
		if metaJSON, err := json.Marshal(meta); err == nil {
			event.Metadata = string(metaJSON)
		}
	}
}

// enrichIP checks the resolved IP against threat intel.
func (e *Enricher) enrichIP(event *models.Event) {
	if event.ResolvedIP == "" || e.ThreatDB == nil {
		return
	}

	result := e.ThreatDB.Lookup(event.ResolvedIP)
	if result.Found {
		event.Tags = appendUnique(event.Tags, "known_bad")
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
				e.Beacon.EvictStale(time.Now())
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

func containsAny(tags []string, candidates []string) bool {
	for _, c := range candidates {
		if containsTag(tags, c) {
			return true
		}
	}
	return false
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
