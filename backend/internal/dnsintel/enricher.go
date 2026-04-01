package dnsintel

import (
	"encoding/json"
	"fmt"
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
	Beacon    *BeaconDetector
	ThreatDB  *threatintel.ThreatIntelDB
	Rebinding *RebindingDetector
	Bypass    *BypassDetector
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

// detectionMeta captures structured output from each detection algorithm
// for storage as JSON in the event's metadata field.
type detectionMeta struct {
	DGA       *dgaMeta       `json:"dga,omitempty"`
	Tunnel    *tunnelMeta    `json:"tunnel,omitempty"`
	Beacon    *beaconMeta    `json:"beacon,omitempty"`
	Rebinding *rebindingMeta `json:"rebinding,omitempty"`
	ThreatDB  *threatDBMeta  `json:"threat_db,omitempty"`
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

// Enrich runs all applicable detection algorithms on the event and
// modifies it in place (tags, anomaly_score, threat_desc, metadata).
// This is called during ingest, before the event is written to the database.
func (e *Enricher) Enrich(event *models.Event) {
	if event.EventType != "dns_query" {
		e.enrichIP(event)
		return
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
		if dgaResult.Score > 0.3 {
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
		if tunnelResult.Score > 0.3 {
			scores = append(scores, tunnelResult.Score)
		}

		// TXT query bonus for tunnel detection
		if IsTXTTunnelCandidate(event.QueryType) && tunnelResult.Score > 0.2 {
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
		if beaconResult.Score > 0.3 {
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
	}

	// 5. DNS bypass detection — reserved for future server_ip integration

	// 6. Threat intel domain lookup
	if event.Domain != "" && e.ThreatDB != nil {
		result := e.ThreatDB.Lookup(event.Domain)
		if result.Found {
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

	// 7. Threat intel IP lookup
	e.enrichIP(event)

	// Composite anomaly score
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
		boost := float64(signalCount-1) * 0.05
		if boost < 0 {
			boost = 0
		}

		composite := math.Min(1.0, maxScore+boost)
		if composite > event.AnomalyScore {
			event.AnomalyScore = composite
		}
	}

	// Set human-readable threat description
	if len(descriptions) > 0 {
		event.ThreatDesc = strings.Join(descriptions, " ")
	}

	// Serialize detection metadata as JSON
	if meta.DGA != nil || meta.Tunnel != nil || meta.Beacon != nil || meta.Rebinding != nil || meta.ThreatDB != nil {
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

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
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
