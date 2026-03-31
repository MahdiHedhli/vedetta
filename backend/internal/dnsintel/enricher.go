package dnsintel

import (
	"math"
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

// Enrich runs all applicable detection algorithms on the event and
// modifies it in place (tags, anomaly_score). This is called during
// ingest, before the event is written to the database.
func (e *Enricher) Enrich(event *models.Event) {
	if event.EventType != "dns_query" {
		// Non-DNS events: only run threat intel IP lookup
		e.enrichIP(event)
		return
	}

	var scores []float64

	// 1. DGA detection on the domain
	if event.Domain != "" {
		dgaResult := ScoreDGA(event.Domain)
		if dgaResult.IsDGA {
			event.Tags = appendUnique(event.Tags, "dga_candidate")
		}
		if dgaResult.Score > 0.3 {
			scores = append(scores, dgaResult.Score)
		}
	}

	// 2. DNS tunnel detection
	if event.Domain != "" {
		tunnelResult := ScoreTunnel(event.Domain)
		if tunnelResult.IsTunnel {
			event.Tags = appendUnique(event.Tags, "dns_tunnel")
		}
		if tunnelResult.Score > 0.3 {
			scores = append(scores, tunnelResult.Score)
		}

		// TXT query bonus for tunnel detection
		if IsTXTTunnelCandidate(event.QueryType) && tunnelResult.Score > 0.2 {
			scores = append(scores, 0.3) // extra weight for TXT queries to suspicious domains
		}
	}

	// 3. Beaconing detection
	if event.Domain != "" && event.SourceHash != "" {
		beaconResult := e.Beacon.RecordAndScore(event.SourceHash, event.Domain, event.Timestamp)
		if beaconResult.IsBeaconing {
			event.Tags = appendUnique(event.Tags, "beaconing")
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
			scores = append(scores, 0.4)
		}
	}

	// 5. DNS bypass detection (when server_ip is available in the event data)
	// Note: This requires the event to have DNS_ServerIP populated by passive capture
	// For now, we check if a bypass detector is configured and alert accordingly
	if event.SourceHash != "" && e.Bypass != nil && event.ResolvedIP != "" {
		// If server_ip is in tags or additional fields, check it here
		// This would require extending the Event model to include server_ip
		// For future integration with passive capture
	}

	// 6. Threat intel domain lookup
	if event.Domain != "" && e.ThreatDB != nil {
		result := e.ThreatDB.Lookup(event.Domain)
		if result.Found {
			event.Tags = appendUnique(event.Tags, "known_bad")
			for _, tag := range result.Indicator.Tags {
				event.Tags = appendUnique(event.Tags, tag)
			}
			scores = append(scores, result.Confidence)
		}
	}

	// 7. Threat intel IP lookup
	e.enrichIP(event)

	// Composite anomaly score: take the max of all individual scores,
	// with a small boost when multiple signals fire (defense in depth).
	if len(scores) > 0 {
		maxScore := 0.0
		for _, s := range scores {
			if s > maxScore {
				maxScore = s
			}
		}

		// Multi-signal boost: each additional signal above threshold adds 0.05
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

		// Only increase the score, never decrease it (ingest may have set it)
		if composite > event.AnomalyScore {
			event.AnomalyScore = composite
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
