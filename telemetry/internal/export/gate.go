package export

import (
	"strings"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

// GateConfig holds the tunable export-gate thresholds.
type GateConfig struct {
	CandidateMinScore float64 // default 0.85
	BehaviorMinScore  float64 // default 0.70
}

// Eligible decides whether an event may enter the export pipeline and, if so,
// which signal kind it becomes. It returns (kind, true) for eligible events and
// ("", false) otherwise.
//
// ALL of the following must hold for any export:
//   - event_type is dns_query
//   - dns_source is not simulation
//   - not acknowledged
//   - not tagged whitelisted / suppressed / deduplicated-only
//   - domain is public (multi-label, non-private, non-IP, PSL-reducible)
//
// Then the kind is chosen by tag + score:
//   - known_bad_domain_hit: tagged known_bad (any score); exact domain allowed
//   - high_confidence_domain_candidate: score >= CandidateMinScore AND a
//     candidate signal tag (c2/dga/tunneling/newly_registered)
//   - behavior_summary: score in [BehaviorMinScore, CandidateMinScore) AND a
//     behavior-bearing tag
//   - otherwise withheld
func Eligible(ev corereader.Event, cfg GateConfig) (Kind, bool) {
	switch ev.EventType {
	case "dns_query":
		// Telemetry exports ONLY dns_query events, where Core's enricher is the sole
		// authority for the verdict: match provenance, anomaly score, and detection
		// tags are reset on ingest and recomputed by Core's own analysis. "anomaly"
		// events are deliberately NOT exported — their score/tags are caller-supplied
		// and not Core-verified, so trusting them let a forged anomaly event encode
		// arbitrary data (e.g. an IP as 198-51-100-77.com) onto the public feed
		// (GHSA-hx86).
	default:
		return "", false
	}
	// Simulator traffic is intentionally persisted in Core so operators can
	// exercise findings and UI workflows. It must never become community
	// evidence, even if a synthetic domain happens to match a live IOC feed.
	if strings.EqualFold(strings.TrimSpace(ev.DNSSource), "simulation") {
		return "", false
	}
	if ev.Acknowledged {
		return "", false
	}
	if hasTag(ev.Tags, "whitelisted") || hasTag(ev.Tags, "suppressed") {
		return "", false
	}
	// deduplicated-only: if the ONLY meaningful tag is a dedup marker, withhold.
	if hasTag(ev.Tags, "deduplicated") && !hasSignalTag(ev.Tags) {
		return "", false
	}
	if !isPublicDomain(ev.Domain) {
		return "", false
	}

	// known_bad wins regardless of score — but ONLY for a known-bad DOMAIN-list
	// match. A resolved-IP known-bad match must NOT become a domain hit: the
	// observed QNAME is not itself known-bad, and exporting it (even reduced to
	// eTLD+1) would leak the user's lookup (GHSA-hx86). Withhold it entirely.
	if hasTag(ev.Tags, "known_bad") {
		if ev.MatchType == "domain" {
			return KindKnownBadDomainHit, true
		}
		return "", false
	}

	// BETA: query-derived candidate + behavior signals are DISABLED (GHSA-hx86).
	// They export a domain derived from the OBSERVED query name and depend on
	// Core-side detection tags/score that a compromised ingest/sensor writer can
	// forge to encode identity in the domain field (e.g. 198-51-100-77.com). The
	// reset/recompute defenses in Core narrow this, but the trust boundary is
	// fragile and drift-prone (the enricher reset list and this vocab can diverge).
	// Until the candidate/behavior trust model is redesigned so Core provably owns
	// those verdicts end-to-end, telemetry exports ONLY Core-confirmed known-bad
	// block-list matches (above), whose indicator comes from the public block list
	// and cannot carry a caller-supplied identifier. Re-enable by restoring the
	// score/tag branches once that redesign lands. (cfg thresholds + the
	// candidate/behavior vocab are retained for that.)
	_ = cfg
	return "", false
}

func hasAnyCandidateTag(tags []string) bool {
	for _, t := range tags {
		if _, ok := candidateSignalTags[t]; ok {
			return true
		}
	}
	return false
}

func hasAnyBehaviorTag(tags []string) bool {
	for _, t := range tags {
		if _, ok := behaviorForTags[t]; ok {
			return true
		}
	}
	return false
}

// hasSignalTag reports whether any tag is a real detection signal (known_bad,
// candidate, or behavior) — used to distinguish deduplicated-only events.
func hasSignalTag(tags []string) bool {
	if hasTag(tags, "known_bad") {
		return true
	}
	return hasAnyCandidateTag(tags) || hasAnyBehaviorTag(tags)
}
