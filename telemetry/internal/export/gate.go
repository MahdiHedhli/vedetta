package export

import "github.com/vedetta-network/vedetta/telemetry/internal/corereader"

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
//   - event_type is dns_query or anomaly
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
	case "dns_query", "anomaly":
	default:
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

	score := ev.AnomalyScore
	if score >= cfg.CandidateMinScore && hasAnyCandidateTag(ev.Tags) {
		return KindHighConfCandidate, true
	}
	if score >= cfg.BehaviorMinScore && score < cfg.CandidateMinScore && hasAnyBehaviorTag(ev.Tags) {
		return KindBehaviorSummary, true
	}
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
