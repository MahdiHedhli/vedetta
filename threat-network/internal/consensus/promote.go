package consensus

import (
	"github.com/vedetta-network/vedetta/threat-network/internal/ingest"
)

// decision is the outcome of the promotion rules for one aggregate.
type decision struct {
	promote         bool
	rule            int    // 1, 2, or 3
	severity        string // high | medium | low
	feedKind        string // domain_indicator | etld1_indicator | behavior_cluster
	indicatorType   string // domain | etld_plus_one | behavior
	sourcesRequired int
	ttl             timeDur
}

type timeDur = int64 // hours, converted at lifecycle

// Promotion rules (plan.md Detection & Enrichment):
//  1. exact domain + known_bad reason, distinct_reporters >= 2 → high (30d TTL)
//  2. exact domain, distinct_reporters >= 3 AND avg_conf >= 0.90 → medium (7d TTL)
//  3. etld+1 candidate or behavior cluster, distinct_reporters >= 4 AND
//     avg_conf >= 0.80 → low (7d TTL)
//
// The allowlist guard is applied by the caller BEFORE evaluate.
func evaluate(ag *aggregate, distinct int, avgConf float64) decision {
	switch ag.kind {
	case ingest.KindKnownBad:
		// Rule 1: known_bad-corroborated exact domain.
		if ag.hasKnownBad && distinct >= 2 {
			return decision{promote: true, rule: 1, severity: "high",
				feedKind: "domain_indicator", indicatorType: "domain",
				sourcesRequired: 2, ttl: 30 * 24}
		}
		// Rule 2: exact domain, stronger corroboration + confidence.
		if distinct >= 3 && avgConf >= 0.90 {
			return decision{promote: true, rule: 2, severity: "medium",
				feedKind: "domain_indicator", indicatorType: "domain",
				sourcesRequired: 3, ttl: 7 * 24}
		}
	case ingest.KindCandidate:
		// Rule 3: eTLD+1 candidate cluster.
		if distinct >= 4 && avgConf >= 0.80 {
			return decision{promote: true, rule: 3, severity: "low",
				feedKind: "etld1_indicator", indicatorType: "etld_plus_one",
				sourcesRequired: 4, ttl: 7 * 24}
		}
	case ingest.KindBehavior:
		// Rule 3: behavior cluster.
		if distinct >= 4 && avgConf >= 0.80 {
			return decision{promote: true, rule: 3, severity: "low",
				feedKind: "behavior_cluster", indicatorType: "behavior",
				sourcesRequired: 4, ttl: 7 * 24}
		}
	}
	return decision{promote: false}
}
