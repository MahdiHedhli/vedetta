package export

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

// Strip projects an eligible event onto the allowlisted ExportCandidate. It is
// the privacy boundary in code: it reads only the fields it is allowed to
// forward and NEVER copies source_ip, resolved_ip, server_ip, event_id, exact
// timestamp, geo, device_vendor, network_segment, dns_source, threat_desc,
// metadata, or any free-form string. The ExportCandidate type has no field
// capable of holding those, so a future edit that tried to forward one would not
// compile.
//
// kind must come from Eligible(ev). salt is the telemetry-local HMAC salt used
// to derive SourceHash (internal only, discarded by the aggregator).
func Strip(ev corereader.Event, kind Kind, salt []byte) (ExportCandidate, bool) {
	c := ExportCandidate{
		Kind:            kind,
		TimeBucket:      ev.Timestamp.UTC().Truncate(time.Hour).Format(time.RFC3339),
		LocalConfidence: clamp01(ev.AnomalyScore),
		LocalReasons:    filterReasons(ev.Tags),
		SourceHash:      sourceHash(ev.SourceIP, salt),
	}

	switch kind {
	case KindKnownBadDomainHit:
		// GHSA-hx86: never export the observed QNAME. Export the canonical
		// matched indicator from Core provenance (the known-bad list entry that
		// fired) instead. Fail closed if provenance is missing or the match was
		// not a domain match — do NOT fall back to the QNAME.
		if ev.MatchType != "domain" || ev.MatchedIndicator == "" {
			return ExportCandidate{}, false
		}
		indicator := strings.ToLower(strings.TrimSpace(ev.MatchedIndicator))
		indicator = strings.TrimSuffix(indicator, ".")
		// The matched indicator must still pass the single public-domain gate.
		if !isPublicDomain(indicator) {
			return ExportCandidate{}, false
		}
		etld, ok := eTLDPlusOne(indicator)
		if !ok {
			return ExportCandidate{}, false
		}
		c.Domain = indicator
		c.ETLDPlusOne = etld
		c.Blocked = ev.Blocked
	case KindHighConfCandidate:
		// Exact domain WITHHELD; eTLD+1 only, derived from the observed QNAME.
		domain := strings.ToLower(strings.TrimSpace(ev.Domain))
		domain = strings.TrimSuffix(domain, ".")
		etld, ok := eTLDPlusOne(domain)
		if !ok {
			// Domain-bearing kind requires a reducible domain; refuse otherwise.
			return ExportCandidate{}, false
		}
		c.ETLDPlusOne = etld
	case KindBehaviorSummary:
		// No domain material at all.
		b, ok := behaviorFromTags(ev.Tags)
		if !ok {
			return ExportCandidate{}, false
		}
		c.Behavior = b
	default:
		return ExportCandidate{}, false
	}

	// A candidate must carry at least one reason (contract: local_reasons 1..8).
	if len(c.LocalReasons) == 0 {
		return ExportCandidate{}, false
	}
	return c, true
}

func behaviorFromTags(tags []string) (Behavior, bool) {
	for _, t := range behaviorTagOrder {
		if hasTag(tags, t) {
			return behaviorForTags[t], true
		}
	}
	return "", false
}

// sourceHash derives an HMAC-SHA256 of the source IP under the telemetry-local
// salt. It is used ONLY to compute distinct_asset_count and never leaves the
// aggregator. An empty source IP yields an empty hash (contributes no asset).
func sourceHash(sourceIP string, salt []byte) string {
	if sourceIP == "" {
		return ""
	}
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(sourceIP))
	return hex.EncodeToString(m.Sum(nil))
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
