package export

import "sort"

// Aggregate collapses candidates into wire Signals. Candidates are grouped by
// (kind, indicator, time_bucket) where the indicator is the exact domain for
// known_bad_domain_hit, the eTLD+1 for candidates, and the behavior for
// behavior_summary. Within a group:
//   - observation_count = number of candidates (capped)
//   - distinct_asset_count = number of distinct non-empty source hashes (capped)
//   - blocked_count = number of blocked candidates (known_bad only)
//   - local_confidence = max
//   - local_reasons = union, in vocabulary order
//
// SourceHash values are used to compute distinct_asset_count and are then
// DISCARDED — they never reach a Signal. newSignalID mints a deterministic-safe
// UUID for each output signal.
func Aggregate(cands []ExportCandidate, newSignalID func() string) []Signal {
	type group struct {
		kind        Kind
		domain      string
		etld        string
		behavior    Behavior
		timeBucket  string
		obs         int
		blocked     int
		maxConf     float64
		reasons     map[string]bool
		assetHashes map[string]bool
	}
	groups := map[string]*group{}
	order := []string{}

	for _, c := range cands {
		indicator := ""
		switch c.Kind {
		case KindKnownBadDomainHit:
			indicator = c.Domain
		case KindHighConfCandidate:
			indicator = c.ETLDPlusOne
		case KindBehaviorSummary:
			indicator = string(c.Behavior)
		}
		key := string(c.Kind) + "\x00" + indicator + "\x00" + c.TimeBucket
		g := groups[key]
		if g == nil {
			g = &group{
				kind:        c.Kind,
				domain:      c.Domain,
				etld:        c.ETLDPlusOne,
				behavior:    c.Behavior,
				timeBucket:  c.TimeBucket,
				reasons:     map[string]bool{},
				assetHashes: map[string]bool{},
			}
			groups[key] = g
			order = append(order, key)
		}
		g.obs++
		if c.Blocked {
			g.blocked++
		}
		if c.LocalConfidence > g.maxConf {
			g.maxConf = c.LocalConfidence
		}
		for _, r := range c.LocalReasons {
			g.reasons[r] = true
		}
		if c.SourceHash != "" {
			g.assetHashes[c.SourceHash] = true
		}
	}

	signals := make([]Signal, 0, len(order))
	for _, key := range order {
		g := groups[key]
		assets := len(g.assetHashes)
		if assets < 1 {
			assets = 1 // contract: distinct_asset_count >= 1
		}
		s := Signal{
			SignalID:           newSignalID(),
			Kind:               g.kind,
			TimeBucket:         g.timeBucket,
			LocalConfidence:    g.maxConf,
			LocalReasons:       unionReasons(g.reasons),
			ObservationCount:   capInt(g.obs, 1, MaxObservationCount),
			DistinctAssetCount: capInt(assets, 1, MaxDistinctAssetCount),
		}
		switch g.kind {
		case KindKnownBadDomainHit:
			s.Domain = g.domain
			s.ETLDPlusOne = g.etld
			bc := capInt(g.blocked, 0, s.ObservationCount)
			s.BlockedCount = &bc
		case KindHighConfCandidate:
			s.ETLDPlusOne = g.etld
		case KindBehaviorSummary:
			s.Behavior = g.behavior
		}
		signals = append(signals, s)
	}
	return signals
}

func unionReasons(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for _, r := range reasonOrder {
		if set[r] {
			out = append(out, r)
			if len(out) == 8 {
				break
			}
		}
	}
	return out
}

func capInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// SortSignals orders signals deterministically for stable batch output (golden
// tests): by kind, then indicator, then time bucket.
func SortSignals(sigs []Signal) {
	sort.SliceStable(sigs, func(i, j int) bool {
		a, b := sigs[i], sigs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		ai := indicatorOf(a)
		bi := indicatorOf(b)
		if ai != bi {
			return ai < bi
		}
		return a.TimeBucket < b.TimeBucket
	})
}

func indicatorOf(s Signal) string {
	switch s.Kind {
	case KindKnownBadDomainHit:
		return s.Domain
	case KindHighConfCandidate:
		return s.ETLDPlusOne
	default:
		return string(s.Behavior)
	}
}
