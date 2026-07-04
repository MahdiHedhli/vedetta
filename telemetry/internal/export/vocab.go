package export

// Fixed reason vocabulary (contract §6). The producer MUST NOT emit values
// outside this pinned set. reasonVocab is the allowlist; anything not in it is
// dropped (never forwarded as free text).
var reasonVocab = map[string]struct{}{
	"known_bad":               {},
	"c2_candidate":            {},
	"dga_candidate":           {},
	"tunneling_candidate":     {},
	"beaconing_candidate":     {},
	"newly_registered":        {},
	"dns_rebinding_candidate": {},
	"public_resolver_bypass":  {},
	"threat_feed_match":       {},
	"high_entropy":            {},
}

// reasonOrder gives a stable ordering for serialized local_reasons so batches
// are byte-stable for golden tests.
var reasonOrder = []string{
	"known_bad",
	"c2_candidate",
	"dga_candidate",
	"tunneling_candidate",
	"beaconing_candidate",
	"newly_registered",
	"dns_rebinding_candidate",
	"public_resolver_bypass",
	"threat_feed_match",
	"high_entropy",
}

// candidateSignalTags are the tags that (with sufficient score) qualify an event
// as a high_confidence_domain_candidate.
var candidateSignalTags = map[string]struct{}{
	"c2_candidate":        {},
	"dga_candidate":       {},
	"tunneling_candidate": {},
	"newly_registered":    {},
}

// behaviorForTags maps a behavior-bearing tag to its behavior_summary value.
// Checked in priority order via behaviorTagOrder.
var behaviorForTags = map[string]Behavior{
	"beaconing_candidate": BehaviorBeaconing,
	"dga_candidate":       BehaviorDGABurst,
	"tunneling_candidate": BehaviorTunneling,
	"newly_registered":    BehaviorNewDomainVolume,
}

var behaviorTagOrder = []string{
	"beaconing_candidate",
	"dga_candidate",
	"tunneling_candidate",
	"newly_registered",
}

// filterReasons returns the intersection of the event's tags with the reason
// vocabulary, in stable vocabulary order, capped at 8 items (contract §4 common
// fields: local_reasons is 1..8). Duplicate tags collapse.
func filterReasons(tags []string) []string {
	present := make(map[string]bool, len(tags))
	for _, t := range tags {
		if _, ok := reasonVocab[t]; ok {
			present[t] = true
		}
	}
	out := make([]string, 0, len(present))
	for _, r := range reasonOrder {
		if present[r] {
			out = append(out, r)
			if len(out) == 8 {
				break
			}
		}
	}
	return out
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
