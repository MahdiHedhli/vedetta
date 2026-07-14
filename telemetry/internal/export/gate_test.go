package export

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

var gateCfg = GateConfig{CandidateMinScore: 0.85, BehaviorMinScore: 0.70}

func ev(domain string, score float64, tags ...string) corereader.Event {
	return corereader.Event{
		EventType: "dns_query",
		Timestamp: time.Now().UTC(),
		Domain:    domain,
		// Default to a known-bad DOMAIN-list match: matched_indicator equals the
		// observed FQDN for today's exact-match logic. Tests exercising
		// resolved-IP matches override MatchType/MatchedIndicator explicitly.
		MatchedIndicator: domain,
		MatchType:        "domain",
		AnomalyScore:     score,
		Tags:             tags,
	}
}

func TestEligible(t *testing.T) {
	cases := []struct {
		name     string
		ev       corereader.Event
		wantKind Kind
		wantOK   bool
	}{
		{"known_bad any score", ev("bad.badzone.example", 0.1, "known_bad"), KindKnownBadDomainHit, true},
		// BETA: query-derived candidate + behavior signals are DISABLED (GHSA-hx86).
		// Every candidate/behavior event is withheld regardless of tag or score;
		// only Core-confirmed known_bad domain matches are exported.
		{"candidate at threshold withheld (beta)", ev("x.qxv-rotator.example", 0.86, "dga_candidate"), "", false},
		{"candidate below floor withheld", ev("x.qxv-rotator.example", 0.84, "c2_candidate"), "", false},
		{"dga in behavior band withheld (beta)", ev("x.qxv-rotator.example", 0.84, "dga_candidate"), "", false},
		{"behavior in band withheld (beta)", ev("x.qxv-rotator.example", 0.75, "beaconing_candidate"), "", false},
		{"behavior below floor withheld", ev("x.qxv-rotator.example", 0.69, "beaconing_candidate"), "", false},
		{"private .local withheld", ev("nas-placeholder-01.local", 0.99, "known_bad"), "", false},
		{"single label withheld", ev("localhost", 0.99, "known_bad"), "", false},
		{"IP literal withheld", ev("192.0.2.10", 0.99, "known_bad"), "", false},
		{"reverse zone withheld", ev("5.2.0.192.in-addr.arpa", 0.99, "known_bad"), "", false},
		{"home.arpa withheld", ev("printer.home.arpa", 0.99, "known_bad"), "", false},
		{"empty domain withheld", ev("", 0.99, "known_bad"), "", false},
		{"no signal tag withheld", ev("x.qxv-rotator.example", 0.9), "", false},
		{"url syntax withheld", ev("evil.example/path", 0.99, "known_bad"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, ok := Eligible(tc.ev, gateCfg)
			if ok != tc.wantOK || k != tc.wantKind {
				t.Errorf("Eligible = (%q,%v), want (%q,%v)", k, ok, tc.wantKind, tc.wantOK)
			}
		})
	}
}

func TestEligibleAcknowledgedWithheld(t *testing.T) {
	e := ev("bad.badzone.example", 0.99, "known_bad")
	e.Acknowledged = true
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("acknowledged known_bad should be withheld")
	}
}

func TestEligibleSimulationWithheld(t *testing.T) {
	e := ev("bad.badzone.example", 0.99, "known_bad")
	e.DNSSource = " Simulation "
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("simulated known_bad event should be withheld")
	}
}

func TestEligibleWhitelistedSuppressedWithheld(t *testing.T) {
	for _, tag := range []string{"whitelisted", "suppressed"} {
		e := ev("bad.badzone.example", 0.99, "known_bad", tag)
		if _, ok := Eligible(e, gateCfg); ok {
			t.Errorf("%s event should be withheld", tag)
		}
	}
}

func TestEligibleDeduplicatedOnlyWithheld(t *testing.T) {
	e := ev("bad.badzone.example", 0.5, "deduplicated")
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("deduplicated-only event should be withheld")
	}
	// deduplicated WITH a real signal tag still passes.
	e2 := ev("bad.badzone.example", 0.5, "deduplicated", "known_bad")
	if _, ok := Eligible(e2, gateCfg); !ok {
		t.Errorf("deduplicated + known_bad should pass")
	}
}

func TestEligibleResolvedIPKnownBadWithheld(t *testing.T) {
	// A known-bad RESOLVED-IP match must NOT be classified as a domain hit: the
	// observed QNAME is not itself known-bad (GHSA-hx86). It is withheld.
	e := ev("lookup.qxv-rotator.example", 0.99, "known_bad")
	e.MatchType = "resolved_ip"
	e.MatchedIndicator = "203.0.113.9"
	if k, ok := Eligible(e, gateCfg); ok {
		t.Errorf("resolved_ip known_bad should be withheld, got kind %q", k)
	}
	// Even with a candidate tag and a high score it must not be downgraded into
	// an exportable domain candidate.
	e2 := ev("lookup.qxv-rotator.example", 0.99, "known_bad", "c2_candidate")
	e2.MatchType = "resolved_ip"
	e2.MatchedIndicator = "203.0.113.9"
	if k, ok := Eligible(e2, gateCfg); ok {
		t.Errorf("resolved_ip known_bad+candidate should be withheld, got kind %q", k)
	}
}

func TestEligibleKnownBadRequiresDomainMatchType(t *testing.T) {
	// Missing/empty match_type on a known_bad event is not a domain hit.
	e := ev("bad.badzone.example", 0.99, "known_bad")
	e.MatchType = ""
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("known_bad without match_type==domain should be withheld")
	}
}

func TestEligibleWrongEventType(t *testing.T) {
	e := ev("bad.badzone.example", 0.99, "known_bad")
	e.EventType = "nmap_discovery"
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("non-dns/anomaly event type should be withheld")
	}
}
