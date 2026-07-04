package export

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

var gateCfg = GateConfig{CandidateMinScore: 0.85, BehaviorMinScore: 0.70}

func ev(domain string, score float64, tags ...string) corereader.Event {
	return corereader.Event{
		EventType:    "dns_query",
		Timestamp:    time.Now().UTC(),
		Domain:       domain,
		AnomalyScore: score,
		Tags:         tags,
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
		{"candidate at threshold", ev("x.qxv-rotator.example", 0.86, "dga_candidate"), KindHighConfCandidate, true},
		// c2_candidate is a candidate-only tag (not a behavior tag): below the
		// candidate floor it has no behavior fallback, so it is withheld.
		{"candidate just below, no behavior fallback", ev("x.qxv-rotator.example", 0.84, "c2_candidate"), "", false},
		// dga_candidate IS both a candidate tag and a behavior tag: below the
		// candidate floor but in the behavior band it downgrades to a behavior_summary.
		{"dga below candidate floor downgrades to behavior", ev("x.qxv-rotator.example", 0.84, "dga_candidate"), KindBehaviorSummary, true},
		{"behavior in band", ev("x.qxv-rotator.example", 0.75, "beaconing_candidate"), KindBehaviorSummary, true},
		{"behavior below floor", ev("x.qxv-rotator.example", 0.69, "beaconing_candidate"), "", false},
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

func TestEligibleWrongEventType(t *testing.T) {
	e := ev("bad.badzone.example", 0.99, "known_bad")
	e.EventType = "nmap_discovery"
	if _, ok := Eligible(e, gateCfg); ok {
		t.Errorf("non-dns/anomaly event type should be withheld")
	}
}
