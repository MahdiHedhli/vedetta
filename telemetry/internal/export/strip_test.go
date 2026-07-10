package export

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
)

var testSalt = []byte("telemetry-local-salt-example")

// fullyPopulatedEvent builds an event stuffed with SYNTHETIC PII in every field
// (RFC 5737 IPs, RFC 2606 domains, doc MACs, placeholder hostnames) so the
// stripper tests can assert none of it survives.
func fullyPopulatedEvent(_ string) corereader.Event {
	return corereader.Event{
		EventID:      "11111111-2222-4333-8444-555555555555",
		Timestamp:    time.Date(2026, 7, 3, 14, 37, 12, 0, time.UTC),
		EventType:    "dns_query",
		SourceHash:   "core-side-hash-should-not-appear",
		SourceIP:     "192.0.2.55",
		ServerIP:     "198.51.100.1",
		Domain:       "c2-payload.badzone.example",
		QueryType:    "A",
		ResolvedIP:   "203.0.113.9",
		Blocked:      true,
		AnomalyScore: 0.99,
		Tags:         []string{"known_bad", "threat_feed_match", "c2_candidate", "some_free_text_tag"},
		// Known-bad DOMAIN-list match: matched_indicator equals the observed FQDN
		// for today's exact-match logic (the value the stripper forwards).
		MatchedIndicator: "c2-payload.badzone.example",
		MatchType:        "domain",
		Geo:              "US",
		DeviceVendor:     "AcmeVendor",
		NetworkSegment:   "iot",
		DNSSource:        "passive_capture",
		ThreatDesc:       "laptop-placeholder contacted c2 at 00:00:5E:00:53:2A",
		Metadata:         `{"mac":"00:00:5E:00:53:2A","hostname":"laptop-placeholder","note":"192.168.1.5"}`,
		Acknowledged:     false,
		AckReason:        "",
	}
}

// forbiddenSubstrings are values that must NEVER appear in a serialized candidate.
var forbiddenSubstrings = []string{
	"192.0.2.55", "198.51.100.1", "203.0.113.9", "192.168.1.5",
	"00:00:5E:00:53:2A", "00:00:5e:00:53:2a",
	"laptop-placeholder", "AcmeVendor", "iot", "passive_capture",
	"US", "some_free_text_tag", "core-side-hash-should-not-appear",
	"11111111-2222-4333-8444-555555555555",
	"contacted c2", "note",
}

func TestStripForbiddenFieldsNeverPass(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
	}{
		{"known_bad", KindKnownBadDomainHit},
		{"candidate", KindHighConfCandidate},
		{"behavior", KindBehaviorSummary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := fullyPopulatedEvent(tc.name)
			// Ensure behavior kind has a behavior tag present.
			if tc.kind == KindBehaviorSummary {
				ev.Tags = []string{"beaconing_candidate", "some_free_text_tag"}
			}
			cand, ok := Strip(ev, tc.kind, testSalt)
			if !ok {
				t.Fatalf("Strip returned not-ok for %s", tc.name)
			}
			data, err := json.Marshal(cand)
			if err != nil {
				t.Fatal(err)
			}
			blob := string(data)
			for _, bad := range forbiddenSubstrings {
				if strings.Contains(blob, bad) {
					t.Errorf("serialized candidate leaked %q: %s", bad, blob)
				}
			}
			// SourceHash must not serialize (json:"-").
			if strings.Contains(blob, "source_hash") || strings.Contains(blob, cand.SourceHash) {
				t.Errorf("source_hash leaked into JSON: %s", blob)
			}
			// Leak scan a batch built from this candidate.
			sigs := Aggregate([]ExportCandidate{cand}, func() string { return "sig-id" })
			batch := Batch{SchemaVersion: 1, BatchID: "b", GeneratedAt: "2026-07-03T14:00:00Z",
				WindowStart: "2026-07-03T14:00:00Z", WindowEnd: "2026-07-03T15:00:00Z", Signals: sigs}
			bjson, _ := json.Marshal(batch)
			if v := LeakScan(bjson); len(v) > 0 {
				t.Errorf("leak scan violations: %v\n%s", v, bjson)
			}
		})
	}
}

func TestStripKnownBadKeepsExactDomain(t *testing.T) {
	ev := fullyPopulatedEvent("kb")
	c, ok := Strip(ev, KindKnownBadDomainHit, testSalt)
	if !ok {
		t.Fatal("not ok")
	}
	if c.Domain != "c2-payload.badzone.example" {
		t.Errorf("domain = %q", c.Domain)
	}
	if c.ETLDPlusOne != "badzone.example" {
		t.Errorf("etld = %q", c.ETLDPlusOne)
	}
	if !c.Blocked {
		t.Errorf("blocked should be preserved")
	}
}

func TestStripKnownBadForwardsMatchedIndicatorNotQNAME(t *testing.T) {
	// The exported Domain must be the canonical matched indicator from Core
	// provenance, never the raw observed QNAME (GHSA-hx86). Here they differ:
	// the matched list entry is the registrable apex while the QNAME is a
	// deeper label that must not leak.
	ev := fullyPopulatedEvent("kb")
	ev.Domain = "secret-host.badzone.example"
	ev.MatchedIndicator = "badzone.example"
	ev.MatchType = "domain"
	c, ok := Strip(ev, KindKnownBadDomainHit, testSalt)
	if !ok {
		t.Fatal("not ok")
	}
	if c.Domain != "badzone.example" {
		t.Errorf("Domain must equal MatchedIndicator, got %q", c.Domain)
	}
	if strings.Contains(c.Domain, "secret-host") {
		t.Errorf("observed QNAME leaked into exported domain: %q", c.Domain)
	}
}

func TestStripKnownBadResolvedIPWithheld(t *testing.T) {
	// A resolved-IP known-bad match yields NO domain candidate: fail closed.
	ev := fullyPopulatedEvent("kb")
	ev.MatchType = "resolved_ip"
	ev.MatchedIndicator = "203.0.113.9"
	if c, ok := Strip(ev, KindKnownBadDomainHit, testSalt); ok {
		t.Errorf("resolved_ip match must withhold, got candidate %+v", c)
	}
}

func TestStripKnownBadEmptyIndicatorWithheld(t *testing.T) {
	// Missing provenance must fail closed — never fall back to the QNAME.
	ev := fullyPopulatedEvent("kb")
	ev.MatchType = "domain"
	ev.MatchedIndicator = ""
	if c, ok := Strip(ev, KindKnownBadDomainHit, testSalt); ok {
		t.Errorf("empty MatchedIndicator must withhold, got candidate %+v", c)
	}
}

func TestStripCandidateWithholdsExactDomain(t *testing.T) {
	ev := fullyPopulatedEvent("cand")
	ev.Tags = []string{"dga_candidate", "newly_registered", "high_entropy"}
	ev.AnomalyScore = 0.91
	c, ok := Strip(ev, KindHighConfCandidate, testSalt)
	if !ok {
		t.Fatal("not ok")
	}
	if c.Domain != "" {
		t.Errorf("candidate must NOT carry exact domain, got %q", c.Domain)
	}
	if c.ETLDPlusOne != "badzone.example" {
		t.Errorf("etld = %q", c.ETLDPlusOne)
	}
}

func TestStripBehaviorHasNoDomain(t *testing.T) {
	ev := fullyPopulatedEvent("beh")
	ev.Tags = []string{"beaconing_candidate"}
	c, ok := Strip(ev, KindBehaviorSummary, testSalt)
	if !ok {
		t.Fatal("not ok")
	}
	if c.Domain != "" || c.ETLDPlusOne != "" {
		t.Errorf("behavior_summary must carry no domain material: domain=%q etld=%q", c.Domain, c.ETLDPlusOne)
	}
	if c.Behavior != BehaviorBeaconing {
		t.Errorf("behavior = %q", c.Behavior)
	}
}

func TestStripReasonVocabularyIntersection(t *testing.T) {
	ev := fullyPopulatedEvent("kb")
	c, _ := Strip(ev, KindKnownBadDomainHit, testSalt)
	for _, r := range c.LocalReasons {
		if _, ok := reasonVocab[r]; !ok {
			t.Errorf("non-vocabulary reason emitted: %q", r)
		}
	}
	if hasStr(c.LocalReasons, "some_free_text_tag") {
		t.Errorf("free-text tag leaked into reasons")
	}
}

func TestStripHMACKnownVector(t *testing.T) {
	// Known vector: HMAC-SHA256("192.0.2.55") under a fixed salt.
	salt := []byte("fixed-salt")
	m := hmac.New(sha256.New, salt)
	m.Write([]byte("192.0.2.55"))
	want := hex.EncodeToString(m.Sum(nil))
	got := sourceHash("192.0.2.55", salt)
	if got != want {
		t.Errorf("sourceHash = %s, want %s", got, want)
	}
	if sourceHash("", salt) != "" {
		t.Errorf("empty source IP should hash to empty")
	}
}

func TestStripTimeBucketHourTruncation(t *testing.T) {
	ev := fullyPopulatedEvent("kb")
	c, _ := Strip(ev, KindKnownBadDomainHit, testSalt)
	if c.TimeBucket != "2026-07-03T14:00:00Z" {
		t.Errorf("time_bucket = %q, want hour-truncated", c.TimeBucket)
	}
}

func TestStripConfidenceClamp(t *testing.T) {
	ev := fullyPopulatedEvent("kb")
	ev.AnomalyScore = 1.7
	c, _ := Strip(ev, KindKnownBadDomainHit, testSalt)
	if c.LocalConfidence != 1.0 {
		t.Errorf("confidence not clamped: %v", c.LocalConfidence)
	}
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
