package dnsintel

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestEnrichDoesNotPromoteSubthresholdDGA(t *testing.T) {
	result := ScoreDGA("a1b2c3d4.example.com")
	if result.Score <= 0.3 || result.IsDGA {
		t.Fatalf("test fixture should be mild only, got score=%.2f isDGA=%v", result.Score, result.IsDGA)
	}

	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "a1b2c3d4.example.com",
		QueryType:  "A",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore != 0 {
		t.Fatalf("expected subthreshold DGA heuristic to stay out of threat view, got %.2f", event.AnomalyScore)
	}
	if len(event.Tags) != 0 {
		t.Fatalf("expected no tags, got %v", event.Tags)
	}
}

func TestEnrichDoesNotPromoteSubthresholdTunnelSignal(t *testing.T) {
	result := ScoreTunnel("aaaaaaaaaaaaaaaa.example.com")
	if result.Score <= 0.3 || result.IsTunnel {
		t.Fatalf("test fixture should be mild only, got score=%.2f isTunnel=%v signals=%v", result.Score, result.IsTunnel, result.Signals)
	}

	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "aaaaaaaaaaaaaaaa.example.com",
		QueryType:  "TXT",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore != 0 {
		t.Fatalf("expected subthreshold tunnel heuristic to stay out of threat view, got %.2f", event.AnomalyScore)
	}
	if len(event.Tags) != 0 {
		t.Fatalf("expected no tags, got %v", event.Tags)
	}
}

func TestEnrichPromotesStrongDGA(t *testing.T) {
	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "r7t2x9k4m1n8.biz",
		QueryType:  "A",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore == 0 {
		t.Fatal("expected strong DGA to raise anomaly score")
	}
	if !hasTag(event.Tags, "dga_candidate") {
		t.Fatalf("expected dga_candidate tag, got %v", event.Tags)
	}
	if event.ThreatDesc == "" {
		t.Fatal("expected threat description")
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// TestEnrich_PlexDirect_SkipsBehaviorHeuristics covers the Plex false positive:
// *.plex.direct subdomains encode the server's local IP + a high-entropy per-server
// hash, which trips DGA/tunneling. plex.direct is a curated known-good domain, so the
// behavioral detectors must be skipped and no dga_candidate/dns_tunnel tag emitted.
func TestEnrich_PlexDirect_SkipsBehaviorHeuristics(t *testing.T) {
	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-plex",
		Domain:     "10-37-129-2.abcdefghijklmnopqrstuvwxyz012345.plex.direct",
		QueryType:  "A",
		Timestamp:  time.Now().UTC(),
	}
	NewEnricher(nil).Enrich(&event)
	if hasTag(event.Tags, "dga_candidate") || hasTag(event.Tags, "dns_tunnel") {
		t.Fatalf("plex.direct must skip behavioral detectors, got tags %v", event.Tags)
	}
	if !hasTag(event.Tags, "known_good_context") {
		t.Fatalf("expected known_good_context tag for plex.direct, got %v", event.Tags)
	}
}

// TestEnrich_SelfDomain_NotFlaggedBeaconing reproduces the exact reported FP: Core
// polling its own community feed at a fixed 900s cadence would otherwise score a
// perfect beacon (CV≈0 -> CRITICAL command_and_control). With the host in SelfDomains
// it must be excluded; WITHOUT it, the identical pattern must still fire (control),
// proving the exclusion is scoped rather than a blanket disable.
func TestEnrich_SelfDomain_NotFlaggedBeaconing(t *testing.T) {
	drive := func(e *Enricher, domain string) models.Event {
		base := time.Now().UTC().Add(-4 * time.Hour)
		var ev models.Event
		for i := 0; i < 13; i++ {
			ev = models.Event{
				EventType:  "dns_query",
				SourceHash: "core-host",
				Domain:     domain,
				QueryType:  "A",
				Timestamp:  base.Add(time.Duration(i) * 900 * time.Second),
			}
			e.Enrich(&ev)
		}
		return ev
	}

	self := NewEnricher(nil)
	self.SelfDomains = []string{" VEDETTAS.COM. "}
	got := drive(self, "FEED.VEDETTAS.COM.")
	if hasTag(got.Tags, "beaconing") {
		t.Fatalf("feed.vedettas.com in SelfDomains must not be flagged beaconing, got %v", got.Tags)
	}
	if !hasTag(got.Tags, "vedetta_self") {
		t.Fatalf("expected vedetta_self tag, got %v", got.Tags)
	}

	ctrl := drive(NewEnricher(nil), "feed.vedettas.com")
	if !hasTag(ctrl.Tags, "beaconing") {
		t.Fatalf("control (no SelfDomains) should flag a perfect 900s cadence as beaconing, got %v", ctrl.Tags)
	}
}

func TestEnrich_ContextExemptionsStillRunNetworkDetectors(t *testing.T) {
	assertRebinding := func(t *testing.T, e *Enricher, domain string) {
		t.Helper()
		base := models.Event{
			EventType: "dns_query", SourceHash: "source-rebind", Domain: domain,
			QueryType: "A", Timestamp: time.Now().UTC(),
		}
		first := base
		first.ResolvedIP = "8.8.8.8"
		e.Enrich(&first)
		second := base
		second.Timestamp = second.Timestamp.Add(time.Second)
		second.ResolvedIP = "192.168.1.10"
		e.Enrich(&second)
		if !hasTag(second.Tags, "dns_rebinding") {
			t.Fatalf("%s context suppressed DNS rebinding: %v", domain, second.Tags)
		}
	}

	self := NewEnricher(nil)
	self.SelfDomains = []string{"feed.vedettas.com"}
	assertRebinding(t, self, "feed.vedettas.com")

	knownGood := NewEnricher(nil)
	assertRebinding(t, knownGood, "plex.tv")

	bypass := NewEnricher(nil)
	bypass.SelfDomains = []string{"feed.vedettas.com"}
	bypass.Bypass = NewBypassDetector(nil, nil, time.Hour)
	event := models.Event{
		EventType: "dns_query", SourceHash: "source-bypass", Domain: "feed.vedettas.com",
		ResolvedIP: "8.8.8.8", QueryType: "A", Timestamp: time.Now().UTC(),
	}
	bypass.Enrich(&event)
	if !hasTag(event.Tags, "dns_bypass") {
		t.Fatalf("self-domain context suppressed DNS bypass: %v", event.Tags)
	}
}

func TestSelfDomainMatchingNormalizesAndBoundsSuffixes(t *testing.T) {
	e := NewEnricher(nil)
	e.SelfDomains = []string{" FEED.VEDETTAS.COM. ", "router", "com"}
	tests := []struct {
		domain string
		want   bool
	}{
		{"feed.vedettas.com", true},
		{"SUB.FEED.VEDETTAS.COM.", true},
		{"evilfeed.vedettas.com", false},
		{"router", true},
		{"child.router", false},
		{"com", true},
		{"example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := e.isSelfDomain(tt.domain); got != tt.want {
				t.Fatalf("isSelfDomain(%q) = %t, want %t", tt.domain, got, tt.want)
			}
		})
	}
}

func TestSelfDomainsFromURLs(t *testing.T) {
	got := SelfDomainsFromURLs(
		"https://feed.vedettas.com",
		"  ",                         // blank -> skipped
		"https://feed.vedettas.com/", // duplicate host -> deduped
		"https://feed.mylab.example:8443/snapshot", // self-hosted mirror
		"::not a url::",                                // unparseable -> skipped
		"ssh://feed.invalid.example",                   // non-HTTP(S) -> skipped
		"//scheme-relative.invalid.example",            // not absolute -> skipped
		"https://user:pass@credential.invalid.example", // userinfo -> skipped
	)
	want := map[string]bool{"feed.vedettas.com": true, "feed.mylab.example": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want hosts %v", got, want)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("unexpected host %q in %v", h, got)
		}
	}
}
