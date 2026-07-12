package dnsintel

// GHSA-hx86: match provenance for known_bad events. Core tags an event known_bad on
// two distinct paths (a threat-intel DOMAIN hit and a threat-intel RESOLVED-IP hit).
// These tests verify that:
//   - a domain match sets match_type="domain" and matched_indicator=the domain;
//   - a resolved-IP match sets match_type="resolved_ip" and matched_indicator=the IP
//     (never the observed QNAME, which used to leak downstream);
//   - when both match on the same event, the domain wins;
//   - the provenance survives InsertEvents + QueryEvents.
//
// Synthetic / documentation-reserved values only.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

func provenanceEnricher(t *testing.T) (*Enricher, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	tdb, err := threatintel.NewThreatIntelDB(db.DB)
	if err != nil {
		t.Fatalf("threat db: %v", err)
	}
	if _, err := tdb.BulkImport([]threatintel.Indicator{
		{Value: "bad.example.com", Type: "domain", Source: "urlhaus", Confidence: 0.9, Tags: []string{"c2"}},
		{Value: "198.51.100.66", Type: "ipv4", Source: "feodotracker", Confidence: 0.8, Tags: []string{"c2"}},
	}); err != nil {
		t.Fatalf("bulk import: %v", err)
	}
	return NewEnricher(tdb), db
}

func TestProvenance_DomainMatch(t *testing.T) {
	e, _ := provenanceEnricher(t)
	event := newDNSEvent("prov-domain", "bad.example.com", "")
	e.Enrich(&event)

	if event.MatchType != "domain" {
		t.Fatalf("expected match_type=domain, got %q", event.MatchType)
	}
	if event.MatchedIndicator != "bad.example.com" {
		t.Fatalf("expected matched_indicator=bad.example.com, got %q", event.MatchedIndicator)
	}
}

func TestProvenance_ResolvedIPMatch_DoesNotLeakQName(t *testing.T) {
	e, _ := provenanceEnricher(t)
	// Domain is NOT known-bad; the resolved IP IS. Provenance must point at the IP.
	event := newDNSEvent("prov-ip", "benign-lookup.example.net", "198.51.100.66")
	e.Enrich(&event)

	if event.MatchType != "resolved_ip" {
		t.Fatalf("expected match_type=resolved_ip, got %q", event.MatchType)
	}
	if event.MatchedIndicator != "198.51.100.66" {
		t.Fatalf("expected matched_indicator=198.51.100.66 (the IP, never the QNAME), got %q", event.MatchedIndicator)
	}
	if event.MatchedIndicator == event.Domain {
		t.Fatal("matched_indicator must never be the observed QNAME on a resolved-IP match")
	}
}

func TestProvenance_DomainWinsOverIP(t *testing.T) {
	e, _ := provenanceEnricher(t)
	// Both the domain and the resolved IP are known-bad. The domain match runs first
	// and must not be overwritten by the later IP match.
	event := newDNSEvent("prov-both", "bad.example.com", "198.51.100.66")
	e.Enrich(&event)

	if event.MatchType != "domain" {
		t.Fatalf("expected domain to win, got match_type=%q", event.MatchType)
	}
	if event.MatchedIndicator != "bad.example.com" {
		t.Fatalf("expected matched_indicator=bad.example.com, got %q", event.MatchedIndicator)
	}
}

func TestProvenance_WhitelistDoesNotBypassKnownBad(t *testing.T) {
	e, _ := provenanceEnricher(t)
	e.IsWhitelisted = func(string) bool { return true }
	event := newDNSEvent("prov-whitelist", "bad.example.com", "")
	e.Enrich(&event)

	if !hasTag(event.Tags, "whitelisted") || !hasTag(event.Tags, "known_bad") {
		t.Fatalf("allowlist context must coexist with IOC evidence; tags=%v", event.Tags)
	}
	if event.MatchType != "domain" || event.MatchedIndicator != "bad.example.com" {
		t.Fatalf("IOC provenance was skipped: type=%q indicator=%q", event.MatchType, event.MatchedIndicator)
	}
	if event.AnomalyScore < 0.8 {
		t.Fatalf("strong IOC score was suppressed: %.2f", event.AnomalyScore)
	}
}

func TestProvenance_EnrichmentPreservesSourceMetadata(t *testing.T) {
	e, _ := provenanceEnricher(t)
	event := newDNSEvent("prov-meta", "bad.example.com", "")
	event.Metadata = `{"dns_answers":["198.51.100.66"],"process":"example.exe","source_only":"keep-me","threat_db":{"source":"forged"}}`
	e.Enrich(&event)

	var got map[string]any
	if err := json.Unmarshal([]byte(event.Metadata), &got); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if got["source_only"] != "keep-me" || got["process"] != "example.exe" {
		t.Fatalf("source metadata was discarded: %#v", got)
	}
	if _, ok := got["dns_answers"]; !ok {
		t.Fatalf("dns_answers missing after enrichment: %#v", got)
	}
	if _, ok := got["detections"].(map[string]any); !ok {
		t.Fatalf("namespaced detection metadata missing: %#v", got)
	}
	threat, ok := got["threat_db"].(map[string]any)
	if !ok || threat["source"] != "urlhaus" {
		t.Fatalf("Core-owned threat metadata did not replace forged input: %#v", got["threat_db"])
	}
}

func TestProvenance_SurvivesInsertAndQuery(t *testing.T) {
	e, db := provenanceEnricher(t)
	event := newDNSEvent("prov-roundtrip", "bad.example.com", "")
	e.Enrich(&event)

	if n, err := db.InsertEvents([]models.Event{event}); err != nil || n != 1 {
		t.Fatalf("insert events: n=%d err=%v", n, err)
	}

	res, err := db.QueryEvents(store.EventQueryParams{Domain: "bad.example.com"})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("expected 1 event, got %d", res.Total)
	}
	got := res.Events[0]
	if got.MatchType != "domain" || got.MatchedIndicator != "bad.example.com" {
		t.Fatalf("provenance did not survive round-trip: match_type=%q matched_indicator=%q", got.MatchType, got.MatchedIndicator)
	}
}

func newDNSEvent(id, domain, resolvedIP string) models.Event {
	return models.Event{
		EventID:    id,
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     domain,
		QueryType:  "A",
		ResolvedIP: resolvedIP,
		Timestamp:  time.Now().UTC(),
	}
}
