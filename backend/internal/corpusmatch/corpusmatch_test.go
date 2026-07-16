package corpusmatch

import (
	"strings"
	"testing"
)

func chromecastSnapshot() *Snapshot {
	return &Snapshot{
		SchemaVersion:  1,
		CorpusRevision: 7,
		Profiles: []Profile{
			{
				ProfileID: "p1",
				Labels:    Labels{Manufacturer: "Google", Model: "Chromecast", DeviceType: "media_player"},
				Variants: []Variant{{
					VariantID:    "v1",
					ShapeHash:    "h1",
					ConfidenceBP: 9000,
					Shape: CanonicalShapeV1{
						SchemaVersion: 1,
						OUIPrefixes:   []string{"acbc32"},
						MDNSServices:  []string{"_googlecast._tcp"},
						MDNSModels:    []string{"Chromecast"},
						TCPPorts:      []uint16{8009},
					},
				}},
			},
			{
				ProfileID: "p2",
				Labels:    Labels{Manufacturer: "Roku", Model: "Streaming Stick", DeviceType: "media_player"},
				Variants: []Variant{{
					VariantID:    "v2",
					ConfidenceBP: 8000,
					Shape: CanonicalShapeV1{
						SchemaVersion:    1,
						OUIPrefixes:      []string{"d4a5d8"},
						SSDPServerTokens: []string{"Roku/DVP"},
					},
				}},
			},
		},
	}
}

func TestMatch_TwoFamilies(t *testing.T) {
	m := NewMatcher(chromecastSnapshot())
	// OUI + mDNS service = two independent families.
	res, ok := m.Match(ObservedSignals{
		OUIPrefixes:  []string{"AC:BC:32"}, // case/format tolerant
		MDNSServices: []string{"_googlecast._tcp"},
	})
	if !ok {
		t.Fatal("expected a match on two families")
	}
	if res.Manufacturer != "Google" || res.DeviceType != "media_player" || res.Families < 2 {
		t.Errorf("got %+v", res)
	}
}

func TestMatch_ExactProductSignature(t *testing.T) {
	m := NewMatcher(chromecastSnapshot())
	// A single product-specific signal (mdns_model) is enough.
	res, ok := m.Match(ObservedSignals{MDNSModels: []string{"chromecast"}})
	if !ok || !res.ProductSig || res.Model != "Chromecast" {
		t.Fatalf("expected a product-signature match, got ok=%v %+v", ok, res)
	}
	// SSDP server token likewise (the Roku profile).
	res, ok = m.Match(ObservedSignals{SSDPServerTokens: []string{"Roku/DVP"}})
	if !ok || !res.ProductSig || res.Manufacturer != "Roku" {
		t.Fatalf("expected a Roku product-signature match, got ok=%v %+v", ok, res)
	}
}

func TestMatch_OneGenericFamilyDoesNotMatch(t *testing.T) {
	m := NewMatcher(chromecastSnapshot())
	for _, obs := range []ObservedSignals{
		{OUIPrefixes: []string{"acbc32"}},      // OUI alone (generic)
		{TCPPorts: []uint16{8009}},             // one port alone (generic)
		{MDNSServices: []string{"_http._tcp"}}, // unrelated
		{},                                     // nothing
	} {
		if res, ok := m.Match(obs); ok {
			t.Errorf("obs %+v should not match, got %+v", obs, res)
		}
	}
}

func TestMatch_PrefersMoreFamilies(t *testing.T) {
	m := NewMatcher(chromecastSnapshot())
	// OUI + mDNS service + mDNS model + port = several families incl. product sig → Chromecast.
	res, ok := m.Match(ObservedSignals{
		OUIPrefixes:  []string{"acbc32"},
		MDNSServices: []string{"_googlecast._tcp"},
		MDNSModels:   []string{"Chromecast"},
		TCPPorts:     []uint16{8009},
	})
	if !ok || res.Model != "Chromecast" || res.Families < 2 || !res.ProductSig {
		t.Fatalf("got ok=%v %+v", ok, res)
	}
}

func TestMatch_Option55ExactSequence(t *testing.T) {
	snap := &Snapshot{SchemaVersion: 1, Profiles: []Profile{{
		Labels: Labels{Manufacturer: "Apple", Model: "iPhone", DeviceType: "phone"},
		Variants: []Variant{{
			VariantID: "vph", ConfidenceBP: 7000,
			Shape: CanonicalShapeV1{SchemaVersion: 1, OUIPrefixes: []string{"acbc32"}, DHCPOption55: []uint16{1, 121, 3, 6, 15, 119, 252}},
		}},
	}}}
	m := NewMatcher(snap)
	// exact opt-55 sequence + OUI = two families.
	if _, ok := m.Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, DHCPOption55: []uint16{1, 121, 3, 6, 15, 119, 252}}); !ok {
		t.Error("exact option-55 sequence + OUI should match")
	}
	// a different order must not match the sequence family (so OUI alone remains, no match).
	if _, ok := m.Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, DHCPOption55: []uint16{121, 1, 3, 6, 15, 119, 252}}); ok {
		t.Error("reordered option-55 should not satisfy the DHCP family")
	}
}

func TestParseSnapshot(t *testing.T) {
	// Lenient: unknown fields (version_facts/sources/curator metadata) are ignored.
	good := `{"schema_version":1,"corpus_revision":7,"generated_at":"2026-07-16T00:00:00Z",
	  "profiles":[{"profile_id":"p1","labels":{"manufacturer":"Google","model":"Chromecast","device_type":"media_player"},
	  "variants":[{"variant_id":"v1","shape_hash":"h","confidence_bp":9000,
	    "shape":{"schema_version":1,"oui_prefixes":["acbc32"],"mdns_services":["_googlecast._tcp"]},
	    "version_facts":[{"attribute":"os","relation":"exact","value":"1.0"}],"sources":[{"source_id":"s1","kind":"vendor"}]}]}]}`
	s, err := ParseSnapshot([]byte(good))
	if err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	if len(s.Profiles) != 1 || len(s.Profiles[0].Variants) != 1 {
		t.Fatalf("parsed %+v", s)
	}
	if _, err := ParseSnapshot([]byte(`{"schema_version":2,"profiles":[]}`)); err == nil {
		t.Error("expected an unsupported-schema error")
	}
	if _, err := ParseSnapshot([]byte(`not json`)); err == nil {
		t.Error("expected a decode error")
	}
	if _, err := ParseSnapshot([]byte(strings.Repeat("x", maxSnapshotBytes+1))); err == nil {
		t.Error("expected an oversize rejection")
	}
}
