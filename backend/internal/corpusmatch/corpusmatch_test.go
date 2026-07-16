package corpusmatch

import (
	"encoding/json"
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
	// Observations and curated shapes use the same whitespace canonicalization.
	snap := chromecastSnapshot()
	snap.Profiles[1].Variants[0].Shape.SSDPServerTokens = []string{"ExampleOS/1.0 UPnP/1.1"}
	res, ok = NewMatcher(snap).Match(ObservedSignals{
		SSDPServerTokens: []string{"  ExampleOS/1.0\t\n  UPnP/1.1  "},
	})
	if !ok || !res.ProductSig || res.Manufacturer != "Roku" {
		t.Fatalf("whitespace-equivalent product token did not match, got ok=%v %+v", ok, res)
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

func TestMatch_ProductSignatureOutranksGenericFamilies(t *testing.T) {
	snap := chromecastSnapshot()
	snap.Profiles[0].Variants[0].Shape = CanonicalShapeV1{
		SchemaVersion: 1,
		MDNSModels:    []string{"Chromecast"},
	}
	snap.Profiles = append(snap.Profiles, Profile{
		ProfileID: "generic-appliance",
		Labels:    Labels{Manufacturer: "Generic", Model: "Appliance", DeviceType: "iot"},
		Variants: []Variant{{
			VariantID: "generic-variant", ConfidenceBP: 10000,
			Shape: CanonicalShapeV1{SchemaVersion: 1, OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}, TCPPorts: []uint16{8009}},
		}},
	})
	res, ok := NewMatcher(snap).Match(ObservedSignals{
		OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"},
		MDNSModels: []string{"Chromecast"}, TCPPorts: []uint16{8009},
	})
	if !ok || res.Model != "Chromecast" || !res.ProductSig {
		t.Fatalf("product signature did not outrank generic families: ok=%v result=%+v", ok, res)
	}
}

func TestMatch_ConflictingEqualRankIsAmbiguous(t *testing.T) {
	snap := chromecastSnapshot()
	snap.Profiles = append(snap.Profiles, Profile{
		ProfileID: "lookalike",
		Labels:    Labels{Manufacturer: "Other", Model: "Lookalike", DeviceType: "media_player"},
		Variants: []Variant{{
			// Different curator confidence cannot identify which class produced the same
			// local evidence; the corpus contract requires ambiguity to remain.
			VariantID: "lookalike-variant", ConfidenceBP: 7000,
			Shape: CanonicalShapeV1{SchemaVersion: 1, OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}},
		}},
	})
	obs := ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}}
	if result, ok := NewMatcher(snap).Match(obs); ok {
		t.Fatalf("equally ranked conflicting classes must remain ambiguous, got %+v", result)
	}
}

func TestMatch_EqualRankSameClassIsDeterministic(t *testing.T) {
	snap := chromecastSnapshot()
	duplicate := snap.Profiles[0]
	duplicate.ProfileID = "same-class"
	duplicate.Variants = append([]Variant(nil), duplicate.Variants...)
	duplicate.Variants[0].VariantID = "a-variant"
	snap.Profiles = append(snap.Profiles, duplicate)
	res, ok := NewMatcher(snap).Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}})
	if !ok || res.VariantID != "a-variant" {
		t.Fatalf("same-class tie should select stable variant id: ok=%v result=%+v", ok, res)
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

func TestParseSnapshot_RejectsIncompleteRuntimeContract(t *testing.T) {
	validShape := `"shape":{"schema_version":1,"oui_prefixes":["acbc32"]}`
	tests := []struct {
		name string
		raw  string
	}{
		{"trailing JSON", `{"schema_version":1,"profiles":[]} {}`},
		{"negative revision", `{"schema_version":1,"corpus_revision":-1,"profiles":[]}`},
		{"empty profile id", `{"schema_version":1,"profiles":[{"profile_id":"","variants":[]}]}`},
		{"duplicate profile id", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[]},{"profile_id":"p","variants":[]}]}`},
		{"empty variant id", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[{"variant_id":"","confidence_bp":1,` + validShape + `}]}]}`},
		{"duplicate variant id", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[{"variant_id":"v","confidence_bp":1,` + validShape + `},{"variant_id":"v","confidence_bp":2,` + validShape + `}]}]}`},
		{"negative confidence", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[{"variant_id":"v","confidence_bp":-1,` + validShape + `}]}]}`},
		{"excess confidence", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[{"variant_id":"v","confidence_bp":10001,` + validShape + `}]}]}`},
		{"unsupported shape schema", `{"schema_version":1,"profiles":[{"profile_id":"p","variants":[{"variant_id":"v","confidence_bp":1,"shape":{"schema_version":2,"oui_prefixes":["acbc32"]}}]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSnapshot([]byte(tt.raw)); err == nil {
				t.Fatalf("ParseSnapshot accepted %s", tt.name)
			}
		})
	}
}

func TestParseSnapshot_EnforcesCountBounds(t *testing.T) {
	profiles := make([]Profile, maxProfiles+1)
	raw, err := json.Marshal(Snapshot{SchemaVersion: 1, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSnapshot(raw); err == nil || !strings.Contains(err.Error(), "too many profiles") {
		t.Fatalf("profile bound error = %v", err)
	}

	variants := make([]Variant, maxVariants+1)
	raw, err = json.Marshal(Snapshot{SchemaVersion: 1, Profiles: []Profile{{ProfileID: "p", Variants: variants}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSnapshot(raw); err == nil || !strings.Contains(err.Error(), "too many variants") {
		t.Fatalf("variant bound error = %v", err)
	}
}
