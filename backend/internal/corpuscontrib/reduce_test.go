package corpuscontrib

import (
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

func TestReduce_AnonymizedShape(t *testing.T) {
	host := discovery.DiscoveredHost{
		MACAddress: "AC:BC:32:11:22:33", // -> 24-bit prefix acbc32, NOT the full MAC
		Hostname:   "Johns-iPhone",      // PII: must never appear in the shape
		Model:      "Chromecast",
		Services:   []string{"_googlecast._tcp", "_googlecast._tcp"}, // deduped
		OpenPorts:  []int{8009, 8008, 8009},
		IdentityEvidence: []discovery.IdentityEvidence{
			{Type: "mdns_txt_vendor", Value: "Google Inc"},
			{Type: "dhcp_option_55", Value: "1,121,3,6,15"},
		},
	}
	s := Reduce(host)

	if len(s.OUIPrefixes) != 1 || s.OUIPrefixes[0] != "acbc32" {
		t.Errorf("oui = %v, want [acbc32] (24-bit prefix, not a full MAC)", s.OUIPrefixes)
	}
	// The concrete hostname must NOT leak anywhere in the shape.
	blob := strings.ToLower(strings.Join(append(append([]string{}, s.MDNSServices...), s.MDNSModels...), " "))
	if strings.Contains(blob, "iphone") || strings.Contains(blob, "john") || len(s.HostnameTemplates) != 0 {
		t.Errorf("hostname/PII leaked into the shape: %+v", s)
	}
	if len(s.MDNSServices) != 1 || s.MDNSServices[0] != "_googlecast._tcp" {
		t.Errorf("mdns services = %v, want deduped/normalized", s.MDNSServices)
	}
	if len(s.DHCPOption55) != 5 || s.DHCPOption55[0] != 1 || s.DHCPOption55[1] != 121 {
		t.Errorf("option-55 = %v, want ordered [1 121 3 6 15]", s.DHCPOption55)
	}
	if len(s.TCPPorts) != 2 || s.TCPPorts[0] != 8008 || s.TCPPorts[1] != 8009 {
		t.Errorf("tcp ports = %v, want sorted-unique [8008 8009]", s.TCPPorts)
	}
	// The whole point: a reduced shape always upholds the #52 invariant.
	if err := AssertAnonymized(s); err != nil {
		t.Errorf("reduced shape violated the anonymization invariant: %v", err)
	}
}

func TestContributable(t *testing.T) {
	// A bare OUI is not worth contributing.
	if Contributable(corpusmatch.CanonicalShapeV1{OUIPrefixes: []string{"acbc32"}}) {
		t.Error("a bare OUI should not be contributable")
	}
	// A product signal alone is enough.
	if !Contributable(corpusmatch.CanonicalShapeV1{MDNSModels: []string{"chromecast"}}) {
		t.Error("a product-specific signal should be contributable")
	}
	// Two families is enough.
	if !Contributable(corpusmatch.CanonicalShapeV1{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}}) {
		t.Error("two families should be contributable")
	}
}

func TestAssertAnonymized_CatchesIdentifiers(t *testing.T) {
	for name, s := range map[string]corpusmatch.CanonicalShapeV1{
		"full MAC": {MDNSModels: []string{"dev ac:bc:32:de:ad:be"}},
		"ipv4":     {MDNSVendors: []string{"seen at 192.0.2.5"}},
		"uuid":     {SSDPDeviceTypes: []string{"uuid:12345678-1234-1234-1234-1234567890ab"}},
		"bad oui":  {OUIPrefixes: []string{"acbc32deadbe"}}, // a full MAC in the OUI field
	} {
		if err := AssertAnonymized(s); err == nil {
			t.Errorf("%s: expected an anonymization violation", name)
		}
	}
	// A clean class shape passes.
	if err := AssertAnonymized(corpusmatch.CanonicalShapeV1{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}, MDNSModels: []string{"chromecast"}}); err != nil {
		t.Errorf("a clean shape should pass: %v", err)
	}
}
