package corpuscontrib

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

func TestReduce_UsesOnlyStructuralAllowlist(t *testing.T) {
	host := discovery.DiscoveredHost{
		MACAddress: "00:00:5E:11:22:33", // global-unicast 24-bit documentation OUI
		Hostname:   "Johns-iPhone",
		Vendor:     "private-room-device",
		Model:      "Johns-iPhone",
		Services:   []string{"_private-room._tcp"},
		OpenPorts:  []int{8009, 8008, 8009},
		IdentityEvidence: []discovery.IdentityEvidence{
			{Type: "mdns_txt_model", Value: "Johns-iPhone"},
			{Type: "mdns_txt_vendor", Value: "private-room-device"},
			{Type: "ssdp_server_token", Value: "0000.5e00.5301"},
			{Type: "ssdp_device_type", Value: "fd12:3456:789a::c0a8:1"},
			{Type: "dhcp_vendor_class", Value: "private-client"},
			{Type: "dhcp_option_55", Value: "1,121,3,6,15"},
		},
	}
	s, err := Reduce(host)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.OUIPrefixes) != 1 || s.OUIPrefixes[0] != "00005e" {
		t.Errorf("OUI = %v, want globally administered 24-bit prefix", s.OUIPrefixes)
	}
	if len(s.DHCPOption55) != 5 || s.DHCPOption55[1] != 121 {
		t.Errorf("option-55 = %v, want ordered sequence", s.DHCPOption55)
	}
	if len(s.TCPPorts) != 2 || s.TCPPorts[0] != 8008 || s.TCPPorts[1] != 8009 {
		t.Errorf("TCP ports = %v, want sorted unique ports", s.TCPPorts)
	}
	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"john", "private", "0000.5e00.5301", "fd12:"} {
		if strings.Contains(strings.ToLower(string(blob)), prohibited) {
			t.Fatalf("device-controlled text leaked into candidate: %s", blob)
		}
	}
	if err := ValidateCandidate(s); err != nil {
		t.Fatalf("reducer returned an invalid candidate: %v", err)
	}
}

func TestReduce_RejectsConflictingOrMalformedShapes(t *testing.T) {
	if shape, err := Reduce(discovery.DiscoveredHost{MACAddress: "02:11:22:33:44:55"}); err != nil || len(shape.OUIPrefixes) != 0 {
		t.Fatalf("locally administered MAC must not become an OUI: shape=%+v err=%v", shape, err)
	}
	if shape, err := Reduce(discovery.DiscoveredHost{MACAddress: "00005é00:53:01"}); err != nil || len(shape.OUIPrefixes) != 0 {
		t.Fatalf("non-ASCII MAC text must not become an OUI: shape=%+v err=%v", shape, err)
	}
	_, err := Reduce(discovery.DiscoveredHost{IdentityEvidence: []discovery.IdentityEvidence{
		{Type: "dhcp_option_55", Value: "1,3,6"},
		{Type: "dhcp_option_55", Value: "1,3,15"},
	}})
	if err == nil {
		t.Fatal("conflicting DHCP option-55 observations were accepted")
	}
	_, err = Reduce(discovery.DiscoveredHost{IdentityEvidence: []discovery.IdentityEvidence{{
		Type: "dhcp_option_55", Value: "1,3,3",
	}}})
	if err == nil {
		t.Fatal("duplicate DHCP option code was accepted")
	}
	for _, value := range []string{"1,999,3", "1,foo,3", "1,,3", "0,3", "1,255"} {
		_, err = Reduce(discovery.DiscoveredHost{IdentityEvidence: []discovery.IdentityEvidence{{
			Type: "dhcp_option_55", Value: value,
		}}})
		if err == nil {
			t.Errorf("malformed DHCP option-55 value %q was accepted", value)
		}
	}
}

func TestContributableRequiresTwoValidatedFamilies(t *testing.T) {
	for name, shape := range map[string]corpusmatch.CanonicalShapeV1{
		"bare OUI":         {SchemaVersion: 1, OUIPrefixes: []string{"00005e"}},
		"bare DHCP":        {SchemaVersion: 1, DHCPOption55: []uint16{1, 3, 6}},
		"bare ports":       {SchemaVersion: 1, TCPPorts: []uint16{443}},
		"raw product text": {SchemaVersion: 1, MDNSModels: []string{"chromecast"}},
	} {
		if Contributable(shape) {
			t.Errorf("%s should not be contributable", name)
		}
	}
	if !Contributable(corpusmatch.CanonicalShapeV1{
		SchemaVersion: 1, OUIPrefixes: []string{"00005e"}, DHCPOption55: []uint16{1, 3, 6},
	}) {
		t.Fatal("two validated families should be contributable")
	}
}

func TestValidateCandidateRejectsEveryStringCarrier(t *testing.T) {
	tests := map[string]corpusmatch.CanonicalShapeV1{
		"full dotted MAC":   {SchemaVersion: 1, MDNSModels: []string{"0000.5e00.5301"}},
		"compressed IPv6":   {SchemaVersion: 1, SSDPDeviceTypes: []string{"fd12:3456:789a::c0a8:1"}},
		"hostname template": {SchemaVersion: 1, HostnameTemplates: []string{"camera-{hex}"}},
		"vendor class":      {SchemaVersion: 1, DHCPVendorClasses: []string{"android-dhcp-14"}},
		"mDNS service":      {SchemaVersion: 1, MDNSServices: []string{"_googlecast._tcp"}},
		"mDNS vendor":       {SchemaVersion: 1, MDNSVendors: []string{"example"}},
		"SSDP token":        {SchemaVersion: 1, SSDPServerTokens: []string{"example/1"}},
		"local OUI":         {SchemaVersion: 1, OUIPrefixes: []string{"021122"}},
		"multicast OUI":     {SchemaVersion: 1, OUIPrefixes: []string{"01005e"}},
	}
	for name, shape := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateCandidate(shape); err == nil {
				t.Fatal("candidate passed structural gate")
			}
		})
	}
}

func TestValidateCandidateAcceptsUppercaseGlobalOUI(t *testing.T) {
	if err := ValidateCandidate(corpusmatch.CanonicalShapeV1{
		SchemaVersion: 1, OUIPrefixes: []string{"00005E"},
	}); err != nil {
		t.Fatalf("uppercase global OUI was rejected: %v", err)
	}
}

func FuzzReduceNeverCarriesDeviceControlledText(f *testing.F) {
	f.Add("Johns-iPhone", "0000.5e00.5301", "fd12:3456:789a::c0a8:1")
	f.Fuzz(func(t *testing.T, model, vendor, token string) {
		host := discovery.DiscoveredHost{
			MACAddress: "00:00:5E:00:53:01", Hostname: model, Model: model, Vendor: vendor,
			Services: []string{token}, IdentityEvidence: []discovery.IdentityEvidence{
				{Type: "mdns_txt_model", Value: model}, {Type: "mdns_txt_vendor", Value: vendor},
				{Type: "ssdp_server_token", Value: token}, {Type: "dhcp_vendor_class", Value: token},
			},
		}
		shape, err := Reduce(host)
		if err != nil {
			return
		}
		if err := ValidateCandidate(shape); err != nil {
			t.Fatalf("reducer escaped its own gate: %v", err)
		}
		if len(shape.DHCPVendorClasses)+len(shape.HostnameTemplates)+len(shape.MDNSServices)+
			len(shape.MDNSModels)+len(shape.MDNSVendors)+len(shape.SSDPDeviceTypes)+len(shape.SSDPServerTokens) != 0 {
			t.Fatalf("reducer emitted a device-controlled string: %+v", shape)
		}
	})
}
