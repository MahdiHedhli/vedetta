package corpuscontrib

import (
	"fmt"
	"regexp"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
)

// The #52 invariant: no field of a contribution candidate may carry a value capable of
// linking it to a specific host — a full MAC, an IP, or a UUID. The OUI field is a 24-bit
// vendor prefix by construction (never a full MAC).
var (
	fullMACRE = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|\b[0-9a-f]{12}\b`)
	ipv4RE    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6RE    = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}`)
	uuidRE    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// AssertAnonymized verifies a candidate shape upholds the #52 invariant: every OUI is a
// 24-bit prefix, and no free-text field carries a full MAC, IP, or UUID. It returns an error
// naming the first violation. The local shadow recorder and any future contribution path must
// gate on this before acting on a shape.
func AssertAnonymized(s corpusmatch.CanonicalShapeV1) error {
	for _, oui := range s.OUIPrefixes {
		if !isHex6(oui) {
			return fmt.Errorf("corpuscontrib: oui_prefix %q is not a 24-bit prefix", oui)
		}
	}
	fields := []struct {
		name string
		vals []string
	}{
		{"dhcp_vendor_classes", s.DHCPVendorClasses},
		{"hostname_templates", s.HostnameTemplates},
		{"mdns_services", s.MDNSServices},
		{"mdns_models", s.MDNSModels},
		{"mdns_vendors", s.MDNSVendors},
		{"ssdp_device_types", s.SSDPDeviceTypes},
		{"ssdp_server_tokens", s.SSDPServerTokens},
	}
	for _, f := range fields {
		for _, v := range f.vals {
			switch {
			case fullMACRE.MatchString(v):
				return fmt.Errorf("corpuscontrib: %s carries a MAC-like value", f.name)
			case ipv4RE.MatchString(v), ipv6RE.MatchString(v):
				return fmt.Errorf("corpuscontrib: %s carries an IP-like value", f.name)
			case uuidRE.MatchString(v):
				return fmt.Errorf("corpuscontrib: %s carries a UUID-like value", f.name)
			}
		}
	}
	return nil
}

func isHex6(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if c := s[i]; !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
