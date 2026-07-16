package corpuscontrib

import (
	"fmt"
	"strconv"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
)

const (
	maxDHCPOption55 = 128
	maxOpenPorts    = 128
)

// ValidateCandidate enforces the stage-1 structural contribution allowlist. The first
// version permits only bounded numeric signal shapes plus one globally administered 24-bit
// OUI. Device-controlled strings are intentionally prohibited: a regex cannot prove that an
// mDNS TXT value, DHCP vendor class, SSDP token, hostname template, or custom service name is
// a product class rather than a household/device identifier.
//
// This is defense against direct identifier carriage, not a claim that a high-dimensional
// fingerprint is anonymous. Real transport remains disabled until the separate cohort and
// unlinkability acceptance gates in the design document are satisfied.
func ValidateCandidate(s corpusmatch.CanonicalShapeV1) error {
	if s.SchemaVersion != 1 {
		return fmt.Errorf("corpuscontrib: unsupported schema_version %d", s.SchemaVersion)
	}
	if len(s.OUIPrefixes) > 1 {
		return fmt.Errorf("corpuscontrib: at most one OUI prefix is allowed")
	}
	for _, oui := range s.OUIPrefixes {
		if !isGlobalUnicastOUI(oui) {
			return fmt.Errorf("corpuscontrib: OUI prefix must be 24-bit globally administered unicast")
		}
	}
	if len(s.DHCPOption55) > maxDHCPOption55 {
		return fmt.Errorf("corpuscontrib: dhcp_option_55 exceeds %d codes", maxDHCPOption55)
	}
	seenOptions := make(map[uint16]struct{}, len(s.DHCPOption55))
	for _, code := range s.DHCPOption55 {
		if code == 0 || code > 254 {
			return fmt.Errorf("corpuscontrib: dhcp_option_55 code must be 1..254")
		}
		if _, duplicate := seenOptions[code]; duplicate {
			return fmt.Errorf("corpuscontrib: dhcp_option_55 contains duplicate code")
		}
		seenOptions[code] = struct{}{}
	}
	if len(s.TCPPorts) > maxOpenPorts || len(s.UDPPorts) > 0 {
		return fmt.Errorf("corpuscontrib: only up to %d observed TCP ports are allowed", maxOpenPorts)
	}
	var previous uint16
	for i, port := range s.TCPPorts {
		if port == 0 || (i > 0 && port <= previous) {
			return fmt.Errorf("corpuscontrib: TCP ports must be nonzero, sorted, and unique")
		}
		previous = port
	}

	for _, field := range []struct {
		name   string
		values []string
	}{
		{"dhcp_vendor_classes", s.DHCPVendorClasses},
		{"hostname_templates", s.HostnameTemplates},
		{"mdns_services", s.MDNSServices},
		{"mdns_models", s.MDNSModels},
		{"mdns_vendors", s.MDNSVendors},
		{"ssdp_device_types", s.SSDPDeviceTypes},
		{"ssdp_server_tokens", s.SSDPServerTokens},
	} {
		if len(field.values) != 0 {
			return fmt.Errorf("corpuscontrib: device-controlled string field %s is not allowed", field.name)
		}
	}
	return nil
}

func isGlobalUnicastOUI(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	first, err := strconv.ParseUint(s[:2], 16, 8)
	return err == nil && first&0x03 == 0
}
