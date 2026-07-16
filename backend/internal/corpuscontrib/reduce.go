// Package corpuscontrib is the local, opt-in device-fingerprint contribution path (spec 008
// Phase 5 / #52). This piece implements only the LOCAL SHADOW MODE (#57 staged-delivery step
// 1): it reduces a device's observed signals to the anonymized CanonicalShapeV1 that WOULD be
// contributed, keeps it entirely local, and is off by default. NOTHING is transmitted here.
//
// A contribution must never be linkable to a specific install, user/device ID, or IP (#52).
// The reduction enforces that structurally: the output is only the domain-free class shape —
// a 24-bit OUI prefix (not a full MAC), mDNS/SSDP service *types* and product/vendor tokens,
// the DHCP option-55 sequence and vendor class, and the port shape. Hostnames are excluded on
// purpose: a concrete hostname can carry PII and templatizing it needs its own analysis
// before it could ever be contributed.
package corpuscontrib

import (
	"sort"
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

// Reduce projects a device observation into the anonymized CanonicalShapeV1 candidate that
// local shadow mode records (and that a future, privacy-reviewed transport could contribute).
func Reduce(host discovery.DiscoveredHost) corpusmatch.CanonicalShapeV1 {
	shape := corpusmatch.CanonicalShapeV1{SchemaVersion: 1}
	if oui := normOUI(host.MACAddress); oui != "" {
		shape.OUIPrefixes = []string{oui}
	}

	mdnsServices := append([]string(nil), host.Services...)
	var mdnsModels, mdnsVendors, ssdpTypes, dhcpVC []string
	if host.Model != "" {
		mdnsModels = append(mdnsModels, host.Model)
	}
	for _, ev := range host.IdentityEvidence {
		switch ev.Type {
		case "mdns_service":
			mdnsServices = append(mdnsServices, ev.Value)
		case "mdns_txt_model":
			mdnsModels = append(mdnsModels, ev.Value)
		case "mdns_txt_vendor":
			mdnsVendors = append(mdnsVendors, ev.Value)
		case "ssdp_device_type":
			ssdpTypes = append(ssdpTypes, ev.Value)
		case "dhcp_vendor_class":
			dhcpVC = append(dhcpVC, ev.Value)
		case "dhcp_option_55":
			shape.DHCPOption55 = parseOption55(ev.Value) // order is the fingerprint
		}
	}
	shape.MDNSServices = sortedUniqueLower(mdnsServices)
	shape.MDNSModels = sortedUniqueLower(mdnsModels)
	shape.MDNSVendors = sortedUniqueLower(mdnsVendors)
	shape.SSDPDeviceTypes = sortedUniqueLower(ssdpTypes)
	shape.DHCPVendorClasses = sortedUniqueLower(dhcpVC)
	shape.TCPPorts = sortedUniqueU16(host.OpenPorts)
	return shape
}

// Contributable reports whether a shape carries enough distinguishing signal to be worth
// contributing — the client side of the corpus publish bar: a product-specific signal, or at
// least two independent signal families. It keeps low-signal, non-identifying shapes (e.g. a
// bare OUI) out of the candidate set.
func Contributable(s corpusmatch.CanonicalShapeV1) bool {
	productSig := len(s.DHCPVendorClasses) > 0 || len(s.MDNSModels) > 0
	families := 0
	if len(s.OUIPrefixes) > 0 {
		families++
	}
	if len(s.DHCPOption55) > 0 || len(s.DHCPVendorClasses) > 0 {
		families++
	}
	if len(s.MDNSServices) > 0 || len(s.MDNSModels) > 0 || len(s.MDNSVendors) > 0 {
		families++
	}
	if len(s.SSDPDeviceTypes) > 0 || len(s.SSDPServerTokens) > 0 {
		families++
	}
	if len(s.TCPPorts) > 0 || len(s.UDPPorts) > 0 {
		families++
	}
	return productSig || families >= 2
}

// --- normalization (mirrors the corpus canonicalization) ---

func sortedUniqueLower(values []string) []string {
	set := map[string]struct{}{}
	for _, v := range values {
		if n := strings.ToLower(strings.Join(strings.Fields(v), " ")); n != "" {
			set[n] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedUniqueU16(ports []int) []uint16 {
	set := map[uint16]struct{}{}
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			set[uint16(p)] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normOUI(v string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(v) {
		if c == ':' || c == '-' || c == '.' || c == ' ' {
			continue
		}
		b.WriteRune(c)
	}
	s := b.String()
	if len(s) < 6 {
		return ""
	}
	s = s[:6]
	for i := 0; i < 6; i++ {
		if c := s[i]; !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return s
}

func parseOption55(v string) []uint16 {
	var out []uint16
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' }) {
		if n, err := strconv.Atoi(tok); err == nil && n >= 1 && n <= 254 {
			out = append(out, uint16(n))
		}
	}
	return out
}
