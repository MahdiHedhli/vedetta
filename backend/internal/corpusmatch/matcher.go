package corpusmatch

import (
	"strconv"
	"strings"
)

// ObservedSignals is a device's already-observed fingerprinting signals, in the same shape
// vocabulary as the corpus. Callers fill only the fields they have; empty fields never match.
type ObservedSignals struct {
	OUIPrefixes       []string
	HostnameTemplates []string
	MDNSServices      []string
	MDNSModels        []string
	MDNSVendors       []string
	SSDPDeviceTypes   []string
	SSDPServerTokens  []string
	DHCPOption55      []uint16
	DHCPVendorClasses []string
	TCPPorts          []uint16
	UDPPorts          []uint16
}

// MatchResult is the class-level recognition emitted for a matched device. It is advisory
// context, never a unique identifier.
type MatchResult struct {
	Manufacturer  string
	Model         string
	ProductFamily string
	DeviceType    string
	OSFamily      string
	VariantID     string
	ConfidenceBP  int
	Families      int  // number of independent signal families that agreed (>=2 to match)
	ProductSig    bool // a product-specific signal agreed (an "exact product signature")
}

// variantRef points at a profile+variant pair inside the loaded snapshot.
type variantRef struct {
	profile *Profile
	variant *Variant
}

// Matcher matches observed device signals against a loaded corpus snapshot. It builds an
// inverted index from each signal value to the variants carrying it, so a device is compared
// only against variants that share at least one signal with it — matching is bounded by the
// device's own signals, not the whole corpus.
type Matcher struct {
	snapshot *Snapshot
	index    map[string][]int // signal key -> variantRefs index
	refs     []variantRef
}

// NewMatcher builds a Matcher over snapshot. A nil snapshot yields an empty matcher that
// never matches.
func NewMatcher(snapshot *Snapshot) *Matcher {
	m := &Matcher{snapshot: snapshot, index: map[string][]int{}}
	if snapshot == nil {
		return m
	}
	for pi := range snapshot.Profiles {
		p := &snapshot.Profiles[pi]
		for vi := range p.Variants {
			ref := variantRef{profile: p, variant: &p.Variants[vi]}
			idx := len(m.refs)
			m.refs = append(m.refs, ref)
			for _, key := range shapeKeys(&p.Variants[vi].Shape) {
				m.index[key] = append(m.index[key], idx)
			}
		}
	}
	return m
}

// Match returns the best class-level match for obs, if any qualifies (>=2 independent signal
// families agree, OR one product-specific signal agrees). Ties break on more families, then a
// product signature, then higher confidence.
func (m *Matcher) Match(obs ObservedSignals) (MatchResult, bool) {
	if m == nil || len(m.refs) == 0 {
		return MatchResult{}, false
	}
	// Gather candidate variants: those sharing at least one signal value with the device.
	seen := map[int]struct{}{}
	for _, key := range observedKeys(obs) {
		for _, idx := range m.index[key] {
			seen[idx] = struct{}{}
		}
	}

	var best MatchResult
	found := false
	for idx := range seen {
		ref := m.refs[idx]
		families, productSig := evaluate(obs, &ref.variant.Shape)
		if families < 2 && !productSig {
			continue
		}
		cand := MatchResult{
			Manufacturer:  ref.profile.Labels.Manufacturer,
			Model:         ref.profile.Labels.Model,
			ProductFamily: ref.profile.Labels.ProductFamily,
			DeviceType:    ref.profile.Labels.DeviceType,
			OSFamily:      ref.profile.Labels.OSFamily,
			VariantID:     ref.variant.VariantID,
			ConfidenceBP:  ref.variant.ConfidenceBP,
			Families:      families,
			ProductSig:    productSig,
		}
		if !found || better(cand, best) {
			best, found = cand, true
		}
	}
	return best, found
}

// better reports whether a should rank above b: more families, then a product signature,
// then higher confidence, then a stable variant-id tiebreak for determinism.
func better(a, b MatchResult) bool {
	if a.Families != b.Families {
		return a.Families > b.Families
	}
	if a.ProductSig != b.ProductSig {
		return a.ProductSig
	}
	if a.ConfidenceBP != b.ConfidenceBP {
		return a.ConfidenceBP > b.ConfidenceBP
	}
	return a.VariantID < b.VariantID
}

// evaluate counts how many independent signal families agree between obs and shape, and
// whether any product-specific signal (dhcp_vendor_class | hostname_template | mdns_model |
// ssdp_server_token) agrees.
func evaluate(obs ObservedSignals, shape *CanonicalShapeV1) (families int, productSig bool) {
	// DHCP family: exact option-55 sequence OR a vendor class.
	dhcpVC := intersectsStr(obs.DHCPVendorClasses, shape.DHCPVendorClasses)
	if dhcpVC || equalU16Seq(obs.DHCPOption55, shape.DHCPOption55) {
		families++
	}
	if intersectsOUI(obs.OUIPrefixes, shape.OUIPrefixes) {
		families++
	}
	hostname := intersectsStr(obs.HostnameTemplates, shape.HostnameTemplates)
	if hostname {
		families++
	}
	// mDNS family: any of service / model / vendor.
	mdnsModel := intersectsStr(obs.MDNSModels, shape.MDNSModels)
	if intersectsStr(obs.MDNSServices, shape.MDNSServices) || mdnsModel || intersectsStr(obs.MDNSVendors, shape.MDNSVendors) {
		families++
	}
	// SSDP family: device type or server token.
	ssdpToken := intersectsStr(obs.SSDPServerTokens, shape.SSDPServerTokens)
	if intersectsStr(obs.SSDPDeviceTypes, shape.SSDPDeviceTypes) || ssdpToken {
		families++
	}
	// Ports family: any tcp or udp port.
	if intersectsU16Set(obs.TCPPorts, shape.TCPPorts) || intersectsU16Set(obs.UDPPorts, shape.UDPPorts) {
		families++
	}
	productSig = dhcpVC || hostname || mdnsModel || ssdpToken
	return families, productSig
}

// --- keying + set helpers (comparison is case-insensitive on normalized tokens) ---

// shapeKeys returns the inverted-index keys for a variant shape.
func shapeKeys(s *CanonicalShapeV1) []string {
	var keys []string
	add := func(prefix string, vals []string) {
		for _, v := range vals {
			if n := normToken(v); n != "" {
				keys = append(keys, prefix+n)
			}
		}
	}
	for _, v := range s.OUIPrefixes {
		if n := normOUI(v); n != "" {
			keys = append(keys, "oui:"+n)
		}
	}
	add("host:", s.HostnameTemplates)
	add("mdnssvc:", s.MDNSServices)
	add("mdnsmodel:", s.MDNSModels)
	add("mdnsvendor:", s.MDNSVendors)
	add("ssdptype:", s.SSDPDeviceTypes)
	add("ssdptoken:", s.SSDPServerTokens)
	add("dhcpvc:", s.DHCPVendorClasses)
	for _, p := range s.TCPPorts {
		keys = append(keys, "tcp:"+strconv.Itoa(int(p)))
	}
	for _, p := range s.UDPPorts {
		keys = append(keys, "udp:"+strconv.Itoa(int(p)))
	}
	if len(s.DHCPOption55) > 0 {
		keys = append(keys, "dhcp55:"+u16Seq(s.DHCPOption55))
	}
	return keys
}

// observedKeys returns the index keys a device's observed signals should look up.
func observedKeys(obs ObservedSignals) []string {
	return shapeKeys(&CanonicalShapeV1{
		OUIPrefixes:       obs.OUIPrefixes,
		HostnameTemplates: obs.HostnameTemplates,
		MDNSServices:      obs.MDNSServices,
		MDNSModels:        obs.MDNSModels,
		MDNSVendors:       obs.MDNSVendors,
		SSDPDeviceTypes:   obs.SSDPDeviceTypes,
		SSDPServerTokens:  obs.SSDPServerTokens,
		DHCPVendorClasses: obs.DHCPVendorClasses,
		TCPPorts:          obs.TCPPorts,
		UDPPorts:          obs.UDPPorts,
		DHCPOption55:      obs.DHCPOption55,
	})
}

func normToken(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// normOUI strips MAC separators and returns the 24-bit prefix as 6 lowercase hex chars, or
// "" if the value is not a usable OUI (mirrors the corpus OUI canonicalization).
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
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return s
}

// intersectsOUI reports whether any observed OUI equals any shape OUI after normalization.
func intersectsOUI(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		if n := normOUI(v); n != "" {
			set[n] = struct{}{}
		}
	}
	for _, v := range a {
		if n := normOUI(v); n != "" {
			if _, ok := set[n]; ok {
				return true
			}
		}
	}
	return false
}

func intersectsStr(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		if n := normToken(v); n != "" {
			set[n] = struct{}{}
		}
	}
	for _, v := range a {
		if _, ok := set[normToken(v)]; ok && normToken(v) != "" {
			return true
		}
	}
	return false
}

func intersectsU16Set(a, b []uint16) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[uint16]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

// equalU16Seq reports whether two option-55 sequences are identical (order matters).
func equalU16Seq(a, b []uint16) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func u16Seq(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ".")
}
