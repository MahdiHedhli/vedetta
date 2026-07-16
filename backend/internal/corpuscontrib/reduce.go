// Package corpuscontrib defines a local-only, default-off shadow candidate for a future
// privacy-preserving device-fingerprint contribution path (spec 008 / #52). Nothing in this
// package stores or transmits a candidate.
//
// Stage 1 is intentionally narrower than the curated public corpus. It keeps only bounded
// numeric shapes and a globally administered 24-bit OUI. Raw hostnames, mDNS/SSDP strings,
// DHCP vendor classes, models, and vendors are device-controlled and therefore excluded:
// local syntax checks cannot prove that those strings contain product data rather than a
// person, room, serial, address, or other identifying value.
package corpuscontrib

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

// Reduce projects an observation into the stage-1 structural allowlist and validates the
// result before returning it. Conflicting DHCP option-55 observations are rejected instead
// of selecting one by input order.
func Reduce(host discovery.DiscoveredHost) (corpusmatch.CanonicalShapeV1, error) {
	shape := corpusmatch.CanonicalShapeV1{SchemaVersion: 1}
	if oui := normOUI(host.MACAddress); oui != "" {
		shape.OUIPrefixes = []string{oui}
	}

	for _, ev := range host.IdentityEvidence {
		if ev.Type != "dhcp_option_55" {
			continue
		}
		candidate := parseOption55(ev.Value)
		if len(candidate) == 0 {
			continue
		}
		if len(shape.DHCPOption55) != 0 && !equalU16(shape.DHCPOption55, candidate) {
			return corpusmatch.CanonicalShapeV1{}, fmt.Errorf("corpuscontrib: conflicting dhcp_option_55 observations")
		}
		shape.DHCPOption55 = candidate
	}
	shape.TCPPorts = sortedUniqueU16(host.OpenPorts)
	if err := ValidateCandidate(shape); err != nil {
		return corpusmatch.CanonicalShapeV1{}, err
	}
	return shape, nil
}

// Contributable reports whether a validated candidate has at least two independent signal
// families. Stage 1 deliberately has no single-field product-signature exception because all
// raw product-bearing strings are outside the contribution allowlist.
func Contributable(s corpusmatch.CanonicalShapeV1) bool {
	if ValidateCandidate(s) != nil {
		return false
	}
	families := 0
	if len(s.OUIPrefixes) > 0 {
		families++
	}
	if len(s.DHCPOption55) > 0 {
		families++
	}
	if len(s.TCPPorts) > 0 {
		families++
	}
	return families >= 2
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
	if !isGlobalUnicastOUI(s) {
		return ""
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

func equalU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
