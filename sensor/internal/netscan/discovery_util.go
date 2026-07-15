package netscan

import (
	"fmt"
	"net"
	"strings"
)

// maxSweepHosts bounds the native ICMP sweep so a large CIDR cannot spawn a runaway
// scan. Shared (untagged) so the pure CIDR/filter helpers below are unit-testable on
// any platform, even though only the Windows native scanner uses them today.
const maxSweepHosts = 1024

// enumerateHosts lists the usable IPv4 host addresses in cidr (excluding network and
// broadcast). A bare IPv4 address returns itself; IPv6 is rejected explicitly. A subnet with more
// than maxSweepHosts usable addresses is REJECTED with an error rather than silently
// truncated — a partial sweep reported as complete would hide devices in the range.
func enumerateHosts(cidr string) ([]string, error) {
	if ip := net.ParseIP(cidr); ip != nil {
		// IPv4-mapped IPv6 must not be normalized silently: Unix Nmap receives the
		// original colon-form operand and skips it without scanning any target.
		if v4 := ip.To4(); v4 != nil && !strings.Contains(cidr, ":") {
			return []string{v4.String()}, nil
		}
		return nil, fmt.Errorf("active discovery is IPv4-only for this beta; IPv6 target %q is unsupported", cidr)
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		if nmapRangeRe.MatchString(cidr) {
			return enumerateNmapIPv4Target(cidr, maxSweepHosts)
		}
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	if strings.Contains(cidr, ":") {
		return nil, fmt.Errorf("active discovery is IPv4-only for this beta; IPv6 target %q is unsupported", cidr)
	}
	base := ipnet.IP.Mask(ipnet.Mask).To4()
	if base == nil {
		return nil, fmt.Errorf("active discovery is IPv4-only for this beta; IPv6 target %q is unsupported", cidr)
	}
	// Reject oversized ranges outright. A /22 (1022 usable hosts) fits under the cap; a
	// /21 or wider would exceed it, so error instead of scanning only the first 1024 and
	// reporting the range as fully swept.
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	addresses := int64(1) << uint(hostBits)
	usable := addresses
	if hostBits >= 2 {
		usable -= 2
	}
	if usable > maxSweepHosts {
		return nil, fmt.Errorf("subnet %s has more than %d hosts and is too large for the native ICMP sweep; scan a /22 or tighter --cidr, or split the range", cidr, maxSweepHosts)
	}
	if hostBits == 0 { // /32: the one address is the target.
		return []string{base.String()}, nil
	}
	if hostBits == 1 { // RFC 3021 /31: both addresses are usable point-to-point endpoints.
		other := cloneIP4(base)
		incIP(other)
		return []string{base.String(), other.String()}, nil
	}
	bcast := make(net.IP, 4)
	for i := range base {
		bcast[i] = base[i] | ^ipnet.Mask[i]
	}
	cur := cloneIP4(base)
	incIP(cur) // start at network+1
	var out []string
	for ipnet.Contains(cur) && !cur.Equal(bcast) && len(out) < maxSweepHosts {
		out = append(out, cur.String())
		incIP(cur)
	}
	return out, nil
}

// ipv4TargetContains prevents a scan from inheriting unrelated entries in the
// machine-wide ARP table. Numeric range/list membership is checked exactly.
func ipv4TargetContains(target, candidate string) bool {
	return targetContainsIPv4(target, candidate)
}

func cloneIP4(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// isRealNeighbor filters out broadcast and multicast ARP pseudo-entries so they are
// not reported as discovered devices.
func isRealNeighbor(ip, mac string) bool {
	if mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") || strings.HasPrefix(mac, "33:33") {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil || p.IsMulticast() || p.Equal(net.IPv4bcast) {
		return false
	}
	if v4 := p.To4(); v4 != nil && v4[3] == 255 { // directed broadcast
		return false
	}
	return true
}
