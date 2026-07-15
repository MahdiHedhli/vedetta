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

// validateSourceBoundWindowsTarget is kept untagged so its stricter target
// grammar is exercised on every CI platform. Unlike Unix Nmap, one Windows
// generation must resolve to exactly one bare IPv4/CIDR scope.
func validateSourceBoundWindowsTarget(target string) error {
	if _, err := parseIPv4Scope(target); err != nil {
		return fmt.Errorf("numeric range/list scan target %q is unsupported by the source-bound Windows scanner; use one IPv4 address or CIDR", target)
	}
	_, err := enumerateHosts(target)
	return err
}

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

// ipv4Scope is the exact IPv4 address range an ARP-cache source is allowed to
// report. ARP is link-local, so accepting cache entries outside this scope would
// mis-attribute Docker, VPN, or another interface's neighbors to the configured
// Vedetta segment.
type ipv4Scope struct {
	network *net.IPNet
	single  net.IP
}

func parseIPv4Scope(target string) (ipv4Scope, error) {
	if ip := net.ParseIP(strings.TrimSpace(target)); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return ipv4Scope{single: append(net.IP(nil), v4...)}, nil
		}
		return ipv4Scope{}, fmt.Errorf("ARP cache discovery supports IPv4 only: %q", target)
	}
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(target))
	if err != nil {
		return ipv4Scope{}, fmt.Errorf("parse ARP discovery CIDR %q: %w", target, err)
	}
	if ipnet.IP.To4() == nil {
		return ipv4Scope{}, fmt.Errorf("ARP cache discovery supports IPv4 only: %q", target)
	}
	ipnet.IP = ipnet.IP.Mask(ipnet.Mask).To4()
	return ipv4Scope{network: ipnet}, nil
}

// containsHost applies the actual prefix when excluding network/broadcast
// addresses. The old last-octet-is-255 heuristic incorrectly dropped .255 hosts
// on wider prefixes and missed broadcasts such as .63 on a /26. /31 and /32 are
// intentionally allowed per RFC 3021/single-host semantics.
func (s ipv4Scope) containsHost(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.To4() == nil {
		return false
	}
	ip = ip.To4()
	if s.single != nil {
		return ip.Equal(s.single)
	}
	if s.network == nil || !s.network.Contains(ip) {
		return false
	}
	ones, bits := s.network.Mask.Size()
	if bits != 32 || ones >= 31 {
		return true
	}
	network := s.network.IP.Mask(s.network.Mask).To4()
	broadcast := append(net.IP(nil), network...)
	for i := range broadcast {
		broadcast[i] |= ^s.network.Mask[i]
	}
	return !ip.Equal(network) && !ip.Equal(broadcast)
}

// isRealNeighbor structurally validates an IPv4/unicast-MAC neighbor. Prefix-aware
// network/broadcast filtering is deliberately handled by ipv4Scope.containsHost.
func isRealNeighbor(ip, mac string) bool {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return false
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil || p.IsUnspecified() || p.IsLoopback() || p.IsMulticast() || p.Equal(net.IPv4bcast) {
		return false
	}
	return true
}
