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
// broadcast). A bare IPv4 address returns itself; IPv6 returns nil. A subnet with more
// than maxSweepHosts usable addresses is REJECTED with an error rather than silently
// truncated — a partial sweep reported as complete would hide devices in the range.
func enumerateHosts(cidr string) ([]string, error) {
	if ip := net.ParseIP(cidr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}, nil
		}
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	base := ipnet.IP.Mask(ipnet.Mask).To4()
	if base == nil {
		return nil, nil // native sweep is IPv4-only for v1
	}
	// Reject oversized ranges outright. A /22 (1022 usable hosts) fits under the cap; a
	// /21 or wider would exceed it, so error instead of scanning only the first 1024 and
	// reporting the range as fully swept.
	if ones, bits := ipnet.Mask.Size(); (1<<uint(bits-ones))-2 > maxSweepHosts {
		return nil, fmt.Errorf("subnet %s has more than %d hosts and is too large for the native ICMP sweep; scan a /22 or tighter --cidr, or split the range", cidr, maxSweepHosts)
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
