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
// broadcast), capped at maxSweepHosts. A bare IPv4 address returns itself; IPv6 and
// over-wide subnets (>20 host bits) return nil / an error.
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
	if ones, bits := ipnet.Mask.Size(); bits-ones > 20 {
		return nil, fmt.Errorf("subnet %s too large for the native ICMP sweep (%d host bits)", cidr, bits-ones)
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
