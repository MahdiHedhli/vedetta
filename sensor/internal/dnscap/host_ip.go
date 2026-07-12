package dnscap

import "net"

// lanHostIP returns this host's IP for attributing host-scoped DNS to a device. It
// PREFERS a local interface address inside cidr — the sensor's LAN/scan range, which
// is the identity Core matches devices on — and only falls back to the default-route
// source address when the host has no address in that range. This avoids stamping a
// VPN/WAN address on LAN DNS. It is empty only when the host has no usable IPv4 at all
// (a transient no-route state); Core drops DNS with an empty client IP, so the
// capturer re-resolves this rather than caching one value forever.
func lanHostIP(cidr string) string {
	if ip := ipInCIDR(cidr); ip != "" {
		return ip
	}
	return primaryHostIP()
}

// ipInCIDR returns a local interface IPv4 that falls inside cidr, or "" if none does
// (or cidr is empty/unparseable).
func ipInCIDR(cidr string) string {
	if cidr == "" {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipn.IP.To4(); v4 != nil && ipnet.Contains(v4) {
			return v4.String()
		}
	}
	return ""
}

// primaryHostIP returns the IP the OS would use to reach the outside world. The UDP
// "dial" sends no packets — it just resolves the default-route source address — so it
// needs no privileges and no reachable peer. Used as the fallback when the host has no
// address inside the sensor's scan CIDR.
func primaryHostIP() string {
	c, err := net.Dial("udp", "192.0.2.1:9") // RFC 5737 TEST-NET-1; nothing is sent
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && a.IP != nil {
		return a.IP.String()
	}
	return ""
}
