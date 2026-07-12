package dnscap

import "net"

// primaryHostIP returns the IP the OS would use to reach the outside world. The UDP
// "dial" sends no packets — it just resolves the default-route source address — so it
// needs no privileges and no reachable peer. The Windows ETW capturer is host-scoped
// (it sees only this machine's resolver traffic), so this IP is the client for every
// query it emits; Core drops any DNS query that arrives without a client IP, so this
// must be non-empty for Windows DNS to be stored.
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
