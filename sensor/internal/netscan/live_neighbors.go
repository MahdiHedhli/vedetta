package netscan

import (
	"net"
	"strings"
)

// corroborateLiveNeighbors returns only unambiguous, same-interface MAC evidence for
// the exact IPs that replied during the current source-bound ICMP generation. It does
// not make a cache row live: callers must supply the independently live IP set.
//
// Proxy ARP and conflicting rows fail closed. A MAC observed for more than one scoped
// IP is not attached to either, even when only one of those IPs answered ICMP. This is
// deliberately stricter than choosing the last OS row and prevents a router/proxy MAC
// from becoming a device identity for every address it answers on behalf of.
func corroborateLiveNeighbors(live []string, rows []neighbor, target ipv4Scope, link localScope) map[string]string {
	result := make(map[string]string)
	if len(live) == 0 || link.ifIndex <= 0 || link.network == nil {
		return result
	}
	liveSet := make(map[string]struct{}, len(live))
	for _, raw := range live {
		if ip := net.ParseIP(strings.TrimSpace(raw)).To4(); ip != nil {
			liveSet[ip.String()] = struct{}{}
		}
	}

	linkScope := ipv4Scope{network: link.network}
	dynamicByIP := make(map[string]map[string]struct{})
	allByIP := make(map[string]map[string]struct{})
	// Proxy-ARP classification is link-wide, not target-wide. A queued scan may
	// request one IP (or a subnet narrower than the directly connected link); if
	// the same MAC is also present for another IP elsewhere on that link, limiting
	// this map to the requested target would incorrectly promote the router/proxy
	// MAC as the target device's identity.
	macIPs := make(map[string]map[string]struct{})
	for _, row := range rows {
		if (row.state != neighborStateDynamic && row.state != neighborStateStatic) ||
			row.ifIndex != link.ifIndex || !isRealNeighbor(row.ip, row.mac) {
			continue
		}
		parsed := net.ParseIP(strings.TrimSpace(row.ip)).To4()
		if parsed == nil {
			continue
		}
		ip := parsed.String()
		mac := strings.ToLower(strings.TrimSpace(row.mac))
		// Interface identity is the L2 trust boundary. One NIC may carry several
		// IPv4 prefixes; MAC reuse anywhere on the selected ifIndex must veto a
		// target-prefix promotion, or a router/proxy row on another prefix can be
		// mistaken for the live device.
		if macIPs[mac] == nil {
			macIPs[mac] = make(map[string]struct{})
		}
		macIPs[mac][ip] = struct{}{}
		if !linkScope.containsHost(ip) {
			continue
		}
		if !target.containsHost(ip) {
			continue
		}
		if allByIP[ip] == nil {
			allByIP[ip] = make(map[string]struct{})
		}
		allByIP[ip][mac] = struct{}{}
		// Static/permanent rows never prove liveness and therefore cannot be
		// promoted. They do describe ambiguity on the selected link, though: a
		// conflicting static row must veto a dynamic row rather than disappear
		// before the proxy/conflict checks run.
		if row.state == neighborStateDynamic {
			if dynamicByIP[ip] == nil {
				dynamicByIP[ip] = make(map[string]struct{})
			}
			dynamicByIP[ip][mac] = struct{}{}
		}
	}

	for ip := range liveSet {
		allMACs := allByIP[ip]
		dynamicMACs := dynamicByIP[ip]
		if len(allMACs) != 1 || len(dynamicMACs) != 1 {
			continue
		}
		for mac := range dynamicMACs {
			if len(macIPs[mac]) == 1 {
				result[ip] = mac
			}
		}
	}
	return result
}
