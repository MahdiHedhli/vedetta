//go:build darwin || freebsd || netbsd || openbsd

package netscan

import (
	"net"
	"strings"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// readNeighbors reads the macOS/BSD kernel routing table and returns the resolved
// IPv4 ARP entries (AF_INET only; IPv6 NDP is not parsed). It is fully unprivileged:
// route.FetchRIB reads the routing information base with no root, raw sockets,
// CAP_NET_RAW, libpcap, or external binary.
func readNeighbors() ([]neighbor, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	return neighborsFromRIB(msgs), nil
}

// neighborsFromRIB extracts completed link-layer (ARP) entries from parsed routing
// messages. Kept separate from the syscall so it is unit-testable with synthetic
// messages. It keeps only RTF_LLINFO routes with both an IPv4 destination and a
// link-layer gateway, normalizes the MAC to lowercase colon form, resolves the
// interface name, and drops broadcast/multicast pseudo-entries via isRealNeighbor.
func neighborsFromRIB(msgs []route.Message) []neighbor {
	var out []neighbor
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_LLINFO == 0 {
			continue
		}
		if len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		dst, _ := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		gw, _ := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if dst == nil || gw == nil || len(gw.Addr) == 0 {
			continue
		}
		ip := net.IP(dst.IP[:]).String()
		mac := strings.ToLower(net.HardwareAddr(gw.Addr).String())
		if mac == "" || !isRealNeighbor(ip, mac) {
			continue
		}
		state := neighborStateDynamic
		if rm.Flags&unix.RTF_STATIC != 0 {
			state = neighborStateStatic
		}
		out = append(out, neighbor{ip: ip, mac: mac, iface: linkName(gw), ifIndex: gw.Index, state: state})
	}
	return out
}

// linkName resolves the interface name for a link-layer address, preferring the name
// carried on the message and falling back to an index lookup.
func linkName(la *route.LinkAddr) string {
	if la.Name != "" {
		return la.Name
	}
	if la.Index > 0 {
		if ifi, err := net.InterfaceByIndex(la.Index); err == nil {
			return ifi.Name
		}
	}
	return ""
}
