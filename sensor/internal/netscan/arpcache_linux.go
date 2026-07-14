//go:build linux

package netscan

import "os"

// readNeighbors reads the Linux kernel ARP table from /proc/net/arp. This is fully
// unprivileged: no root, no raw sockets, no CAP_NET_RAW, no libpcap, no external
// binary — just reading a procfs file. Returns completed IP↔MAC entries only, with
// broadcast/multicast pseudo-entries filtered out.
func readNeighbors() ([]neighbor, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNetARP(f), nil
}
