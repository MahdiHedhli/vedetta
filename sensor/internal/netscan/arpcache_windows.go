//go:build windows

package netscan

// readNeighbors adapts the existing Windows ARP-cache reader (arpTable, which shells
// `arp -a`) to the shared neighbor shape. It reuses arpTable verbatim — no duplication
// — and applies the same isRealNeighbor filter as the other platforms. arpTable
// already normalizes MACs to lowercase colon form.
func readNeighbors() ([]neighbor, error) {
	var out []neighbor
	for ip, mac := range arpTable() {
		if !isRealNeighbor(ip, mac) {
			continue
		}
		out = append(out, neighbor{ip: ip, mac: mac})
	}
	return out, nil
}
