//go:build !linux

package netscan

// readNeighbors is a no-op on platforms whose unprivileged neighbor-cache reader is
// not yet wired here. The macOS/BSD reader (route.FetchRIB) and a Windows adapter over
// arpTable() narrow this build constraint in the following pieces of the ARP source.
func readNeighbors() ([]neighbor, error) { return nil, nil }
