//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package netscan

// readNeighbors is a no-op on platforms that have no supported unprivileged
// neighbor-cache reader. Linux (/proc/net/arp), macOS/BSD (route.FetchRIB), and
// Windows (GetIpNetTable) each provide a real implementation in a build-tagged sibling.
func readNeighbors() ([]neighbor, error) { return nil, nil }
