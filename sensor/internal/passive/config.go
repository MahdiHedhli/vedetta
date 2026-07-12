package passive

import "github.com/vedetta-network/vedetta/sensor/internal/netscan"

// Config controls passive device discovery. It is platform-neutral so main.go can
// build it identically everywhere; the pcap-backed Capturer is Unix-only (capture.go),
// and Windows gets a driver-free no-op stub (capture_windows.go) until the optional
// Npcap tier exists.
type Config struct {
	Interface  string
	CoreURL    string
	CIDR       string
	EnableARP  bool
	EnableDHCP bool
	EnableMDNS bool
	EnableSSDP bool
	OnHost     func(netscan.DiscoveredHost)
}
