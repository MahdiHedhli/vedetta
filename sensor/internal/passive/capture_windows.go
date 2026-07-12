//go:build windows

package passive

import "fmt"

// Capturer is a driver-free no-op on Windows. Passive discovery is pcap-backed and
// requires Npcap; the base Windows sensor (spec 006 v1) is host-scoped — ETW DNS +
// native ICMP/ARP — so NewCapturer returns an error and main.go simply continues.
// This guarantees no untested pcap parsing ever runs as LocalSystem just because
// Npcap happens to be installed. Npcap-backed L2 capture is a future opt-in tier.
type Capturer struct{}

// NewCapturer reports that passive discovery is unavailable on the base Windows build.
func NewCapturer(cfg Config) (*Capturer, error) {
	return nil, fmt.Errorf("passive discovery is not available on Windows without the optional Npcap tier (spec 006 Phase 3); the base sensor captures DNS via ETW and discovers devices via native ICMP/ARP")
}

// The methods below exist only so the shared main.go compiles on Windows; they are
// never reached because NewCapturer always returns an error there.
func (c *Capturer) Start() error      { return fmt.Errorf("passive discovery not available on Windows") }
func (c *Capturer) Stop()             {}
func (c *Capturer) Interface() string { return "" }
