//go:build windows

package netscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sweepConcurrency caps in-flight ICMP echoes. maxSweepHosts and the pure CIDR/
// filter helpers (enumerateHosts, isRealNeighbor, …) live in discovery_util.go.
const sweepConcurrency = 64

// Scanner is the native Windows discovery backend. Unlike the Unix nmap scanner it
// needs no external binary and no Npcap. Every production scan first resolves one
// directly-connected link, then binds ICMP to that link's IPv4 source address. The
// separately polling ARP Source and the scan use the same preferred-interface input.
type Scanner struct {
	BinaryPath string // "native" — kept for API parity with the nmap scanner

	preferredInterface   string
	corroborateNeighbors bool

	// Private seams keep the source/link/neighbor contract deterministic in Windows CI.
	detectSubnets  func() ([]DetectedSubnet, error)
	interfaceIndex func(string) (int, error)
	readNeighbors  func() ([]neighbor, error)
	sweepBound     func(context.Context, []string, string) ([]string, error)
}

// NewScanner returns the native Windows scanner. It never errors on a missing tool.
func NewScanner() (*Scanner, error) {
	return &Scanner{
		BinaryPath:    "native",
		detectSubnets: DetectSubnets,
		interfaceIndex: func(name string) (int, error) {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return 0, err
			}
			return iface.Index, nil
		},
		readNeighbors: readNeighbors,
		sweepBound:    icmpSweepBound,
	}, nil
}

// ConfigureNativeDiscovery aligns active Windows discovery with the passive neighbor
// source. preferredInterface is empty for auto-resolution or an operator-pinned OS
// interface. corroborateNeighbors follows --arp-discovery exactly: disabling that
// switch retains bound liveness but performs no neighbor-cache identity lookup.
func (s *Scanner) ConfigureNativeDiscovery(preferredInterface string, corroborateNeighbors bool) {
	if s == nil {
		return
	}
	s.preferredInterface = strings.TrimSpace(preferredInterface)
	s.corroborateNeighbors = corroborateNeighbors
}

// Scan discovers live hosts with source-bound ICMP. A target that is off-link,
// ambiguous, or whose selected interface disappears fails closed; the scanner never
// falls back to an unbound route-selected probe. A safe same-generation neighbor row
// can add a MAC and native_icmp_arp source. Otherwise the result is explicitly
// native_icmp_bound and remains IP-only.
func (s *Scanner) Scan(cidr string, withPorts bool) (*ScanResult, error) {
	return s.ScanContext(context.Background(), cidr, withPorts)
}

// Check is a no-op dependency check for the in-process Windows backend. It
// still honors cancellation so callers can use the same bounded API on every
// platform.
func (s *Scanner) Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("self-check context is nil")
	}
	return ctx.Err()
}

func (s *Scanner) SelfCheck(ctx context.Context) error { return s.Check(ctx) }

// ScanContext is the cancellable native discovery entry point. IcmpSendEcho2Ex is a
// synchronous bounded call (500 ms), so cancellation stops new calls immediately and
// waits at most for the already-running generation to return.
func (s *Scanner) ScanContext(ctx context.Context, cidr string, withPorts bool) (*ScanResult, error) {
	if ctx == nil {
		return nil, errors.New("scan context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = withPorts // native port scanning remains a later optional tier
	if s == nil {
		return nil, fmt.Errorf("nil native scanner")
	}
	if err := ValidateLocalTarget(cidr); err != nil {
		return nil, err
	}
	target, err := parseIPv4Scope(cidr)
	if err != nil {
		return nil, err
	}
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return &ScanResult{ScanTime: time.Now().UTC()}, nil
	}
	detect := s.detectSubnets
	if detect == nil {
		detect = DetectSubnets
	}
	index := s.interfaceIndex
	if index == nil {
		index = func(name string) (int, error) {
			iface, lookupErr := net.InterfaceByName(name)
			if lookupErr != nil {
				return 0, lookupErr
			}
			return iface.Index, nil
		}
	}
	link, err := resolveLocalScope(target, s.preferredInterface, detect, index)
	if err != nil {
		return nil, fmt.Errorf("resolve source-bound ICMP link for %q: %w", cidr, err)
	}
	if link.ifIndex <= 0 || net.ParseIP(link.ownIP).To4() == nil {
		return nil, fmt.Errorf("resolved source-bound ICMP link for %q has no stable IPv4/interface index", cidr)
	}

	start := time.Now().UTC()
	sweep := s.sweepBound
	if sweep == nil {
		sweep = icmpSweepBound
	}
	live, err := sweep(ctx, hosts, link.ownIP)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Detect a link removal/re-address/ambiguity during the sweep. Every individual
	// echo was source-bound, but a changed topology invalidates the generation as a
	// whole and must not be attributed to the previously selected segment.
	current, currentErr := resolveLocalScope(target, s.preferredInterface, detect, index)
	if currentErr != nil || !sameLocalScope(link, current) {
		if currentErr != nil {
			return nil, fmt.Errorf("source-bound ICMP link changed during scan of %q: %w", cidr, currentErr)
		}
		return nil, fmt.Errorf("source-bound ICMP link changed during scan of %q", cidr)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	macs := map[string]string{}
	if s.corroborateNeighbors && len(live) > 0 {
		reader := s.readNeighbors
		if reader == nil {
			reader = readNeighbors
		}
		rows, readErr := reader()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if readErr == nil {
			// The cache read is a separate OS operation and may outlive a route or
			// address change. Revalidate once more before attaching any link-layer
			// identity so rows from the old interface generation cannot be joined
			// to otherwise valid source-bound liveness.
			postCache, postCacheErr := resolveLocalScope(target, s.preferredInterface, detect, index)
			if postCacheErr != nil || !sameLocalScope(link, postCache) {
				if postCacheErr != nil {
					return nil, fmt.Errorf("source-bound ICMP link changed during neighbor read for %q: %w", cidr, postCacheErr)
				}
				return nil, fmt.Errorf("source-bound ICMP link changed during neighbor read for %q", cidr)
			}
			macs = corroborateLiveNeighbors(live, rows, target, link)
		}
		// A cache read failure does not erase proven liveness; it only withholds MAC
		// evidence. The result remains native_icmp_bound and IP-only.
	}

	result := &ScanResult{ScanTime: start}
	for _, ip := range live {
		host := DiscoveredHost{
			IPAddress: ip, Status: "up", DiscoverySource: "native_icmp_bound", ObservedAt: start,
		}
		if mac := macs[ip]; mac != "" {
			host.MACAddress = mac
			host.DiscoverySource = "native_icmp_arp"
		}
		result.Hosts = append(result.Hosts, host)
	}
	result.Duration = time.Since(start)
	return result, nil
}

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = iphlpapi.NewProc("IcmpSendEcho2Ex")
)

// icmpEchoReply mirrors ICMP_ECHO_REPLY (iphlpapi). Only Address and Status are
// read; the layout matches amd64 (Data pointer is 8-byte aligned at offset 16).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpSweepBound pings each host concurrently from one explicit local IPv4 address.
// Each worker uses its own ICMP handle (the API is not safe on a shared handle).
func icmpSweepBound(ctx context.Context, hosts []string, sourceIP string) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("ICMP sweep context is nil")
	}
	var (
		mu   sync.Mutex
		live []string
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, sweepConcurrency)
	cancelled := false
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			cancelled = true
		case sem <- struct{}{}:
		}
		if cancelled {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() == nil && pingICMPBound(sourceIP, ip) {
				mu.Lock()
				live = append(live, ip)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return live, nil
}

func ipAddrDWORD(ipStr string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr)).To4()
	if ip == nil {
		return 0, false
	}
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24, true
}

// pingICMPBound sends one synchronous echo with IcmpSendEcho2Ex's SourceAddress set.
// Windows therefore cannot silently route the probe through a VPN/other interface.
func pingICMPBound(sourceIP, destinationIP string) bool {
	source, sourceOK := ipAddrDWORD(sourceIP)
	destination, destinationOK := ipAddrDWORD(destinationIP)
	if !sourceOK || !destinationOK {
		return false
	}
	h, _, _ := procIcmpCreateFile.Call()
	handle := windows.Handle(h)
	if handle == windows.InvalidHandle {
		return false
	}
	defer procIcmpCloseHandle.Call(uintptr(handle))

	var requestData [32]byte
	// Microsoft requires room for the reply header, echoed request, eight ICMP error
	// bytes, and an IO_STATUS_BLOCK even though this call uses synchronous completion.
	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(requestData) + 8 +
		int(unsafe.Sizeof(windows.IO_STATUS_BLOCK{}))
	reply := make([]byte, replySize)
	ret, _, _ := procIcmpSendEcho2Ex.Call(
		uintptr(handle),
		0, // synchronous: no event
		0, // no APC callback
		0, // no APC context
		uintptr(source),
		uintptr(destination),
		uintptr(unsafe.Pointer(&requestData[0])),
		uintptr(len(requestData)),
		0, // no IP options
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(500),
	)
	if ret == 0 {
		return false
	}
	replyHeader := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	return replyHeader.Status == 0
}
