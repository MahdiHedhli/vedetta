//go:build windows

package netscan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sweepConcurrency caps in-flight ICMP echoes. maxSweepHosts and the pure CIDR/
// filter helpers (enumerateHosts, isRealNeighbor, …) live in discovery_util.go.
const sweepConcurrency = 64

const (
	windowsARPTimeout   = 3 * time.Second
	maxWindowsARPOutput = 1 << 20
)

// Scanner is the native Windows discovery backend. Unlike the Unix nmap scanner it
// needs no external binary and no Npcap: host liveness comes from IcmpSendEcho
// (iphlpapi, in-process) and MACs from the system ARP table.
type Scanner struct {
	BinaryPath string // "native" — kept for API parity with the nmap scanner
}

// NewScanner returns the native Windows scanner. It never errors on a missing tool.
func NewScanner() (*Scanner, error) {
	return &Scanner{BinaryPath: "native"}, nil
}

// Scan discovers live hosts in cidr with a bounded, concurrent ICMP echo sweep
// (which also warms the ARP cache), then attaches MACs from the ARP table.
// withPorts is ignored — port scanning is the optional Npcap/nmap Phase-3 tier.
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

// ScanContext is the cancellable form of Scan. Individual ICMP calls are
// bounded by the native 500 ms timeout; cancellation prevents new calls and
// discards a partial sweep instead of reporting it as complete.
func (s *Scanner) ScanContext(ctx context.Context, cidr string, withPorts bool) (*ScanResult, error) {
	if ctx == nil {
		return nil, errors.New("scan context is nil")
	}
	start := time.Now()
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return nil, err
	}
	live, err := icmpSweepContext(ctx, hosts)
	if err != nil {
		return nil, err
	}
	// The sweep's L2 resolution populates the ARP cache for every reachable host on
	// the segment — including ones whose firewall drops the ICMP echo — so the ARP
	// table catches hosts the ping sweep alone misses.
	macs := arpTableContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &ScanResult{ScanTime: start}
	seen := map[string]bool{}
	for _, ip := range live {
		seen[ip] = true
		h := DiscoveredHost{IPAddress: ip, Status: "up", DiscoverySource: "native_icmp"}
		if mac, ok := macs[ip]; ok {
			h.MACAddress = mac
		}
		result.Hosts = append(result.Hosts, h)
	}

	// Add ARP-known neighbors within the CIDR that did not answer ICMP (e.g. ping
	// blocked by the host firewall). Skip broadcast/multicast pseudo-entries.
	for ip, mac := range macs {
		if seen[ip] || !isRealNeighbor(ip, mac) {
			continue
		}
		if !ipv4TargetContains(cidr, ip) {
			continue
		}
		seen[ip] = true
		result.Hosts = append(result.Hosts, DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "up", DiscoverySource: "arp",
		})
	}
	result.Duration = time.Since(start)
	return result, nil
}

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
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

// icmpSweep pings each host concurrently and returns those that replied. Each
// worker uses its own ICMP handle (IcmpSendEcho is not safe on a shared handle).
func icmpSweep(hosts []string) []string {
	live, _ := icmpSweepContext(context.Background(), hosts)
	return live
}

func icmpSweepContext(ctx context.Context, hosts []string) ([]string, error) {
	var (
		mu   sync.Mutex
		live []string
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, sweepConcurrency)
	canceled := false
	for _, h := range hosts {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			canceled = true
		}
		if canceled {
			break
		}
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if pingICMP(ipStr) {
				mu.Lock()
				live = append(live, ipStr)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return live, nil
}

// pingICMP sends one ICMP echo to ipStr and reports whether it replied (Status 0).
func pingICMP(ipStr string) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	h, _, _ := procIcmpCreateFile.Call()
	handle := windows.Handle(h)
	if handle == windows.InvalidHandle {
		return false
	}
	defer procIcmpCloseHandle.Call(uintptr(handle))

	dest := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
	var reqData [32]byte
	replySize := uint32(unsafe.Sizeof(icmpEchoReply{})) + uint32(len(reqData)) + 8
	reply := make([]byte, replySize)

	ret, _, _ := procIcmpSendEcho.Call(
		uintptr(handle),
		uintptr(dest),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		0, // no IP options
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(500), // timeout ms
	)
	if ret == 0 {
		return false // no reply within the timeout
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	return r.Status == 0 // IP_SUCCESS
}

var arpLineRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})`)

// arpTable returns IP -> MAC (colon-lowercased) from the system ARP cache.
func arpTable() map[string]string {
	return arpTableContext(context.Background())
}

func arpTableContext(ctx context.Context) map[string]string {
	out := map[string]string{}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return out
	}
	runCtx, cancel := context.WithTimeout(ctx, windowsARPTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, filepath.Join(systemDirectory, "arp.exe"), "-a")
	buf := &windowsBoundedBuffer{limit: maxWindowsARPOutput}
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return out
	}
	if buf.truncated {
		return out
	}
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		if m := arpLineRe.FindStringSubmatch(sc.Text()); m != nil {
			out[m[1]] = strings.ToLower(strings.ReplaceAll(m[2], "-", ":"))
		}
	}
	return out
}

type windowsBoundedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *windowsBoundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		keep := len(data)
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.Buffer.Write(data[:keep])
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return written, nil
}
