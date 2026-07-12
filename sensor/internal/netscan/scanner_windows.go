//go:build windows

package netscan

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
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
	start := time.Now()
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return nil, err
	}
	live := icmpSweep(hosts)
	// The sweep's L2 resolution populates the ARP cache for every reachable host on
	// the segment — including ones whose firewall drops the ICMP echo — so the ARP
	// table catches hosts the ping sweep alone misses.
	macs := arpTable()

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
	_, ipnet, _ := net.ParseCIDR(cidr)
	for ip, mac := range macs {
		if seen[ip] || !isRealNeighbor(ip, mac) {
			continue
		}
		if ipnet != nil {
			if p := net.ParseIP(ip); p == nil || !ipnet.Contains(p) {
				continue
			}
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
	var (
		mu   sync.Mutex
		live []string
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, sweepConcurrency)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			if pingICMP(ipStr) {
				mu.Lock()
				live = append(live, ipStr)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return live
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
	out := map[string]string{}
	cmd := exec.Command("arp", "-a")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return out
	}
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		if m := arpLineRe.FindStringSubmatch(sc.Text()); m != nil {
			out[m[1]] = strings.ToLower(strings.ReplaceAll(m[2], "-", ":"))
		}
	}
	return out
}
