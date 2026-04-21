package netinfo

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/google/gopacket/pcap"
)

// CaptureSelectionOptions controls automatic capture-interface selection.
type CaptureSelectionOptions struct {
	Preferred string
	CoreURL   string
	ScanCIDR  string
	Purpose   string
}

// CaptureSelection is the result of choosing a capture interface.
type CaptureSelection struct {
	Name         string
	Reason       string
	RouteSource  string
	ScanCIDR     string
	Candidates   []CaptureCandidate
	WasPreferred bool
}

// CaptureCandidate summarizes one ranked capture-interface candidate.
type CaptureCandidate struct {
	Name    string
	Score   int
	IPs     []string
	Reasons []string
}

type captureCandidate struct {
	Name          string
	IPs           []net.IP
	Score         int
	Reasons       []string
	IsLoopback    bool
	IsTunnel      bool
	IsVirtual     bool
	IsPhysicalish bool
}

// SelectCaptureInterface chooses the best pcap-capable interface for DNS/passive capture.
func SelectCaptureInterface(opts CaptureSelectionOptions) (*CaptureSelection, error) {
	pcapIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list capture devices: %w", err)
	}
	if len(pcapIfaces) == 0 {
		return nil, fmt.Errorf("no capture-capable interfaces found")
	}

	preferred := strings.TrimSpace(opts.Preferred)
	if preferred != "" && preferred != "auto" {
		for _, dev := range pcapIfaces {
			if dev.Name == preferred {
				return &CaptureSelection{
					Name:         preferred,
					Reason:       fmt.Sprintf("%s interface explicitly pinned with --%s", humanPurpose(opts.Purpose), preferredFlag(opts.Purpose)),
					ScanCIDR:     NormalizeSubnet(opts.ScanCIDR),
					Candidates:   []CaptureCandidate{{Name: preferred, Score: 0, Reasons: []string{"explicit override"}}},
					WasPreferred: true,
				}, nil
			}
		}
		return nil, fmt.Errorf("requested interface %q was not found among capture devices", preferred)
	}

	routeSourceIP := resolveRouteSourceIP(opts.CoreURL)
	scanNet := parseOptionalCIDR(opts.ScanCIDR)
	ranked := rankCaptureCandidates(buildCaptureCandidates(pcapIfaces), scanNet, routeSourceIP)
	if len(ranked) == 0 {
		return nil, fmt.Errorf("no capture-capable interfaces found")
	}

	best := ranked[0]
	return &CaptureSelection{
		Name:        best.Name,
		Reason:      strings.Join(best.Reasons, ", "),
		RouteSource: ipString(routeSourceIP),
		ScanCIDR:    NormalizeSubnet(opts.ScanCIDR),
		Candidates:  summarizeCandidates(ranked),
	}, nil
}

// FormatCaptureSelection returns a human-readable explanation of interface selection.
func FormatCaptureSelection(sel *CaptureSelection, purpose string) string {
	if sel == nil {
		return fmt.Sprintf("%s: unavailable", humanPurpose(purpose))
	}

	lines := []string{
		fmt.Sprintf("%s: %s", humanPurpose(purpose), sel.Name),
		fmt.Sprintf("  Why: %s", sel.Reason),
	}
	if sel.ScanCIDR != "" {
		lines = append(lines, fmt.Sprintf("  Scan CIDR: %s", sel.ScanCIDR))
	}
	if sel.RouteSource != "" {
		lines = append(lines, fmt.Sprintf("  Route-to-Core source IP: %s", sel.RouteSource))
	}
	if len(sel.Candidates) > 1 {
		lines = append(lines, "  Next best candidates:")
		limit := len(sel.Candidates)
		if limit > 4 {
			limit = 4
		}
		for i := 1; i < limit; i++ {
			candidate := sel.Candidates[i]
			lines = append(lines, fmt.Sprintf("    - %s (score %d): %s", candidate.Name, candidate.Score, strings.Join(candidate.Reasons, ", ")))
		}
	}
	if !sel.WasPreferred {
		lines = append(lines, fmt.Sprintf("  Override: --%s <iface>", preferredFlag(purpose)))
	}
	return strings.Join(lines, "\n")
}

func buildCaptureCandidates(devices []pcap.Interface) []captureCandidate {
	systemIfaces, _ := ListInterfaces()
	systemByName := make(map[string]NetworkInterface, len(systemIfaces))
	for _, iface := range systemIfaces {
		systemByName[iface.Name] = iface
	}

	candidates := make([]captureCandidate, 0, len(devices))
	for _, dev := range devices {
		candidate := captureCandidate{Name: dev.Name}
		candidate.IsLoopback = isLoopbackInterface(dev.Name)
		candidate.IsTunnel = isTunnelInterface(dev.Name)
		candidate.IsVirtual = isVirtualInterface(dev.Name)
		candidate.IsPhysicalish = isPhysicalishInterface(dev.Name)

		for _, addr := range dev.Addresses {
			if ip := addr.IP; ip != nil {
				candidate.IPs = append(candidate.IPs, ip)
			}
		}

		if len(candidate.IPs) == 0 {
			if sys, ok := systemByName[dev.Name]; ok {
				for _, rawIP := range sys.IPs {
					if parsed := net.ParseIP(rawIP); parsed != nil {
						candidate.IPs = append(candidate.IPs, parsed)
					}
				}
			}
		}

		candidates = append(candidates, candidate)
	}
	return candidates
}

func rankCaptureCandidates(candidates []captureCandidate, scanNet *net.IPNet, routeSourceIP net.IP) []captureCandidate {
	for i := range candidates {
		scoreCaptureCandidate(&candidates[i], scanNet, routeSourceIP)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].Name < candidates[j].Name
		}
		return candidates[i].Score > candidates[j].Score
	})
	return candidates
}

func scoreCaptureCandidate(candidate *captureCandidate, scanNet *net.IPNet, routeSourceIP net.IP) {
	candidate.Score = 0
	candidate.Reasons = nil

	if candidate.IsLoopback {
		candidate.Score -= 200
		candidate.Reasons = append(candidate.Reasons, "loopback interface")
	}
	if candidate.IsTunnel {
		candidate.Score -= 120
		candidate.Reasons = append(candidate.Reasons, "tunnel/VPN interface")
	}
	if candidate.IsVirtual {
		candidate.Score -= 80
		candidate.Reasons = append(candidate.Reasons, "virtual or side-channel interface")
	}
	if candidate.IsPhysicalish {
		candidate.Score += 35
		candidate.Reasons = append(candidate.Reasons, "physical LAN/Wi-Fi interface")
	}

	hasIPv4 := false
	hasPrivateIPv4 := false
	for _, ip := range candidate.IPs {
		if ip == nil || ip.To4() == nil {
			continue
		}
		hasIPv4 = true
		if ip.IsPrivate() {
			hasPrivateIPv4 = true
		}
		if scanNet != nil && scanNet.Contains(ip) {
			candidate.Score += 120
			candidate.Reasons = append(candidate.Reasons, fmt.Sprintf("scan CIDR matches host IP %s", ip.String()))
			break
		}
	}
	if hasIPv4 {
		candidate.Score += 15
		candidate.Reasons = append(candidate.Reasons, "has IPv4 address")
	} else {
		candidate.Score -= 20
		candidate.Reasons = append(candidate.Reasons, "no IPv4 address")
	}
	if hasPrivateIPv4 {
		candidate.Score += 25
		candidate.Reasons = append(candidate.Reasons, "private IPv4 address")
	}

	if routeSourceIP != nil && routeSourceIP.To4() != nil && !routeSourceIP.IsLoopback() {
		for _, ip := range candidate.IPs {
			if ip.Equal(routeSourceIP) {
				candidate.Score += 70
				candidate.Reasons = append(candidate.Reasons, fmt.Sprintf("route to Core uses %s", routeSourceIP.String()))
				break
			}
		}
	}

	if len(candidate.Reasons) == 0 {
		candidate.Reasons = append(candidate.Reasons, "best available capture candidate")
	}
}

func summarizeCandidates(candidates []captureCandidate) []CaptureCandidate {
	out := make([]CaptureCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ips := make([]string, 0, len(candidate.IPs))
		for _, ip := range candidate.IPs {
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
		out = append(out, CaptureCandidate{
			Name:    candidate.Name,
			Score:   candidate.Score,
			IPs:     ips,
			Reasons: append([]string(nil), candidate.Reasons...),
		})
	}
	return out
}

func resolveRouteSourceIP(coreURL string) net.IP {
	coreURL = strings.TrimSpace(coreURL)
	if coreURL == "" {
		return nil
	}

	parsed, err := url.Parse(coreURL)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return nil
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}

	conn, err := net.Dial("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return udpAddr.IP
}

func parseOptionalCIDR(raw string) *net.IPNet {
	raw = NormalizeSubnet(strings.TrimSpace(raw))
	if raw == "" {
		return nil
	}
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil
	}
	return ipNet
}

func preferredFlag(purpose string) string {
	switch strings.ToLower(strings.TrimSpace(purpose)) {
	case "dns", "dns capture":
		return "dns-iface"
	default:
		return "passive-iface"
	}
}

func humanPurpose(purpose string) string {
	switch strings.ToLower(strings.TrimSpace(purpose)) {
	case "dns", "dns capture":
		return "DNS capture recommendation"
	case "passive", "passive discovery":
		return "Passive discovery recommendation"
	default:
		return "Capture recommendation"
	}
}

func isLoopbackInterface(name string) bool {
	lower := strings.ToLower(name)
	return lower == "lo" || lower == "lo0" || strings.HasPrefix(lower, "lo")
}

func isTunnelInterface(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{"utun", "tun", "tap", "ppp", "wg", "tailscale", "zt", "ipsec"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{"awdl", "llw", "ap", "docker", "veth", "br-", "virbr", "vmnet", "bridge", "gif", "stf"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isPhysicalishInterface(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{"en", "eth", "wlan", "wl", "eno", "ens", "enp"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
