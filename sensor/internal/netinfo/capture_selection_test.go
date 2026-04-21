package netinfo

import (
	"net"
	"strings"
	"testing"
)

func TestRankCaptureCandidatesPrefersScanCIDRMatchOverTunnelRoute(t *testing.T) {
	scanNet := parseOptionalCIDR("10.0.0.0/24")
	routeIP := net.ParseIP("100.64.0.10")

	candidates := rankCaptureCandidates([]captureCandidate{
		{
			Name:          "utun2",
			IPs:           []net.IP{routeIP},
			IsTunnel:      true,
			IsPhysicalish: false,
		},
		{
			Name:          "en0",
			IPs:           []net.IP{net.ParseIP("10.0.0.182")},
			IsPhysicalish: true,
		},
	}, scanNet, routeIP)

	if candidates[0].Name != "en0" {
		t.Fatalf("expected en0 to win, got %s", candidates[0].Name)
	}
	if candidates[0].Score <= candidates[1].Score {
		t.Fatalf("expected scan-match candidate to outrank tunnel: %+v", candidates)
	}
}

func TestRankCaptureCandidatesPenalizesVirtualMacInterfaces(t *testing.T) {
	candidates := rankCaptureCandidates([]captureCandidate{
		{
			Name:          "ap1",
			IPs:           []net.IP{net.ParseIP("10.0.0.50")},
			IsVirtual:     true,
			IsPhysicalish: false,
		},
		{
			Name:          "en0",
			IPs:           []net.IP{net.ParseIP("10.0.0.182")},
			IsPhysicalish: true,
		},
	}, parseOptionalCIDR("10.0.0.0/24"), nil)

	if candidates[0].Name != "en0" {
		t.Fatalf("expected en0 to outrank ap1, got %s", candidates[0].Name)
	}
}

func TestFormatCaptureSelectionIncludesOverrideHint(t *testing.T) {
	sel := &CaptureSelection{
		Name:   "en0",
		Reason: "scan CIDR matches host IP 10.0.0.182, physical LAN/Wi-Fi interface",
		Candidates: []CaptureCandidate{
			{Name: "en0", Score: 100, Reasons: []string{"best"}},
			{Name: "utun2", Score: -20, Reasons: []string{"tunnel/VPN interface"}},
		},
	}

	output := FormatCaptureSelection(sel, "passive discovery")
	if !strings.Contains(output, "--passive-iface <iface>") {
		t.Fatalf("expected passive override hint, got:\n%s", output)
	}
	if !strings.Contains(output, "Passive discovery recommendation: en0") {
		t.Fatalf("expected heading, got:\n%s", output)
	}
}
