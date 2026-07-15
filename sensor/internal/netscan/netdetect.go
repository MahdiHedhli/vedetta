package netscan

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// DetectedSubnet represents a network interface and its subnet.
type DetectedSubnet struct {
	Interface string `json:"interface"`
	IPAddress string `json:"ip_address"`
	CIDR      string `json:"cidr"`
	IsDefault bool   `json:"is_default"`
}

// DetectSubnets inspects local network interfaces and returns candidate subnets.
// Since the sensor runs natively on the host, this sees the real LAN interfaces.
func DetectSubnets() ([]DetectedSubnet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var subnets []DetectedSubnet

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if subnet, ok := detectedIPv4Subnet(iface.Name, ipNet); ok {
				subnets = append(subnets, subnet)
			}
		}
	}

	if len(subnets) > 0 {
		sort.Slice(subnets, func(i, j int) bool {
			return subnetPriority(subnets[i]) > subnetPriority(subnets[j])
		})
		subnets[0].IsDefault = true
	}

	return subnets, nil
}

func detectedIPv4Subnet(interfaceName string, ipNet *net.IPNet) (DetectedSubnet, bool) {
	if ipNet == nil {
		return DetectedSubnet{}, false
	}
	ip := ipNet.IP
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.To4() == nil {
		return DetectedSubnet{}, false
	}
	// Skip interfaces whose identity marks them as container/VM plumbing. Never
	// infer "virtual" from the address itself: 172.17-31/16 and 192.168.65/24 are
	// perfectly valid physical LAN ranges too.
	if isVirtualInterface(interfaceName) {
		return DetectedSubnet{}, false
	}
	network := ipNet.IP.Mask(ipNet.Mask)
	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits != 32 {
		return DetectedSubnet{}, false
	}
	return DetectedSubnet{
		Interface: interfaceName,
		IPAddress: ip.String(),
		CIDR:      fmt.Sprintf("%s/%d", network.String(), ones),
	}, true
}

// BestSubnet returns the most likely LAN CIDR, or fallback.
func BestSubnet(fallback string) string {
	subnets, err := DetectSubnets()
	if err != nil || len(subnets) == 0 {
		return fallback
	}
	return subnets[0].CIDR
}

func isVirtualInterface(name string) bool {
	// Common container, CNI, VPN, WSL, and desktop-hypervisor interface names.
	// Keep this identity-based: private IP ranges do not reveal whether a link is
	// physical or virtual. This is necessarily a conservative name classifier;
	// operators with renamed/custom adapters can pin the intended LAN interface.
	virtualPrefixes := []string{
		"docker", "br-", "veth", "virbr", "vmnet", "vboxnet",
		"cni", "flannel", "cali", "tunl", "vxlan.calico", "weave", "kube-ipvs", "podman",
		"vethernet", "wsl", "utun", "tun", "tap", "tailscale", "wg", "zt",
		"awdl", "llw", "gif", "stf",
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "bridge100" { // macOS Internet Sharing / VM bridge
		return true
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func subnetPriority(s DetectedSubnet) int {
	score := 0
	ip := net.ParseIP(s.IPAddress)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}

	// Prefer common LAN ranges
	if ip4[0] == 10 {
		score += 10
	} else if ip4[0] == 192 && ip4[1] == 168 {
		score += 9
	}

	// Prefer common interface names
	lower := strings.ToLower(s.Interface)
	switch {
	case lower == "eth0" || lower == "en0":
		score += 5
	case lower == "wlan0" || lower == "wlp2s0":
		score += 3
	case strings.HasPrefix(lower, "en"):
		score += 4
	case strings.HasPrefix(lower, "wl"):
		score += 2
	}

	return score
}
