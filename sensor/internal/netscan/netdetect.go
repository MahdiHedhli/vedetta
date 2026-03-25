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

			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// IPv4 only for now
			if ip.To4() == nil {
				continue
			}

			// Skip Docker/virtual interfaces
			if isVirtualNetwork(iface.Name, ip) {
				continue
			}

			network := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			cidr := fmt.Sprintf("%s/%d", network.String(), ones)

			subnets = append(subnets, DetectedSubnet{
				Interface: iface.Name,
				IPAddress: ip.String(),
				CIDR:      cidr,
			})
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

// BestSubnet returns the most likely LAN CIDR, or fallback.
func BestSubnet(fallback string) string {
	subnets, err := DetectSubnets()
	if err != nil || len(subnets) == 0 {
		return fallback
	}
	return subnets[0].CIDR
}

func isVirtualNetwork(name string, ip net.IP) bool {
	// Docker bridge interfaces
	virtualPrefixes := []string{"docker0", "br-", "veth", "virbr", "vmnet", "vboxnet"}
	lower := strings.ToLower(name)
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// Docker default bridge 172.17-31.x.x
	if ip4[0] == 172 && ip4[1] >= 17 && ip4[1] <= 31 {
		return true
	}

	// Docker Desktop VM network (macOS/Windows)
	if ip4[0] == 192 && ip4[1] == 168 && ip4[2] == 65 {
		return true
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
