package discovery

import (
	"fmt"
	"net"
	"sort"
)

// DetectedSubnet represents a network interface and its subnet.
type DetectedSubnet struct {
	Interface string `json:"interface"`
	IPAddress string `json:"ip_address"`
	CIDR      string `json:"cidr"`
	IsDefault bool   `json:"is_default"` // Most likely the user's LAN
}

// DetectSubnets inspects local network interfaces and returns candidate subnets.
// Filters out loopback, Docker bridges, and link-local addresses.
func DetectSubnets() ([]DetectedSubnet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var subnets []DetectedSubnet

	for _, iface := range ifaces {
		// Skip down, loopback, and point-to-point interfaces
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

			// Only IPv4 for now
			if ip.To4() == nil {
				continue
			}

			// Skip Docker bridge (typically 172.17.0.0/16 or 172.18-31.x.x)
			if isDockerBridge(iface.Name, ip) {
				continue
			}

			// Compute the network CIDR from the interface address
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

	// Heuristic: mark the most likely LAN interface as default
	// Prefer: eth0 > en0 > wlan0 > anything else; prefer 10.x/192.168.x over 172.x
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

func isDockerBridge(name string, ip net.IP) bool {
	// Common Docker interface names
	dockerNames := []string{"docker0", "br-", "veth"}
	for _, dn := range dockerNames {
		if len(name) >= len(dn) && name[:len(dn)] == dn {
			return true
		}
	}

	// Docker's default bridge uses 172.17.0.0/16
	// User-defined bridges use 172.18-31.x.x
	if ip[0] == 172 && ip[1] >= 17 && ip[1] <= 31 {
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
		score += 10 // 10.x.x.x — very common home/SMB
	} else if ip4[0] == 192 && ip4[1] == 168 {
		score += 9 // 192.168.x.x — standard home
	}

	// Prefer common interface names
	switch {
	case s.Interface == "eth0" || s.Interface == "en0":
		score += 5
	case s.Interface == "wlan0" || s.Interface == "wlp2s0":
		score += 3
	case len(s.Interface) >= 2 && s.Interface[:2] == "en":
		score += 4 // macOS ethernet
	}

	return score
}
