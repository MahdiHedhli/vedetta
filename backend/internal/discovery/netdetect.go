package discovery

import (
	"fmt"
	"net"
	"os"
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

			// Skip Docker/container networks (bridges, Desktop VM, etc.)
			if isDockerNetwork(iface.Name, ip) {
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
// When running inside Docker, detected interfaces are container-internal,
// so this returns the fallback to trigger the frontend confirmation dialog.
func BestSubnet(fallback string) string {
	if IsInsideDocker() {
		// Inside a container, interface detection shows container/VM networks
		// not the host LAN. Return empty to trigger the subnet confirmation UI.
		return ""
	}
	subnets, err := DetectSubnets()
	if err != nil || len(subnets) == 0 {
		return fallback
	}
	return subnets[0].CIDR
}

// IsInsideDocker checks if the process is running inside a Docker container.
func IsInsideDocker() bool {
	// Check for /.dockerenv (standard Docker marker)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check for container-specific cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if len(s) > 0 && (contains(s, "docker") || contains(s, "containerd") || contains(s, "kubepods")) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func isDockerNetwork(name string, ip net.IP) bool {
	// Common Docker interface names
	dockerNames := []string{"docker0", "br-", "veth"}
	for _, dn := range dockerNames {
		if len(name) >= len(dn) && name[:len(dn)] == dn {
			return true
		}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// Docker's default bridge uses 172.17.0.0/16
	// User-defined bridges use 172.18-31.x.x
	if ip4[0] == 172 && ip4[1] >= 17 && ip4[1] <= 31 {
		return true
	}

	// Docker Desktop for Mac/Windows uses 192.168.65.0/24 VM network
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
