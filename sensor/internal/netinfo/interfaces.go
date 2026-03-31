package netinfo

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NetworkInterface represents a discovered NIC on the sensor host.
type NetworkInterface struct {
	Name       string   `json:"name"`        // e.g. "en0", "eth0", "wlan0"
	MAC        string   `json:"mac"`         // hardware address
	IPs        []string `json:"ips"`         // IPv4/IPv6 addresses
	Subnet     string   `json:"subnet"`      // first IPv4 CIDR, e.g. "10.0.0.0/24"
	IsUp       bool     `json:"is_up"`
	IsLoopback bool     `json:"is_loopback"`
}

// ListInterfaces enumerates active network interfaces on the host.
// Filters out loopback and down interfaces.
// Returns only interfaces that have at least one IPv4 address.
func ListInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var result []NetworkInterface

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if (iface.Flags&net.FlagLoopback != 0) || (iface.Flags&net.FlagUp == 0) {
			continue
		}

		// Get addresses
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ips []string
		var subnet string

		// Extract IPv4 and IPv6 addresses
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP.String()
			ips = append(ips, ip)

			// Capture first IPv4 CIDR for subnet
			if subnet == "" && ipnet.IP.To4() != nil {
				subnet = ipnet.String()
			}
		}

		// Only include if it has at least one IP
		if len(ips) == 0 {
			continue
		}

		ni := NetworkInterface{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			IPs:        ips,
			Subnet:     subnet,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		result = append(result, ni)
	}

	return result, nil
}

// parseCIDRMask converts IP and netmask to CIDR notation.
func parseCIDRMask(ip net.IP, mask net.IPMask) string {
	if mask == nil {
		return ""
	}
	ones, bits := mask.Size()
	if bits == 0 {
		return ""
	}
	// Calculate network address by applying mask
	network := ip.Mask(mask)
	return network.String() + "/" + strconv.Itoa(ones)
}

// NormalizeSubnet takes a CIDR string and ensures it's a valid network address.
func NormalizeSubnet(subnet string) string {
	if subnet == "" {
		return ""
	}

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}

	return ipnet.String()
}

// SubnetFromIPAndMask converts an IP and netmask string to CIDR.
func SubnetFromIPAndMask(ip, maskStr string) string {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return ""
	}

	// Try parsing as dotted decimal IP/mask (e.g., 255.255.255.0)
	if strings.Contains(maskStr, ".") {
		// Dotted decimal notation
		parts := strings.Split(maskStr, ".")
		if len(parts) == 4 {
			var maskBytes []byte
			for _, p := range parts {
				if b, err := strconv.Atoi(p); err == nil && b >= 0 && b <= 255 {
					maskBytes = append(maskBytes, byte(b))
				}
			}
			if len(maskBytes) == 4 {
				return parseCIDRMask(ipAddr, net.IPMask(maskBytes))
			}
		}
	}

	// Try parsing as CIDR bits (e.g., "24")
	if bits, err := strconv.Atoi(maskStr); err == nil && bits >= 0 && bits <= 32 {
		mask := net.CIDRMask(bits, 32)
		return parseCIDRMask(ipAddr, mask)
	}

	return ""
}
