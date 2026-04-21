package passive

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

func parsePacket(packet gopacket.Packet, cfg Config) []netscan.DiscoveredHost {
	if cfg.EnableARP {
		if hosts := parseARP(packet); len(hosts) > 0 {
			return hosts
		}
	}
	if cfg.EnableDHCP {
		if hosts := parseDHCPv4(packet); len(hosts) > 0 {
			return hosts
		}
	}
	if cfg.EnableMDNS {
		if hosts := parseMDNS(packet); len(hosts) > 0 {
			return hosts
		}
	}
	if cfg.EnableSSDP {
		if hosts := parseSSDP(packet); len(hosts) > 0 {
			return hosts
		}
	}
	return nil
}

func parseARP(packet gopacket.Packet) []netscan.DiscoveredHost {
	layer := packet.Layer(layers.LayerTypeARP)
	if layer == nil {
		return nil
	}

	arp, ok := layer.(*layers.ARP)
	if !ok {
		return nil
	}
	if len(arp.SourceProtAddress) == 0 || len(arp.SourceHwAddress) == 0 {
		return nil
	}

	return []netscan.DiscoveredHost{{
		IPAddress:  net.IP(arp.SourceProtAddress).String(),
		MACAddress: normalizeMAC(arp.SourceHwAddress),
		Status:     "up",
	}}
}

func parseDHCPv4(packet gopacket.Packet) []netscan.DiscoveredHost {
	layer := packet.Layer(layers.LayerTypeDHCPv4)
	if layer == nil {
		return nil
	}

	dhcp, ok := layer.(*layers.DHCPv4)
	if !ok {
		return nil
	}
	host := hostFromDHCPv4(dhcp, sourceIP(packet))
	if host == nil {
		return nil
	}
	return []netscan.DiscoveredHost{*host}
}

func hostFromDHCPv4(dhcp *layers.DHCPv4, srcIP string) *netscan.DiscoveredHost {
	host := netscan.DiscoveredHost{
		IPAddress:  firstNonEmptyIP(dhcp.YourClientIP, dhcp.ClientIP),
		MACAddress: normalizeMAC(dhcp.ClientHWAddr),
		Status:     "up",
	}
	if host.IPAddress == "" {
		host.IPAddress = srcIP
	}

	for _, option := range dhcp.Options {
		switch option.Type {
		case layers.DHCPOptHostname:
			host.Hostname = strings.TrimSpace(string(option.Data))
		case layers.DHCPOptClassID:
			host.Vendor = strings.TrimSpace(string(option.Data))
		}
	}

	if host.IPAddress == "" {
		return nil
	}
	return &host
}

func parseMDNS(packet gopacket.Packet) []netscan.DiscoveredHost {
	layer := packet.Layer(layers.LayerTypeDNS)
	if layer == nil {
		return nil
	}

	dns, ok := layer.(*layers.DNS)
	if !ok {
		return nil
	}
	return hostsFromMDNS(dns, sourceIP(packet))
}

func hostsFromMDNS(dns *layers.DNS, srcIP string) []netscan.DiscoveredHost {
	var hosts []netscan.DiscoveredHost
	for _, answer := range append(dns.Answers, dns.Additionals...) {
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			ip := answer.IP.String()
			if ip == "" {
				continue
			}
			hosts = append(hosts, netscan.DiscoveredHost{
				IPAddress: ip,
				Hostname:  trimDNSName(answer.Name),
				Status:    "up",
			})
		}
	}

	if len(hosts) == 0 {
		name := ""
		for _, answer := range dns.Answers {
			name = trimDNSName(answer.Name)
			if name != "" {
				break
			}
		}
		if name == "" && len(dns.Questions) > 0 {
			name = trimDNSName(dns.Questions[0].Name)
		}
		if !strings.HasPrefix(name, "_") {
			if ip := srcIP; ip != "" {
				hosts = append(hosts, netscan.DiscoveredHost{
					IPAddress: ip,
					Hostname:  name,
					Status:    "up",
				})
			}
		}
	}

	return dedupeHosts(hosts)
}

func parseSSDP(packet gopacket.Packet) []netscan.DiscoveredHost {
	app := packet.ApplicationLayer()
	if app == nil {
		return nil
	}

	payload := bytes.TrimSpace(app.Payload())
	if len(payload) == 0 {
		return nil
	}
	host := hostFromSSDPPayload(payload, sourceIP(packet))
	if host == nil {
		return nil
	}
	return []netscan.DiscoveredHost{*host}
}

func hostFromSSDPPayload(payload []byte, srcIP string) *netscan.DiscoveredHost {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		resp, respErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
		if respErr != nil {
			return nil
		}
		req = &http.Request{Header: resp.Header}
	}

	host := netscan.DiscoveredHost{
		IPAddress: srcIP,
		Status:    "up",
	}

	if server := strings.TrimSpace(req.Header.Get("SERVER")); server != "" {
		host.Vendor = server
	}
	if location := strings.TrimSpace(req.Header.Get("LOCATION")); location != "" {
		if parsedHost := hostFromURL(location); parsedHost != "" && net.ParseIP(parsedHost) == nil {
			host.Hostname = parsedHost
		}
	}
	if host.Hostname == "" {
		if usn := strings.TrimSpace(req.Header.Get("USN")); usn != "" && !strings.Contains(usn, "uuid:") {
			host.Hostname = usn
		}
	}

	if host.IPAddress == "" {
		return nil
	}
	return &host
}

func sourceIP(packet gopacket.Packet) string {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		return layer.(*layers.IPv4).SrcIP.String()
	}
	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		return layer.(*layers.IPv6).SrcIP.String()
	}
	return ""
}

func normalizeMAC(hw net.HardwareAddr) string {
	if len(hw) == 0 {
		return ""
	}
	return strings.ToUpper(hw.String())
}

func firstNonEmptyIP(values ...net.IP) string {
	for _, value := range values {
		if value == nil {
			continue
		}
		if !value.IsUnspecified() {
			return value.String()
		}
	}
	return ""
}

func trimDNSName(name []byte) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(string(name)), ".")
	if trimmed == "" || strings.HasPrefix(trimmed, "_") {
		return ""
	}
	return trimmed
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func dedupeHosts(hosts []netscan.DiscoveredHost) []netscan.DiscoveredHost {
	seen := make(map[string]netscan.DiscoveredHost)
	for _, host := range hosts {
		key := host.MACAddress
		if key == "" {
			key = host.IPAddress
		}
		if key == "" {
			continue
		}
		existing := seen[key]
		if existing.IPAddress == "" {
			seen[key] = host
			continue
		}
		if existing.Hostname == "" {
			existing.Hostname = host.Hostname
		}
		if existing.Vendor == "" {
			existing.Vendor = host.Vendor
		}
		if existing.IPAddress == "" {
			existing.IPAddress = host.IPAddress
		}
		seen[key] = existing
	}

	result := make([]netscan.DiscoveredHost, 0, len(seen))
	for _, host := range seen {
		result = append(result, host)
	}
	return result
}
