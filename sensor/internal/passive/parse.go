package passive

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode"

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
		IPAddress:       net.IP(arp.SourceProtAddress).String(),
		MACAddress:      normalizeMAC(arp.SourceHwAddress),
		Status:          "up",
		DiscoverySource: "passive_arp",
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
		IPAddress:       firstNonEmptyIP(dhcp.YourClientIP, dhcp.ClientIP),
		MACAddress:      normalizeMAC(dhcp.ClientHWAddr),
		Status:          "up",
		DiscoverySource: "passive_dhcp",
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
	// Copy Answers+Additionals into a fresh slice: append(dns.Answers, ...) can
	// mutate the decoded Answers' backing array when cap(dns.Answers) > len.
	records := make([]layers.DNSResourceRecord, 0, len(dns.Answers)+len(dns.Additionals))
	records = append(records, dns.Answers...)
	records = append(records, dns.Additionals...)

	var hosts []netscan.DiscoveredHost
	for _, answer := range records {
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			ip := answer.IP.String()
			if ip == "" {
				continue
			}
			h := netscan.DiscoveredHost{
				IPAddress:       ip,
				Hostname:        trimDNSName(answer.Name),
				Status:          "up",
				DiscoverySource: "passive_mdns",
			}
			hosts = append(hosts, h)
		}
	}

	// Also parse TXT records for model / service info (common in IoT, printers, etc. for actionability).
	// NOTE: attaching metadata to hosts[len(hosts)-1] is a heuristic — mDNS packets
	// can carry records for multiple hosts, and the TXT record's owner is not
	// necessarily the last A/AAAA host seen. Guarded against empty hosts below;
	// a proper fix would correlate TXT owner names with host records.
	for _, answer := range records {
		if answer.Type == layers.DNSTypeTXT && len(answer.TXT) > 0 && len(hosts) > 0 {
			last := &hosts[len(hosts)-1]
			for _, txt := range answer.TXT {
				// Each TXT element is one segment, usually a single key=value pair,
				// but some devices pack several pairs separated by whitespace/NULs.
				for _, pair := range splitTXTPairs(string(txt)) {
					key, value, ok := strings.Cut(pair, "=")
					if !ok {
						continue
					}
					key = strings.ToLower(strings.TrimSpace(key))
					value = strings.TrimSpace(value)
					if value == "" {
						continue
					}
					switch key {
					case "model", "modelname", "mn":
						if last.Model == "" {
							last.Model = value
						}
					case "manufacturer", "mf", "vendor":
						if last.Vendor == "" {
							last.Vendor = value
						}
					}
				}
			}
		}
		if answer.Type == layers.DNSTypePTR {
			svc := trimDNSName(answer.Name)
			if svc != "" && strings.HasPrefix(svc, "_") {
				// service type e.g. _http._tcp.local
				if len(hosts) > 0 {
					hosts[len(hosts)-1].Services = append(hosts[len(hosts)-1].Services, svc)
				}
			}
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
					IPAddress:       ip,
					Hostname:        name,
					Status:          "up",
					DiscoverySource: "passive_mdns",
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
		IPAddress:       srcIP,
		Status:          "up",
		DiscoverySource: "passive_ssdp",
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

// splitTXTPairs splits a TXT segment into candidate key=value tokens.
// Splits on whitespace and NUL separators so keys are anchored to token start
// (avoids "mn=" matching mid-string, e.g. inside another value).
func splitTXTPairs(segment string) []string {
	return strings.FieldsFunc(segment, func(r rune) bool {
		return r == 0 || unicode.IsSpace(r)
	})
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
