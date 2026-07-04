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

// Flood guards: an mDNS packet is untrusted network input. Bound every map and
// per-host accumulation so a hostile/oversized packet degrades gracefully rather
// than exhausting memory. Sizes are generous relative to legitimate mDNS.
const (
	maxMDNSRecords   = 128 // total A/AAAA/SRV/TXT/PTR records processed per packet
	maxMDNSTXTPairs  = 32  // key=value pairs parsed per TXT record set
	maxServicesHost  = 16  // service types attached to a single host
	maxMDNSInstances = 64  // distinct service instances tracked per packet
	maxMDNSHosts     = 64  // distinct A/AAAA owner names tracked per packet
)

// mdnsInstance is a service-instance node in the per-packet record graph
// (e.g. "Living Room TV._googlecast._tcp.local").
type mdnsInstance struct {
	target   string   // SRV target host owner (e.g. "chromecast-1.local"), trimmed of trailing dot
	model    string   // from TXT md=/mn=/model=
	vendor   string   // from TXT mf=/manufacturer=
	txtName  string   // from TXT fn=/n= (highest-priority friendly name)
	label    string   // service-instance label (fallback friendly name)
	services []string // service types this instance advertises (e.g. "_googlecast._tcp")
}

// friendlyName resolves the instance's display name: an explicit TXT fn=/n=
// wins over the derived service-instance label (FR-3 source ordering).
func (i *mdnsInstance) friendlyName() string {
	if i.txtName != "" {
		return i.txtName
	}
	return i.label
}

// hostsFromMDNS correlates the records in a single mDNS packet as a graph keyed
// by owner name, instead of the old "attach to the last A host" heuristic:
//
//	A/AAAA (host owner → IP)
//	SRV    (instance owner → target host owner + port)
//	TXT    (instance owner → key/values: model, vendor, friendly name)
//	PTR    (service type owner → instance) — using the RAW owner name, so the
//	        service type (e.g. "_googlecast._tcp") is preserved before the
//	        trailing "._<domain>" is stripped.
//
// Each service instance is resolved to its host THROUGH the graph (SRV target →
// A-record host) and model/vendor/services/friendly-name are attached to THAT
// host — never to hosts[len(hosts)-1].
func hostsFromMDNS(dns *layers.DNS, srcIP string) []netscan.DiscoveredHost {
	// Copy Answers+Additionals into a fresh slice: append(dns.Answers, ...) can
	// mutate the decoded Answers' backing array when cap(dns.Answers) > len.
	records := make([]layers.DNSResourceRecord, 0, len(dns.Answers)+len(dns.Additionals))
	records = append(records, dns.Answers...)
	records = append(records, dns.Additionals...)
	if len(records) > maxMDNSRecords {
		records = records[:maxMDNSRecords]
	}

	// host owner name (trimmed) → resolved DiscoveredHost. Insertion order is
	// preserved separately for deterministic output.
	hostByName := make(map[string]*netscan.DiscoveredHost)
	var hostOrder []string
	// instance owner name (trimmed) → graph node. instanceOrder preserves
	// insertion order so the no-A fallback below can pick a friendly name
	// deterministically (map iteration order is randomized).
	instances := make(map[string]*mdnsInstance)
	var instanceOrder []string

	getInstance := func(name string) *mdnsInstance {
		inst, ok := instances[name]
		if ok {
			return inst
		}
		if len(instances) >= maxMDNSInstances {
			return nil
		}
		inst = &mdnsInstance{}
		instances[name] = inst
		instanceOrder = append(instanceOrder, name)
		return inst
	}

	// Pass 1: A/AAAA → hosts; SRV → instance target; TXT → instance kv;
	// PTR → instance + service type (raw owner name).
	for _, answer := range records {
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			ip := answer.IP.String()
			if ip == "" || ip == "<nil>" {
				continue
			}
			name := trimDNSName(answer.Name)
			key := name
			if key == "" {
				key = ip // owner name unusable; key host by IP so SRV cannot resolve to it but it still surfaces
			}
			if _, exists := hostByName[key]; !exists {
				if len(hostByName) >= maxMDNSHosts {
					continue
				}
				hostByName[key] = &netscan.DiscoveredHost{
					IPAddress:       ip,
					Hostname:        name,
					Status:          "up",
					DiscoverySource: "passive_mdns",
				}
				hostOrder = append(hostOrder, key)
			}
		case layers.DNSTypeSRV:
			instName := trimDNSName(answer.Name)
			if instName == "" {
				continue
			}
			inst := getInstance(instName)
			if inst == nil {
				continue
			}
			if target := trimDNSName(answer.SRV.Name); target != "" {
				inst.target = target
			}
			if svc := serviceTypeFromInstance(answer.Name); svc != "" {
				addService(inst, svc)
			}
			if fn := friendlyFromInstance(answer.Name); fn != "" && inst.label == "" {
				inst.label = fn
			}
		case layers.DNSTypeTXT:
			instName := trimDNSName(answer.Name)
			if instName == "" {
				continue
			}
			inst := getInstance(instName)
			if inst == nil {
				continue
			}
			applyTXT(inst, answer.TXTs)
			if fn := friendlyFromInstance(answer.Name); fn != "" && inst.label == "" {
				inst.label = fn
			}
		case layers.DNSTypePTR:
			// Service type is the RAW owner name (e.g. "_googlecast._tcp.local")
			// BEFORE underscore-stripping. The PTR data is the instance name.
			svc := serviceTypeFromRawName(answer.Name)
			instName := trimDNSName(answer.PTR)
			if instName == "" {
				continue
			}
			inst := getInstance(instName)
			if inst == nil {
				continue
			}
			if svc != "" {
				addService(inst, svc)
			}
			if fn := friendlyFromInstance(answer.PTR); fn != "" && inst.label == "" {
				inst.label = fn
			}
		}
	}

	// Pass 2: resolve each instance to its host through the graph and attach
	// its metadata to that host. Iterate in insertion order so that when
	// multiple instances resolve to the same host the attached metadata is
	// deterministic (map iteration order is randomized).
	for _, name := range instanceOrder {
		inst := instances[name]
		host := resolveInstanceHost(inst, hostByName)
		if host == nil {
			continue
		}
		if host.Model == "" && inst.model != "" {
			host.Model = inst.model
		}
		if host.Vendor == "" && inst.vendor != "" {
			host.Vendor = inst.vendor
		}
		if fn := inst.friendlyName(); host.FriendlyName == "" && fn != "" {
			host.FriendlyName = fn
		}
		for _, svc := range inst.services {
			addHostService(host, svc)
		}
	}

	hosts := make([]netscan.DiscoveredHost, 0, len(hostOrder))
	for _, key := range hostOrder {
		hosts = append(hosts, *hostByName[key])
	}

	// Fallback: no A/AAAA records in the packet (e.g. a query, or a PTR-only
	// announcement). Surface the source IP with the best available name so the
	// observation is not lost.
	if len(hosts) == 0 {
		// Friendly name: iterate instances in insertion order (not map order,
		// which is randomized) so the same packet yields the same label
		// run-to-run.
		var friendly string
		for _, instName := range instanceOrder {
			if fn := instances[instName].friendlyName(); fn != "" {
				friendly = fn
				break
			}
		}
		// Hostname: take the first owner name that is a real host name, NOT a
		// service-instance name (e.g. "Inst._x._tcp.local") or a service-type
		// name (e.g. "_x._tcp.local"). An SRV/TXT/PTR owner is an instance
		// string, not a hostname, and must not become Hostname — it would feed
		// Core's identity resolver hostname rule with garbage. If no real host
		// name is present, leave Hostname empty and rely on friendly_name/IP.
		name := ""
		for _, answer := range dns.Answers {
			candidate := trimDNSName(answer.Name)
			if candidate == "" || looksLikeServiceName(answer.Name) {
				continue
			}
			name = candidate
			break
		}
		if name == "" && len(dns.Questions) > 0 {
			if q := trimDNSName(dns.Questions[0].Name); q != "" && !looksLikeServiceName(dns.Questions[0].Name) {
				name = q
			}
		}
		if ip := srcIP; ip != "" {
			hosts = append(hosts, netscan.DiscoveredHost{
				IPAddress:       ip,
				Hostname:        name,
				FriendlyName:    friendly,
				Status:          "up",
				DiscoverySource: "passive_mdns",
			})
		}
	}

	return dedupeHosts(hosts)
}

// resolveInstanceHost walks SRV target → A-record host. If the SRV target owner
// name matches a known host, that host wins. Otherwise the instance is
// unresolved (PTR/SRV with no A record in this packet) and returns nil — the
// metadata degrades to "not attached" rather than attaching to a wrong host.
func resolveInstanceHost(inst *mdnsInstance, hostByName map[string]*netscan.DiscoveredHost) *netscan.DiscoveredHost {
	if inst == nil || inst.target == "" {
		return nil
	}
	return hostByName[inst.target]
}

// applyTXT parses TXT key/value segments into model/vendor/friendly-name.
// Per RFC 6763 §6.3, each decoded TXT element (one entry in TXTs) is exactly one
// key=value pair whose value may contain spaces (e.g. "md=Chromecast Ultra"), so
// the value is NOT whitespace-split. NUL is treated as a hard separator only as
// a defense against malformed devices that pack multiple pairs into one element.
func applyTXT(inst *mdnsInstance, txts [][]byte) {
	pairsSeen := 0
	for _, txt := range txts {
		for _, pair := range splitTXTPairs(string(txt)) {
			if pairsSeen >= maxMDNSTXTPairs {
				return
			}
			pairsSeen++
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
			case "model", "modelname", "mn", "md":
				if inst.model == "" {
					inst.model = value
				}
			case "manufacturer", "mf", "vendor":
				if inst.vendor == "" {
					inst.vendor = value
				}
			case "fn", "n":
				if inst.txtName == "" {
					inst.txtName = value
				}
			}
		}
	}
}

func addService(inst *mdnsInstance, svc string) {
	if len(inst.services) >= maxServicesHost {
		return
	}
	for _, s := range inst.services {
		if s == svc {
			return
		}
	}
	inst.services = append(inst.services, svc)
}

func addHostService(host *netscan.DiscoveredHost, svc string) {
	if len(host.Services) >= maxServicesHost {
		return
	}
	for _, s := range host.Services {
		if s == svc {
			return
		}
	}
	host.Services = append(host.Services, svc)
}

// looksLikeServiceName reports whether an mDNS owner name is a service-type name
// (e.g. "_googlecast._tcp.local") or a service-instance name (e.g. "Living Room
// TV._googlecast._tcp.local"), as opposed to a plain host name (e.g.
// "chromecast-1.local"). Used by the no-A fallback to avoid promoting an
// instance/service string into a host Hostname, which would poison Core's
// identity resolver. It reuses the existing service classification helpers:
// serviceTypeFromRawName matches service-type owners, serviceTypeFromInstance
// matches service-instance owners.
func looksLikeServiceName(name []byte) bool {
	return serviceTypeFromRawName(name) != "" || serviceTypeFromInstance(name) != ""
}

// serviceTypeFromRawName extracts the "_service._proto" prefix from a raw mDNS
// owner name such as "_googlecast._tcp.local" → "_googlecast._tcp". Returns ""
// when the name is not an underscore-prefixed service type.
func serviceTypeFromRawName(name []byte) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(string(name)), ".")
	if !strings.HasPrefix(trimmed, "_") {
		return ""
	}
	return serviceTypeLabels(trimmed)
}

// serviceTypeFromInstance extracts the service type from a service-instance
// name such as "Living Room TV._googlecast._tcp.local" → "_googlecast._tcp".
func serviceTypeFromInstance(name []byte) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(string(name)), ".")
	idx := strings.Index(trimmed, "._")
	if idx < 0 {
		return ""
	}
	return serviceTypeLabels(trimmed[idx+1:])
}

// serviceTypeLabels reduces a service string to its first two underscore labels
// (e.g. "_googlecast._tcp.local" → "_googlecast._tcp"). Returns "" if it does
// not look like a service type.
func serviceTypeLabels(s string) string {
	labels := strings.Split(s, ".")
	if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return ""
	}
	return labels[0] + "." + labels[1]
}

// friendlyFromInstance extracts the human-readable instance label from a
// service-instance name: "Living Room TV._googlecast._tcp.local" → "Living Room
// TV". Returns "" for bare service types or host records.
func friendlyFromInstance(name []byte) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(string(name)), ".")
	if trimmed == "" || strings.HasPrefix(trimmed, "_") {
		return ""
	}
	idx := strings.Index(trimmed, "._")
	if idx <= 0 {
		return ""
	}
	label := strings.TrimSpace(trimmed[:idx])
	// DNS-SD escapes dots and spaces in instance labels as "\." / "\032".
	label = unescapeDNSSDLabel(label)
	return label
}

// unescapeDNSSDLabel decodes DNS-SD instance-label escaping (RFC 6763 §4.3):
// "\." → ".", "\\" → "\", "\DDD" → byte DDD (used for spaces as "\032").
func unescapeDNSSDLabel(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		if next >= '0' && next <= '9' && i+3 < len(s) &&
			s[i+2] >= '0' && s[i+2] <= '9' && s[i+3] >= '0' && s[i+3] <= '9' {
			val := int(next-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if val <= 255 {
				b.WriteByte(byte(val))
				i += 3
				continue
			}
		}
		b.WriteByte(next)
		i++
	}
	return b.String()
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

	// Friendly name (spec 004 FR-3): derive a human-readable label from SSDP
	// headers without any active HTTP fetch (passive-first — LOCATION XML is
	// explicitly out of scope). Prefer an explicit "FRIENDLYNAME.SMARTSPEAKER"
	// style vendor header or a readable USN device suffix.
	if fn := ssdpFriendlyName(req.Header); fn != "" {
		host.FriendlyName = fn
	}

	if host.IPAddress == "" {
		return nil
	}
	return &host
}

// ssdpFriendlyName extracts a human-readable name from SSDP NOTIFY/response
// headers without fetching the LOCATION description XML. Some devices expose a
// friendly name directly in a header (e.g. Sonos "FRIENDLYNAME.SMARTSPEAKER");
// otherwise a USN that carries a readable "::" device suffix (not a bare
// uuid/urn) is used.
func ssdpFriendlyName(h http.Header) string {
	for _, key := range []string{"Friendlyname", "Friendly-Name", "X-Friendly-Name"} {
		if v := strings.TrimSpace(h.Get(key)); v != "" {
			return v
		}
	}
	// Some vendors namespace it, e.g. "FRIENDLYNAME.SMARTSPEAKER".
	for name, values := range h {
		if strings.HasPrefix(strings.ToUpper(name), "FRIENDLYNAME") && len(values) > 0 {
			if v := strings.TrimSpace(values[0]); v != "" {
				return v
			}
		}
	}
	return ""
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

// splitTXTPairs splits a TXT segment into candidate key=value tokens. A properly
// decoded DNS-SD TXT element is a single key=value pair whose value may legally
// contain spaces (RFC 6763 §6.3), so this splits ONLY on NUL — a hard separator
// that never appears inside a legitimate pair — to defend against malformed
// devices that concatenate several pairs into one element. Whitespace inside a
// value (e.g. "md=Chromecast Ultra") is preserved.
func splitTXTPairs(segment string) []string {
	return strings.FieldsFunc(segment, func(r rune) bool {
		return r == 0
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
		if existing.Model == "" {
			existing.Model = host.Model
		}
		if existing.FriendlyName == "" {
			existing.FriendlyName = host.FriendlyName
		}
		for _, svc := range host.Services {
			addHostService(&existing, svc)
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
