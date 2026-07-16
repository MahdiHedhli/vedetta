package store

import (
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

// corpusObservedSignals projects a discovery observation into the corpus shape vocabulary so
// the local matcher can compare it against curated device-class shapes. Hostname templates are
// intentionally not populated here — matching a concrete hostname to a template is pattern
// work, out of scope for this cut; the other signal families carry recognition.
func corpusObservedSignals(host discovery.DiscoveredHost) corpusmatch.ObservedSignals {
	obs := corpusmatch.ObservedSignals{
		MDNSServices: host.Services,
		TCPPorts:     portsToUint16(host.OpenPorts),
	}
	if host.MACAddress != "" {
		obs.OUIPrefixes = []string{host.MACAddress} // the matcher normalizes to a 24-bit prefix
	}
	if host.Model != "" {
		obs.MDNSModels = append(obs.MDNSModels, host.Model)
	}
	for _, ev := range host.IdentityEvidence {
		switch ev.Type {
		case "mdns_service":
			obs.MDNSServices = append(obs.MDNSServices, ev.Value)
		case "mdns_txt_model":
			obs.MDNSModels = append(obs.MDNSModels, ev.Value)
		case "mdns_txt_vendor":
			obs.MDNSVendors = append(obs.MDNSVendors, ev.Value)
		case "ssdp_device_type":
			obs.SSDPDeviceTypes = append(obs.SSDPDeviceTypes, ev.Value)
		case "ssdp_server_token":
			obs.SSDPServerTokens = append(obs.SSDPServerTokens, ev.Value)
		case "dhcp_vendor_class":
			obs.DHCPVendorClasses = append(obs.DHCPVendorClasses, ev.Value)
		case "dhcp_option_55":
			obs.DHCPOption55 = parseOption55(ev.Value)
		}
	}
	return obs
}

// corpusDerivedSignals runs the active corpus matcher over an observation and returns the
// descriptive signal upserts for a class match. Confidence is capped by both SourceCorpus
// (below a device's own mDNS TXT and user_corrected) and the curated variant's confidence, so
// it cannot inflate a weak corpus claim. Returns nil when no corpus is loaded or nothing matches.
func corpusDerivedSignals(host discovery.DiscoveredHost) []signalUpsert {
	res, ok := corpusmatch.Active().Match(corpusObservedSignals(host))
	if !ok {
		return nil
	}
	// Source trust is a ceiling, not a replacement for the curator's variant
	// confidence. A low-confidence corpus record must not become a 0.85 signal.
	conf := min(ConfidenceForSource(SourceCorpus), float64(res.ConfidenceBP)/10000)
	if conf <= 0 {
		return nil
	}
	var out []signalUpsert
	add := func(field, value string) {
		if value != "" {
			out = append(out, signalUpsert{field: field, value: value, source: SourceCorpus, confidence: conf})
		}
	}
	add("vendor", res.Manufacturer)
	add("model", res.Model)
	add("device_type", res.DeviceType)
	add("os_family", res.OSFamily)
	return out
}

func portsToUint16(ports []int) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			out = append(out, uint16(p))
		}
	}
	return out
}

// parseOption55 extracts the DHCP option-55 parameter-request codes from an evidence value,
// preserving order (the sequence is the fingerprint). Any non-digit separates codes.
func parseOption55(v string) []uint16 {
	var out []uint16
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' }) {
		if n, err := strconv.Atoi(tok); err == nil && n >= 1 && n <= 254 {
			out = append(out, uint16(n))
		}
	}
	return out
}
