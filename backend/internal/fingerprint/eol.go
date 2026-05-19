package fingerprint

import "strings"

// EOLMatch contains detection result for end-of-life / high-risk devices.
// Based on FBI IC3 FLASH 2026-03-12 (AVrecon malware / SocksEscort residential proxy botnet).
// https://www.ic3.gov/CSA/2026/260312.pdf
// These devices are frequently exploited via unpatched RCE/command injection because they are EOL.
type EOLMatch struct {
	IsEOL      bool    `json:"is_eol"`
	Model      string  `json:"model,omitempty"`
	Vendor     string  `json:"vendor,omitempty"`
	Confidence float64 `json:"confidence"`
}

// eolSignatures lists the "Top 20 Most Represented Device Models" from the advisory,
// plus the major affected vendors (Cisco, D-Link, Hikvision, MikroTik, Netgear, TP-Link, Zyxel).
// Matching is done case-insensitively on hostname, DHCP vendor class, SSDP SERVER, nmap vendor, etc.
var eolSignatures = []struct {
	VendorHints   []string
	ModelPatterns []string
	DisplayModel  string
	DisplayVendor string
}{
	// D-Link routers (heavily represented)
	{
		VendorHints:   []string{"d-link", "dlink"},
		ModelPatterns: []string{"dir-818lw", "dir-850l", "dir-860l"},
		DisplayModel:  "DIR-818LW / DIR-850L / DIR-860L Wireless Router",
		DisplayVendor: "D-Link",
	},
	// Netgear routers
	{
		VendorHints:   []string{"netgear"},
		ModelPatterns: []string{"dgn2200v4", "dgn2200", "r7000", "ac1900"},
		DisplayModel:  "DGN2200v4 / AC1900 R7000",
		DisplayVendor: "Netgear",
	},
	// TP-Link routers (very common in the infections)
	{
		VendorHints:   []string{"tp-link", "tp link", "tplink", "tapo"},
		ModelPatterns: []string{"archer c20", "tl-wr840n", "tl-wr849n", "wr841n", "tl-wr841n"},
		DisplayModel:  "Archer C20 / TL-WR840N / TL-WR849N / WR841N",
		DisplayVendor: "TP-Link",
	},
	// Zyxel routers/gateways (largest group in the top 20)
	{
		VendorHints:   []string{"zyxel"},
		ModelPatterns: []string{"emg6726", "pmg5617ga", "vmg1312", "vmg3925", "vmg4825", "vmg4927", "vmg8825"},
		DisplayModel:  "VMG1312 / VMG3925 / VMG4825 / VMG4927 / VMG8825 / EMG6726 / PMG5617GA series",
		DisplayVendor: "Zyxel",
	},
	// Hikvision IP cameras (also heavily abused in the campaign)
	{
		VendorHints:   []string{"hikvision"},
		ModelPatterns: []string{"ds-2cd2020", "ds-2cd2420", "ds2cd2020", "ds2cd2420"},
		DisplayModel:  "DS-2CD2020F-I / DS-2CD2420F-IW IP Camera",
		DisplayVendor: "Hikvision",
	},
}

// DetectEOLFromSignals inspects available device signals (hostname from mDNS/DHCP, vendor from OUI/nmap/DHCP class ID,
// SSDP SERVER header, etc.) for matches against the IC3 advisory EOL/vulnerable models.
// Returns IsEOL=true + specific model info when a high-confidence pattern hits.
// Lower-confidence broad vendor matches are also returned for affected manufacturers.
func DetectEOLFromSignals(hostname, vendor, extraInfo string) EOLMatch {
	combined := strings.ToLower(strings.TrimSpace(hostname + " " + vendor + " " + extraInfo))
	// Normalize common separators so "DIR-818LW" matches "dir 818lw" patterns
	normalized := strings.ReplaceAll(combined, "-", " ")
	normalized = strings.ReplaceAll(normalized, "_", " ")
	normalized = strings.ReplaceAll(normalized, ".", " ")

	for _, sig := range eolSignatures {
		vendorMatch := false
		for _, vh := range sig.VendorHints {
			if strings.Contains(combined, vh) || strings.Contains(normalized, vh) {
				vendorMatch = true
				break
			}
		}
		if !vendorMatch {
			continue
		}

		for _, mp := range sig.ModelPatterns {
			mpNorm := strings.ReplaceAll(mp, "-", " ")
			if strings.Contains(combined, mp) || strings.Contains(normalized, mpNorm) || strings.Contains(normalized, mp) {
				return EOLMatch{
					IsEOL:      true,
					Model:      sig.DisplayModel,
					Vendor:     sig.DisplayVendor,
					Confidence: 0.78,
				}
			}
		}
	}

	// Broad vendor-level risk flag for the manufacturers named in the advisory (~1,200 models total).
	// These get lower confidence because not every device from the vendor is EOL/vulnerable,
	// but they warrant extra scrutiny (common source of unpatched SOHO routers in the wild).
	broadAffected := map[string]string{
		"d-link":    "D-Link",
		"dlink":     "D-Link",
		"netgear":   "Netgear",
		"tp-link":   "TP-Link",
		"tplink":    "TP-Link",
		"zyxel":     "Zyxel",
		"hikvision": "Hikvision",
		"mikrotik":  "MikroTik",
		"cisco":     "Cisco",
	}
	for key, disp := range broadAffected {
		if strings.Contains(combined, key) {
			return EOLMatch{
				IsEOL:      true,
				Model:      "Potentially EOL / vulnerable model (see IC3 FLASH 2026-03-12 AVrecon advisory)",
				Vendor:     disp,
				Confidence: 0.32,
			}
		}
	}

	return EOLMatch{}
}
