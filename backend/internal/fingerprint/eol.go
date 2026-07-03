package fingerprint

import "strings"

// EOLMatch contains detection result for end-of-life / high-risk devices.
// Originally based on FBI IC3 FLASH 2026-03-12 (AVrecon malware / SocksEscort residential proxy botnet),
// https://www.ic3.gov/CSA/2026/260312.pdf, since expanded with generic high-risk IoT camera lines.
//
// Category carries the generalized risk category (migration 016):
//   - "known_exploited": models named in an active-campaign advisory (currently the IC3 AVrecon list)
//   - "eol_eos":         end-of-life / end-of-support, no active-campaign evidence
//   - "high_risk_iot":   vendor lines with weak defaults / rarely patched firmware
//
// A non-empty Category means a signature matched. IsEOL is true only when the matched
// signature represents devices that are actually end-of-life (kept for the legacy
// eol_risk / eol_model columns); known_exploited IC3 models are also EOL.
type EOLMatch struct {
	IsEOL      bool     `json:"is_eol"`
	Model      string   `json:"model,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	Confidence float64  `json:"confidence"`
	Category   string   `json:"category,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
}

// eolSignatures lists the "Top 20 Most Represented Device Models" from the advisory,
// plus the major affected vendors (Cisco, D-Link, Hikvision, MikroTik, Netgear, TP-Link, Zyxel).
// Matching is done case-insensitively on hostname, DHCP vendor class, SSDP SERVER, nmap vendor, etc.
//
// Expansion note (2026-05 onward):
// The initial implementation is deliberately narrow and high-confidence, focused on one well-documented
// residential proxy campaign (FBI IC3 FLASH 2026-03-12). Future increments will add other high-confidence
// vulnerable/EOL device classes (common Mirai targets, other RCE-heavy camera/router lines with public
// exploits, weak default-credential IoT) while preserving precision. Richer passive signals (mDNS service
// types/TXT, full DHCP option fingerprints, SSDP device descriptions) from the sensor will be leveraged
// once the passive discovery pipeline exposes more structured metadata. See research/08-device-fingerprint-database.md.
var eolSignatures = []struct {
	VendorHints   []string
	ModelPatterns []string
	DisplayModel  string
	DisplayVendor string
	Category      string   // "known_exploited" | "eol_eos" | "high_risk_iot" (migration 016)
	Reasons       []string // machine-readable risk reasons stored in devices.risk_reasons
	EOL           bool     // true when the matched models are actually end-of-life (drives legacy eol_risk flag)
}{
	// --- FBI IC3 FLASH 2026-03-12 (AVrecon / SocksEscort) "Top 20 Most Represented Device Models" ---
	// These specific models are documented as actively exploited in the campaign, and are all EOL.
	// Category: known_exploited (with EOL=true so the legacy eol_risk flag stays set).

	// D-Link routers (heavily represented)
	{
		VendorHints:   []string{"d-link", "dlink"},
		ModelPatterns: []string{"dir-818lw", "dir-850l", "dir-860l"},
		DisplayModel:  "DIR-818LW / DIR-850L / DIR-860L Wireless Router",
		DisplayVendor: "D-Link",
		Category:      "known_exploited",
		Reasons:       []string{"ic3_avrecon", "eol"},
		EOL:           true,
	},
	// Netgear routers
	{
		VendorHints:   []string{"netgear"},
		ModelPatterns: []string{"dgn2200v4", "dgn2200", "r7000", "ac1900"},
		DisplayModel:  "DGN2200v4 / AC1900 R7000",
		DisplayVendor: "Netgear",
		Category:      "known_exploited",
		Reasons:       []string{"ic3_avrecon", "eol"},
		EOL:           true,
	},
	// TP-Link routers (very common in the infections)
	{
		VendorHints:   []string{"tp-link", "tp link", "tplink", "tapo"},
		ModelPatterns: []string{"archer c20", "tl-wr840n", "tl-wr849n", "wr841n", "tl-wr841n"},
		DisplayModel:  "Archer C20 / TL-WR840N / TL-WR849N / WR841N",
		DisplayVendor: "TP-Link",
		Category:      "known_exploited",
		Reasons:       []string{"ic3_avrecon", "eol"},
		EOL:           true,
	},
	// Zyxel routers/gateways (largest group in the top 20)
	{
		VendorHints:   []string{"zyxel"},
		ModelPatterns: []string{"emg6726", "pmg5617ga", "vmg1312", "vmg3925", "vmg4825", "vmg4927", "vmg8825"},
		DisplayModel:  "VMG1312 / VMG3925 / VMG4825 / VMG4927 / VMG8825 / EMG6726 / PMG5617GA series",
		DisplayVendor: "Zyxel",
		Category:      "known_exploited",
		Reasons:       []string{"ic3_avrecon", "eol"},
		EOL:           true,
	},
	// Hikvision IP cameras (also heavily abused in the campaign)
	{
		VendorHints:   []string{"hikvision"},
		ModelPatterns: []string{"ds-2cd2020", "ds-2cd2420", "ds2cd2020", "ds2cd2420"},
		DisplayModel:  "DS-2CD2020F-I / DS-2CD2420F-IW IP Camera",
		DisplayVendor: "Hikvision",
		Category:      "known_exploited",
		Reasons:       []string{"ic3_avrecon", "eol"},
		EOL:           true,
	},

	// --- Post-IC3 expansion: generic weak-default camera / IoT vendor lines ---
	// Common in Mirai-family and similar botnets due to weak default credentials,
	// public RCEs, and rarely-updated firmware. There is no specific active-campaign
	// advisory tying these patterns to a named campaign, and the patterns also match
	// current (non-EOL) models, so: Category=high_risk_iot, EOL=false (the legacy
	// eol_risk flag must not fire for devices that may still receive patches).
	{
		VendorHints:   []string{"foscam"},
		ModelPatterns: []string{"foscam", "fi89", "fi98", "c1", "c2"},
		DisplayModel:  "Foscam IP Camera (line with known RCE / weak auth models)",
		DisplayVendor: "Foscam",
		Category:      "high_risk_iot",
		Reasons:       []string{"weak_defaults"},
		EOL:           false,
	},
	{
		VendorHints:   []string{"reolink"},
		ModelPatterns: []string{"reolink", "rlc", "rlk"},
		DisplayModel:  "Reolink IP Camera / NVR (line with vulnerable firmware history)",
		DisplayVendor: "Reolink",
		Category:      "high_risk_iot",
		Reasons:       []string{"weak_defaults"},
		EOL:           false,
	},
	{
		VendorHints:   []string{"dahua"},
		ModelPatterns: []string{"dahua", "ipc", "sd", "nvr"},
		DisplayModel:  "Dahua IP Camera / NVR (line with vulnerable firmware history)",
		DisplayVendor: "Dahua",
		Category:      "high_risk_iot",
		Reasons:       []string{"weak_defaults"},
		EOL:           false,
	},
	{
		VendorHints:   []string{"axis"},
		ModelPatterns: []string{"axis", "m10", "p13", "q16"},
		DisplayModel:  "Axis Communications camera (older vulnerable models)",
		DisplayVendor: "Axis",
		Category:      "high_risk_iot",
		Reasons:       []string{"weak_defaults"},
		EOL:           false,
	},
	// Common vulnerable IoT camera lines (often "GoAhead" or cheap white-label firmware with public RCEs/default creds).
	{
		VendorHints:   []string{"goahead", "realtek"},
		ModelPatterns: []string{"ipcam", "ipc", "camera", "dvr"},
		DisplayModel:  "GoAhead/Realtek-based IP Camera (common RCE / default credential vulnerabilities)",
		DisplayVendor: "Various (GoAhead/Realtek)",
		Category:      "high_risk_iot",
		Reasons:       []string{"weak_defaults"},
		EOL:           false,
	},
}

// DetectEOLFromSignals inspects available device signals (hostname from mDNS/DHCP, vendor from OUI/nmap/DHCP class ID,
// SSDP SERVER header, etc.) for matches against the IC3 advisory EOL/vulnerable models.
// Also considers richer fingerprint data (deviceType, model) produced by the engine from combined OUI + hostname + nmap signals.
// Returns IsEOL=true + specific model info when a high-confidence pattern hits.
// Lower-confidence broad vendor matches are also returned for affected manufacturers.
func DetectEOLFromSignals(hostname, vendor, extraInfo, deviceType, model string) EOLMatch {
	combined := strings.ToLower(strings.TrimSpace(hostname + " " + vendor + " " + extraInfo + " " + deviceType + " " + model))
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
					IsEOL:      sig.EOL,
					Model:      sig.DisplayModel,
					Vendor:     sig.DisplayVendor,
					Confidence: 0.78,
					Category:   sig.Category,
					Reasons:    sig.Reasons,
				}
			}
		}
	}

	// Broad vendor-level risk flag for the manufacturers named in the advisory (~1,200 models total).
	// These get lower confidence because not every device from the vendor is EOL/vulnerable,
	// but they warrant extra scrutiny (common source of unpatched SOHO routers in the wild).
	// Category is eol_eos (possibly end-of-life), NOT known_exploited: a vendor-only match is
	// not evidence the specific device is one of the actively exploited campaign models.
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
				Model:      "Potentially EOL / vulnerable model (vendor has many EOL models in the wild)",
				Vendor:     disp,
				Confidence: 0.32,
				Category:   "eol_eos",
				Reasons:    []string{"possible_eol"},
			}
		}
	}

	return EOLMatch{}
}
