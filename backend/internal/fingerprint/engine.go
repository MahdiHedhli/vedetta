package fingerprint

import (
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// FingerprintResult contains all enriched device information.
type FingerprintResult struct {
	DeviceType            string  `json:"device_type"`
	OSFamily              string  `json:"os_family"`
	OSVersion             string  `json:"os_version"`
	Model                 string  `json:"model"`
	Vendor                string  `json:"vendor"`
	FingerprintConfidence float64 `json:"fingerprint_confidence"`
	DiscoveryMethod       string  `json:"discovery_method"`
	// EOLRisk / EOLModel kept for backward compatibility.
	EOLRisk  bool   `json:"eol_risk,omitempty"`
	EOLModel string `json:"eol_model,omitempty"`

	// Generalized risk fields (migration 016).
	// Categories: "known_exploited", "eol_eos", "high_risk_iot".
	RiskCategory string   `json:"risk_category,omitempty"`
	RiskModel    string   `json:"risk_model,omitempty"`
	RiskReasons  []string `json:"risk_reasons,omitempty"`
}

// Engine orchestrates multi-signal device fingerprinting.
type Engine struct {
	// Can be extended for additional enrichment sources
}

// NewEngine creates a new fingerprint engine.
func NewEngine() *Engine {
	return &Engine{}
}

// FingerprintSignals is the widened entry point (spec 004, FR-10 / T3.6). In
// addition to hostname/vendor/MAC it feeds correlated passive signals — the
// advertised service list, a TXT/SSDP-derived model string, and a friendly name
// — into risk detection so device typing and EOL/high-risk classification key
// off the best available evidence. It delegates the base OUI+hostname fusion to
// Fingerprint, then augments risk detection with the extra signals.
//
// The risk-category "apply even at lower confidence" safety behavior is
// preserved: a risk match found via the widened signals is applied to the
// device even when the overall fingerprint confidence did not increase.
func (e *Engine) FingerprintSignals(device *models.Device, services []string, model, friendlyName string) *FingerprintResult {
	result := e.Fingerprint(device)

	// Combine the extra passive signals into one searchable string for risk
	// detection. Services (e.g. "_googlecast._tcp"), the TXT/SSDP model, and the
	// friendly name frequently carry the exact model/vendor that OUI/hostname miss.
	extra := strings.Join(services, " ")
	if model != "" {
		extra += " " + model
	}
	if friendlyName != "" {
		extra += " " + friendlyName
	}
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return result
	}

	// Run risk detection again with the widened evidence. Feed the extra signals
	// through the hostname + extraInfo slots so both vendor-hint and model-pattern
	// matching can fire on them.
	risk := DetectEOLFromSignals(device.Hostname+" "+friendlyName, result.Vendor, extra, result.DeviceType, firstNonEmptyFP(model, result.Model))
	if risk.Category == "" {
		return result
	}

	// Apply the risk fields even when confidence did not rise (safety-relevant).
	if risk.IsEOL && !result.EOLRisk {
		result.EOLRisk = true
		result.EOLModel = risk.Model
		device.EOLRisk = true
		device.EOLModel = risk.Model
	}
	// Adopt the widened risk category when the base classification is empty OR the
	// widened signals produced a more specific/severe category. A specific
	// known_exploited model match from a TXT/friendly-name signal must not be
	// masked by a broad eol_eos vendor guess from the base hostname/OUI pass.
	if result.RiskCategory == "" || riskCategoryRank(risk.Category) > riskCategoryRank(result.RiskCategory) {
		result.RiskCategory = risk.Category
		result.RiskModel = risk.Model
		result.RiskReasons = risk.Reasons
		device.RiskCategory = risk.Category
		device.RiskModel = risk.Model
		device.RiskReasons = risk.Reasons
	}
	if risk.Model != "" && result.Model == "" {
		result.Model = risk.Model
	}
	if risk.Confidence > result.FingerprintConfidence {
		result.FingerprintConfidence = risk.Confidence
	}
	return result
}

// riskCategoryRank orders risk categories by severity/specificity so a more
// specific widened-signal match can supersede a broad base match.
// known_exploited (named in an active campaign) > high_risk_iot > eol_eos.
func riskCategoryRank(category string) int {
	switch category {
	case "known_exploited":
		return 3
	case "high_risk_iot":
		return 2
	case "eol_eos":
		return 1
	default:
		return 0
	}
}

// firstNonEmptyFP returns the first non-empty string (local helper to avoid a
// cross-package dependency).
func firstNonEmptyFP(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Fingerprint analyzes a device and returns enriched fingerprint data.
// Multi-signal fusion strategy:
// 1. OUI lookup on MAC → manufacturer + possible device_type (confidence 0.2)
// 2. Hostname pattern match → device_type + os_family (confidence 0.5-0.8)
// 3. Combine signals: higher confidence wins for each field, confidences accumulate
// Returns the best estimate with overall confidence (0.0-1.0)
func (e *Engine) Fingerprint(device *models.Device) *FingerprintResult {
	result := &FingerprintResult{
		DiscoveryMethod: "nmap_active", // default; could be expanded based on device source
	}

	// Signal 1: OUI lookup
	ouiResult := e.Lookup(device.MACAddress)

	// Signal 2: Hostname pattern match
	hostnameResult := e.Match(device.Hostname)

	// Merge signals with confidence-based priority
	// OUI provides vendor + weak device type
	if ouiResult != nil {
		if result.Vendor == "" {
			result.Vendor = ouiResult.Vendor
		}
		if result.DeviceType == "" && ouiResult.DeviceType != "" {
			result.DeviceType = ouiResult.DeviceType
		}
		result.FingerprintConfidence = ouiResult.Confidence
	}

	// Hostname provides stronger signals (confidence 0.5-0.8)
	// Higher confidence values override lower confidence values
	if hostnameResult != nil {
		// Device type: prefer hostname if confidence is higher
		if hostnameResult.Confidence > result.FingerprintConfidence {
			result.DeviceType = hostnameResult.DeviceType
			result.FingerprintConfidence = hostnameResult.Confidence
		} else if hostnameResult.Confidence == result.FingerprintConfidence && result.DeviceType == "" {
			result.DeviceType = hostnameResult.DeviceType
		}

		// OS and vendor: take from hostname if not already set
		if result.OSFamily == "" && hostnameResult.OSFamily != "" {
			result.OSFamily = hostnameResult.OSFamily
		}
		if result.Vendor == "" && hostnameResult.Vendor != "" {
			result.Vendor = hostnameResult.Vendor
		}
		if result.Model == "" && hostnameResult.Model != "" {
			result.Model = hostnameResult.Model
		}

		// Combine confidence: if both signals agree on device type, confidence increases
		if ouiResult != nil && hostnameResult.DeviceType == result.DeviceType {
			// Both signals agree; boost confidence
			combined := ouiResult.Confidence + hostnameResult.Confidence
			if combined > 1.0 {
				combined = 1.0
			}
			result.FingerprintConfidence = combined
		} else if hostnameResult.Confidence >= result.FingerprintConfidence {
			result.FingerprintConfidence = hostnameResult.Confidence
		}
	}

	// Fallback: use provided vendor if we don't have one
	if result.Vendor == "" && device.Vendor != "" {
		result.Vendor = device.Vendor
		// Vendor from nmap scan gets low confidence
		if result.FingerprintConfidence < 0.1 {
			result.FingerprintConfidence = 0.1
		}
	}

	// Risk classification using the generalized categories (migration 016).
	// The signature database assigns the category directly:
	//   "known_exploited" — IC3 FLASH 2026-03-12 AVrecon/SocksEscort campaign models (also EOL)
	//   "eol_eos"         — end-of-life / likely-EOL devices with no active-campaign evidence
	//   "high_risk_iot"   — weak-default camera/IoT vendor lines
	// The legacy EOLRisk/EOLModel fields are only set when the match is actually EOL
	// (risk.IsEOL), so known_exploited IC3 models keep eol_risk=true but high_risk_iot
	// vendor matches do not.
	risk := DetectEOLFromSignals(device.Hostname, result.Vendor, device.Vendor, result.DeviceType, result.Model)
	if risk.Category != "" {
		if risk.IsEOL {
			result.EOLRisk = true
			result.EOLModel = risk.Model
		}
		if risk.Model != "" && result.Model == "" {
			result.Model = risk.Model
		}
		if risk.Confidence > result.FingerprintConfidence {
			result.FingerprintConfidence = risk.Confidence
		}
		if result.Vendor == "" && risk.Vendor != "" {
			result.Vendor = risk.Vendor
		}

		result.RiskCategory = risk.Category
		result.RiskModel = risk.Model
		result.RiskReasons = risk.Reasons
	}

	// Fallback high_risk_iot classification for cameras with no specific signature match.
	// The enumerated camera vendors (Foscam, Reolink, Dahua, Axis, GoAhead/Realtek, plus
	// Hikvision via the broad IC3 vendor list) are already covered by DetectEOLFromSignals
	// above; this catches the remaining white-label cameras built on generic IoT chipsets
	// (or with no identifiable vendor), which almost universally ship with weak default
	// credentials and rarely receive firmware updates.
	if result.RiskCategory == "" && result.DeviceType == "camera" {
		lowerVendor := strings.ToLower(result.Vendor)
		if result.Vendor == "" ||
			strings.Contains(lowerVendor, "espressif") ||
			strings.Contains(lowerVendor, "realtek") ||
			strings.Contains(lowerVendor, "mediatek") {
			result.RiskCategory = "high_risk_iot"
			result.RiskModel = result.Model
			result.RiskReasons = []string{"weak_defaults"}
		}
	}

	// Clamp confidence to [0, 1]
	if result.FingerprintConfidence > 1.0 {
		result.FingerprintConfidence = 1.0
	}
	if result.FingerprintConfidence < 0.0 {
		result.FingerprintConfidence = 0.0
	}

	// Apply result to device (only if confidence is higher than existing)
	if result.FingerprintConfidence > device.FingerprintConfidence {
		device.DeviceType = result.DeviceType
		device.OSFamily = result.OSFamily
		device.OSVersion = result.OSVersion
		device.Model = result.Model
		device.Vendor = result.Vendor
		device.FingerprintConfidence = result.FingerprintConfidence
		device.EOLRisk = result.EOLRisk
		device.EOLModel = result.EOLModel
		// New generalized risk fields
		device.RiskCategory = result.RiskCategory
		device.RiskModel = result.RiskModel
		device.RiskReasons = result.RiskReasons
	} else if (!device.EOLRisk && result.EOLRisk) || (device.RiskCategory == "" && result.RiskCategory != "") {
		// Still apply risk flags even on lower confidence (risk is safety-relevant, not just typing)
		if !device.EOLRisk && result.EOLRisk {
			device.EOLRisk = result.EOLRisk
			device.EOLModel = result.EOLModel
		}
		if device.RiskCategory == "" && result.RiskCategory != "" {
			device.RiskCategory = result.RiskCategory
			device.RiskModel = result.RiskModel
			device.RiskReasons = result.RiskReasons
		}
	}

	return result
}

// EnrichFromVendor tries to infer device type from vendor name alone.
// This is a lower-confidence fallback (0.15) when no other signals are available.
func EnrichFromVendor(vendor string) *FingerprintResult {
	vendor = strings.ToLower(vendor)

	result := &FingerprintResult{
		Vendor:          vendor,
		FingerprintConfidence: 0.15,
	}

	// Very basic inference
	switch {
	case strings.Contains(vendor, "apple"):
		result.Vendor = "Apple"
	case strings.Contains(vendor, "google") || strings.Contains(vendor, "nest"):
		result.Vendor = "Google"
		if strings.Contains(vendor, "nest") {
			result.DeviceType = "iot_generic"
		}
	case strings.Contains(vendor, "amazon"):
		result.Vendor = "Amazon"
		result.DeviceType = "smart_speaker"
	case strings.Contains(vendor, "samsung"):
		result.Vendor = "Samsung"
	case strings.Contains(vendor, "philips"):
		result.Vendor = "Philips"
		result.DeviceType = "smart_light"
	case strings.Contains(vendor, "tp-link") || strings.Contains(vendor, "tapo"):
		result.Vendor = "TP-Link"
		result.DeviceType = "iot_generic"
	case strings.Contains(vendor, "ubiquiti"):
		result.Vendor = "Ubiquiti"
		result.DeviceType = "access_point"
	}

	// Also run risk detection on the raw vendor string (catches broad affected manufacturers)
	// deviceType/model are empty here (vendor-only path). The signature match carries the
	// category and reasons; the legacy EOL flag is only set for genuinely EOL matches.
	if r := DetectEOLFromSignals("", vendor, "", "", ""); r.Category != "" {
		if r.IsEOL {
			result.EOLRisk = true
			result.EOLModel = r.Model
		}
		result.RiskCategory = r.Category
		result.RiskModel = r.Model
		result.RiskReasons = r.Reasons
	}

	return result
}
