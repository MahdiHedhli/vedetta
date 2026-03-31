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
}

// Engine orchestrates multi-signal device fingerprinting.
type Engine struct {
	// Can be extended for additional enrichment sources
}

// NewEngine creates a new fingerprint engine.
func NewEngine() *Engine {
	return &Engine{}
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

	return result
}
