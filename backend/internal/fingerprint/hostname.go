package fingerprint

import (
	"regexp"
	"strings"
)

// HostnameResult contains device type, vendor, OS, and confidence from hostname pattern matching.
type HostnameResult struct {
	DeviceType string  `json:"device_type"`
	Vendor     string  `json:"vendor"`
	OSFamily   string  `json:"os_family"`
	Model      string  `json:"model"`
	Confidence float64 `json:"confidence"`
}

// hostnamePatterns defines regex patterns for device identification from hostname/mDNS names.
// Patterns are matched in order; first match wins.
var hostnamePatterns = []struct {
	Pattern    *regexp.Regexp
	DeviceType string
	Vendor     string
	OSFamily   string
	Model      string
	Confidence float64
}{
	// Apple devices
	{regexp.MustCompile(`(?i)^iPhone`), "phone", "Apple", "iOS", "", 0.7},
	{regexp.MustCompile(`(?i)^iPad`), "tablet", "Apple", "iPadOS", "", 0.7},
	{regexp.MustCompile(`(?i)^MacBook|^Mahdi.*MacBook`), "computer", "Apple", "macOS", "", 0.7},
	{regexp.MustCompile(`(?i)^iMac`), "computer", "Apple", "macOS", "", 0.7},
	{regexp.MustCompile(`(?i)^Mac.*`), "computer", "Apple", "macOS", "", 0.6},

	// Samsung devices
	{regexp.MustCompile(`(?i)^Galaxy`), "phone", "Samsung", "Android", "", 0.7},
	{regexp.MustCompile(`(?i)^SM-`), "phone", "Samsung", "Android", "", 0.6},

	// Google devices
	{regexp.MustCompile(`(?i)^Pixel`), "phone", "Google", "Android", "", 0.7},
	{regexp.MustCompile(`(?i)^Nest-`), "thermostat", "Google Nest", "", "", 0.6},
	{regexp.MustCompile(`(?i)^Google-Home`), "smart_speaker", "Google", "", "", 0.7},
	{regexp.MustCompile(`(?i)^Chromecast`), "media_player", "Google", "", "", 0.7},

	// Windows computers
	{regexp.MustCompile(`(?i)^DESKTOP-`), "computer", "Microsoft", "Windows", "", 0.7},
	{regexp.MustCompile(`(?i)^WIN-`), "computer", "Microsoft", "Windows", "", 0.6},
	{regexp.MustCompile(`(?i)^LAPTOP-`), "computer", "Microsoft", "Windows", "", 0.7},

	// Raspberry Pi
	{regexp.MustCompile(`(?i)^raspberrypi`), "computer", "Raspberry Pi Foundation", "Linux", "", 0.8},

	// Ring
	{regexp.MustCompile(`(?i)^Ring-`), "camera", "Ring", "", "", 0.7},

	// LIFX smart lighting
	{regexp.MustCompile(`(?i)^LIFX`), "smart_light", "LIFX", "", "", 0.7},

	// Amazon Alexa / Echo
	{regexp.MustCompile(`(?i)^Amazon-`), "smart_speaker", "Amazon", "", "", 0.6},
	{regexp.MustCompile(`(?i)^Echo-`), "smart_speaker", "Amazon", "", "", 0.7},
	{regexp.MustCompile(`(?i)^Fire`), "media_player", "Amazon", "", "", 0.6},

	// HP Printers
	{regexp.MustCompile(`(?i)^HP`), "printer", "HP", "", "", 0.6},
	{regexp.MustCompile(`(?i)^HPCOLOR`), "printer", "HP", "", "", 0.7},

	// Epson Printers
	{regexp.MustCompile(`(?i)^EPSON`), "printer", "Epson", "", "", 0.7},

	// Brother Printers
	{regexp.MustCompile(`(?i)^Brother`), "printer", "Brother", "", "", 0.7},
	{regexp.MustCompile(`(?i)^BRN`), "printer", "Brother", "", "", 0.6},

	// Xerox
	{regexp.MustCompile(`(?i)^Xerox`), "printer", "Xerox", "", "", 0.6},

	// Ubiquiti UniFi
	{regexp.MustCompile(`(?i)^UniFi`), "access_point", "Ubiquiti", "", "", 0.7},
	{regexp.MustCompile(`(?i)^UAP-`), "access_point", "Ubiquiti", "", "", 0.7},

	// PlayStation
	{regexp.MustCompile(`(?i)^PS5`), "game_console", "Sony", "", "PlayStation 5", 0.8},
	{regexp.MustCompile(`(?i)^PS4`), "game_console", "Sony", "", "PlayStation 4", 0.8},
	{regexp.MustCompile(`(?i)^PSVita`), "game_console", "Sony", "", "PS Vita", 0.7},

	// Xbox
	{regexp.MustCompile(`(?i)^Xbox`), "game_console", "Microsoft", "", "", 0.7},

	// Nintendo
	{regexp.MustCompile(`(?i)^Nintendo`), "game_console", "Nintendo", "", "", 0.6},
	{regexp.MustCompile(`(?i)^Switch`), "game_console", "Nintendo", "", "Nintendo Switch", 0.7},

	// LG WebOS TV
	{regexp.MustCompile(`(?i)^LGwebOS`), "smart_tv", "LG", "webOS", "", 0.7},
	{regexp.MustCompile(`(?i)^LG.*TV`), "smart_tv", "LG", "", "", 0.6},

	// Samsung TV
	{regexp.MustCompile(`(?i)^Samsung.*TV`), "smart_tv", "Samsung", "", "", 0.6},

	// Roku
	{regexp.MustCompile(`(?i)^Roku`), "smart_tv", "Roku", "", "", 0.7},

	// TP-Link
	{regexp.MustCompile(`(?i)^TP-Link`), "iot_generic", "TP-Link", "", "", 0.5},
	{regexp.MustCompile(`(?i)^Tapo`), "iot_generic", "TP-Link Tapo", "", "", 0.6},

	// Sonos
	{regexp.MustCompile(`(?i)^Sonos`), "smart_speaker", "Sonos", "", "", 0.7},

	// Bose
	{regexp.MustCompile(`(?i)^Bose`), "smart_speaker", "Bose", "", "", 0.6},

	// Denon
	{regexp.MustCompile(`(?i)^Denon`), "smart_speaker", "Denon", "", "", 0.5},

	// Yamaha
	{regexp.MustCompile(`(?i)^Yamaha`), "smart_speaker", "Yamaha", "", "", 0.5},

	// Logitech
	{regexp.MustCompile(`(?i)^Logitech`), "iot_generic", "Logitech", "", "", 0.5},

	// Meross
	{regexp.MustCompile(`(?i)^Meross`), "iot_generic", "Meross", "", "", 0.6},

	// August Smart Lock
	{regexp.MustCompile(`(?i)^August`), "iot_generic", "August", "", "", 0.6},

	// Yale Smart Lock
	{regexp.MustCompile(`(?i)^Yale`), "iot_generic", "Yale", "", "", 0.6},

	// Schlage Lock
	{regexp.MustCompile(`(?i)^Schlage`), "iot_generic", "Schlage", "", "", 0.6},

	// WiZ
	{regexp.MustCompile(`(?i)^WiZ`), "smart_light", "WiZ", "", "", 0.7},

	// Innr
	{regexp.MustCompile(`(?i)^Innr`), "smart_light", "Innr", "", "", 0.6},

	// Eve Systems
	{regexp.MustCompile(`(?i)^Eve`), "iot_generic", "Eve Systems", "", "", 0.6},

	// SmartThings
	{regexp.MustCompile(`(?i)^SmartThings`), "iot_generic", "SmartThings", "", "", 0.6},

	// Arlo camera (Netgear)
	{regexp.MustCompile(`(?i)^Arlo`), "camera", "Arlo (Netgear)", "", "", 0.7},

	// Blink camera (Amazon)
	{regexp.MustCompile(`(?i)^Blink`), "camera", "Blink (Amazon)", "", "", 0.7},

	// Wyze
	{regexp.MustCompile(`(?i)^Wyze`), "camera", "Wyze", "", "", 0.6},

	// Reolink
	{regexp.MustCompile(`(?i)^Reolink`), "camera", "Reolink", "", "", 0.6},

	// Foscam
	{regexp.MustCompile(`(?i)^Foscam`), "camera", "Foscam", "", "", 0.6},

	// Hikvision
	{regexp.MustCompile(`(?i)^Hikvision`), "camera", "Hikvision", "", "", 0.6},

	// Dahua
	{regexp.MustCompile(`(?i)^Dahua`), "camera", "Dahua", "", "", 0.6},

	// Axis
	{regexp.MustCompile(`(?i)^Axis`), "camera", "Axis Communications", "", "", 0.6},

	// D-Link Camera
	{regexp.MustCompile(`(?i)^D-Link.*Cam`), "camera", "D-Link", "", "", 0.6},

	// GoPro
	{regexp.MustCompile(`(?i)^GoPro`), "camera", "GoPro", "", "", 0.7},
}

// Match returns device info from hostname pattern matching.
// Returns nil if no pattern matches.
func (e *Engine) Match(hostname string) *HostnameResult {
	if hostname == "" {
		return nil
	}

	// Normalize: trim and lowercase for pattern matching
	hostname = strings.TrimSpace(hostname)

	for _, pattern := range hostnamePatterns {
		if pattern.Pattern.MatchString(hostname) {
			return &HostnameResult{
				DeviceType: pattern.DeviceType,
				Vendor:     pattern.Vendor,
				OSFamily:   pattern.OSFamily,
				Model:      pattern.Model,
				Confidence: pattern.Confidence,
			}
		}
	}

	return nil
}
