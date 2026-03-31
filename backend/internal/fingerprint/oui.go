package fingerprint

import (
	"strings"
)

// OUIResult contains vendor and device type information from a MAC prefix lookup.
type OUIResult struct {
	Vendor     string  `json:"vendor"`
	DeviceType string  `json:"device_type"`
	Confidence float64 `json:"confidence"` // OUI match only = 0.2
}

// ouiDatabase maps MAC prefix (6 hex chars, case-insensitive) to vendor + device type.
// Curated top ~200 home/SMB manufacturers with device type hints.
var ouiDatabase = map[string]OUIResult{
	// Apple ecosystem
	"ac:bc:32": {Vendor: "Apple", DeviceType: ""},
	"00:03:93": {Vendor: "Apple", DeviceType: ""},
	"00:05:02": {Vendor: "Apple", DeviceType: ""},
	"00:0a:27": {Vendor: "Apple", DeviceType: ""},
	"00:0b:46": {Vendor: "Apple", DeviceType: ""},
	"00:14:51": {Vendor: "Apple", DeviceType: ""},
	"00:16:41": {Vendor: "Apple", DeviceType: ""},
	"00:17:f2": {Vendor: "Apple", DeviceType: ""},
	"00:19:e3": {Vendor: "Apple", DeviceType: ""},
	"00:1a:92": {Vendor: "Apple", DeviceType: ""},
	"00:1d:4f": {Vendor: "Apple", DeviceType: ""},
	"00:1e:52": {Vendor: "Apple", DeviceType: ""},
	"00:1e:c2": {Vendor: "Apple", DeviceType: ""},
	"00:1f:5b": {Vendor: "Apple", DeviceType: ""},
	"00:1f:f3": {Vendor: "Apple", DeviceType: ""},
	"00:21:e9": {Vendor: "Apple", DeviceType: ""},
	"00:23:12": {Vendor: "Apple", DeviceType: ""},
	"00:23:20": {Vendor: "Apple", DeviceType: ""},
	"00:24:36": {Vendor: "Apple", DeviceType: ""},
	"00:25:00": {Vendor: "Apple", DeviceType: ""},
	"00:25:86": {Vendor: "Apple", DeviceType: ""},
	"00:25:bc": {Vendor: "Apple", DeviceType: ""},
	"00:26:4a": {Vendor: "Apple", DeviceType: ""},
	"00:26:b0": {Vendor: "Apple", DeviceType: ""},
	"00:27:13": {Vendor: "Apple", DeviceType: ""},
	"00:2a:95": {Vendor: "Apple", DeviceType: ""},

	// Raspberry Pi Foundation
	"b8:27:eb": {Vendor: "Raspberry Pi Foundation", DeviceType: "computer"},
	"dc:a6:32": {Vendor: "Raspberry Pi Foundation", DeviceType: "computer"},

	// Google / Nest
	"d8:6c:63": {Vendor: "Google", DeviceType: ""},
	"34:68:95": {Vendor: "Google", DeviceType: ""},
	"18:b4:30": {Vendor: "Nest Labs", DeviceType: "thermostat"},
	"18:b4:31": {Vendor: "Nest Labs", DeviceType: ""},
	"34:80:0d": {Vendor: "Google Nest", DeviceType: ""},

	// Amazon ecosystem
	"74:c7:f0": {Vendor: "Amazon Technologies", DeviceType: "smart_speaker"},
	"00:1a:7d": {Vendor: "Kindle", DeviceType: "tablet"},
	"ac:63:be": {Vendor: "Amazon", DeviceType: ""},

	// Ring (Amazon subsidiary)
	"f0:b4:29": {Vendor: "Ring", DeviceType: "camera"},

	// Philips Lighting / Hue
	"00:17:88": {Vendor: "Philips Lighting", DeviceType: "smart_light"},

	// TP-Link
	"60:a4:4c": {Vendor: "TP-Link", DeviceType: "router"},
	"f4:f2:6d": {Vendor: "TP-Link", DeviceType: ""},
	"68:54:fd": {Vendor: "TP-Link", DeviceType: ""},
	"d8:0d:17": {Vendor: "TP-Link", DeviceType: ""},

	// Tapo (TP-Link IoT brand)
	"70:4f:57": {Vendor: "Tapo (TP-Link)", DeviceType: "iot_generic"},

	// Samsung
	"08:ed:b7": {Vendor: "Samsung", DeviceType: ""},
	"1c:bd:b9": {Vendor: "Samsung", DeviceType: ""},
	"38:2c:4a": {Vendor: "Samsung", DeviceType: ""},

	// LG
	"00:0e:6e": {Vendor: "LG Electronics", DeviceType: "smart_tv"},
	"18:6f:32": {Vendor: "LG Electronics", DeviceType: ""},
	"78:bd:bc": {Vendor: "LG Electronics", DeviceType: ""},

	// Sony
	"08:3e:8e": {Vendor: "Sony", DeviceType: ""},
	"1c:37:8f": {Vendor: "Sony", DeviceType: ""},

	// Ubiquiti Networks (UniFi)
	"80:2a:a8": {Vendor: "Ubiquiti Networks", DeviceType: "access_point"},
	"18:e8:29": {Vendor: "Ubiquiti Networks", DeviceType: "access_point"},

	// Netgear
	"78:d2:94": {Vendor: "Netgear", DeviceType: "router"},
	"bc:f5:ac": {Vendor: "Netgear", DeviceType: ""},
	"c0:c9:e3": {Vendor: "Netgear", DeviceType: ""},

	// LIFX
	"d0:73:d5": {Vendor: "LIFX", DeviceType: "smart_light"},

	// Ecobee
	"00:21:26": {Vendor: "Ecobee", DeviceType: "thermostat"},

	// Honeywell
	"00:12:4b": {Vendor: "Honeywell", DeviceType: "thermostat"},

	// Lenovo
	"00:1e:74": {Vendor: "Lenovo", DeviceType: "computer"},
	"28:5f:78": {Vendor: "Lenovo", DeviceType: ""},

	// HP
	"00:14:38": {Vendor: "HP", DeviceType: "printer"},
	"00:1d:09": {Vendor: "HP", DeviceType: ""},
	"08:5b:d6": {Vendor: "HP", DeviceType: ""},
	"cc:46:d6": {Vendor: "HP", DeviceType: "printer"},

	// Canon
	"00:1a:4a": {Vendor: "Canon", DeviceType: "printer"},
	"08:ee:8b": {Vendor: "Canon", DeviceType: ""},

	// Epson
	"00:0e:9f": {Vendor: "Epson", DeviceType: "printer"},
	"00:11:22": {Vendor: "Epson", DeviceType: ""},

	// Brother
	"00:0b:be": {Vendor: "Brother", DeviceType: "printer"},
	"a8:5e:60": {Vendor: "Brother", DeviceType: "printer"},

	// Xerox
	"00:00:37": {Vendor: "Xerox", DeviceType: "printer"},

	// Intel
	"00:1f:3c": {Vendor: "Intel", DeviceType: ""},
	"54:e1:ad": {Vendor: "Intel", DeviceType: ""},

	// Qualcomm/Atheros
	"00:26:86": {Vendor: "Qualcomm", DeviceType: ""},

	// Broadcom
	"00:10:18": {Vendor: "Broadcom", DeviceType: ""},

	// Realtek
	"00:e0:4c": {Vendor: "Realtek", DeviceType: ""},

	// Mediatek
	"00:0c:43": {Vendor: "Mediatek", DeviceType: ""},

	// Marvell
	"00:11:88": {Vendor: "Marvell", DeviceType: ""},

	// Nvidia
	"00:04:4b": {Vendor: "Nvidia", DeviceType: ""},

	// Roku
	"d4:a5:d8": {Vendor: "Roku", DeviceType: "media_player"},
	"fc:7a:80": {Vendor: "Roku", DeviceType: "media_player"},

	// Chromecast
	"54:a0:50": {Vendor: "Google Chromecast", DeviceType: "media_player"},

	// Apple TV
	"00:1d:4f": {Vendor: "Apple", DeviceType: "media_player"},

	// Xbox
	"00:04:4b": {Vendor: "Microsoft Xbox", DeviceType: "game_console"},

	// PlayStation
	"00:04:1f": {Vendor: "Sony PlayStation", DeviceType: "game_console"},

	// Nintendo
	"00:17:ab": {Vendor: "Nintendo", DeviceType: "game_console"},

	// Cisco / Meraki
	"00:18:0a": {Vendor: "Cisco", DeviceType: "router"},
	"00:1a:2b": {Vendor: "Cisco", DeviceType: ""},

	// Arista
	"00:05:73": {Vendor: "Arista", DeviceType: "switch"},

	// Juniper
	"00:10:db": {Vendor: "Juniper Networks", DeviceType: "router"},

	// Dell
	"00:0a:95": {Vendor: "Dell", DeviceType: "computer"},
	"00:14:22": {Vendor: "Dell", DeviceType: ""},
	"44:a8:42": {Vendor: "Dell", DeviceType: ""},

	// Hewlett Packard Enterprise
	"00:0e:4e": {Vendor: "HPE", DeviceType: ""},

	// Supermicro
	"00:30:48": {Vendor: "Supermicro", DeviceType: ""},

	// APC / Schneider Electric
	"00:c0:b7": {Vendor: "APC", DeviceType: ""},

	// Eaton
	"00:04:ac": {Vendor: "Eaton", DeviceType: ""},

	// Siemens
	"00:0e:8c": {Vendor: "Siemens", DeviceType: ""},

	// FLIR / Infrared
	"00:a8:e0": {Vendor: "FLIR", DeviceType: "camera"},

	// Hikvision
	"00:09:c5": {Vendor: "Hikvision", DeviceType: "camera"},

	// Dahua
	"00:0a:95": {Vendor: "Dahua", DeviceType: "camera"},

	// Axis Communications
	"00:40:8c": {Vendor: "Axis Communications", DeviceType: "camera"},

	// Ubiquiti UniFi Protect
	"80:2a:a8": {Vendor: "Ubiquiti", DeviceType: "camera"},

	// Reolink
	"6c:72:20": {Vendor: "Reolink", DeviceType: "camera"},

	// Wyoming Security (Wyze)
	"84:0d:8e": {Vendor: "Wyze", DeviceType: "camera"},

	// TP-Link Kasa Smart Plug
	"f4:f2:6d": {Vendor: "TP-Link Kasa", DeviceType: "iot_generic"},

	// iHome
	"00:1d:43": {Vendor: "iHome", DeviceType: "smart_speaker"},

	// Sonos
	"00:0e:58": {Vendor: "Sonos", DeviceType: "smart_speaker"},
	"5c:aa:51": {Vendor: "Sonos", DeviceType: "smart_speaker"},

	// Bose
	"00:02:5b": {Vendor: "Bose", DeviceType: "smart_speaker"},

	// Jbl / Harman Kardon
	"00:02:5b": {Vendor: "JBL", DeviceType: "smart_speaker"},

	// Bang & Olufsen
	"b8:ae:ed": {Vendor: "Bang & Olufsen", DeviceType: "smart_speaker"},

	// Denon / Marantz
	"00:05:cd": {Vendor: "Denon", DeviceType: "smart_speaker"},

	// Yamaha
	"00:04:74": {Vendor: "Yamaha", DeviceType: "smart_speaker"},

	// Logitech
	"00:04:0e": {Vendor: "Logitech", DeviceType: ""},
	"1c:1a:c0": {Vendor: "Logitech", DeviceType: ""},

	// SteelSeries
	"70:14:a3": {Vendor: "SteelSeries", DeviceType: ""},

	// Corsair
	"d0:17:c2": {Vendor: "Corsair", DeviceType: ""},

	// ASUS
	"00:0c:6e": {Vendor: "ASUS", DeviceType: "router"},
	"00:13:10": {Vendor: "ASUS", DeviceType: ""},
	"08:10:76": {Vendor: "ASUS", DeviceType: ""},

	// D-Link
	"00:18:f8": {Vendor: "D-Link", DeviceType: "router"},
	"c4:6e:1f": {Vendor: "D-Link", DeviceType: ""},

	// Buffalo
	"00:1f:3a": {Vendor: "Buffalo", DeviceType: "router"},

	// Belkin
	"00:1a:7d": {Vendor: "Belkin", DeviceType: "router"},
	"30:46:9a": {Vendor: "Belkin", DeviceType: ""},

	// Linksys (Cisco subsidiary)
	"00:1a:70": {Vendor: "Linksys", DeviceType: "router"},
	"ec:1f:72": {Vendor: "Linksys", DeviceType: ""},

	// Dlink
	"08:17:35": {Vendor: "D-Link", DeviceType: ""},

	// Ralink / Mediatek
	"00:0c:43": {Vendor: "Ralink", DeviceType: ""},

	// Broadcom wireless
	"00:10:18": {Vendor: "Broadcom", DeviceType: ""},

	// AVM / Fritzbox
	"00:04:0e": {Vendor: "AVM Fritzbox", DeviceType: "router"},

	// Synology
	"00:11:32": {Vendor: "Synology", DeviceType: ""},

	// QNAP
	"00:08:9b": {Vendor: "QNAP", DeviceType: ""},

	// Western Digital
	"00:13:10": {Vendor: "Western Digital", DeviceType: ""},

	// Seagate
	"00:14:38": {Vendor: "Seagate", DeviceType: ""},

	// Buffalo
	"00:1f:3a": {Vendor: "Buffalo", DeviceType: ""},

	// NAS/Storage (continued)
	"00:01:29": {Vendor: "Iomega", DeviceType: ""},
	"00:0e:8c": {Vendor: "Eaton", DeviceType: ""},

	// Wemo (Belkin smart home)
	"78:99:7b": {Vendor: "Wemo (Belkin)", DeviceType: "iot_generic"},

	// Inovelli
	"48:6e:10": {Vendor: "Inovelli", DeviceType: "smart_light"},

	// Lutron
	"00:06:97": {Vendor: "Lutron", DeviceType: "smart_light"},

	// Leviton
	"14:91:82": {Vendor: "Leviton", DeviceType: "iot_generic"},

	// GE Enbrighten
	"84:18:26": {Vendor: "GE Enbrighten", DeviceType: "smart_light"},

	// Innr
	"d0:73:d5": {Vendor: "Innr", DeviceType: "smart_light"},

	// nanoleaf
	"00:2e:d9": {Vendor: "Nanoleaf", DeviceType: "smart_light"},

	// WiZ
	"38:68:d7": {Vendor: "WiZ", DeviceType: "smart_light"},

	// Eve (Elgato/Eve Systems)
	"00:1d:25": {Vendor: "Eve Systems", DeviceType: "iot_generic"},

	// Meross
	"f0:93:49": {Vendor: "Meross", DeviceType: "iot_generic"},

	// SmartThings (Samsung)
	"90:e2:ba": {Vendor: "SmartThings", DeviceType: "iot_generic"},

	// August Home Lock
	"c0:ee:fb": {Vendor: "August", DeviceType: "iot_generic"},

	// Yale Smart Lock
	"00:07:7f": {Vendor: "Yale", DeviceType: "iot_generic"},

	// Schlage
	"00:0b:6b": {Vendor: "Schlage", DeviceType: "iot_generic"},

	// Kwikset
	"cc:33:f1": {Vendor: "Kwikset", DeviceType: "iot_generic"},

	// U-BLOX (GPS/GNSS)
	"00:17:f4": {Vendor: "u-blox", DeviceType: ""},

	// Garmin
	"00:1f:4b": {Vendor: "Garmin", DeviceType: ""},

	// Fitbit
	"00:1d:43": {Vendor: "Fitbit", DeviceType: ""},

	// Polar
	"00:22:d0": {Vendor: "Polar", DeviceType: ""},

	// Withings
	"00:24:e4": {Vendor: "Withings", DeviceType: ""},

	// Omron
	"00:1a:7d": {Vendor: "Omron", DeviceType: ""},

	// Philips Healthcare
	"00:14:6b": {Vendor: "Philips Healthcare", DeviceType: ""},

	// GoPro
	"00:1a:a0": {Vendor: "GoPro", DeviceType: "camera"},

	// Dropcam / Nest (now Google)
	"d4:6d:50": {Vendor: "Nest / Google", DeviceType: "camera"},

	// Arlo (Netgear subsidiary)
	"78:d2:94": {Vendor: "Arlo", DeviceType: "camera"},

	// Blink (Amazon subsidiary)
	"38:5d:e4": {Vendor: "Blink", DeviceType: "camera"},

	// Logitech Circle
	"44:b4:3e": {Vendor: "Logitech Circle", DeviceType: "camera"},

	// D-Link Camera
	"c0:3f:0e": {Vendor: "D-Link", DeviceType: "camera"},

	// Foscam
	"00:13:f7": {Vendor: "Foscam", DeviceType: "camera"},

	// Netgear Arlo Pro
	"a0:04:60": {Vendor: "Arlo Pro (Netgear)", DeviceType: "camera"},

	// Yoyo
	"94:10:3e": {Vendor: "Yoyo", DeviceType: "camera"},

	// EZVIZ
	"00:04:9f": {Vendor: "EZVIZ", DeviceType: "camera"},

	// Mobotix
	"00:08:94": {Vendor: "Mobotix", DeviceType: "camera"},

	// Hanwha Techwin (Samsung surveillance)
	"08:ed:b7": {Vendor: "Hanwha", DeviceType: "camera"},

	// Vivotek
	"00:10:04": {Vendor: "Vivotek", DeviceType: "camera"},

	// Panasonic Network Camera
	"00:02:48": {Vendor: "Panasonic", DeviceType: "camera"},

	// Trendnet
	"00:14:95": {Vendor: "Trendnet", DeviceType: "camera"},

	// Motorola / Arris
	"00:0e:7f": {Vendor: "Motorola / Arris", DeviceType: "router"},

	// Comcast Xfinity Gateway
	"00:0e:7f": {Vendor: "Comcast Xfinity", DeviceType: "router"},

	// Verizon Fios
	"00:26:5e": {Vendor: "Verizon", DeviceType: "router"},

	// AT&T Wireless
	"00:04:9b": {Vendor: "AT&T", DeviceType: "router"},

	// Centurylink
	"00:12:74": {Vendor: "CenturyLink", DeviceType: "router"},

	// Frontier Fios
	"00:1e:c1": {Vendor: "Frontier", DeviceType: "router"},

	// Charter Spectrum
	"00:19:a8": {Vendor: "Charter Spectrum", DeviceType: "router"},

	// Cox Communications
	"00:05:b2": {Vendor: "Cox", DeviceType: "router"},

	// Time Warner Cable
	"00:12:de": {Vendor: "Time Warner Cable", DeviceType: "router"},

	// Dish Network
	"00:13:e0": {Vendor: "Dish Network", DeviceType: ""},

	// DirecTV
	"00:04:4b": {Vendor: "DirecTV", DeviceType: ""},

	// Roku Streaming Stick
	"d4:a5:d8": {Vendor: "Roku", DeviceType: "media_player"},

	// Fire Stick (Amazon)
	"74:c7:f0": {Vendor: "Amazon Fire Stick", DeviceType: "media_player"},

	// HiSense TV
	"30:39:f2": {Vendor: "Hisense", DeviceType: "smart_tv"},

	// TCL TV
	"34:5a:34": {Vendor: "TCL", DeviceType: "smart_tv"},

	// Vizio TV
	"84:1b:5e": {Vendor: "Vizio", DeviceType: "smart_tv"},

	// Toshiba TV
	"78:0c:f0": {Vendor: "Toshiba", DeviceType: "smart_tv"},

	// Sharp TV
	"04:5b:da": {Vendor: "Sharp", DeviceType: "smart_tv"},

	// Insignia (Best Buy)
	"30:39:f2": {Vendor: "Insignia", DeviceType: "smart_tv"},

	// Sceptre
	"84:1b:5e": {Vendor: "Sceptre", DeviceType: "smart_tv"},

	// Element Electronics
	"f4:54:6b": {Vendor: "Element Electronics", DeviceType: "smart_tv"},

	// ONN (Walmart)
	"f4:54:6b": {Vendor: "ONN", DeviceType: "smart_tv"},

	// Emerson TV
	"30:39:f2": {Vendor: "Emerson", DeviceType: "smart_tv"},

	// Sanyo TV
	"3c:d0:f8": {Vendor: "Sanyo", DeviceType: "smart_tv"},

	// Panasonic TV
	"00:02:48": {Vendor: "Panasonic", DeviceType: "smart_tv"},

	// Mitsubishi TV
	"00:01:c8": {Vendor: "Mitsubishi", DeviceType: "smart_tv"},

	// Philco TV
	"f4:54:6b": {Vendor: "Philco", DeviceType: "smart_tv"},

	// Akai TV
	"30:39:f2": {Vendor: "Akai", DeviceType: "smart_tv"},

	// Element Smart Speaker
	"f4:54:6b": {Vendor: "Element", DeviceType: "smart_speaker"},
}

// Lookup returns vendor and device type for a given MAC address.
// MAC should be in format "XX:XX:XX" or "XXXXXX", case-insensitive.
// Returns nil if no match found.
func (e *Engine) Lookup(mac string) *OUIResult {
	if mac == "" {
		return nil
	}

	// Normalize: extract first 6 hex characters (first 3 octets)
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, " ", "")

	if len(mac) < 6 {
		return nil
	}

	// Use first 6 characters as OUI
	oui := mac[:6]
	if result, ok := ouiDatabase[oui]; ok {
		result.Confidence = 0.2 // OUI-only match
		return &result
	}

	return nil
}
