# Building a Device Fingerprint Database

> Priority: P1 — Differentiator for device identification accuracy; feeds community threat network

## Current State in Vedetta

Device identification relies solely on nmap's OUI lookup (MAC address → manufacturer name). The `vendor` field in the Device model captures this, but it only tells you "Espressif" or "Apple, Inc." — not whether a device is an iPhone 15, a Ring doorbell, or a Sonos speaker.

The schema defines `device_vendor` and `network_segment` but has no fields for device type, OS, or model.

## Why This Matters

Accurate device identification enables:
- **Security policy**: IoT cameras should not be making DNS queries to unknown domains; a laptop doing the same is normal
- **Anomaly detection**: A smart thermostat opening port 22 (SSH) is suspicious; a Linux server doing so is expected
- **User experience**: Showing "Ring Doorbell Pro" instead of "Amazon Technologies Inc." in the dashboard
- **Community intelligence**: Knowing that 40% of compromised home devices are IP cameras vs. smart TVs helps the threat network produce actionable feeds

## Research Findings

### 1. Fingerprint Data Sources

**DHCP Fingerprinting (Highest Signal)**

When devices request an IP via DHCP, the parameter request list (option 55) contains a sequence of option codes in a specific order. This order is a fingerprint — different devices and OS versions request options in different, consistent sequences.

Example fingerprints:
```
iPhone (iOS 17):    1,121,3,6,15,119,252,95,44,46
Windows 11:         1,3,6,15,31,33,43,44,46,47,121,249,252
Chromecast:         1,3,6,15,26,28,51,58,59,43
Ring Doorbell:      1,3,6,15,28,42
```

**Fingerbank (Open Source, MIT License)**
- https://www.fingerbank.org/
- 6M+ DHCP fingerprints mapping to 110K+ device profiles
- SQLite database export available (~5MB compressed)
- REST API for real-time lookups (free tier: 300 requests/hour)
- Combination matching: DHCP fingerprint + OUI vendor + hostname patterns
- Returns: device type, OS family, OS version, device model
- **Recommendation**: Bundle the SQLite export with Vedetta for offline matching. Use API as supplementary.

**mDNS / DNS-SD Service Announcements**

Devices advertising services on the local network reveal their purpose:

| Service Type | Device Category | Examples |
|-------------|----------------|----------|
| `_airplay._tcp` | Apple TV / AirPlay receiver | Apple TV, HomePod, Mac |
| `_googlecast._tcp` | Chromecast / Google device | Chromecast, Nest Hub, Google TV |
| `_spotify-connect._tcp` | Spotify speaker | Sonos, Echo, various |
| `_hap._tcp` | HomeKit accessory | Smart plugs, locks, sensors |
| `_ipp._tcp` | Printer | HP, Canon, Epson |
| `_raop._tcp` | AirPlay audio | HomePod, AirPort Express |
| `_smb._tcp` | File sharing (SMB) | NAS, Windows PC, Mac |
| `_http._tcp` | Web interface | Routers, NAS, IoT hubs |
| `_ssh._tcp` | SSH server | Linux servers, NAS |

The TXT records often contain model identifiers:
```
_googlecast._tcp → md=Chromecast Ultra, fn=Living Room TV
_hap._tcp → md=Eve Energy, ci=7
_airplay._tcp → model=AppleTV14,1
```

**SSDP / UPnP Device Descriptions**

UPnP devices provide an XML description at the URL in their SSDP response:
```xml
<device>
  <friendlyName>Living Room TV</friendlyName>
  <manufacturer>Samsung</manufacturer>
  <modelName>UN65CU8000</modelName>
  <modelNumber>8.0</modelNumber>
  <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
</device>
```

This gives exact manufacturer, model, and device purpose.

**TCP/IP Stack Fingerprinting**

OS identification from passive TCP SYN analysis (p0f-style):
```
Windows 11:  TTL=128, Window=65535, DF=1, MSS=1460, Options=[MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK]
macOS 14:    TTL=64, Window=65535, DF=1, MSS=1460, Options=[MSS,NOP,WS,NOP,NOP,TS,SACK,EOL]
Linux 6.x:   TTL=64, Window=65535, DF=1, MSS=1460, Options=[MSS,SACK,TS,NOP,WS]
iOS 17:      TTL=64, Window=65535, DF=1, MSS=1460, Options=[MSS,NOP,WS,NOP,NOP,TS,SACK,EOL]
Android 14:  TTL=64, Window=65535, DF=1, MSS=1460, Options=[MSS,SACK,TS,NOP,WS]
```

Distinguishing iOS from macOS or Android from Linux requires combining TCP fingerprints with other signals (DHCP, mDNS, hostname patterns).

**JA3/JA4 TLS Fingerprinting**

TLS ClientHello fingerprints identify the application, not just the OS:
```
Chrome 120 on Windows:  ja3=cd08e31494f9531f560d64c695473da9
Safari on iOS 17:       ja3=773906b0efdefa24a7f2b8eb6985bf37
Mirai botnet:           ja3=e7d705a3286e19ea42f587b344ee6865
```

Known-bad JA3 hashes (from abuse.ch SSLBL) can identify malware communication.

### 2. Hostname Pattern Matching

Many devices include identifying information in their DHCP or mDNS hostnames:

```
iPhone:         iPhone-* , *s-iPhone, *-iPhone
iPad:           iPad-*, *s-iPad
Mac:            *s-MacBook-Pro, *-Mac-mini, *s-iMac
Android:        Galaxy-*, Pixel-*, android-*
Ring:           Ring-*, ring-*
Nest:           Nest-*, NestAudio-*
Echo:           echo-*, amazon-*
Roku:           Roku-*
PS5:            PS5-*
Xbox:           Xbox-*, XBOX-*
```

A regex-based hostname classifier can provide device type even without other fingerprints.

### 3. Multi-Signal Fusion

No single fingerprint method is 100% reliable. The highest accuracy comes from combining multiple signals:

```
Confidence Scoring Model:
─────────────────────────
OUI vendor match only                           → 0.2 (low — just manufacturer)
OUI + hostname pattern match                    → 0.5 (medium)
DHCP fingerprint match (Fingerbank)             → 0.7 (good)
DHCP fingerprint + OUI + hostname               → 0.85 (high)
DHCP + mDNS service type + OUI                  → 0.9 (very high)
DHCP + mDNS + SSDP device description           → 0.95 (excellent)
All above + TCP fingerprint + JA3               → 0.98 (definitive)
```

## Recommended Database Schema

```sql
-- Device fingerprint profiles (local reference database)
CREATE TABLE fingerprint_profiles (
    profile_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,      -- phone, tablet, laptop, desktop, smart_tv, camera,
                                    -- doorbell, speaker, thermostat, printer, nas, router,
                                    -- gaming_console, streaming_device, iot_generic
    manufacturer TEXT,
    model TEXT,
    os_family TEXT,                  -- Windows, macOS, iOS, Android, Linux, ChromeOS,
                                    -- tvOS, FireOS, Tizen, webOS, custom_firmware
    os_version_range TEXT,
    dhcp_fingerprints TEXT,          -- JSON array of known option 55 sequences
    hostname_patterns TEXT,          -- JSON array of regex patterns
    mdns_services TEXT,              -- JSON array of service types
    ssdp_device_types TEXT,          -- JSON array of UPnP device types
    oui_prefixes TEXT,               -- JSON array of MAC OUI prefixes
    tcp_signatures TEXT,             -- JSON array of p0f-style signatures
    ja3_hashes TEXT,                 -- JSON array of known JA3 hashes
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_fp_device_type ON fingerprint_profiles(device_type);
CREATE INDEX idx_fp_manufacturer ON fingerprint_profiles(manufacturer);

-- Observed fingerprints per device (what Vedetta has seen)
CREATE TABLE device_fingerprints (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    fingerprint_type TEXT NOT NULL,  -- dhcp, mdns, ssdp, tcp, ja3, hostname
    fingerprint_value TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (device_id, fingerprint_type)
);

-- Match results (device → profile mapping)
CREATE TABLE device_identifications (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
    profile_id TEXT REFERENCES fingerprint_profiles(profile_id),
    confidence REAL NOT NULL DEFAULT 0.0,  -- 0.0-1.0
    match_signals TEXT,                     -- JSON: which signals contributed
    identified_at TEXT NOT NULL,
    reviewed_by_user BOOLEAN DEFAULT FALSE  -- User confirmed/corrected
);
```

## Implementation Plan

### Phase 1: Bundle Fingerbank + OUI + Hostname Patterns (M1 Extension)

1. Download Fingerbank SQLite export, embed in sensor binary or Docker image
2. Add hostname pattern regex database (curated list of 50+ patterns for common home devices)
3. On device discovery, attempt identification: OUI → hostname → Fingerbank DHCP (if available)
4. Store results in `device_identifications` table
5. Expose in API: `GET /api/v1/devices` now includes `device_type`, `os_family`, `model`, `confidence`
6. Dashboard shows device icons and human-readable names instead of just vendor strings

### Phase 2: Passive DHCP + mDNS Listeners (Post-M1)

1. Add DHCP sniffer to sensor (gopacket, BPF filter on UDP 67/68)
2. Extract option 55 fingerprint, match against Fingerbank DB
3. Add mDNS listener (multicast 224.0.0.251:5353)
4. Parse service types and TXT records for model information
5. Update device identification with higher-confidence multi-signal matches

### Phase 3: Community Fingerprint Contribution (M6 Extension)

1. When telemetry is enabled, contribute anonymized fingerprint data:
   - DHCP option 55 sequence + matched device type (no MAC, no IP, no hostname)
   - New/unmatched fingerprints flagged for community review
2. Threat network aggregates submissions, builds community fingerprint database
3. Nodes pull updated fingerprint profiles as part of threat feed subscriptions
4. This creates a **virtuous cycle**: more nodes → better fingerprints → better identification → more value → more nodes

### Phase 4: User Correction UI (M4 Extension)

1. Dashboard allows users to manually identify/correct device types
2. Corrections stored locally and optionally contributed to community
3. User-corrected devices get confidence 1.0 and are locked from auto-reclassification

## Size Estimates for Pi 4

| Component | Size | RAM Impact |
|-----------|------|------------|
| Fingerbank SQLite DB | ~5MB | ~2MB (index in memory) |
| OUI database | ~2MB | ~1MB |
| Hostname patterns | <100KB | Negligible |
| mDNS service types | <50KB | Negligible |
| Total | ~8MB | ~4MB |

Well within Pi 4 constraints.

## References

- Fingerbank: https://www.fingerbank.org/
- Fingerbank GitHub: https://github.com/fingerbank/fingerbank
- DHCP Fingerprinting explained: https://efficientip.com/glossary/dhcp-fingerprinting/
- IEEE OUI Database: https://standards-oui.ieee.org/
- mDNS/DNS-SD service types: https://www.iana.org/assignments/service-names-port-numbers/
- JA3 fingerprinting: https://github.com/salesforce/ja3
- JA4 fingerprinting: https://github.com/FoxIO-LLC/ja4
- p0f signatures: https://lcamtuf.coredump.cx/p0f3/
