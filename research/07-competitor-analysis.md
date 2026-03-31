# Competitor & Comparable Tool Analysis

> Vedetta occupies a unique niche: lightweight, open-source, home/SMB-focused SIEM with community threat intelligence. No single competitor covers this exact space.

## Competitive Landscape Map

```
                    ┌─────────────────────────────────────────────┐
                    │              Enterprise / Complex            │
                    │                                             │
                    │   Security Onion    Elastic SIEM            │
                    │   Splunk (Free)     QRadar CE               │
                    │                                             │
          Open ─────┤                                             ├───── Proprietary
          Source     │   Wazuh             CrowdSec               │
                    │   SELKS             GreyNoise               │
                    │                                             │
                    │   ★ VEDETTA         Firewalla               │
                    │   ntopng            Fingbox                 │
                    │                                             │
                    │              Home / Lightweight              │
                    └─────────────────────────────────────────────┘
```

## Direct Competitors (Home/SMB Network Security)

### Firewalla ($170-$500 hardware)

**What it is:** Dedicated hardware appliance that sits on your network. Combines firewall, IDS, ad blocker, VPN, and device management.

**Strengths:**
- Zero-config setup (plug in and go)
- Active + passive device discovery (ARP, DHCP, nmap, p0f-style fingerprinting)
- Cloud-backed device identification database (proprietary, millions of fingerprints)
- Mobile app with push notifications for new devices, blocked threats
- Built-in VPN server for remote access
- Ad blocking (Pi-hole-like) integrated
- Family features (parental controls, per-device rules)

**Weaknesses:**
- Proprietary, closed-source
- Requires their hardware ($170+ for Blue, $500+ for Gold/Purple)
- Cloud dependency for device identification and updates
- No community threat intelligence contribution — one-way
- Limited customization for power users
- No self-host option

**Vedetta differentiation:**
- FOSS / self-hosted / no hardware purchase
- Community threat intelligence (two-way contribution)
- Runs on hardware users already own (Pi 4, old laptop, VM)
- Extensible and auditable codebase
- No cloud dependency for core functions

### Fingbox ($99-$129 hardware)

**What it is:** Network scanner and monitor focused on device discovery and bandwidth analysis.

**Strengths:**
- Excellent device recognition (leverages Fing app's massive device database from 50M+ users)
- Bandwidth monitoring per device
- Network security alerts (new devices, open ports, ARP spoofing detection)
- ISP speed tracking and outage detection
- Simple, consumer-friendly UI

**Weaknesses:**
- Not a firewall — cannot block traffic
- No DNS threat detection
- No log aggregation or SIEM capability
- Requires cloud account (Fing Cloud)
- Proprietary, closed-source
- Limited threat detection beyond device discovery
- No community threat intelligence

**Vedetta differentiation:**
- Full SIEM capability (log aggregation, event correlation, threat scoring)
- DNS threat hunting (DGA, beaconing, C2 detection) — Fingbox has none of this
- Community threat network
- No cloud account requirement

### ntopng (Open Source / Commercial)

**What it is:** Network traffic analysis and flow collection tool. Deep packet inspection via nDPI library.

**Strengths:**
- Excellent protocol-level visibility (250+ application protocols)
- JA3/JA4 TLS fingerprinting
- Flow analysis (NetFlow, sFlow, IPFIX)
- Real-time traffic dashboards
- Runs on Pi 4 (community edition)
- Active development, strong community
- GeoIP enrichment

**Weaknesses:**
- Primarily a traffic analyzer, not a SIEM
- No log aggregation from external sources
- No DNS-specific threat hunting
- No device management or inventory
- Complex configuration for non-experts
- Community edition limited (enterprise features paywalled)
- No community threat intelligence network

**Vedetta differentiation:**
- Purpose-built for security monitoring (not just traffic analysis)
- DNS-first threat detection approach
- Device inventory with fingerprinting
- Log aggregation from Pi-hole, firewalls, etc.
- Community threat network
- Consumer-friendly UX (setup wizard, plain-language alerts)

## Indirect Competitors (Open Source SIEM / IDS)

### Wazuh (Open Source XDR/SIEM)

**What it is:** Full-featured open-source SIEM platform with endpoint agents, log management, vulnerability detection, and compliance.

**Strengths:**
- Most complete open-source SIEM available
- Agent-based endpoint monitoring (file integrity, rootkit detection, log collection)
- Pre-built decoders for 500+ log formats
- MITRE ATT&CK mapping
- Active directory integration
- Compliance modules (PCI DSS, GDPR, HIPAA)
- Large community, extensive documentation
- Regular updates and professional support available

**Weaknesses:**
- **Heavy**: Minimum 8GB RAM, 50GB storage for small deployments
- Dashboard and indexer don't run on ARM (Raspberry Pi) — only the manager does, without UI
- Complex setup (Wazuh server + indexer + dashboard = 3 components minimum)
- Agent-centric — requires installing agents on every endpoint
- Overkill for home users who just want network visibility
- No passive network discovery
- No community-sourced threat intelligence
- Steep learning curve

**Vedetta differentiation:**
- Runs on Pi 4 (4GB RAM, 32GB storage) — Wazuh cannot
- Agentless network discovery (no installing agents on every device)
- Zero-config target (setup wizard, one command install)
- DNS-first threat hunting (home network's richest data source)
- Community threat network (unique to Vedetta)
- Consumer-friendly UX vs. SOC analyst UX

### Security Onion

**What it is:** Linux distribution bundling Suricata, Zeek, Wazuh, Elastic, and dozens of security tools into a unified SOC platform.

**Strengths:**
- Comprehensive — full packet capture, IDS, log management, case management
- Integrates best-of-breed open-source tools
- Active community and regular releases
- Professional training available
- PCAP analysis and threat hunting workflows

**Weaknesses:**
- **Extremely heavy**: Minimum 16GB RAM, 200GB+ storage
- Not viable on anything less than a dedicated server
- Complex — designed for SOC analysts, not home users
- Long setup process
- No mobile/simple dashboard
- No community threat intelligence sharing

**Vedetta differentiation:**
- 50x lighter resource footprint
- Home user audience vs. SOC analyst audience
- Network-centric (no agents required)
- Community threat intelligence network

### CrowdSec (Open Source)

**What it is:** Crowdsourced IP reputation and blocking system. Closest architectural analog to Vedetta's threat network.

**Strengths:**
- **Community-powered blocklists** — the model Vedetta should study most closely
- Lightweight agent (Go binary, low resource usage)
- Consensus algorithm for IP reputation
- Real-time community intelligence sharing
- MIT license
- Active development, strong funding
- Integration with firewalls, WAFs, CDNs

**Weaknesses:**
- IP-focused (not domain-focused like Vedetta)
- Primarily a blocking/remediation tool, not a SIEM
- No device discovery or inventory
- No DNS threat hunting
- No log aggregation
- Designed for servers/infrastructure, not home networks
- Console (SaaS) required for full community features

**Vedetta opportunity:**
- CrowdSec's consensus model is the blueprint for Vedetta's domain reputation system
- CrowdSec focuses on server-side IP blocking; Vedetta focuses on home/SMB DNS visibility
- The two are **complementary**, not competitive — potential integration partner
- Vedetta could contribute domain intelligence to CrowdSec's ecosystem and vice versa

## Feature Matrix

| Capability | Vedetta | Firewalla | Fingbox | ntopng | Wazuh | CrowdSec |
|-----------|---------|-----------|---------|--------|-------|----------|
| Open source | ✅ AGPL | ❌ | ❌ | ✅/💰 | ✅ | ✅ MIT |
| Runs on Pi 4 | ✅ | ❌ (own HW) | ❌ (own HW) | ✅ | ⚠️ (no UI) | ✅ |
| Device discovery | ✅ nmap | ✅ multi-method | ✅ best-in-class | ❌ | ❌ | ❌ |
| DNS threat hunting | 🔜 P0 | ✅ basic | ❌ | ❌ | ⚠️ manual | ❌ |
| Log aggregation | 🔜 P0 | ❌ | ❌ | ❌ | ✅ best-in-class | ❌ |
| IDS/IPS | 🔜 (Suricata) | ✅ built-in | ❌ | ✅ nDPI | ✅ (rules) | ✅ (scenarios) |
| Community threat intel | 🔜 P1 | ❌ | ❌ | ❌ | ❌ | ✅ best-in-class |
| Passive fingerprinting | 🔜 P0 | ✅ | ✅ | ✅ | ❌ | ❌ |
| Zero-config setup | 🔜 M4 | ✅ | ✅ | ❌ | ❌ | ⚠️ |
| No hardware purchase | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Mobile app | ❌ V2 | ✅ | ✅ | ❌ | ❌ | ❌ |
| Self-hosted | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |

## Strategic Positioning

Vedetta's unique position is the intersection of four attributes no competitor combines:

1. **Lightweight enough for Pi 4** (eliminates Wazuh, Security Onion)
2. **Open source and self-hosted** (eliminates Firewalla, Fingbox)
3. **DNS-first threat hunting** (eliminates CrowdSec, ntopng)
4. **Community threat intelligence network** (eliminates everything except CrowdSec, which is IP-not-domain focused)

The primary competitive risk is Firewalla adding a self-hosted/open-source option, or CrowdSec expanding into DNS domain reputation. Both are unlikely in the near term given their business models.

## Key Takeaways for Vedetta Development

1. **Steal from Firewalla**: Multi-method passive device discovery (ARP + DHCP + mDNS + SSDP) is table stakes. Vedetta's nmap-only approach needs supplementing.

2. **Steal from CrowdSec**: The consensus algorithm and node reputation model are exactly what Vedetta's threat network needs. Study their architecture closely.

3. **Steal from Wazuh**: The decoder/rule-chain model for log normalization is battle-tested. Implement a lightweight version via Fluent Bit Lua scripts.

4. **Steal from ntopng**: JA3/JA4 fingerprinting and nDPI-style protocol classification would massively enrich Vedetta's passive fingerprinting.

5. **Don't compete with Wazuh/Security Onion on feature breadth.** Compete on simplicity, resource efficiency, and the community threat network. Vedetta should be the tool that someone installs in 5 minutes on a Pi 4 and immediately gets value from — not another SOC platform.

## References

- Firewalla: https://firewalla.com/
- Fingbox: https://www.fing.com/products/fingbox
- ntopng: https://www.ntop.org/products/traffic-analysis/ntop/
- Wazuh: https://wazuh.com/
- Security Onion: https://securityonionsolutions.com/
- CrowdSec: https://www.crowdsec.net/
- CrowdSec GitHub: https://github.com/crowdsecurity/crowdsec
- Open Source SIEM comparison (2026): https://aimultiple.com/open-source-siem
- Wazuh on Pi 4: https://jacobriggs.io/blog/posts/how-to-install-a-wazuh-siem-server-on-a-raspberry-pi-4b-26
