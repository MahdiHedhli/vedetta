package dnsintel

import (
	"net"
	"strings"
	"sync"
	"time"
)

// KnownPublicResolvers maps public DNS resolver IPs to their providers.
// These are well-known, legitimate DNS services that devices should not be
// querying directly if they're behind a local DNS filter (Pi-hole, AdGuard).
var KnownPublicResolvers = map[string]string{
	// Google Public DNS
	"8.8.8.8":                 "Google Public DNS",
	"8.8.4.4":                 "Google Public DNS",
	"2001:4860:4860::8888":    "Google Public DNS (IPv6)",
	"2001:4860:4860::8844":    "Google Public DNS (IPv6)",

	// Cloudflare 1.1.1.1
	"1.1.1.1":                 "Cloudflare 1.1.1.1",
	"1.0.0.1":                 "Cloudflare 1.1.1.1",
	"2606:4700:4700::1111":    "Cloudflare 1.1.1.1 (IPv6)",
	"2606:4700:4700::1001":    "Cloudflare 1.1.1.1 (IPv6)",
	"2606:4700:4700::64":      "Cloudflare 1.1.1.1 (IPv6)",

	// Quad9
	"9.9.9.9":                 "Quad9 DNS",
	"149.112.112.112":         "Quad9 DNS",
	"2620:fe::fe":             "Quad9 DNS (IPv6)",

	// OpenDNS
	"208.67.222.222":          "OpenDNS",
	"208.67.220.220":          "OpenDNS",
	"208.67.222.220":          "OpenDNS",

	// NextDNS
	"45.90.28.0":              "NextDNS",
	"45.90.30.0":              "NextDNS",

	// AdGuard DNS (public)
	"94.140.14.14":            "AdGuard DNS",
	"94.140.15.15":            "AdGuard DNS",
	"2a10:50c0::ad1:ff":       "AdGuard DNS (IPv6)",

	// Verisign DNS (public)
	"64.6.64.6":               "Verisign DNS",
	"64.6.65.6":               "Verisign DNS",
}

// KnownDNSProviderDomains maps DNS provider domains (used for DoH/DoT) to their providers.
// Queries to these domains indicate DNS-over-HTTPS or DNS-over-TLS bypass attempts.
var KnownDNSProviderDomains = map[string]string{
	// Google DoH/DoT
	"dns.google":              "Google DNS-over-HTTPS",
	"dns.google.com":          "Google DNS-over-HTTPS",

	// Cloudflare DoH/DoT
	"cloudflare-dns.com":      "Cloudflare DNS-over-HTTPS",
	"1dot1dot1dot1.cloudflare-dns.com": "Cloudflare DNS-over-HTTPS",
	"one.one.one.one":         "Cloudflare DNS-over-HTTPS",

	// Quad9 DoH/DoT
	"dns.quad9.net":           "Quad9 DNS-over-HTTPS",

	// OpenDNS DoH/DoT
	"doh.opendns.com":         "OpenDNS DNS-over-HTTPS",

	// NextDNS DoH/DoT
	"dns.nextdns.io":          "NextDNS DNS-over-HTTPS",

	// AdGuard DoH/DoT
	"dns.adguard.com":         "AdGuard DNS-over-HTTPS",
	"unfiltered.adguard.com":  "AdGuard DNS-over-HTTPS",
}

// BypassDetector identifies when devices make DNS queries directly to external
// resolvers, bypassing the local DNS resolver (Pi-hole, AdGuard, or Vedetta).
// This is a sign of misconfiguration or compromise (hardcoded DNS, malware).
type BypassDetector struct {
	mu             sync.RWMutex
	localNets      []*net.IPNet    // configured local subnets
	localResolvers []string        // known local DNS resolvers
	alerts         map[string]time.Time // source_hash -> last alert time
	cooldown       time.Duration   // don't re-alert for same source within cooldown
}

// BypassResult describes a detected DNS bypass.
type BypassResult struct {
	IsBypass         bool   // true if external DNS was detected
	SourceHash       string // the source of the query
	ExternalResolver string // the external DNS resolver IP
}

// NewBypassDetector creates a new DNS bypass detector.
// localNets should be the subnets that are considered "local" (e.g., 192.168.1.0/24).
// localResolvers should be a list of IP addresses of known local DNS servers.
// cooldown controls how often to alert for the same source (default 1h).
func NewBypassDetector(localNets []*net.IPNet, localResolvers []string, cooldown time.Duration) *BypassDetector {
	if cooldown == 0 {
		cooldown = 1 * time.Hour
	}
	return &BypassDetector{
		localNets:      localNets,
		localResolvers: localResolvers,
		alerts:         make(map[string]time.Time),
		cooldown:       cooldown,
	}
}

// Check determines whether a DNS query was sent to an external resolver.
// Returns nil if the query went to a local resolver, or a BypassResult if
// it went to an external DNS server. The result will check the cooldown
// before returning a bypass (to avoid alert spam).
func (b *BypassDetector) Check(sourceHash, serverIP string) *BypassResult {
	if sourceHash == "" || serverIP == "" {
		return nil
	}

	// Check if this resolver is a known local one
	if b.isLocalResolver(serverIP) {
		return nil
	}

	// External resolver detected
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if we've already alerted for this source recently
	lastAlert, seen := b.alerts[sourceHash]
	now := time.Now()

	if seen && now.Before(lastAlert.Add(b.cooldown)) {
		// Still within cooldown, don't return a result
		return nil
	}

	// Update alert time for this source
	b.alerts[sourceHash] = now

	return &BypassResult{
		IsBypass:         true,
		SourceHash:       sourceHash,
		ExternalResolver: serverIP,
	}
}

// AddLocalResolver registers a local DNS resolver IP (e.g., the router).
func (b *BypassDetector) AddLocalResolver(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, existing := range b.localResolvers {
		if existing == ip {
			return // already registered
		}
	}

	b.localResolvers = append(b.localResolvers, ip)
}

// isLocalResolver checks whether an IP is a known local DNS resolver.
func (b *BypassDetector) isLocalResolver(ip string) bool {
	// Check against registered local resolvers
	for _, resolver := range b.localResolvers {
		if resolver == ip {
			return true
		}
	}

	// Check against local subnets (e.g., 192.168.1.0/24)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, subnet := range b.localNets {
		if subnet.Contains(parsed) {
			return true
		}
	}

	return false
}

// GetAlertStatus returns information about bypass alerts (for monitoring).
func (b *BypassDetector) GetAlertStatus() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"recent_bypasses": len(b.alerts),
		"local_resolvers": b.localResolvers,
		"cooldown":        b.cooldown.String(),
	}
}

// CleanupStaleAlerts removes alert entries that are older than cooldown.
// This prevents the alerts map from growing unbounded.
func (b *BypassDetector) CleanupStaleAlerts(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := now.Add(-b.cooldown)
	for source, lastAlert := range b.alerts {
		if lastAlert.Before(cutoff) {
			delete(b.alerts, source)
		}
	}
}

// DetectPublicResolverBypass checks if an event indicates DNS bypass by querying
// a well-known public DNS resolver directly. Returns nil if no bypass detected,
// or a BypassResult with details about the bypass.
func (b *BypassDetector) DetectPublicResolverBypass(resolvedIP string) (string, string) {
	if resolvedIP == "" {
		return "", ""
	}

	// Check if this IP is a known public DNS resolver
	if provider, ok := KnownPublicResolvers[resolvedIP]; ok {
		return resolvedIP, provider
	}

	return "", ""
}

// DetectDoHDotBypass checks if a domain indicates DNS-over-HTTPS/TLS bypass.
// Returns the provider name if found, or empty string otherwise.
func (b *BypassDetector) DetectDoHDotBypass(domain string) string {
	if domain == "" {
		return ""
	}

	// Normalize domain to lowercase for comparison
	domainLower := strings.ToLower(domain)

	// Direct exact match
	if provider, ok := KnownDNSProviderDomains[domainLower]; ok {
		return provider
	}

	// Check for subdomains (e.g., "1dot1dot1dot1.cloudflare-dns.com" contains "cloudflare-dns.com")
	for knownDomain, provider := range KnownDNSProviderDomains {
		if domainLower == knownDomain || strings.HasSuffix(domainLower, "."+knownDomain) {
			return provider
		}
	}

	return ""
}
