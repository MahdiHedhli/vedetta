package dnsintel

import (
	"net"
	"sync"
	"time"
)

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
