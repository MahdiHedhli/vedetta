package dnsintel

import (
	"net"
	"sync"
	"time"
)

// RebindingDetector identifies DNS rebinding attacks where a domain resolves
// to a public IP on first resolution, then to a private IP on subsequent resolutions.
type RebindingDetector struct {
	mu      sync.RWMutex
	history map[string]*domainHistory // domain -> resolution history
	maxAge  time.Duration             // how long to track history (default 24h)
}

// domainHistory tracks IP resolution history for a domain.
type domainHistory struct {
	lastPublicIP  string
	lastPrivateIP string
	hasPublic     bool
	hasPrivate    bool
	lastSeen      time.Time
}

// RebindingResult describes a detected rebinding attack.
type RebindingResult struct {
	IsRebinding bool   // true if rebinding detected
	Domain      string // the affected domain
	PublicIP    string // the previously resolved public IP
	PrivateIP   string // the newly resolved private IP
}

// NewRebindingDetector creates a new DNS rebinding detector.
// maxAge controls how long domain history is retained (default 24h).
func NewRebindingDetector(maxAge time.Duration) *RebindingDetector {
	if maxAge == 0 {
		maxAge = 24 * time.Hour
	}
	return &RebindingDetector{
		history: make(map[string]*domainHistory),
		maxAge:  maxAge,
	}
}

// Check examines whether a domain resolution represents a rebinding attack.
// Returns nil if no rebinding is detected, or a RebindingResult if rebinding is found.
func (r *RebindingDetector) Check(domain, resolvedIP string) *RebindingResult {
	if domain == "" || resolvedIP == "" {
		return nil
	}

	// Determine if the resolved IP is private (RFC 1918 or link-local)
	isPrivate := isPrivateIP(resolvedIP)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clean up stale entries
	r.evictStale(time.Now())

	// Get or create history for this domain
	history, exists := r.history[domain]
	if !exists {
		history = &domainHistory{
			lastSeen: time.Now(),
		}
		r.history[domain] = history
	}

	// Update history
	now := time.Now()
	history.lastSeen = now

	// Check for rebinding: previous resolution was public, current is private
	if !isPrivate {
		// Current resolution is public
		history.lastPublicIP = resolvedIP
		history.hasPublic = true
	} else {
		// Current resolution is private
		if history.hasPublic && !history.hasPrivate {
			// First private resolution after seeing a public IP = rebinding!
			history.lastPrivateIP = resolvedIP
			history.hasPrivate = true

			return &RebindingResult{
				IsRebinding: true,
				Domain:      domain,
				PublicIP:    history.lastPublicIP,
				PrivateIP:   resolvedIP,
			}
		}
		history.lastPrivateIP = resolvedIP
		history.hasPrivate = true
	}

	return nil
}

// evictStale removes domain history entries that haven't been updated recently.
// Must be called with the lock held.
func (r *RebindingDetector) evictStale(now time.Time) {
	cutoff := now.Add(-r.maxAge)
	for domain, history := range r.history {
		if history.lastSeen.Before(cutoff) {
			delete(r.history, domain)
		}
	}
}

// isPrivateIP checks if an IP address is private (RFC 1918) or link-local (169.254.0.0/16).
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Check RFC 1918 ranges
	if parsed.IsPrivate() {
		return true
	}

	// Check link-local (169.254.0.0/16)
	if parsed.String()[:7] == "169.254" {
		_, linkLocal, _ := net.ParseCIDR("169.254.0.0/16")
		if linkLocal != nil && linkLocal.Contains(parsed) {
			return true
		}
	}

	return false
}

// Stats returns statistics about the detector's history (for monitoring/debugging).
func (r *RebindingDetector) Stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]interface{}{
		"tracked_domains": len(r.history),
		"max_age":         r.maxAge.String(),
	}
}
