package dnscap

import (
	"log"
	"net"
	"sync"
	"time"
)

// EncryptedDNSDetector identifies encrypted DNS (DoH/DoT) flows.
type EncryptedDNSDetector struct {
	knownDoHIPs []string
	knownDoTIPs []string
	mu          sync.RWMutex
	deviceFlows map[string]*deviceFlow
	onDetect    func(EncryptedDNSEvent)
}

// EncryptedDNSEvent represents a detected encrypted DNS flow.
type EncryptedDNSEvent struct {
	Timestamp   time.Time
	ClientIP    string
	Method      string // "doh" or "dot"
	Endpoint    string // e.g., "104.16.248.249" for Cloudflare
	QueryCount  int
	LastSeen    time.Time
	Source      string // "encrypted_dns_detected"
}

// deviceFlow tracks encrypted DNS activity per device.
type deviceFlow struct {
	lastSeen   time.Time
	queryCount int
	method     string
	endpoint   string
}

// NewEncryptedDNSDetector creates a new detector with known DoH/DoT endpoints.
func NewEncryptedDNSDetector(onDetect func(EncryptedDNSEvent)) *EncryptedDNSDetector {
	return &EncryptedDNSDetector{
		knownDoHIPs: []string{
			"104.16.248.249",     // Cloudflare
			"104.16.249.249",     // Cloudflare
			"8.8.8.8",            // Google
			"8.8.4.4",            // Google
			"1.1.1.1",            // Cloudflare
			"1.0.0.1",            // Cloudflare
			"208.67.222.222",     // OpenDNS
			"208.67.220.220",     // OpenDNS
		},
		knownDoTIPs: []string{
			"104.16.248.249",     // Cloudflare
			"104.16.249.249",     // Cloudflare
			"8.8.8.8",            // Google
			"8.8.4.4",            // Google
			"1.1.1.1",            // Cloudflare
			"1.0.0.1",            // Cloudflare
			"208.67.222.222",     // OpenDNS
			"208.67.220.220",     // OpenDNS
		},
		deviceFlows: make(map[string]*deviceFlow),
		onDetect:    onDetect,
	}
}

// CheckFlow analyzes a network flow for encrypted DNS indicators.
func (d *EncryptedDNSDetector) CheckFlow(srcIP, dstIP string, dstPort uint16) {
	if !d.isKnownResolver(dstIP) {
		return
	}

	method := ""
	if dstPort == 443 {
		if d.isDoHEndpoint(dstIP) {
			method = "doh"
		}
	} else if dstPort == 853 {
		if d.isDoTEndpoint(dstIP) {
			method = "dot"
		}
	}

	if method == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	key := srcIP + ":" + dstIP
	flow := d.deviceFlows[key]
	if flow == nil {
		flow = &deviceFlow{
			method:   method,
			endpoint: dstIP,
		}
		d.deviceFlows[key] = flow
	}

	flow.lastSeen = time.Now()
	flow.queryCount++

	// Report after threshold or periodic update
	if flow.queryCount%10 == 0 {
		if d.onDetect != nil {
			d.onDetect(EncryptedDNSEvent{
				Timestamp:  time.Now(),
				ClientIP:   srcIP,
				Method:     method,
				Endpoint:   dstIP,
				QueryCount: flow.queryCount,
				LastSeen:   flow.lastSeen,
				Source:     "encrypted_dns_detected",
			})
		}
	}
}

// isKnownResolver checks if an IP is a known DNS resolver.
func (d *EncryptedDNSDetector) isKnownResolver(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, known := range d.knownDoHIPs {
		if ip == known {
			return true
		}
	}
	for _, known := range d.knownDoTIPs {
		if ip == known {
			return true
		}
	}
	return false
}

// isDoHEndpoint checks if an IP is a known DoH endpoint.
func (d *EncryptedDNSDetector) isDoHEndpoint(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, known := range d.knownDoHIPs {
		if ip == known {
			return true
		}
	}
	return false
}

// isDoTEndpoint checks if an IP is a known DoT endpoint.
func (d *EncryptedDNSDetector) isDoTEndpoint(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, known := range d.knownDoTIPs {
		if ip == known {
			return true
		}
	}
	return false
}

// AddDoHEndpoint adds a known DoH endpoint.
func (d *EncryptedDNSDetector) AddDoHEndpoint(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownDoHIPs = append(d.knownDoHIPs, ip)
}

// AddDoTEndpoint adds a known DoT endpoint.
func (d *EncryptedDNSDetector) AddDoTEndpoint(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownDoTIPs = append(d.knownDoTIPs, ip)
}

// ClearFlows removes all cached device flows (e.g., on startup or periodic cleanup).
func (d *EncryptedDNSDetector) ClearFlows() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deviceFlows = make(map[string]*deviceFlow)
	log.Printf("encrypted_dns_detector: flows cleared")
}
