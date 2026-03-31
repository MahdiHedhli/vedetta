package dnsingest

import (
	"log"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dnspoller"
)

// AdGuardSource wraps the existing AdGuard poller as a DNSSource.
type AdGuardSource struct {
	poller *dnspoller.AdGuardPoller
	name   string
}

// NewAdGuardSource creates a new AdGuard DNS source using an existing Poller.
func NewAdGuardSource(poller *dnspoller.AdGuardPoller) *AdGuardSource {
	return &AdGuardSource{
		poller: poller,
		name:   "adguard",
	}
}

// Name returns the source identifier.
func (a *AdGuardSource) Name() string {
	return a.name
}

// Start begins the AdGuard polling loop.
func (a *AdGuardSource) Start() error {
	if a.poller == nil {
		return nil // gracefully handle nil poller
	}
	a.poller.Start()
	log.Printf("AdGuardSource started")
	return nil
}

// Stop gracefully stops the AdGuard poller.
func (a *AdGuardSource) Stop() {
	if a.poller == nil {
		return
	}
	a.poller.Stop()
	log.Printf("AdGuardSource stopped")
}

// UpdatePollerInterval allows adjusting the polling interval at runtime.
func (a *AdGuardSource) UpdatePollerInterval(interval time.Duration) {
	if a.poller == nil {
		return
	}
	a.poller.SetInterval(interval)
}
