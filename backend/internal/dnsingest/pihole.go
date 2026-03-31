package dnsingest

import (
	"log"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dnspoller"
)

// PiHoleSource wraps the existing Pi-hole poller as a DNSSource.
type PiHoleSource struct {
	poller *dnspoller.Poller
	name   string
}

// NewPiHoleSource creates a new Pi-hole DNS source using an existing Poller.
func NewPiHoleSource(poller *dnspoller.Poller) *PiHoleSource {
	return &PiHoleSource{
		poller: poller,
		name:   "pihole",
	}
}

// Name returns the source identifier.
func (p *PiHoleSource) Name() string {
	return p.name
}

// Start begins the Pi-hole polling loop.
func (p *PiHoleSource) Start() error {
	if p.poller == nil {
		return nil // gracefully handle nil poller
	}
	p.poller.Start()
	log.Printf("PiHoleSource started")
	return nil
}

// Stop gracefully stops the Pi-hole poller.
func (p *PiHoleSource) Stop() {
	if p.poller == nil {
		return
	}
	p.poller.Stop()
	log.Printf("PiHoleSource stopped")
}

// UpdatePollerInterval allows adjusting the polling interval at runtime.
func (p *PiHoleSource) UpdatePollerInterval(interval time.Duration) {
	if p.poller == nil {
		return
	}
	p.poller.SetInterval(interval)
}
