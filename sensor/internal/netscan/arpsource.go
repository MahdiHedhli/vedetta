package netscan

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// defaultARPPollInterval is used when the configured reader cadence is non-positive
// (time.Ticker requires a positive duration).
const defaultARPPollInterval = 30 * time.Second

// errAlreadyRunning is returned by Source.Start when the source is already running.
var errAlreadyRunning = errors.New("arp source already running")

// SourceConfig configures the unprivileged ARP-cache discovery source.
type SourceConfig struct {
	CIDR          string        // subnet to warm when Sweep is on (e.g. netscan.BestSubnet(""))
	OwnIP         string        // sensor's own IP to exclude from the sweep; auto-detected if ""
	Sweep         bool          // active cache warming (OFF by default)
	PollInterval  time.Duration // how often to read the neighbor cache
	SweepInterval time.Duration // how often to re-warm; <=0 => warm once at startup only
	OnHost        func(DiscoveredHost)
}

// Source reads the OS neighbor (ARP) cache on an interval and emits each resolved
// IP↔MAC as a DiscoveredHost{DiscoverySource:"arp"} via OnHost. Reading is passive and
// unprivileged; the optional sweeper (Sweep) warms the cache first. Its lifecycle
// mirrors passive.Capturer: Start launches a background loop, Stop signals it and
// blocks until it has drained.
type Source struct {
	cfg      SourceConfig
	mu       sync.Mutex
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	run      bool
}

// NewSource builds a Source. A missing CIDR is auto-detected and a non-positive poll
// interval falls back to the default.
func NewSource(cfg SourceConfig) *Source {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultARPPollInterval
	}
	if cfg.CIDR == "" {
		cfg.CIDR = BestSubnet("")
	}
	return &Source{cfg: cfg, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
}

// Start launches the background poll loop. It errors if already running.
func (s *Source) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run {
		return errAlreadyRunning
	}
	s.run = true
	go s.loop()
	return nil
}

// Stop signals the loop and blocks until it has fully returned (mirrors
// passive.Capturer.Stop, so callers get a clean shutdown before the sink closes). It is
// safe to call concurrently and more than once: stopOnce guards the channel close, and
// every caller waits on doneCh.
func (s *Source) Stop() {
	s.mu.Lock()
	running := s.run
	s.mu.Unlock()
	if !running {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	<-s.doneCh
	s.mu.Lock()
	s.run = false
	s.mu.Unlock()
}

func (s *Source) loop() {
	defer close(s.doneCh)

	// Warm the cache FIRST (if enabled) so the initial read isn't empty for silent hosts.
	if s.cfg.Sweep {
		s.sweepOnce()
	}
	s.readOnce()

	readT := time.NewTicker(s.cfg.PollInterval)
	defer readT.Stop()

	var sweepC <-chan time.Time
	if s.cfg.Sweep && s.cfg.SweepInterval > 0 {
		sweepT := time.NewTicker(s.cfg.SweepInterval)
		defer sweepT.Stop()
		sweepC = sweepT.C
	}

	for {
		select {
		case <-s.stopCh:
			return
		case <-readT.C:
			s.readOnce()
		case <-sweepC:
			s.sweepOnce()
			s.readOnce() // read right after warming so freshly-resolved hosts surface
		}
	}
}

// readOnce reads the neighbor cache and emits each entry via OnHost. readNeighbors has
// already filtered pseudo-entries (isRealNeighbor), so this only maps to DiscoveredHost.
func (s *Source) readOnce() {
	neigh, err := readNeighbors()
	if err != nil {
		log.Printf("[arp] neighbor cache read failed: %v", err)
		return
	}
	for _, n := range neigh {
		if s.cfg.OnHost != nil {
			s.cfg.OnHost(DiscoveredHost{
				IPAddress:       n.ip,
				MACAddress:      n.mac,
				Status:          "up",
				DiscoverySource: "arp",
			})
		}
	}
}

// sweepOnce warms the neighbor cache for the configured subnet, excluding the sensor's
// own IP. Oversized/invalid subnets are logged and skipped (never truncated/dialed).
func (s *Source) sweepOnce() {
	own := s.cfg.OwnIP
	if own == "" {
		own = outboundIPv4()
	}
	targets, err := sweepTargets(s.cfg.CIDR, own)
	if err != nil {
		log.Printf("[arp] sweep skipped: %v", err)
		return
	}
	warmARPCache(s.stopCh, targets)
}

// outboundIPv4 returns the local IPv4 the OS would use to reach the default route. A
// UDP "dial" sends no packets — it only selects the source address — so this is a
// passive, unprivileged self-IP probe.
func outboundIPv4() string {
	c, err := net.Dial("udp", "192.0.2.1:9") // RFC 5737 TEST-NET-1; nothing is sent
	if err != nil {
		return ""
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		return ua.IP.String()
	}
	return ""
}
