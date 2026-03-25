package discovery

import (
	"log"
	"sync"
	"time"
)

// ScanStatus represents the current state of the scanner.
type ScanStatus struct {
	Running       bool      `json:"running"`
	CurrentTarget string    `json:"current_target,omitempty"` // CIDR currently being scanned
	LastScan      time.Time `json:"last_scan,omitempty"`
	LastResult    *NmapResult `json:"-"`
	HostsFound    int       `json:"hosts_found"`
	Error         string    `json:"error,omitempty"`
}

// ScanTarget describes a network to scan (passed from the store layer).
type ScanTarget struct {
	ID        string
	Name      string
	CIDR      string
	Segment   string // default | iot | guest
	ScanPorts bool
}

// DeviceStore is the interface the scheduler uses to persist discoveries.
type DeviceStore interface {
	UpsertDevice(host DiscoveredHost, scanTime time.Time, segment ...string) (isNew bool, err error)
}

// TargetProvider loads scan targets from the database.
type TargetProvider interface {
	GetEnabledScanTargets() ([]ScanTarget, error)
	UpdateScanTargetLastScan(targetID string, t time.Time) error
}

// Scheduler runs nmap scans on a configurable interval.
type Scheduler struct {
	scanner        *Scanner
	store          DeviceStore
	targetProvider TargetProvider
	interval       time.Duration
	defaultCIDR    string
	defaultPorts   bool

	mu     sync.RWMutex
	status ScanStatus
	stop   chan struct{}
}

// NewScheduler creates a scan scheduler.
// defaultCIDR is the auto-detected or env-configured primary subnet.
// Additional targets come from the database via targetProvider.
func NewScheduler(scanner *Scanner, store DeviceStore, targetProvider TargetProvider, defaultCIDR string, interval time.Duration, defaultPorts bool) *Scheduler {
	return &Scheduler{
		scanner:        scanner,
		store:          store,
		targetProvider: targetProvider,
		interval:       interval,
		defaultCIDR:    defaultCIDR,
		defaultPorts:   defaultPorts,
		stop:           make(chan struct{}),
	}
}

// Start begins the periodic scan loop in a goroutine.
func (s *Scheduler) Start() {
	go func() {
		// Run first scan immediately
		s.runAllTargets()

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.runAllTargets()
			case <-s.stop:
				return
			}
		}
	}()
	log.Printf("Scan scheduler started: default_cidr=%s interval=%s", s.defaultCIDR, s.interval)
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	close(s.stop)
}

// RunNow triggers an immediate full scan of all targets.
func (s *Scheduler) RunNow() {
	go s.runAllTargets()
}

// RunTarget triggers a scan of a specific CIDR (for custom scan targets).
func (s *Scheduler) RunTarget(cidr, segment string, withPorts bool) {
	go s.runSingleTarget(ScanTarget{CIDR: cidr, Segment: segment, ScanPorts: withPorts})
}

// Status returns the current scan status.
func (s *Scheduler) Status() ScanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// DefaultCIDR returns the auto-detected or configured default scan CIDR.
func (s *Scheduler) DefaultCIDR() string {
	return s.defaultCIDR
}

// SetDefaultCIDR updates the default scan CIDR (e.g., after user confirmation).
func (s *Scheduler) SetDefaultCIDR(cidr string) {
	s.defaultCIDR = cidr
	log.Printf("Default scan CIDR updated to: %s", cidr)
}

// runAllTargets scans the default CIDR plus all enabled custom targets.
func (s *Scheduler) runAllTargets() {
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		log.Println("Scan already in progress, skipping")
		return
	}
	s.status.Running = true
	s.status.Error = ""
	s.mu.Unlock()

	totalHosts := 0

	// 1. Scan default CIDR
	if s.defaultCIDR != "" {
		hosts := s.scanCIDR(s.defaultCIDR, "default", s.defaultPorts)
		totalHosts += hosts
	}

	// 2. Scan custom targets from database
	if s.targetProvider != nil {
		targets, err := s.targetProvider.GetEnabledScanTargets()
		if err != nil {
			log.Printf("Failed to load scan targets: %v", err)
		} else {
			for _, t := range targets {
				hosts := s.scanCIDR(t.CIDR, t.Segment, t.ScanPorts)
				totalHosts += hosts
				if s.targetProvider != nil && t.ID != "" {
					s.targetProvider.UpdateScanTargetLastScan(t.ID, time.Now())
				}
			}
		}
	}

	s.mu.Lock()
	s.status.Running = false
	s.status.HostsFound = totalHosts
	s.status.LastScan = time.Now()
	s.status.CurrentTarget = ""
	s.mu.Unlock()

	log.Printf("All scans complete: %d total hosts found", totalHosts)
}

// runSingleTarget scans one specific target (used for on-demand custom scans).
func (s *Scheduler) runSingleTarget(target ScanTarget) {
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		log.Println("Scan already in progress, skipping")
		return
	}
	s.status.Running = true
	s.status.Error = ""
	s.mu.Unlock()

	hosts := s.scanCIDR(target.CIDR, target.Segment, target.ScanPorts)

	if s.targetProvider != nil && target.ID != "" {
		s.targetProvider.UpdateScanTargetLastScan(target.ID, time.Now())
	}

	s.mu.Lock()
	s.status.Running = false
	s.status.HostsFound = hosts
	s.status.LastScan = time.Now()
	s.status.CurrentTarget = ""
	s.mu.Unlock()
}

// scanCIDR runs nmap on a single CIDR and persists results. Returns host count.
func (s *Scheduler) scanCIDR(cidr, segment string, withPorts bool) int {
	s.mu.Lock()
	s.status.CurrentTarget = cidr
	s.mu.Unlock()

	log.Printf("Scanning %s (segment=%s, ports=%v)", cidr, segment, withPorts)
	result, err := s.scanner.Scan(cidr, withPorts)
	if err != nil {
		s.mu.Lock()
		s.status.Error = err.Error()
		s.mu.Unlock()
		log.Printf("Scan failed for %s: %v", cidr, err)
		return 0
	}

	log.Printf("Scan of %s complete: %d hosts in %s", cidr, len(result.Hosts), result.Duration)

	newCount := 0
	for _, host := range result.Hosts {
		isNew, err := s.store.UpsertDevice(host, result.ScanTime, segment)
		if err != nil {
			log.Printf("Failed to store device %s: %v", host.IPAddress, err)
			continue
		}
		if isNew {
			newCount++
			log.Printf("New device [%s]: %s (%s) vendor=%s", segment, host.IPAddress, host.MACAddress, host.Vendor)
		}
	}

	if newCount > 0 {
		log.Printf("%d new device(s) on %s", newCount, cidr)
	}

	return len(result.Hosts)
}
