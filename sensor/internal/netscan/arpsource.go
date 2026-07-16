package netscan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// defaultARPPollInterval is used when the configured reader cadence is non-positive
// (time.Ticker requires a positive duration).
const defaultARPPollInterval = 30 * time.Second

var (
	// errAlreadyRunning is returned by Source.Start when the source is already running.
	errAlreadyRunning = errors.New("arp source already running")
	// errStopped is returned by Source.Start after Stop. A Source is single-use: its
	// lifecycle channels are closed exactly once, so it cannot be restarted.
	errStopped = errors.New("arp source has been stopped and cannot be restarted")
)

// SourceConfig configures the unprivileged ARP-cache discovery source.
type SourceConfig struct {
	CIDR          string        // subnet to warm when Sweep is on (e.g. netscan.BestSubnet(""))
	OwnIP         string        // optional assertion of the resolved local IP; auto-detected if ""
	Interface     string        // optional interface scope; ""/"auto" resolves from CIDR
	Sweep         bool          // active cache warming (OFF by default)
	PollInterval  time.Duration // how often to read the neighbor cache
	SweepInterval time.Duration // how often to re-warm; <=0 => warm once at startup only
	// WaitForLink keeps a long-running source alive when an explicit CIDR is
	// configured before DHCP has assigned the matching local address. Resolution
	// retries are context-cancellable; the service does not need to restart.
	WaitForLink bool
	OnHost      func(DiscoveredHost) // legacy callback; must not block
	// OnHostContext is preferred for channel delivery. Returning false stops the
	// current snapshot; callers should select on ctx so Stop can interrupt backpressure.
	OnHostContext func(context.Context, DiscoveredHost) bool

	// Test seams are intentionally private so production callers cannot replace the
	// OS reader/dialer while package tests remain deterministic and race-safe.
	readNeighbors   func() ([]neighbor, error)
	dialContext     dialContextFunc
	now             func() time.Time
	detectSubnets   func() ([]DetectedSubnet, error)
	interfaceIndex  func(string) (int, error)
	scopeRetryDelay time.Duration
}

// Source reads the OS neighbor (ARP) cache on an interval and emits each resolved
// IP↔MAC as a cache-only DiscoveredHost{DiscoverySource:"arp_cache"} through the
// configured host callback.
// It emits only dynamic entries within the configured CIDR/interface and never marks
// cache presence as live/up. Reading is passive and unprivileged; the optional sweeper
// (Sweep) warms the cache first. Its lifecycle
// mirrors passive.Capturer: Start launches a background loop, Stop signals it and
// blocks until it has drained.
type Source struct {
	cfg               SourceConfig
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	doneCh            chan struct{}
	stopOnce          sync.Once
	run               bool
	stopped           bool
	scope             ipv4Scope
	selectedInterface string
	selectedIfIndex   int
	linkNetwork       *net.IPNet
	sweepCIDR         string
	ownIP             string
	snapshot          map[string]string
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
	if cfg.readNeighbors == nil {
		cfg.readNeighbors = readNeighbors
	}
	if cfg.dialContext == nil {
		cfg.dialContext = defaultDialContext
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.detectSubnets == nil {
		cfg.detectSubnets = DetectSubnets
	}
	if cfg.interfaceIndex == nil {
		cfg.interfaceIndex = func(name string) (int, error) {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return 0, err
			}
			return iface.Index, nil
		}
	}
	if cfg.scopeRetryDelay <= 0 {
		cfg.scopeRetryDelay = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Source{cfg: cfg, ctx: ctx, cancel: cancel, doneCh: make(chan struct{})}
}

// Start launches the background poll loop. It errors if the source is already running
// or has already been stopped (a Source is single-use — restarting would reuse the
// closed lifecycle channels and panic in loop()).
func (s *Source) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errStopped
	}
	if s.run {
		return errAlreadyRunning
	}
	scope, err := parseIPv4Scope(s.cfg.CIDR)
	if err != nil {
		return fmt.Errorf("invalid ARP discovery scope %q: %w", s.cfg.CIDR, err)
	}
	s.scope = scope
	if !s.cfg.WaitForLink {
		if err := s.configureLocalScope(); err != nil {
			return fmt.Errorf("resolve ARP discovery interface for %q: %w", s.cfg.CIDR, err)
		}
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
	s.stopOnce.Do(s.cancel)
	<-s.doneCh
	s.mu.Lock()
	s.run = false
	s.stopped = true
	s.mu.Unlock()
}

func (s *Source) loop() {
	defer close(s.doneCh)
	if s.linkNetwork == nil && !s.waitForLocalScope() {
		return
	}

	// Warm the cache FIRST (if enabled) so the initial read isn't empty for silent hosts.
	if s.cfg.Sweep {
		s.sweepCurrentScopeOnce()
	}
	s.readCurrentScopeOnce()

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
		case <-s.ctx.Done():
			return
		case <-readT.C:
			s.readCurrentScopeOnce()
		case <-sweepC:
			s.sweepCurrentScopeOnce()
			s.readCurrentScopeOnce() // read right after warming so freshly-resolved hosts surface
		}
	}
}

// readCurrentScopeOnce fail-closes each production poll around the OS cache
// read. Interface/address discovery and the neighbor-table read are separate OS
// operations; a DHCP readdress, route change, or ifIndex reuse between them must
// not attach rows from an old link generation to the configured segment.
func (s *Source) readCurrentScopeOnce() {
	if s.ctx.Err() != nil {
		return
	}
	before, err := s.refreshLocalScope()
	if err != nil {
		log.Printf("[arp] link revalidation failed for %s; withholding cache snapshot: %v", s.cfg.CIDR, err)
		return
	}
	neigh, err := s.cfg.readNeighbors()
	if err != nil {
		log.Printf("[arp] neighbor cache read failed: %v", err)
		return
	}
	if err := s.ctx.Err(); err != nil {
		return
	}
	after, err := s.resolveConfiguredLocalScope()
	if err != nil {
		s.invalidateLocalScope()
		log.Printf("[arp] link disappeared during neighbor read for %s; withholding snapshot: %v", s.cfg.CIDR, err)
		return
	}
	if !sameLocalScope(before, after) {
		s.applyLocalScope(after)
		log.Printf("[arp] link changed during neighbor read for %s; withholding old-generation snapshot", s.cfg.CIDR)
		return
	}
	s.processNeighborSnapshot(neigh)
}

// readOnce reads a cache snapshot and emits only new or changed dynamic mappings in
// the configured CIDR/interface. An unchanged OS cache row is not a new observation:
// re-emitting it on every poll would keep stale device/address timestamps alive in
// Core. A mapping that disappears from one successful snapshot is forgotten and will
// be emitted if it later reappears. Read errors deliberately retain the prior snapshot.
// Static/permanent mappings are configuration, not proof of current liveness, and are
// withheld from device observations.
func (s *Source) readOnce() {
	if s.ctx.Err() != nil {
		return
	}
	neigh, err := s.cfg.readNeighbors()
	if err != nil {
		log.Printf("[arp] neighbor cache read failed: %v", err)
		return
	}
	s.processNeighborSnapshot(neigh)
}

// processNeighborSnapshot applies an already source-scoped cache generation.
// Production reaches it only after readCurrentScopeOnce revalidates the link on
// both sides of the OS read; readOnce keeps deterministic unit seams concise.
func (s *Source) processNeighborSnapshot(neigh []neighbor) {
	if s.ctx.Err() != nil {
		return
	}
	type snapshotEntry struct {
		key      string
		value    string
		neighbor neighbor
	}
	current := make(map[string]string)
	dynamicByIP := make(map[string]map[string]neighbor)
	allByIP := make(map[string]map[string]struct{})
	carrierByIP := make(map[string]neighbor)
	// Count MAC reuse across the entire selected link, even when the configured
	// target is one IP or a narrower subnet. Proxy ARP outside the requested target
	// is still evidence that the MAC is not a safe device identity for an in-target
	// row. Candidate emission remains restricted to s.scope below.
	linkMACIPs := make(map[string]map[string]struct{})
	order := make([]string, 0, len(neigh))
	linkScope := ipv4Scope{network: s.linkNetwork}
	for _, n := range neigh {
		if (n.state != neighborStateDynamic && n.state != neighborStateStatic) ||
			!isRealNeighbor(n.ip, n.mac) {
			continue
		}
		parsedIP := net.ParseIP(n.ip).To4()
		if parsedIP == nil || s.linkNetwork == nil {
			continue
		}
		if !s.neighborOnSelectedInterface(n) {
			continue
		}
		ip := parsedIP.String()
		mac := strings.ToLower(n.mac)
		if linkMACIPs[mac] == nil {
			linkMACIPs[mac] = make(map[string]struct{})
		}
		linkMACIPs[mac][ip] = struct{}{}
		// Interface identity is the L2 boundary. A selected NIC can carry multiple
		// prefixes, so the link-wide MAC-reuse veto above deliberately includes
		// valid same-ifIndex rows outside the one resolved IPv4 prefix. Candidate
		// emission remains confined to the resolved link and requested scope.
		if !linkScope.containsHost(ip) {
			continue
		}
		if !s.scope.containsHost(ip) {
			continue
		}
		if allByIP[ip] == nil {
			allByIP[ip] = make(map[string]struct{})
			order = append(order, ip)
		}
		allByIP[ip][mac] = struct{}{}
		n.ip = ip
		n.mac = mac
		if _, exists := carrierByIP[ip]; !exists {
			carrierByIP[ip] = n
		}
		// Static/permanent rows can veto a dynamic mapping but never create a
		// new device observation by themselves. They remain in the snapshot so a
		// transition away from a prior unique dynamic edge emits a blank veto.
		if n.state != neighborStateDynamic {
			continue
		}
		if dynamicByIP[ip] == nil {
			dynamicByIP[ip] = make(map[string]neighbor)
		}
		dynamicByIP[ip][mac] = n
	}

	// Multiple different MACs for one IP on the selected interface are ambiguous.
	// Preserve an explicit blank transition when a formerly unique edge becomes
	// ambiguous, so Core's latest-state ledger cannot retain the stale MAC. A
	// static-only row still has no dynamic candidate and is never emitted.
	entries := make(map[string]snapshotEntry)
	for _, ip := range order {
		dynamicMACs := dynamicByIP[ip]
		entry := snapshotEntry{key: ip}
		if len(dynamicMACs) == 1 {
			for mac, n := range dynamicMACs {
				entry.value = mac
				entry.neighbor = n
			}
		} else if len(dynamicMACs) > 1 {
			// The MAC is intentionally blank; choose a deterministic-enough carrier
			// only for the shared IP/provenance fields. Map order cannot affect the
			// emitted identity because every conflicting case emits no MAC.
			for _, n := range dynamicMACs {
				entry.neighbor = n
				break
			}
		} else {
			entry.neighbor = carrierByIP[ip]
		}
		emittedMAC := entry.value
		if len(allByIP[ip]) != 1 || emittedMAC == "" || len(linkMACIPs[emittedMAC]) > 1 {
			emittedMAC = ""
		}
		entries[ip] = entry
		// Snapshot the externally emitted identity, not only the raw cache row.
		// Unique->ambiguous and ambiguous->unique transitions each produce an edge.
		current[ip] = emittedMAC
	}

	previous := s.snapshot
	s.snapshot = current
	observedAt := s.cfg.now().UTC()
	for _, key := range order {
		entry, exists := entries[key]
		if !exists {
			continue
		}
		if previous != nil {
			if previousValue, existed := previous[entry.key]; existed && previousValue == current[entry.key] {
				continue
			}
		}
		// An initially conflicting same-IP snapshot has no safe identity edge to
		// report. Remember its blank state locally so convergence emits a fresh
		// unique edge, but only send a blank veto when replacing prior state (or
		// when link-wide proxy reuse made an otherwise unique row ambiguous).
		if current[entry.key] == "" &&
			(len(dynamicByIP[entry.key]) == 0 || len(allByIP[entry.key]) > 1) {
			if _, existed := previous[entry.key]; !existed {
				continue
			}
		}
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		// A blank emitted MAC means the scoped edge is now ambiguous (same-IP
		// conflict, static veto, or one cache MAC answering for multiple IPs).
		// Keep IP presence, but assert no device identity.
		mac := current[entry.key]
		host := DiscoveredHost{
			IPAddress:       entry.neighbor.ip,
			MACAddress:      mac,
			Status:          "observed",
			DiscoverySource: "arp_cache",
			ObservedAt:      observedAt,
		}
		if s.cfg.OnHostContext != nil {
			if !s.cfg.OnHostContext(s.ctx, host) {
				return
			}
		} else if s.cfg.OnHost != nil {
			s.cfg.OnHost(host)
		}
	}
}

func (s *Source) neighborOnSelectedInterface(n neighbor) bool {
	if s.selectedIfIndex > 0 && n.ifIndex > 0 {
		return n.ifIndex == s.selectedIfIndex
	}
	// Missing interface evidence is never accepted: otherwise an unresolvable
	// Windows row or a parser regression can bypass the configured-link filter.
	return s.selectedInterface != "" && strings.TrimSpace(n.iface) != "" && n.iface == s.selectedInterface
}

func (s *Source) sweepCurrentScopeOnce() {
	if _, err := s.refreshLocalScope(); err != nil {
		log.Printf("[arp] link revalidation failed for %s; skipping sweep: %v", s.cfg.CIDR, err)
		return
	}
	s.sweepOnce()
}

// sweepOnce warms the neighbor cache for the configured subnet, excluding the sensor's
// own IP. Oversized/invalid subnets are logged and skipped (never truncated/dialed).
func (s *Source) sweepOnce() {
	if s.ownIP == "" {
		log.Printf("[arp] sweep skipped: no local IPv4 on resolved interface for %s", s.cfg.CIDR)
		return
	}
	targets, err := sweepTargets(s.sweepCIDR, s.ownIP)
	if err != nil {
		log.Printf("[arp] sweep skipped: %v", err)
		return
	}
	warmARPCache(s.ctx, targets, s.ownIP, s.cfg.dialContext)
}

// configureLocalScope resolves and stores one directly connected link. It performs no
// network traffic, and callers invoke it either synchronously from Start or from the
// single source loop before polling begins.
func (s *Source) configureLocalScope() error {
	scopeContext, err := s.resolveConfiguredLocalScope()
	if err != nil {
		return err
	}
	s.applyLocalScope(scopeContext)
	return nil
}

func (s *Source) resolveConfiguredLocalScope() (localScope, error) {
	scopeContext, err := resolveLocalScope(s.scope, s.cfg.Interface, s.cfg.detectSubnets, s.cfg.interfaceIndex)
	if err != nil {
		return localScope{}, err
	}
	if configured := strings.TrimSpace(s.cfg.OwnIP); configured != "" {
		parsed := net.ParseIP(configured).To4()
		assigned := net.ParseIP(scopeContext.ownIP).To4()
		if parsed == nil || assigned == nil || !parsed.Equal(assigned) {
			return localScope{}, fmt.Errorf("ARP sweep own IP %q is not assigned to the resolved link %s", s.cfg.OwnIP, scopeContext.iface)
		}
		scopeContext.ownIP = parsed.String()
	}
	return scopeContext, nil
}

func (s *Source) currentLocalScope() localScope {
	return localScope{
		iface: s.selectedInterface, ifIndex: s.selectedIfIndex,
		ownIP: s.ownIP, network: s.linkNetwork,
	}
}

func (s *Source) applyLocalScope(scopeContext localScope) {
	if !sameLocalScope(s.currentLocalScope(), scopeContext) {
		// A change-only snapshot belongs to one link generation. Clear it whenever
		// interface identity, source address, or connected prefix changes so the
		// recovered link emits its current edges afresh.
		s.snapshot = nil
	}
	s.selectedInterface = scopeContext.iface
	s.selectedIfIndex = scopeContext.ifIndex
	s.linkNetwork = scopeContext.network
	s.sweepCIDR = intersectingSweepTarget(s.scope, scopeContext.network)
	s.ownIP = scopeContext.ownIP
}

func (s *Source) invalidateLocalScope() {
	s.selectedInterface = ""
	s.selectedIfIndex = 0
	s.linkNetwork = nil
	s.sweepCIDR = ""
	s.ownIP = ""
	s.snapshot = nil
}

func (s *Source) refreshLocalScope() (localScope, error) {
	resolved, err := s.resolveConfiguredLocalScope()
	if err != nil {
		s.invalidateLocalScope()
		return localScope{}, err
	}
	s.applyLocalScope(resolved)
	return resolved, nil
}

// waitForLocalScope lets a service configured with an explicit CIDR survive a
// boot-before-DHCP race. It remains entirely post-front-end/SCM because Source.Start
// is invoked from startCaptures, and cancellation releases the retry promptly.
func (s *Source) waitForLocalScope() bool {
	for {
		if err := s.configureLocalScope(); err == nil {
			log.Printf("[arp] resolved %s on interface %s (%s)", s.cfg.CIDR, s.selectedInterface, s.ownIP)
			return true
		} else {
			log.Printf("[arp] no matching local link for %s yet; retrying in %s: %v", s.cfg.CIDR, s.cfg.scopeRetryDelay, err)
		}
		timer := time.NewTimer(s.cfg.scopeRetryDelay)
		select {
		case <-s.ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false
		case <-timer.C:
		}
	}
}

type localScope struct {
	iface   string
	ifIndex int
	ownIP   string
	network *net.IPNet
}

func sameLocalScope(a, b localScope) bool {
	return a.iface != "" && a.iface == b.iface && a.ifIndex > 0 && a.ifIndex == b.ifIndex &&
		a.ownIP == b.ownIP && a.network != nil && b.network != nil && a.network.String() == b.network.String()
}

// resolveLocalScope chooses the directly-connected link overlapping the configured
// target. It deliberately does not require the sensor's address to be inside a
// narrower scan target: 192.0.2.200/24 can safely monitor 192.0.2.0/26 on the same
// link. Off-link and ambiguous targets fail closed so cache rows from a VPN or other
// interface cannot be attributed to the LAN segment.
func resolveLocalScope(scope ipv4Scope, preferred string, detect func() ([]DetectedSubnet, error), interfaceIndex func(string) (int, error)) (localScope, error) {
	preferred = strings.TrimSpace(preferred)
	if preferred == "auto" {
		preferred = ""
	}
	subnets, err := detect()
	if err != nil {
		return localScope{}, fmt.Errorf("detect local subnets: %w", err)
	}
	candidatesByInterface := make(map[string]localScope)
	for _, subnet := range subnets {
		if preferred != "" && subnet.Interface != preferred {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(subnet.IPAddress)).To4()
		_, link, parseErr := net.ParseCIDR(strings.TrimSpace(subnet.CIDR))
		if ip == nil || parseErr != nil || link.IP.To4() == nil || !scopeOverlapsLink(scope, link) {
			continue
		}
		link.IP = link.IP.Mask(link.Mask).To4()
		index := 0
		if interfaceIndex != nil {
			var indexErr error
			index, indexErr = interfaceIndex(subnet.Interface)
			if indexErr != nil || index <= 0 {
				// Interface enumeration and index lookup are separate OS calls. The
				// link may disappear between them; never silently turn that race into
				// an unscoped cache/ICMP operation.
				continue
			}
		}
		candidate := localScope{iface: subnet.Interface, ifIndex: index, ownIP: ip.String(), network: link}
		// Multiple IPv4 addresses/aliases on one physical interface are still one
		// link choice. Prefer the most-specific containing subnet for sweep context.
		existing, exists := candidatesByInterface[candidate.iface]
		if exists && existing.network.String() != candidate.network.String() &&
			!existing.network.Contains(candidate.network.IP) &&
			!candidate.network.Contains(existing.network.IP) {
			return localScope{}, fmt.Errorf(
				"target matches multiple disjoint prefixes on interface %q; narrow the target",
				candidate.iface,
			)
		}
		candidatePrefix, _ := candidate.network.Mask.Size()
		existingPrefix := -1
		if exists {
			existingPrefix, _ = existing.network.Mask.Size()
		}
		if !exists || candidatePrefix > existingPrefix {
			candidatesByInterface[candidate.iface] = candidate
		}
	}
	if len(candidatesByInterface) == 0 {
		if preferred != "" {
			return localScope{}, fmt.Errorf("target is not directly connected on interface %q", preferred)
		}
		return localScope{}, errors.New("target is not directly connected to a local interface")
	}
	if len(candidatesByInterface) > 1 {
		return localScope{}, fmt.Errorf("target matches multiple local interfaces; select one explicitly")
	}
	for _, candidate := range candidatesByInterface {
		return candidate, nil
	}
	return localScope{}, errors.New("resolved local interface disappeared")
}

func scopeOverlapsLink(scope ipv4Scope, link *net.IPNet) bool {
	if link == nil || link.IP.To4() == nil {
		return false
	}
	if scope.single != nil {
		return link.Contains(scope.single)
	}
	if scope.network == nil {
		return false
	}
	targetStart := scope.network.IP.Mask(scope.network.Mask).To4()
	linkStart := link.IP.Mask(link.Mask).To4()
	return link.Contains(targetStart) || scope.network.Contains(linkStart)
}

// intersectingSweepTarget returns the narrower of two overlapping IPv4 CIDRs. ARP
// warming must stay on-link even when a configured scan target is wider than the
// interface subnet; passive reads remain filtered by both target and interface.
func intersectingSweepTarget(scope ipv4Scope, link *net.IPNet) string {
	if scope.single != nil {
		return scope.single.String()
	}
	if scope.network == nil || link == nil {
		return ""
	}
	targetPrefix, _ := scope.network.Mask.Size()
	linkPrefix, _ := link.Mask.Size()
	if targetPrefix >= linkPrefix {
		return scope.network.String()
	}
	return link.String()
}
