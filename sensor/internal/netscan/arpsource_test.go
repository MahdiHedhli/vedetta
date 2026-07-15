package netscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sourceConfigOnTestLink(cfg SourceConfig) SourceConfig {
	cfg.detectSubnets = func() ([]DetectedSubnet, error) {
		return []DetectedSubnet{{Interface: "test0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
	}
	cfg.interfaceIndex = func(name string) (int, error) {
		if name != "test0" {
			return 0, errors.New("unknown test interface")
		}
		return 7, nil
	}
	return cfg
}

func mustTestNetwork(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse test network %q: %v", cidr, err)
	}
	return network
}

func TestNewSourceDefaults(t *testing.T) {
	if got := NewSource(SourceConfig{}).cfg.PollInterval; got != defaultARPPollInterval {
		t.Errorf("poll interval = %v, want default %v", got, defaultARPPollInterval)
	}
	// A supplied CIDR must be preserved (not overwritten by auto-detect).
	if got := NewSource(SourceConfig{CIDR: "192.0.2.0/24", PollInterval: time.Minute}).cfg.CIDR; got != "192.0.2.0/24" {
		t.Errorf("CIDR = %q, want preserved", got)
	}
}

func TestSourceLifecycleAndConcurrentStop(t *testing.T) {
	s := NewSource(sourceConfigOnTestLink(SourceConfig{
		CIDR:         "192.0.2.0/24",
		PollInterval: time.Hour,
		OnHost:       func(DiscoveredHost) {},
		readNeighbors: func() ([]neighbor, error) {
			return nil, nil
		},
	}))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Start(); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("second Start error = %v, want %v", err, errAlreadyRunning)
	}

	// Stop must be safe for simultaneous service-shutdown paths. The race suite
	// exercises the state transitions while every caller waits for the same loop.
	const callers = 20
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			s.Stop()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Stop calls did not return within 2s")
	}

	s.Stop() // idempotent after stopped
	if err := s.Start(); !errors.Is(err, errStopped) {
		t.Fatalf("Start after Stop error = %v, want %v", err, errStopped)
	}
}

func TestSourceFiltersScopeInterfaceStaticAndInvalidEntries(t *testing.T) {
	fixed := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	emitted := make(chan DiscoveredHost, 8)
	s := NewSource(sourceConfigOnTestLink(SourceConfig{
		CIDR:         "192.0.2.0/26",
		Interface:    "test0",
		PollInterval: time.Hour,
		OnHost:       func(host DiscoveredHost) { emitted <- host },
		now:          func() time.Time { return fixed },
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{
				{ip: "192.0.2.5", mac: "00:00:5e:00:53:01", iface: "test0", state: neighborStateDynamic},
				{ip: "192.0.2.6", mac: "00:00:5e:00:53:02", iface: "other0", state: neighborStateDynamic},
				{ip: "192.0.2.70", mac: "00:00:5e:00:53:03", iface: "test0", state: neighborStateDynamic},
				{ip: "192.0.2.63", mac: "00:00:5e:00:53:04", iface: "test0", state: neighborStateDynamic},
				{ip: "192.0.2.7", mac: "00:00:5e:00:53:05", iface: "test0", state: neighborStateStatic},
				{ip: "192.0.2.8", mac: "01:80:c2:00:00:00", iface: "test0", state: neighborStateDynamic},
			}, nil
		},
	}))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var got DiscoveredHost
	select {
	case got = <-emitted:
	case <-time.After(time.Second):
		s.Stop()
		t.Fatal("valid scoped dynamic neighbor was not emitted")
	}
	s.Stop()
	if got.IPAddress != "192.0.2.5" || got.MACAddress != "00:00:5e:00:53:01" {
		t.Fatalf("emitted host = %+v, want only scoped test0 mapping", got)
	}
	if got.Status != "observed" || got.DiscoverySource != "arp_cache" || !got.ObservedAt.Equal(fixed) {
		t.Fatalf("emitted provenance = %+v, want cache-only observation at %v", got, fixed)
	}
	select {
	case extra := <-emitted:
		t.Fatalf("unexpected unscoped/static/invalid observation: %+v", extra)
	default:
	}
}

func TestSourceUnchangedCacheRowDoesNotRefreshObservation(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	current := []neighbor{{ip: "192.0.2.9", mac: "00:00:5e:00:53:09", iface: "test0", state: neighborStateDynamic}}
	var readErr error
	now := time.Date(2026, 7, 15, 13, 0, 0, 0, time.UTC)
	var emitted []DiscoveredHost
	s := NewSource(sourceConfigOnTestLink(SourceConfig{
		CIDR:   "192.0.2.0/24",
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
		now:    func() time.Time { return now },
		readNeighbors: func() ([]neighbor, error) {
			return current, readErr
		},
	}))
	s.scope = scope
	s.selectedInterface = "test0"
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")

	s.readOnce()
	if len(emitted) != 1 {
		t.Fatalf("initial cache edge emitted %d observations, want 1", len(emitted))
	}
	firstObservedAt := emitted[0].ObservedAt

	now = now.Add(time.Hour)
	s.readOnce() // unchanged row must not refresh Core timestamps
	if len(emitted) != 1 || !emitted[0].ObservedAt.Equal(firstObservedAt) {
		t.Fatalf("unchanged cache row refreshed observation: %+v", emitted)
	}

	readErr = errors.New("synthetic read failure")
	s.readOnce()
	readErr = nil
	s.readOnce() // a read error must not manufacture a disappearance/reappearance edge
	if len(emitted) != 1 {
		t.Fatalf("read failure caused unchanged row to re-emit: %+v", emitted)
	}

	current = []neighbor{{ip: "192.0.2.9", mac: "00:00:5e:00:53:0a", iface: "test0", state: neighborStateDynamic}}
	now = now.Add(time.Hour)
	s.readOnce() // changed owner at the same IP is a real edge
	if len(emitted) != 2 || emitted[1].MACAddress != "00:00:5e:00:53:0a" {
		t.Fatalf("changed cache mapping was not emitted: %+v", emitted)
	}

	current = nil
	s.readOnce()
	current = []neighbor{{ip: "192.0.2.9", mac: "00:00:5e:00:53:0a", iface: "test0", state: neighborStateDynamic}}
	now = now.Add(time.Hour)
	s.readOnce() // reappearance after a successful absent snapshot is a real edge
	if len(emitted) != 3 || !emitted[2].ObservedAt.Equal(now) {
		t.Fatalf("cache reappearance was not emitted: %+v", emitted)
	}
}

func TestSourceProxyARPAndConflictingRowsStayProvisional(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	proxyMAC := "00:00:5e:00:53:44"
	rows := []neighbor{
		{ip: "192.0.2.41", mac: proxyMAC, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.42", mac: proxyMAC, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.43", mac: "00:00:5e:00:53:45", iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.43", mac: "00:00:5e:00:53:46", iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		// An identical duplicate is unambiguous and must collapse to one edge.
		{ip: "192.0.2.44", mac: "00:00:5e:00:53:47", iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.44", mac: "00:00:5e:00:53:47", iface: "test0", ifIndex: 7, state: neighborStateDynamic},
	}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		readNeighbors: func() ([]neighbor, error) {
			return rows, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "test0"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()

	got := make(map[string]DiscoveredHost)
	for _, host := range emitted {
		got[host.IPAddress] = host
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d unique hosts, want two proxy IPs plus one deduplicated row: %+v", len(got), emitted)
	}
	for _, ip := range []string{"192.0.2.41", "192.0.2.42"} {
		if host, ok := got[ip]; !ok || host.MACAddress != "" {
			t.Fatalf("proxy-ARP host %s = %+v, want provisional host with blank MAC", ip, host)
		}
	}
	if _, ok := got["192.0.2.43"]; ok {
		t.Fatalf("conflicting same-IP rows were not withheld: %+v", got["192.0.2.43"])
	}
	if host := got["192.0.2.44"]; host.MACAddress != "00:00:5e:00:53:47" {
		t.Fatalf("identical duplicate did not collapse cleanly: %+v", host)
	}

	rows = []neighbor{{
		ip: "192.0.2.43", mac: "00:00:5e:00:53:46", iface: "test0", ifIndex: 7, state: neighborStateDynamic,
	}}
	s.readOnce()
	if len(emitted) != 4 || emitted[3].IPAddress != "192.0.2.43" || emitted[3].MACAddress == "" {
		t.Fatalf("resolved ambiguity did not produce a new unambiguous cache edge: %+v", emitted)
	}
}

func TestSourceEmitsProxyClassificationTransitions(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	mac := "00:00:5e:00:53:60"
	rows := []neighbor{{
		ip: "192.0.2.60", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateDynamic,
	}}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		readNeighbors: func() ([]neighbor, error) {
			return rows, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "test0"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()
	if len(emitted) != 1 || emitted[0].MACAddress != mac {
		t.Fatalf("initial unique cache edge = %+v", emitted)
	}

	rows = append(rows, neighbor{
		ip: "192.0.2.61", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateDynamic,
	})
	s.readOnce()
	if len(emitted) != 3 || emitted[1].IPAddress != "192.0.2.60" || emitted[1].MACAddress != "" ||
		emitted[2].IPAddress != "192.0.2.61" || emitted[2].MACAddress != "" {
		t.Fatalf("unique-to-proxy transition did not blank every affected IP: %+v", emitted)
	}

	rows = rows[:1]
	s.readOnce()
	if len(emitted) != 4 || emitted[3].IPAddress != "192.0.2.60" || emitted[3].MACAddress != mac {
		t.Fatalf("proxy-to-unique transition was not re-emitted: %+v", emitted)
	}
}

func TestSourceEmitsBlankWhenStaticEvidenceVetoesPriorUniqueMapping(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	mac := "00:00:5e:00:53:68"
	rows := []neighbor{{
		ip: "192.0.2.68", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateDynamic,
	}}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		readNeighbors: func() ([]neighbor, error) {
			return rows, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "test0"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()
	if len(emitted) != 1 || emitted[0].MACAddress != mac {
		t.Fatalf("initial unique cache edge = %+v", emitted)
	}

	rows = []neighbor{{
		ip: "192.0.2.68", mac: "00:00:5e:00:53:69", iface: "test0", ifIndex: 7, state: neighborStateStatic,
	}}
	s.readOnce()
	if len(emitted) != 2 || emitted[1].IPAddress != "192.0.2.68" || emitted[1].MACAddress != "" {
		t.Fatalf("static-only transition did not emit a blank veto: %+v", emitted)
	}

	rows = []neighbor{
		{ip: "192.0.2.68", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.68", mac: "00:00:5e:00:53:69", iface: "test0", ifIndex: 7, state: neighborStateStatic},
	}
	s.readOnce()
	if len(emitted) != 2 {
		t.Fatalf("equally ambiguous dynamic/static state re-emitted unexpectedly: %+v", emitted)
	}

	// Static reuse on a second prefix of the same interface is also link-wide
	// ambiguity even though the candidate itself remains inside linkNetwork.
	rows = []neighbor{
		{ip: "192.0.2.68", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		{ip: "198.51.100.68", mac: mac, iface: "test0", ifIndex: 7, state: neighborStateStatic},
	}
	s.readOnce()
	if len(emitted) != 2 {
		t.Fatalf("equally ambiguous cross-prefix state re-emitted unexpectedly: %+v", emitted)
	}

	rows = rows[:1]
	s.readOnce()
	if len(emitted) != 3 || emitted[2].MACAddress != mac {
		t.Fatalf("static-veto convergence did not restore unique edge: %+v", emitted)
	}
}

func TestSourceNarrowTargetClassifiesProxyAcrossWholeSelectedLink(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/26")
	if err != nil {
		t.Fatal(err)
	}
	proxyMAC := "00:00:5e:00:53:70"
	rows := []neighbor{
		{ip: "192.0.2.10", mac: proxyMAC, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
		// Outside /26 but inside the selected /24 link. It must make the in-target
		// row provisional instead of disappearing from proxy classification.
		{ip: "192.0.2.200", mac: proxyMAC, iface: "test0", ifIndex: 7, state: neighborStateDynamic},
	}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/26",
		readNeighbors: func() ([]neighbor, error) {
			return rows, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "test0"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()

	if len(emitted) != 1 || emitted[0].IPAddress != "192.0.2.10" || emitted[0].MACAddress != "" {
		t.Fatalf("narrow target did not withhold link-wide proxy MAC: %+v", emitted)
	}
}

func TestSourceInterfaceIndexScopesOverlappingNeighborRows(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{
				{ip: "192.0.2.50", mac: "00:00:5e:00:53:50", iface: "lan", ifIndex: 7, state: neighborStateDynamic},
				{ip: "192.0.2.50", mac: "00:00:5e:00:53:51", iface: "vpn", ifIndex: 8, state: neighborStateDynamic},
				{ip: "192.0.2.51", mac: "00:00:5e:00:53:52", state: neighborStateDynamic},
			}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "lan"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()
	if len(emitted) != 1 || emitted[0].IPAddress != "192.0.2.50" || emitted[0].MACAddress != "00:00:5e:00:53:50" {
		t.Fatalf("selected interface did not isolate overlapping rows: %+v", emitted)
	}
}

func TestSourceRevalidatesScopeAndRecoversAfterLinkDisappears(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	phase := 0
	reads := 0
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		detectSubnets: func() ([]DetectedSubnet, error) {
			switch phase {
			case 0:
				return []DetectedSubnet{{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
			case 1:
				return nil, nil
			default:
				return []DetectedSubnet{{Interface: "lan1", IPAddress: "192.0.2.201", CIDR: "192.0.2.0/24"}}, nil
			}
		},
		interfaceIndex: func(name string) (int, error) {
			if name == "lan0" {
				return 7, nil
			}
			if name == "lan1" {
				return 8, nil
			}
			return 0, errors.New("unknown interface")
		},
		readNeighbors: func() ([]neighbor, error) {
			reads++
			if phase == 0 {
				return []neighbor{{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", iface: "lan0", ifIndex: 7, state: neighborStateDynamic}}, nil
			}
			return []neighbor{{ip: "192.0.2.11", mac: "00:00:5e:00:53:11", iface: "lan1", ifIndex: 8, state: neighborStateDynamic}}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.readCurrentScopeOnce()
	if len(emitted) != 1 || emitted[0].IPAddress != "192.0.2.10" {
		t.Fatalf("initial link generation = %+v", emitted)
	}

	phase = 1
	s.readCurrentScopeOnce()
	if reads != 1 || s.linkNetwork != nil || len(emitted) != 1 {
		t.Fatalf("missing link was not withheld/invalidated: reads=%d scope=%+v emitted=%+v", reads, s.currentLocalScope(), emitted)
	}

	phase = 2
	s.readCurrentScopeOnce()
	if len(emitted) != 2 || emitted[1].IPAddress != "192.0.2.11" || s.selectedIfIndex != 8 {
		t.Fatalf("recovered link generation = scope=%+v emitted=%+v", s.currentLocalScope(), emitted)
	}
}

func TestSourceDiscardsRowsWhenScopeChangesDuringNeighborRead(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	phase := 0
	reads := 0
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		detectSubnets: func() ([]DetectedSubnet, error) {
			if phase == 0 {
				return []DetectedSubnet{{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
			}
			return []DetectedSubnet{{Interface: "lan1", IPAddress: "192.0.2.201", CIDR: "192.0.2.0/24"}}, nil
		},
		interfaceIndex: func(name string) (int, error) {
			if name == "lan0" {
				return 7, nil
			}
			return 8, nil
		},
		readNeighbors: func() ([]neighbor, error) {
			reads++
			if reads == 1 {
				phase = 1
				return []neighbor{{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", iface: "lan0", ifIndex: 7, state: neighborStateDynamic}}, nil
			}
			return []neighbor{{ip: "192.0.2.11", mac: "00:00:5e:00:53:11", iface: "lan1", ifIndex: 8, state: neighborStateDynamic}}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.readCurrentScopeOnce()
	if len(emitted) != 0 || s.selectedIfIndex != 8 {
		t.Fatalf("old-generation rows escaped topology change: scope=%+v emitted=%+v", s.currentLocalScope(), emitted)
	}
	s.readCurrentScopeOnce()
	if len(emitted) != 1 || emitted[0].IPAddress != "192.0.2.11" {
		t.Fatalf("new generation did not recover cleanly: %+v", emitted)
	}
}

func TestSourceFiltersWideTargetToResolvedLinkNetwork(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.0.0/16",
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{
				{ip: "192.0.2.50", mac: "00:00:5e:00:53:50", iface: "lan", ifIndex: 7, state: neighborStateDynamic},
				// This row is in the configured /16 and on the same interface, but
				// outside that interface's resolved /24 link.
				{ip: "192.0.3.51", mac: "00:00:5e:00:53:51", iface: "lan", ifIndex: 7, state: neighborStateDynamic},
				// The wide configured target must not turn the resolved link's network
				// and broadcast addresses into hosts either.
				{ip: "192.0.2.0", mac: "00:00:5e:00:53:52", iface: "lan", ifIndex: 7, state: neighborStateDynamic},
				{ip: "192.0.2.255", mac: "00:00:5e:00:53:53", iface: "lan", ifIndex: 7, state: neighborStateDynamic},
			}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "lan"
	s.selectedIfIndex = 7
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()
	if len(emitted) != 1 || emitted[0].IPAddress != "192.0.2.50" {
		t.Fatalf("wide target emitted off-link cache rows: %+v", emitted)
	}
}

func TestResolveLocalScopeUsesContainingLinkAndFailsClosed(t *testing.T) {
	detect := func() ([]DetectedSubnet, error) {
		return []DetectedSubnet{
			{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"},
			{Interface: "vpn0", IPAddress: "198.51.100.2", CIDR: "198.51.100.0/24"},
		}, nil
	}
	index := func(name string) (int, error) {
		if name == "lan0" {
			return 7, nil
		}
		return 8, nil
	}
	narrow, _ := parseIPv4Scope("192.0.2.0/26")
	resolved, err := resolveLocalScope(narrow, "", detect, index)
	if err != nil {
		t.Fatalf("narrow same-link target did not resolve: %v", err)
	}
	if resolved.iface != "lan0" || resolved.ifIndex != 7 || resolved.ownIP != "192.0.2.200" {
		t.Fatalf("resolved link = %+v, want lan0/index 7/own IP outside target", resolved)
	}
	if got := intersectingSweepTarget(narrow, resolved.network); got != "192.0.2.0/26" {
		t.Fatalf("narrow-target sweep scope = %q, want target /26", got)
	}
	wider, _ := parseIPv4Scope("192.0.0.0/16")
	wideResolved, err := resolveLocalScope(wider, "", detect, index)
	if err != nil || wideResolved.iface != "lan0" {
		t.Fatalf("wider overlapping target did not resolve its only local link: resolved=%+v err=%v", wideResolved, err)
	}
	if got := intersectingSweepTarget(wider, wideResolved.network); got != "192.0.2.0/24" {
		t.Fatalf("wide-target sweep escaped local link: got %q, want local /24", got)
	}

	offLink, _ := parseIPv4Scope("203.0.113.0/24")
	if _, err := resolveLocalScope(offLink, "", detect, index); err == nil {
		t.Fatal("off-link target unexpectedly resolved")
	}
	if _, err := resolveLocalScope(narrow, "vpn0", detect, index); err == nil {
		t.Fatal("explicit wrong interface unexpectedly resolved")
	}
	if _, err := resolveLocalScope(narrow, "", func() ([]DetectedSubnet, error) { return nil, nil }, index); err == nil {
		t.Fatal("empty interface detection unexpectedly resolved")
	}
	aliases := func() ([]DetectedSubnet, error) {
		return []DetectedSubnet{
			{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"},
			{Interface: "lan0", IPAddress: "192.0.2.100", CIDR: "192.0.2.0/25"},
		}, nil
	}
	if resolved, err := resolveLocalScope(narrow, "", aliases, index); err != nil || resolved.iface != "lan0" || resolved.network.String() != "192.0.2.0/25" {
		t.Fatalf("same-interface aliases were treated as ambiguity: resolved=%+v err=%v", resolved, err)
	}

	ambiguous := func() ([]DetectedSubnet, error) {
		return []DetectedSubnet{
			{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"},
			{Interface: "lan1", IPAddress: "192.0.2.201", CIDR: "192.0.2.0/24"},
		}, nil
	}
	if _, err := resolveLocalScope(narrow, "", ambiguous, index); err == nil {
		t.Fatal("ambiguous directly-connected interfaces unexpectedly auto-selected")
	}
	if resolved, err := resolveLocalScope(narrow, "lan0", ambiguous, index); err != nil || resolved.iface != "lan0" {
		t.Fatalf("explicit interface did not disambiguate: resolved=%+v err=%v", resolved, err)
	}
	if _, err := resolveLocalScope(narrow, "lan0", detect, func(string) (int, error) {
		return 0, errors.New("interface disappeared")
	}); err == nil {
		t.Fatal("interface-index disappearance unexpectedly produced an unscoped link")
	}
}

func TestSourceStartRejectsInvalidScopeAndOutOfScopeOwnIP(t *testing.T) {
	invalid := NewSource(SourceConfig{CIDR: "not-a-cidr", readNeighbors: func() ([]neighbor, error) { return nil, nil }})
	if err := invalid.Start(); err == nil {
		t.Fatal("invalid CIDR unexpectedly started")
	}
	outside := NewSource(sourceConfigOnTestLink(SourceConfig{
		CIDR: "192.0.2.0/24", OwnIP: "198.51.100.7",
		readNeighbors: func() ([]neighbor, error) { return nil, nil },
	}))
	if err := outside.Start(); err == nil {
		t.Fatal("out-of-scope sweep own IP unexpectedly started")
	}
}

func TestSourceStopCancelsActiveSweep(t *testing.T) {
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/29", OwnIP: "192.0.2.1", Interface: "test0", Sweep: true,
		PollInterval: time.Hour,
		detectSubnets: func() ([]DetectedSubnet, error) {
			return []DetectedSubnet{{Interface: "test0", IPAddress: "192.0.2.1", CIDR: "192.0.2.0/29"}}, nil
		},
		interfaceIndex: func(string) (int, error) { return 7, nil },
		readNeighbors:  func() ([]neighbor, error) { return nil, nil },
		dialContext: func(ctx context.Context, _, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			select {
			case cancelled <- struct{}{}:
			default:
			}
			return nil, ctx.Err()
		},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		s.Stop()
		t.Fatal("active sweep did not begin")
	}
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel an in-flight sweep")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("sweep dial did not observe context cancellation")
	}
}

func TestSourceStopCancelsBlockedHostEnqueue(t *testing.T) {
	blocked := make(chan DiscoveredHost) // deliberately full: no receiver
	callbackStarted := make(chan struct{}, 1)
	s := NewSource(sourceConfigOnTestLink(SourceConfig{
		CIDR: "192.0.2.0/24", Interface: "test0", PollInterval: time.Hour,
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{{
				ip: "192.0.2.31", mac: "00:00:5e:00:53:31", iface: "test0", state: neighborStateDynamic,
			}}, nil
		},
		OnHostContext: func(ctx context.Context, host DiscoveredHost) bool {
			select {
			case callbackStarted <- struct{}{}:
			default:
			}
			select {
			case blocked <- host:
				return true
			case <-ctx.Done():
				return false
			}
		},
	}))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		s.Stop()
		t.Fatal("host callback did not reach blocked enqueue")
	}
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel a blocked host enqueue")
	}
}

func TestSourceWaitForLinkReconcilesAfterBootBeforeDHCP(t *testing.T) {
	var calls atomic.Int32
	emitted := make(chan DiscoveredHost, 1)
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24", WaitForLink: true, PollInterval: time.Hour,
		scopeRetryDelay: 5 * time.Millisecond,
		detectSubnets: func() ([]DetectedSubnet, error) {
			if calls.Add(1) == 1 {
				return nil, nil // service started before DHCP assigned the link
			}
			return []DetectedSubnet{{Interface: "lan0", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
		},
		interfaceIndex: func(string) (int, error) { return 7, nil },
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{{
				ip: "192.0.2.31", mac: "00:00:5e:00:53:31", iface: "lan0", ifIndex: 7, state: neighborStateDynamic,
			}}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted <- host },
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start before DHCP: %v", err)
	}
	defer s.Stop()
	select {
	case host := <-emitted:
		if host.IPAddress != "192.0.2.31" || s.selectedInterface != "lan0" || s.ownIP != "192.0.2.200" {
			t.Fatalf("reconciled observation/scope = host %+v interface %q ownIP %q", host, s.selectedInterface, s.ownIP)
		}
	case <-time.After(time.Second):
		t.Fatal("ARP source did not reconcile after matching link appeared")
	}
	if calls.Load() < 2 {
		t.Fatalf("subnet detection calls = %d, want initial empty topology plus retry", calls.Load())
	}
}

func TestSourceWaitForLinkStopCancelsRetry(t *testing.T) {
	firstAttempt := make(chan struct{}, 1)
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24", WaitForLink: true, scopeRetryDelay: time.Hour,
		detectSubnets: func() ([]DetectedSubnet, error) {
			firstAttempt <- struct{}{}
			return nil, nil
		},
		readNeighbors: func() ([]neighbor, error) { return nil, nil },
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start before link: %v", err)
	}
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		t.Fatal("initial link resolution did not run")
	}
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel boot-before-DHCP retry")
	}
}

func TestSourceSweepBindsResolvedLinkAddress(t *testing.T) {
	dialed := make(chan struct {
		network, address, source string
	}, 4)
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/30", Interface: "test0", Sweep: true, PollInterval: time.Hour,
		detectSubnets: func() ([]DetectedSubnet, error) {
			return []DetectedSubnet{{Interface: "test0", IPAddress: "192.0.2.1", CIDR: "192.0.2.0/30"}}, nil
		},
		interfaceIndex: func(string) (int, error) { return 7, nil },
		readNeighbors:  func() ([]neighbor, error) { return nil, nil },
		dialContext: func(_ context.Context, network, address, source string) (net.Conn, error) {
			dialed <- struct{ network, address, source string }{network, address, source}
			return nil, errors.New("synthetic no-connect")
		},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	for i := 0; i < 4; i++ { // TCP 80/443 plus UDP 9/33434 for the only non-own host
		select {
		case got := <-dialed:
			if got.source != "192.0.2.1" {
				t.Fatalf("dial %d source = %q, want selected-link address", i, got.source)
			}
			if host, _, err := net.SplitHostPort(got.address); err != nil || host != "192.0.2.2" {
				t.Fatalf("dial %d address = %q err=%v, want only on-link target 192.0.2.2", i, got.address, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("sweep dial %d did not run", i)
		}
	}
}
