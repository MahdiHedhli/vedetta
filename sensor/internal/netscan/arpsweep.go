package netscan

import (
	"net"
	"sync"
	"time"
)

const (
	// arpSweepConcurrency bounds in-flight warm dials so a full subnet cannot spawn a
	// runaway goroutine pool on a Pi 4.
	arpSweepConcurrency = 200
	// arpSweepDialTimeout is the per-dial budget. The goal is only to elicit an L2 ARP
	// resolution, so a refused/timed-out connect is a success.
	arpSweepDialTimeout = 300 * time.Millisecond
)

// sweepTargets returns the addresses to warm for a subnet: every usable host in cidr
// minus the sensor's own IP. It reuses enumerateHosts verbatim, so the network and
// broadcast addresses are already excluded and a subnet larger than maxSweepHosts is
// REJECTED (error) rather than truncated. Deterministic and side-effect free — the
// unit-tested half of the sweeper.
func sweepTargets(cidr, ownIP string) ([]string, error) {
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range hosts {
		if ip == ownIP {
			continue
		}
		out = append(out, ip)
	}
	return out, nil
}

// warmARPCache performs unprivileged L2 warming: for each target it briefly touches a
// few common TCP/UDP ports so the kernel resolves the target's MAC into the neighbor
// cache. It opens NO raw sockets and needs no privilege; every dial error is expected
// and ignored (even a RST / ICMP-unreachable still triggers ARP resolution).
// Concurrency and per-dial time are bounded for the Pi 4 budget. It stops promptly when
// stopCh is closed, so shutdown is not blocked by an in-progress sweep.
func warmARPCache(stopCh <-chan struct{}, targets []string) {
	sem := make(chan struct{}, arpSweepConcurrency)
	var wg sync.WaitGroup
	for _, ip := range targets {
		select {
		case <-stopCh:
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			warmHost(stopCh, ip)
		}(ip)
	}
	wg.Wait()
}

// warmHost touches a small fixed set of TCP/UDP ports on one host to elicit an ARP
// resolution. All errors are intentionally ignored — no response is needed. It bails
// early if stopCh is closed (shutdown).
func warmHost(stopCh <-chan struct{}, ip string) {
	// TCP 80/443: a connect attempt (even one that RSTs) resolves the next-hop MAC.
	for _, p := range []string{"80", "443"} {
		select {
		case <-stopCh:
			return
		default:
		}
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, p), arpSweepDialTimeout); err == nil {
			_ = c.Close()
		}
	}
	// UDP discard (9) + traceroute (33434): a single-byte write makes the kernel
	// resolve the destination MAC; no reply is expected or required.
	for _, p := range []string{"9", "33434"} {
		select {
		case <-stopCh:
			return
		default:
		}
		c, err := net.DialTimeout("udp", net.JoinHostPort(ip, p), arpSweepDialTimeout)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(arpSweepDialTimeout))
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}
}
