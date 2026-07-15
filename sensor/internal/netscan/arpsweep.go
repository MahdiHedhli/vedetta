package netscan

import (
	"context"
	"net"
	"strings"
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

// dialContextFunc receives the resolved IPv4 address on the selected link. Passing
// it on every attempt makes source selection explicit and testable. LocalAddr is not
// an OS-level interface bind, so unusual policy routing may still choose another path;
// the cache reader separately revalidates and filters every accepted neighbor row.
type dialContextFunc func(context.Context, string, string, string) (net.Conn, error)

func defaultDialContext(ctx context.Context, network, address, sourceIP string) (net.Conn, error) {
	ip := net.ParseIP(sourceIP).To4()
	if ip == nil {
		return nil, &net.AddrError{Err: "invalid local IPv4 source", Addr: sourceIP}
	}
	dialer := net.Dialer{Timeout: arpSweepDialTimeout}
	switch {
	case strings.HasPrefix(network, "tcp"):
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	case strings.HasPrefix(network, "udp"):
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	default:
		return nil, &net.AddrError{Err: "unsupported ARP sweep network", Addr: network}
	}
	return dialer.DialContext(ctx, network, address)
}

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
// Concurrency and per-dial time are bounded for the Pi 4 budget. Context cancellation
// interrupts queued and in-flight dials so shutdown is not blocked by a sweep.
func warmARPCache(ctx context.Context, targets []string, sourceIP string, dial dialContextFunc) {
	sem := make(chan struct{}, arpSweepConcurrency)
	var wg sync.WaitGroup
	for _, ip := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			warmHost(ctx, ip, sourceIP, dial)
		}(ip)
	}
	wg.Wait()
}

// warmHost touches a small fixed set of TCP/UDP ports on one host to elicit an ARP
// resolution. All errors are intentionally ignored — no response is needed. It bails
// early if the context is cancelled (shutdown).
func warmHost(ctx context.Context, ip, sourceIP string, dial dialContextFunc) {
	// TCP 80/443: a connect attempt (even one that RSTs) resolves the next-hop MAC.
	for _, p := range []string{"80", "443"} {
		if ctx.Err() != nil {
			return
		}
		if c, err := dial(ctx, "tcp", net.JoinHostPort(ip, p), sourceIP); err == nil {
			_ = c.Close()
		}
	}
	// UDP discard (9) + traceroute (33434): a single-byte write makes the kernel
	// resolve the destination MAC; no reply is expected or required.
	for _, p := range []string{"9", "33434"} {
		if ctx.Err() != nil {
			return
		}
		c, err := dial(ctx, "udp", net.JoinHostPort(ip, p), sourceIP)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(arpSweepDialTimeout))
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}
}
