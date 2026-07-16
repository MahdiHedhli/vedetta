package netscan

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestWarmARPCacheHonorsCancelledContext(t *testing.T) {
	// A pre-cancelled context must make the sweep return promptly without dialing,
	// so shutdown is never blocked by an in-progress sweep.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dials := 0
	done := make(chan struct{})
	go func() {
		warmARPCache(ctx, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, "192.0.2.254", func(context.Context, string, string, string) (net.Conn, error) {
			dials++
			return nil, nil
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("warmARPCache did not honor a cancelled context promptly")
	}
	if dials != 0 {
		t.Fatalf("cancelled sweep made %d dials, want 0", dials)
	}
}

func TestWarmARPCacheCancelsInFlightDials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		warmARPCache(ctx, []string{"192.0.2.1"}, "192.0.2.254", func(ctx context.Context, _, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sweep dial did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("in-flight sweep dial ignored cancellation")
	}
}

func TestSweepTargets(t *testing.T) {
	// /29 -> usable .1..6 (network .0 and broadcast .7 excluded by enumerateHosts);
	// own IP .3 is dropped by sweepTargets. Order is deterministic (ascending).
	got, err := sweepTargets("192.0.2.0/29", "192.0.2.3")
	if err != nil {
		t.Fatalf("sweepTargets: %v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (network/broadcast excluded, own IP skipped)", got, want)
	}
}

func TestSweepTargets_RejectsOversizedSubnet(t *testing.T) {
	// A /16 exceeds maxSweepHosts (1024); enumerateHosts rejects it, so the sweep is
	// never run against a runaway range rather than being silently truncated.
	if _, err := sweepTargets("10.0.0.0/16", "10.0.0.5"); err == nil {
		t.Fatal("expected an oversized subnet to be rejected, got nil error")
	}
}

func TestSweepTargets_SingleHostAndIPv6(t *testing.T) {
	// A bare IPv4 yields just itself (unless it's our own IP).
	got, err := sweepTargets("192.0.2.50", "")
	if err != nil {
		t.Fatalf("sweepTargets bare IP: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"192.0.2.50"}) {
		t.Fatalf("bare IP: got %v, want [192.0.2.50]", got)
	}
	// Active discovery is explicitly IPv4-only. Reject IPv6 instead of silently
	// treating an unsupported operator target as a successful empty sweep.
	if got, err := sweepTargets("2001:db8::/64", ""); err == nil || len(got) != 0 {
		t.Fatalf("IPv6: got %v err %v, want explicit unsupported-target error", got, err)
	}
}
