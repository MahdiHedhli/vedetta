package netscan

import (
	"reflect"
	"testing"
)

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
	// IPv6 has no ARP; enumerateHosts returns no targets (nil, nil), so nothing to warm.
	if got, err := sweepTargets("2001:db8::/64", ""); err != nil || len(got) != 0 {
		t.Fatalf("IPv6: got %v err %v, want empty", got, err)
	}
}
