package main

import (
	"sync"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/dnscap"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// Synthetic values only (constitution): RFC 5737 IPs, 00:00:5E:00:53:xx MACs.

// TestMergePassiveHostPreservesFriendlyName verifies the enriched mDNS metadata
// (friendly name, model, services) survives folding with a later bare
// ARP/DHCP observation, so it reaches Core in the device report (spec 004 FR-3).
func TestMergePassiveHostPreservesFriendlyName(t *testing.T) {
	mdns := netscan.DiscoveredHost{
		IPAddress:       "192.0.2.57",
		Hostname:        "chromecast-1.local",
		FriendlyName:    "Living Room TV",
		Model:           "Chromecast Ultra",
		Services:        []string{"_googlecast._tcp"},
		Status:          "up",
		DiscoverySource: "passive_mdns",
	}
	// A later ARP observation carrying only IP+MAC for the same device.
	arp := netscan.DiscoveredHost{
		IPAddress:       "192.0.2.57",
		MACAddress:      "00:00:5E:00:53:0A",
		Status:          "up",
		DiscoverySource: "passive_arp",
	}

	merged := mergePassiveHost(mdns, arp)

	if merged.FriendlyName != "Living Room TV" {
		t.Fatalf("friendly name dropped on merge: got %q", merged.FriendlyName)
	}
	if merged.Model != "Chromecast Ultra" {
		t.Fatalf("model dropped on merge: got %q", merged.Model)
	}
	if len(merged.Services) != 1 || merged.Services[0] != "_googlecast._tcp" {
		t.Fatalf("services dropped on merge: got %v", merged.Services)
	}
	if merged.MACAddress != "00:00:5E:00:53:0A" {
		t.Fatalf("MAC not folded in: got %q", merged.MACAddress)
	}
}

// TestMergePassiveHostFromEmpty: merging into a zero-value host takes the
// observation wholesale (including friendly name).
func TestMergePassiveHostFromEmpty(t *testing.T) {
	observed := netscan.DiscoveredHost{
		IPAddress:    "192.0.2.58",
		FriendlyName: "Kitchen Display",
		Status:       "up",
	}
	merged := mergePassiveHost(netscan.DiscoveredHost{}, observed)
	if merged.FriendlyName != "Kitchen Display" {
		t.Fatalf("friendly name lost from empty merge: got %q", merged.FriendlyName)
	}
}

// TestShutdownCapturesClosesDNSChannel is the regression test for the beta-gate
// B8 shutdown deadlock: pushDNSQueries only returns when its channel is closed,
// and shutdown used to close only passiveHosts, so wg.Wait() blocked forever
// whenever DNS capture had started. shutdownCaptures must close the DNS channel
// too and return promptly.
func TestShutdownCapturesClosesDNSChannel(t *testing.T) {
	dnsQueries := make(chan dnscap.Query, 8)
	passiveHosts := make(chan netscan.DiscoveredHost, 8)

	var wg sync.WaitGroup
	wg.Add(2)
	// Model both push goroutines: each returns only when its channel is closed.
	go func() {
		defer wg.Done()
		for range dnsQueries {
		}
	}()
	go func() {
		defer wg.Done()
		for range passiveHosts {
		}
	}()

	done := make(chan struct{})
	go func() {
		shutdownCaptures(nil, nil, dnsQueries, passiveHosts, &wg) // nil capturers are guarded
		close(done)
	}()

	select {
	case <-done:
		// Both goroutines drained and returned → no deadlock.
	case <-time.After(3 * time.Second):
		t.Fatal("shutdownCaptures did not return within 3s — a capture channel was left open (B8 deadlock)")
	}
}

// TestShutdownCapturesNilChannels ensures shutdown is safe when capture is
// disabled (channels never created).
func TestShutdownCapturesNilChannels(t *testing.T) {
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		shutdownCaptures(nil, nil, nil, nil, &wg)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdownCaptures hung with nil channels")
	}
}
