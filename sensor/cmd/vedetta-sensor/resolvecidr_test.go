package main

import (
	"context"
	"testing"
	"time"
)

// TestResolveScanCIDR covers the boot-before-DHCP path that the Windows service must
// survive: auto-detection must retry (not fatal) until an address appears, abort
// promptly on cancel, and never block when a subnet is explicitly configured.
func TestResolveScanCIDR(t *testing.T) {
	origBest, origDelay := bestSubnet, subnetRetryDelay
	t.Cleanup(func() { bestSubnet, subnetRetryDelay = origBest, origDelay })
	subnetRetryDelay = time.Millisecond

	t.Run("explicit cidr never calls the detector", func(t *testing.T) {
		bestSubnet = func(string) string { t.Fatal("detector must not run for an explicit CIDR"); return "" }
		r := &sensorRun{cidrFlag: "192.168.5.0/24"}
		got, err := r.resolveScanCIDR(context.Background(), true)
		if err != nil || got != "192.168.5.0/24" {
			t.Fatalf("got (%q,%v), want (192.168.5.0/24,nil)", got, err)
		}
	})

	t.Run("no wait: empty detection errors, not fatal", func(t *testing.T) {
		bestSubnet = func(string) string { return "" }
		r := &sensorRun{cidrFlag: "auto"}
		if _, err := r.resolveScanCIDR(context.Background(), false); err == nil {
			t.Fatal("expected an error when auto-detect finds nothing and wait=false")
		}
	})

	t.Run("wait: retries until an address appears (boot before DHCP)", func(t *testing.T) {
		calls := 0
		bestSubnet = func(string) string {
			calls++
			if calls < 3 {
				return "" // no address yet
			}
			return "10.0.30.0/24" // DHCP assigned
		}
		r := &sensorRun{cidrFlag: "auto"}
		got, err := r.resolveScanCIDR(context.Background(), true)
		if err != nil || got != "10.0.30.0/24" {
			t.Fatalf("got (%q,%v) after %d tries, want (10.0.30.0/24,nil)", got, err, calls)
		}
		if calls < 3 {
			t.Fatalf("expected retries, got %d calls", calls)
		}
	})

	t.Run("wait: cancel aborts promptly (never hangs, never fatal)", func(t *testing.T) {
		bestSubnet = func(string) string { return "" } // never resolves
		subnetRetryDelay = time.Hour                    // would hang if cancel were ignored
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() {
			_, err := (&sensorRun{cidrFlag: "auto"}).resolveScanCIDR(ctx, true)
			if err == nil {
				t.Error("expected ctx error on cancel")
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("resolveScanCIDR did not return promptly after cancel")
		}
	})
}
