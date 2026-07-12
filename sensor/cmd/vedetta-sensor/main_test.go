package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
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

// TestRegisterWithRetryReusesEnrollmentCode is the regression test for the sensor
// side of enrollment recovery (issue #44). It models a lost/failed registration
// response: the first attempt fails after the backend would have consumed the
// enrollment code, and the retry must present the SAME code so the idempotent
// backend can hand the sensor its token back — rather than discarding the code or
// switching to a fresh one.
func TestRegisterWithRetryReusesEnrollmentCode(t *testing.T) {
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", filepath.Join(t.TempDir(), "sensor-token"))
	old := registerRetryBaseDelay
	registerRetryBaseDelay = time.Millisecond
	defer func() { registerRetryBaseDelay = old }()

	var attempts int
	var seenCodes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		seenCodes = append(seenCodes, r.Header.Get("X-Vedetta-Enrollment-Code"))
		if attempts == 1 {
			// Backend consumed the code and minted a token, but the response is
			// "lost" from the sensor's perspective.
			http.Error(w, "core hiccup", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "registered",
			"sensor_id":  "sensor-test",
			"auth_token": "idempotent-token",
			"token_id":   "tok-1",
		})
	}))
	defer srv.Close()

	core, err := client.New(srv.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-test"
	core.EnrollCode = "ENROLL-CODE-1"

	if !registerWithRetry(context.Background(), core, "192.0.2.0/24", false, nil) {
		t.Fatal("expected registration to recover on retry")
	}
	if attempts < 2 {
		t.Fatalf("expected a retry after the lost response, got %d attempt(s)", attempts)
	}
	for i, c := range seenCodes {
		if c != "ENROLL-CODE-1" {
			t.Fatalf("attempt %d presented code %q, want the SAME enrollment code reused", i+1, c)
		}
	}
	if !core.TokenConfigured() {
		t.Fatal("expected the idempotent token to be persisted after recovery")
	}
}

// TestEnsureRegisteredRecoversThenIsNoOp verifies the scan-loop recovery path:
// while unregistered it retries (reusing the enrollment code) and, once a token is
// persisted, becomes a no-op that does not hit the network again (issue #44).
func TestEnsureRegisteredRecoversThenIsNoOp(t *testing.T) {
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", filepath.Join(t.TempDir(), "sensor-token"))

	var registerHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registerHits++
		if got := r.Header.Get("X-Vedetta-Enrollment-Code"); got != "ENROLL-CODE-2" {
			t.Errorf("expected enrollment code reused, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "registered",
			"sensor_id":  "sensor-test",
			"auth_token": "recovered-token",
		})
	}))
	defer srv.Close()

	core, err := client.New(srv.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-test"
	core.EnrollCode = "ENROLL-CODE-2"

	if !ensureRegistered(context.Background(), core, "192.0.2.0/24", false, nil) {
		t.Fatal("expected ensureRegistered to succeed")
	}
	if registerHits != 1 {
		t.Fatalf("expected exactly one register call, got %d", registerHits)
	}
	// Second call must be a no-op now that a token is configured.
	if !ensureRegistered(context.Background(), core, "192.0.2.0/24", false, nil) {
		t.Fatal("expected ensureRegistered to remain true once registered")
	}
	if registerHits != 1 {
		t.Fatalf("ensureRegistered re-hit Core after a token was configured (%d calls)", registerHits)
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
