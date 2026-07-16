package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/dnscap"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// Synthetic values only (constitution): RFC 5737 IPs, 00:00:5E:00:53:xx MACs.

func testTokenPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Vedetta", "sensor-token")
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", path)
	if _, err := client.New("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("prepare protected test token directory: %v", err)
	}
	return path
}

func makeSelfCheckScannerAvailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // the Windows scanner is native and has no external executable
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunSelfCheckUsesReadOnlyAuthEndpoint(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-self-check-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	var healthChecks, authChecks int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			healthChecks++
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/sensor/auth-check":
			authChecks++
			if got := r.Header.Get("Authorization"); got != "Bearer synthetic-self-check-token" {
				t.Errorf("auth-check bearer = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("self-check made mutating/unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if code := runSelfCheck(server.URL, "auto", true); code != 0 {
		t.Fatalf("self-check exit = %d, want 0", code)
	}
	if healthChecks != 1 || authChecks != 1 {
		t.Fatalf("self-check requests: health=%d auth=%d, want 1/1", healthChecks, authChecks)
	}
}

func TestRunSelfCheckRequireTokenRejectsMissingToken(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("missing-token check unexpectedly requested %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if code := runSelfCheck(server.URL, "auto", true); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for missing required token", code)
	}
}

func TestRunSelfCheckRejectsInvalidTokenWhenCoreIsReachable(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/api/v1/sensor/auth-check" {
			t.Errorf("unexpected invalid-token check request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
	}))
	defer server.Close()

	if code := runSelfCheck(server.URL, "auto", true); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for rejected token", code)
	}
}

func TestRunSelfCheckResetPreflightDoesNotValidateObsoleteToken(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	var authChecks int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/sensor/auth-check":
			authChecks++
			http.Error(w, "synthetic revoked token", http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if code := runSelfCheck(server.URL, "auto", false); code != 0 {
		t.Fatalf("reset-mode self-check exit = %d, want 0", code)
	}
	if authChecks != 0 {
		t.Fatalf("reset-mode self-check validated obsolete bearer %d time(s)", authChecks)
	}
}

func TestRunSelfCheckAllowsOfflineCoreWithRequiredLocalToken(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-offline-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	if code := runSelfCheck(url, "auto", true); code != 0 {
		t.Fatalf("self-check exit = %d, want 0 while Core is offline and local token exists", code)
	}
}

func TestRunSelfCheckRejectsMalformedCoreURL(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-malformed-url-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	if code := runSelfCheck("://malformed", "auto", true); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for malformed Core URL", code)
	}
}

func TestRunSelfCheckRejectsInvalidExplicitCorePort(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-invalid-port-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	if code := runSelfCheck("http://127.0.0.1:99999", "auto", true); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for an out-of-range Core port", code)
	}
}

func TestRunSelfCheckRejectsHostlessAndUnsupportedCoreURLs(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))
	for _, rawURL := range []string{"http://", "ftp://127.0.0.1"} {
		t.Run(rawURL, func(t *testing.T) {
			if code := runSelfCheck(rawURL, "auto", false); code != 1 {
				t.Fatalf("self-check exit = %d, want 1 for %q", code, rawURL)
			}
		})
	}
}

func TestRunSelfCheckRejectsInvalidExplicitScanTarget(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected preflight request: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if code := runSelfCheck(server.URL, "0.0.0.0/0", false); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for an over-broad scan target", code)
	}
}

func TestValidateResetEnrollmentRequiresBoundCodeForExplicitCore(t *testing.T) {
	if err := validateResetEnrollment(true, true, ""); err == nil {
		t.Fatal("explicit reset without a bound code was accepted")
	}
	if err := validateResetEnrollment(true, true, " SYNTHETIC-BOUND-RESET "); err != nil {
		t.Fatalf("explicit reset with bound code rejected: %v", err)
	}
	if err := validateResetEnrollment(true, false, ""); err != nil {
		t.Fatalf("bare destructive reset unexpectedly rejected: %v", err)
	}
}

func TestRunSelfCheckRejectsUntrustedCoreTLSCertificate(t *testing.T) {
	makeSelfCheckScannerAvailable(t)
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-untrusted-tls-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()

	if code := runSelfCheck(server.URL, "auto", true); code != 1 {
		t.Fatalf("self-check exit = %d, want 1 for untrusted Core TLS certificate", code)
	}
}

func TestClearPersistedSensorTokenKeepsBareResetSemantics(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-reset-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	if err := clearPersistedSensorToken(); err != nil {
		t.Fatalf("clear persisted token: %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("bare reset left token in place: %v", err)
	}
}

func TestClearPersistedSensorTokenReportsRemovalFailure(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenPath, "block-removal"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	if err := clearPersistedSensorToken(); err == nil {
		t.Fatal("clearPersistedSensorToken reported success although the token path remained")
	}
}

// TestMergePassiveHostPreservesFriendlyName verifies the enriched mDNS metadata
// (friendly name, model, services) survives folding with a later bare
// ARP/DHCP observation, so it reaches Core in the device report (spec 004 FR-3).
func TestMergePassiveHostPreservesFriendlyName(t *testing.T) {
	mdns := netscan.DiscoveredHost{
		IPAddress:        "192.0.2.57",
		Hostname:         "chromecast-1.local",
		FriendlyName:     "Living Room TV",
		Model:            "Chromecast Ultra",
		Services:         []string{"_googlecast._tcp"},
		IdentityEvidence: []netscan.IdentityEvidence{{Type: "mdns_txt_id", Value: "synthetic-id-57", Sensitive: true}},
		Status:           "up",
		DiscoverySource:  "passive_mdns",
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
	if len(merged.IdentityEvidence) != 1 || merged.IdentityEvidence[0].Type != "mdns_txt_id" {
		t.Fatalf("identity evidence dropped on merge: %+v", merged.IdentityEvidence)
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

func TestMergePassiveHostCapsServicesAcrossObservations(t *testing.T) {
	services := make([]string, netscan.MaxServicesPerHost*2)
	for i := range services {
		services[i] = fmt.Sprintf("_synthetic-%02d._tcp", i)
	}

	fromEmpty := mergePassiveHost(netscan.DiscoveredHost{}, netscan.DiscoveredHost{
		IPAddress: "192.0.2.59", Status: "up", Services: services,
	})
	if len(fromEmpty.Services) != netscan.MaxServicesPerHost {
		t.Fatalf("empty merge retained %d services, want cap %d", len(fromEmpty.Services), netscan.MaxServicesPerHost)
	}

	existing := netscan.DiscoveredHost{
		IPAddress: "192.0.2.60", Status: "observed",
		Services: append([]string(nil), services[:netscan.MaxServicesPerHost-1]...),
	}
	observed := netscan.DiscoveredHost{
		IPAddress: "192.0.2.60", Status: "up",
		Services: append([]string{services[0]}, services[netscan.MaxServicesPerHost-1:]...),
	}
	merged := mergePassiveHost(existing, observed)
	if len(merged.Services) != netscan.MaxServicesPerHost {
		t.Fatalf("retained outbox merge grew to %d services, want cap %d: %v", len(merged.Services), netscan.MaxServicesPerHost, merged.Services)
	}
	if got := merged.Services[netscan.MaxServicesPerHost-1]; got != services[netscan.MaxServicesPerHost-1] {
		t.Fatalf("service merge order/dedup changed: final=%q want=%q", got, services[netscan.MaxServicesPerHost-1])
	}

	pending := newPendingHostSet()
	if !pending.add(netscan.DiscoveredHost{
		IPAddress: "192.0.2.61", Status: "up", DiscoverySource: "passive_mdns", Services: services,
	}, 1, time.Now()) {
		t.Fatal("first observation was not accepted by retained outbox")
	}
	queued := pending.pop(1)
	if len(queued) != 1 || len(queued[0].Services) != netscan.MaxServicesPerHost {
		t.Fatalf("first retained observation bypassed service cap: %+v", queued)
	}
}

func TestExplicitARPInterfaceRequiresValidUserPin(t *testing.T) {
	lookupCalls := 0
	lookup := func(name string) (*net.Interface, error) {
		lookupCalls++
		if name != "lan0" {
			return nil, errors.New("synthetic missing interface")
		}
		return &net.Interface{Name: name}, nil
	}

	for _, tc := range []struct {
		name     string
		value    string
		explicit bool
		want     string
	}{
		{name: "auto default cannot pin", value: "lan0", explicit: false},
		{name: "explicit auto cannot pin", value: "auto", explicit: true},
		{name: "pcap any cannot pin", value: "any", explicit: true},
		{name: "invalid OS interface cannot pin", value: "missing0", explicit: true},
		{name: "valid explicit OS interface", value: "lan0", explicit: true, want: "lan0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := explicitARPInterface(tc.value, tc.explicit, lookup); got != tc.want {
				t.Fatalf("explicitARPInterface(%q, %v) = %q, want %q", tc.value, tc.explicit, got, tc.want)
			}
		})
	}
	if lookupCalls != 2 {
		t.Fatalf("interface lookup calls = %d, want only invalid+valid explicit names", lookupCalls)
	}
}

func TestPendingHostSetKeepsLatestPerMappingAndBoundsMemory(t *testing.T) {
	base := time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC)
	deliveryEpoch := "core-issued-epoch-one"
	pending := newPendingHostSet(func() string { return deliveryEpoch })
	oldCache := netscan.DiscoveredHost{
		IPAddress: "192.0.2.58", MACAddress: "00:00:5e:00:53:0b",
		Status: "observed", DiscoverySource: "arp_cache", ObservedAt: base,
	}
	newCache := netscan.DiscoveredHost{
		IPAddress: "192.0.2.58", MACAddress: "00:00:5e:00:53:0c",
		// Simulate an NTP correction between observations: queue order, not a
		// backwards wall clock, must decide which cache mapping is newer.
		Status: "observed", DiscoverySource: "arp_cache", ObservedAt: base.Add(-time.Minute),
	}
	if !pending.add(oldCache, 1, base) {
		t.Fatal("initial cache mapping was not queued")
	}
	failedOld := pending.pop(1)
	deliveryEpoch = "core-issued-epoch-two"
	if !pending.add(newCache, 1, base) || !pending.add(failedOld[0], 1, base) {
		t.Fatal("new cache edge plus failed old retry should fit one IP key")
	}
	if pending.add(netscan.DiscoveredHost{
		IPAddress: "192.0.2.59", MACAddress: "00:00:5e:00:53:0c",
	}, 1, base) {
		t.Fatal("new key unexpectedly exceeded the pending-set cap")
	}
	batch := pending.pop(1)
	if len(batch) != 1 {
		t.Fatalf("pop returned %d hosts, want 1", len(batch))
	}
	got := batch[0]
	if got.MACAddress != newCache.MACAddress || !got.ObservedAt.Equal(newCache.ObservedAt) {
		t.Fatalf("failed old cache retry replaced the newer mapping: %+v", got)
	}
	if got.DeliveryEpoch != deliveryEpoch || got.DeliverySequence == 0 {
		t.Fatalf("cache delivery ordering metadata was not retained: %+v", got)
	}

	oldIP := oldCache
	newIP := oldCache
	newIP.IPAddress = "192.0.2.60"
	if passiveHostKey(oldIP) == passiveHostKey(newIP) {
		t.Fatal("one MAC at different IPs collapsed into one temporal mapping")
	}
}

func TestPushPassiveHostsDrainsFullSubnetWhileCoreIsSlowAndRetries(t *testing.T) {
	const totalHosts = 1022 // a complete /22 usable-host snapshot
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }

	var mu sync.Mutex
	attempts := 0
	successRequests := 0
	successful := make(map[string]time.Time, totalHosts)
	var firstFailed []netscan.DiscoveredHost
	var invalidScanTime string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report client.DeviceReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		latest := time.Time{}
		for _, host := range report.Hosts {
			if host.ObservedAt.After(latest) {
				latest = host.ObservedAt
			}
		}
		mu.Lock()
		attempts++
		attempt := attempts
		if !report.ScanTime.Equal(latest) && invalidScanTime == "" {
			invalidScanTime = fmt.Sprintf("scan_time %s, latest host observation %s", report.ScanTime, latest)
		}
		if attempt == 1 {
			firstFailed = append([]netscan.DiscoveredHost(nil), report.Hosts...)
		}
		mu.Unlock()

		if attempt == 1 {
			close(firstStarted)
			<-releaseFirst
			http.Error(w, "synthetic transient failure", http.StatusServiceUnavailable)
			return
		}

		mu.Lock()
		successRequests++
		for _, host := range report.Hosts {
			successful[passiveHostKey(host)] = host.ObservedAt
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(report.Hosts), "failed": 0, "new_devices": 0})
	}))
	defer func() {
		release()
		server.Close()
	}()

	core := testAuthenticatedCore(t, server.URL, "sensor-arp-outbox")
	observations := make(chan netscan.DiscoveredHost, 200) // production capture capacity
	producerDone := make(chan struct{})
	base := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)
	go func() {
		prefixes := [3]string{"192.0.2", "198.51.100", "203.0.113"}
		for i := 0; i < totalHosts; i++ {
			pool := i % len(prefixes)
			hostPart := (i/len(prefixes))%254 + 1
			generation := i / (len(prefixes) * 254)
			observations <- netscan.DiscoveredHost{
				IPAddress:  fmt.Sprintf("%s.%d", prefixes[pool], hostPart),
				MACAddress: fmt.Sprintf("00:00:5e:00:53:%02x", generation+1),
				Status:     "up", DiscoverySource: "passive_arp",
				ObservedAt: base.Add(time.Duration(i) * time.Second),
			}
		}
		close(observations)
		close(producerDone)
	}()

	var dropped atomic.Int64
	outboxDone := make(chan struct{})
	go func() {
		pushPassiveHostsWithConfig(core, "192.0.2.0/22", observations, &dropped, hostPushConfig{
			BatchSize: 50, MaxPending: 2048, FlushInterval: time.Hour,
			RetryBaseDelay: time.Millisecond, RetryMaxDelay: 2 * time.Millisecond,
			AttemptTimeout: 3 * time.Second, ShutdownFlushLimit: 5 * time.Second,
			Now: func() time.Time { return base.Add(24 * time.Hour) },
		})
		close(outboxDone)
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("outbox did not begin its first delivery")
	}
	select {
	case <-producerDone:
		// The full /22 entered the bounded outbox while HTTP remained blocked.
	case <-time.After(time.Second):
		release()
		t.Fatal("slow Core starved the tail of a full /22 observation snapshot")
	}
	release()
	select {
	case <-outboxDone:
	case <-time.After(6 * time.Second):
		t.Fatal("outbox did not retry and drain within its shutdown budget")
	}

	mu.Lock()
	defer mu.Unlock()
	if invalidScanTime != "" {
		t.Error(invalidScanTime)
	}
	if attempts < 2 {
		t.Fatalf("HTTP attempts = %d, want initial failure plus retry", attempts)
	}
	if successRequests != (totalHosts+49)/50 {
		t.Fatalf("successful requests = %d, want %d", successRequests, (totalHosts+49)/50)
	}
	if len(successful) != totalHosts {
		t.Fatalf("successfully delivered unique mappings = %d, want %d", len(successful), totalHosts)
	}
	if dropped.Load() != 0 {
		t.Fatalf("dropped observations = %d, want 0", dropped.Load())
	}
	for _, host := range firstFailed {
		if got, ok := successful[passiveHostKey(host)]; !ok || !got.Equal(host.ObservedAt) {
			t.Fatalf("failed batch was not retried with original observation time: host=%+v got=%v present=%v", host, got, ok)
		}
	}
}

func TestPushPassiveHostsAuthorizationRejectionClosesGateAndDrainsProducer(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(w, "synthetic revoked sensor", http.StatusForbidden)
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-passive-revoked")
	run := &sensorRun{}
	run.registrationConfirmed.Store(true)
	rejected := make(chan error, 1)
	observations := make(chan netscan.DiscoveredHost)
	var dropped atomic.Int64
	done := make(chan struct{})
	go func() {
		pushPassiveHostsWithConfig(core, "192.0.2.0/24", observations, &dropped, hostPushConfig{
			BatchSize: 1, MaxPending: 4, FlushInterval: time.Hour,
			RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond,
			AttemptTimeout: time.Second, ShutdownFlushLimit: time.Second, Now: time.Now,
			OnAuthorizationError: func(err error) {
				run.authorizationRejected(err)
				rejected <- err
			},
		})
		close(done)
	}()
	observations <- netscan.DiscoveredHost{IPAddress: "192.0.2.40", Status: "up", ObservedAt: time.Now().UTC()}
	select {
	case err := <-rejected:
		if !client.IsAuthorizationError(err) {
			t.Fatalf("terminal callback = %v, want authorization error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("passive delivery retried a rejected credential instead of closing the gate")
	}
	producerDone := make(chan struct{})
	go func() {
		observations <- netscan.DiscoveredHost{IPAddress: "192.0.2.41", Status: "up", ObservedAt: time.Now().UTC()}
		close(observations)
		close(producerDone)
	}()
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("terminal passive delivery stopped draining and backpressured its producer")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal passive delivery did not finish after its source closed")
	}
	if run.registrationConfirmed.Load() {
		t.Fatal("passive 403 left the process registration gate open")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("passive HTTP attempts = %d, want one terminal attempt", got)
	}
	if got := dropped.Load(); got != 2 {
		t.Fatalf("explicitly dropped hosts = %d, want retained plus drained observation", got)
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

func TestHeartbeatLoopRunsIndependentlyOfScanScheduler(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-loop-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	heartbeat := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor/heartbeat" {
			t.Errorf("unexpected request before scan tick: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		heartbeat <- struct{}{}
	}))
	defer server.Close()

	core, err := client.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-loop-heartbeat"

	previous := sensorHeartbeatInterval
	sensorHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() { sensorHeartbeatInterval = previous })

	run := &sensorRun{core: core, interval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		run.heartbeatLoop(ctx)
		close(done)
	}()

	select {
	case <-heartbeat:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("independent heartbeat loop did not tick")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sensor loop did not stop after heartbeat cancellation")
	}
}

func TestHeartbeatStopCancelsBeforeWaitingDuringPanic(t *testing.T) {
	previous := sensorHeartbeatInterval
	sensorHeartbeatInterval = time.Hour
	t.Cleanup(func() { sensorHeartbeatInterval = previous })

	// The same stop function serve defers must cancel the child heartbeat during
	// panic unwinding rather than wait forever on a live parent context.
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		stopHeartbeat := (&sensorRun{}).startHeartbeat(context.Background())
		defer stopHeartbeat()
		panic("synthetic downstream panic")
	}()

	select {
	case recovered := <-done:
		if recovered == nil {
			t.Fatal("serve returned without the expected synthetic panic")
		}
	case <-time.After(time.Second):
		t.Fatal("serve deadlocked waiting for heartbeat during panic unwinding")
	}
}

func TestDeliverScanResultRetries207WithImmutableScopeAndPayload(t *testing.T) {
	observed := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	result := &netscan.ScanResult{
		ScanTime: observed, Duration: 123 * time.Millisecond,
		Hosts: []netscan.DiscoveredHost{{
			IPAddress: "192.0.2.81", MACAddress: "00:00:5e:00:53:51", Status: "up",
			ObservedAt: observed, DiscoverySource: "nmap", OpenPorts: []int{80, 443},
		}},
	}
	firstReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var reports []client.DeviceReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report client.DeviceReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		reports = append(reports, report)
		attempt := len(reports)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			close(firstReceived)
			<-releaseFirst
			w.WriteHeader(http.StatusMultiStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 0, "failed": 1, "status": "partial"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "failed": 0})
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-active-retry")
	done := make(chan error, 1)
	go func() {
		done <- deliverScanResultWithConfig(context.Background(), core, result, "192.0.2.0/24", "guest-lan", scanDeliveryConfig{
			RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond, AttemptTimeout: time.Second,
		})
	}()
	select {
	case <-firstReceived:
	case <-time.After(time.Second):
		t.Fatal("first scan report did not reach Core")
	}
	// Mutating the scanner-owned object after delivery begins must not alter the
	// retained retry payload.
	result.Hosts[0].IPAddress = "198.51.100.99"
	result.Hosts[0].OpenPorts[0] = 22
	close(releaseFirst)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("207 -> 200 delivery: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial scan report was not retried")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("report attempts = %d, want 2", len(reports))
	}
	for i, report := range reports {
		if report.CIDR != "192.0.2.0/24" || report.Segment != "guest-lan" {
			t.Fatalf("attempt %d lost scope: cidr=%q segment=%q", i+1, report.CIDR, report.Segment)
		}
		if len(report.Hosts) != 1 || report.Hosts[0].IPAddress != "192.0.2.81" ||
			len(report.Hosts[0].OpenPorts) != 2 || report.Hosts[0].OpenPorts[0] != 80 ||
			!report.Hosts[0].ObservedAt.Equal(observed) || !report.ScanTime.Equal(observed) {
			t.Fatalf("attempt %d mutated retained result: %+v", i+1, report)
		}
	}
}

func TestDeliverScanResultCancellationInterruptsInFlightAttempt(t *testing.T) {
	started := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
		close(handlerDone)
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-active-cancel")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- deliverScanResultWithConfig(ctx, core, &netscan.ScanResult{
			ScanTime: time.Now(), Hosts: []netscan.DiscoveredHost{{IPAddress: "192.0.2.82", Status: "up"}},
		}, "192.0.2.0/24", "default", scanDeliveryConfig{
			RetryBaseDelay: time.Hour, RetryMaxDelay: time.Hour, AttemptTimeout: time.Hour,
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan report attempt did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("delivery cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("service cancellation did not interrupt scan report delivery")
	}
	close(releaseHandler) // permit httptest cleanup on transports that defer peer cancellation
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("test HTTP handler did not release")
	}
}

func TestPushPassiveHostsRetries207AndKeepsNewCacheMappingUnderFutureSkew(t *testing.T) {
	base := time.Now().UTC().Add(2 * time.Hour)
	oldMapping := netscan.DiscoveredHost{
		IPAddress: "192.0.2.71", MACAddress: "00:00:5e:00:53:71",
		Status: "observed", DiscoverySource: "arp_cache", ObservedAt: base,
	}
	newMapping := oldMapping
	newMapping.MACAddress = "00:00:5e:00:53:72"
	newMapping.ObservedAt = base.Add(time.Minute)
	unrelated := netscan.DiscoveredHost{
		IPAddress: "198.51.100.72", MACAddress: "00:00:5e:00:53:73",
		Status: "up", DiscoverySource: "passive_dhcp", ObservedAt: base.Add(30 * time.Second),
	}

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var reports []client.DeviceReport
	currentCacheMAC := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report client.DeviceReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		reports = append(reports, report)
		attempt := len(reports)
		for _, host := range report.Hosts {
			if host.DiscoverySource == "arp_cache" && host.IPAddress == oldMapping.IPAddress {
				currentCacheMAC = host.MACAddress
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			close(firstStarted)
			<-releaseFirst
			w.WriteHeader(http.StatusMultiStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "failed": 1, "new_devices": 1, "status": "partial"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(report.Hosts), "failed": 0, "new_devices": 0})
	}))
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
		server.Close()
	}()

	core := testAuthenticatedCore(t, server.URL, "sensor-cache-order")
	observations := make(chan netscan.DiscoveredHost, 3)
	observations <- oldMapping
	observations <- unrelated
	done := make(chan struct{})
	var dropped atomic.Int64
	go func() {
		pushPassiveHostsWithConfig(core, "192.0.2.0/24", observations, &dropped, hostPushConfig{
			BatchSize: 2, MaxPending: 8, FlushInterval: time.Hour,
			RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond,
			AttemptTimeout: 2 * time.Second, ShutdownFlushLimit: 3 * time.Second,
			Now: time.Now,
		})
		close(done)
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first device-report attempt did not start")
	}
	observations <- newMapping
	close(observations)
	close(releaseFirst)
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("207 device-report response was not retried")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("device-report attempts = %d, want 2 (207 then 200)", len(reports))
	}
	cacheHosts := 0
	for _, host := range reports[1].Hosts {
		if host.DiscoverySource != "arp_cache" {
			continue
		}
		cacheHosts++
		if host.MACAddress != newMapping.MACAddress || !host.ObservedAt.Equal(newMapping.ObservedAt) {
			t.Fatalf("retry carried stale cache identity/time: %+v", host)
		}
	}
	if cacheHosts != 1 || currentCacheMAC != newMapping.MACAddress {
		t.Fatalf("cache retry outcome: hosts=%d current MAC=%q, want one latest mapping %q", cacheHosts, currentCacheMAC, newMapping.MACAddress)
	}
	if dropped.Load() != 0 {
		t.Fatalf("dropped observations = %d, want 0", dropped.Load())
	}
}

func testDNSPushConfig() dnsPushConfig {
	return dnsPushConfig{
		BatchSize: 1, QueuedBatches: 2, MaxUnpaired: 8,
		PairWindow: time.Second, FlushInterval: time.Millisecond,
		RetryBaseDelay: time.Millisecond, RetryMaxDelay: 2 * time.Millisecond,
		AttemptTimeout: 250 * time.Millisecond, ShutdownFlushLimit: time.Second,
	}
}

func testAuthenticatedCore(t *testing.T, baseURL, sensorID string) *client.CoreClient {
	t.Helper()
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-sensor-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	core, err := client.New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = sensorID
	return core
}

// A failed push must retain the exact coalesced payload and retry it. BatchSize=1
// is intentional: without pre-chunk coalescing, the query and answerless response
// would have crossed an HTTP boundary and produced two events.
func TestPushDNSQueries_RetriesIdenticalCoalescedNXDOMAINPayload(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		attempt := len(bodies)
		mu.Unlock()
		if attempt == 1 {
			http.Error(w, "synthetic transient failure", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	core := testAuthenticatedCore(t, server.URL, "sensor-dns-retry")
	observed := time.Unix(1_751_000_000, 123_000_000).UTC()
	queries := make(chan dnscap.Query, 2)
	queries <- dnscap.Query{
		Timestamp: observed, Domain: "missing.example", QueryType: "A",
		ClientIP: "192.0.2.21", ServerIP: "192.0.2.53", Direction: "query",
		Source: "passive_capture", Process: "synthetic-resolver",
	}
	queries <- dnscap.Query{
		Timestamp: observed.Add(25 * time.Millisecond), Domain: "missing.example", QueryType: "A",
		ClientIP: "192.0.2.21", ServerIP: "192.0.2.53", Direction: "response",
		RCode: "NXDOMAIN", Source: "passive_capture",
	}
	close(queries)
	pushDNSQueriesWithConfig(core, queries, testDNSPushConfig())

	mu.Lock()
	gotBodies := append([][]byte(nil), bodies...)
	mu.Unlock()
	if len(gotBodies) != 2 {
		t.Fatalf("HTTP attempts = %d, want one failure plus one retry", len(gotBodies))
	}
	if string(gotBodies[0]) != string(gotBodies[1]) {
		t.Fatalf("retry mutated payload:\nfirst:  %s\nsecond: %s", gotBodies[0], gotBodies[1])
	}
	var payload dnscap.DNSPushRequest
	if err := json.Unmarshal(gotBodies[1], &payload); err != nil {
		t.Fatalf("decode successful payload: %v", err)
	}
	if len(payload.Queries) != 1 {
		t.Fatalf("query/answerless-response crossed batch boundary: got %d records", len(payload.Queries))
	}
	got := payload.Queries[0]
	if got.ObservationID == "" {
		t.Fatalf("coalesced observation has no durable ID: %+v", got)
	}
	if got.Direction != "response" || got.RCode != "NXDOMAIN" || len(got.Answers) != 0 {
		t.Fatalf("NXDOMAIN response semantics lost: %+v", got)
	}
	if got.Process != "synthetic-resolver" {
		t.Fatalf("query-side process was not preserved in merged response: %+v", got)
	}
}

func TestPushDNSQueriesAuthorizationRejectionClosesGateAndDrainsProducer(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(w, "synthetic revoked sensor", http.StatusUnauthorized)
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-dns-revoked")
	run := &sensorRun{}
	run.registrationConfirmed.Store(true)
	rejected := make(chan error, 1)
	queries := make(chan dnscap.Query)
	cfg := testDNSPushConfig()
	cfg.PairWindow = time.Millisecond
	cfg.OnAuthorizationError = func(err error) {
		run.authorizationRejected(err)
		rejected <- err
	}
	done := make(chan struct{})
	go func() {
		pushDNSQueriesWithConfig(core, queries, cfg)
		close(done)
	}()
	queries <- dnscap.Query{
		Timestamp: time.Now().UTC(), Domain: "revoked.example", QueryType: "A",
		ClientIP: "192.0.2.42", ServerIP: "192.0.2.53", Direction: "query",
	}
	select {
	case err := <-rejected:
		if !client.IsAuthorizationError(err) {
			t.Fatalf("terminal callback = %v, want authorization error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS delivery retried a rejected credential instead of closing the gate")
	}
	producerDone := make(chan struct{})
	go func() {
		queries <- dnscap.Query{
			Timestamp: time.Now().UTC(), Domain: "drained.example", QueryType: "A",
			ClientIP: "192.0.2.43", ServerIP: "192.0.2.53", Direction: "query",
		}
		close(queries)
		close(producerDone)
	}()
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("terminal DNS delivery stopped draining and backpressured its producer")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal DNS delivery did not finish after its source closed")
	}
	if run.registrationConfirmed.Load() {
		t.Fatal("DNS 401 left the process registration gate open")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("DNS HTTP attempts = %d, want one terminal attempt", got)
	}
}

func TestDNSQueryCoalescer_PreservesRepeatedSameDirection(t *testing.T) {
	coalescer := newDNSQueryCoalescer(time.Second, 8)
	now := time.Now().UTC()
	base := dnscap.Query{
		Timestamp: now, Domain: "repeat.example", QueryType: "AAAA",
		ClientIP: "192.0.2.22", ServerIP: "192.0.2.53", Direction: "query",
	}
	if got := coalescer.add(base, now); len(got) != 0 {
		t.Fatalf("first query released early: %+v", got)
	}
	repeated := base
	repeated.Timestamp = now.Add(20 * time.Millisecond)
	if got := coalescer.add(repeated, now.Add(time.Millisecond)); len(got) != 0 {
		t.Fatalf("same-direction query was incorrectly paired: %+v", got)
	}
	response := base
	response.Direction = "response"
	response.Timestamp = now.Add(40 * time.Millisecond)
	response.RCode = "NOERROR"
	response.Answers = []string{"2001:db8::20"}
	paired := coalescer.add(response, now.Add(2*time.Millisecond))
	if len(paired) != 1 || paired[0].Direction != "response" {
		t.Fatalf("response did not pair one-to-one: %+v", paired)
	}
	remaining := coalescer.flush()
	if len(remaining) != 1 || normalizedDNSDirection(remaining[0].Direction) != "query" {
		t.Fatalf("repeated same-direction query was lost: %+v", remaining)
	}
}

func TestCapturedDNSQueryPreservesCNAMETargetForCore(t *testing.T) {
	query := dnscap.Query{
		Timestamp: time.Unix(1_751_000_000, 0).UTC(),
		Domain:    "portal.example",
		QueryType: "A",
		ClientIP:  "192.0.2.25",
		ServerIP:  "192.0.2.53",
		Direction: "response",
		RCode:     "NOERROR",
		Answers:   []string{"c2.badzone.example"},
	}
	wire := capturedDNSQuery(query)
	if len(wire.Answers) != 1 || wire.Answers[0] != "c2.badzone.example" {
		t.Fatalf("CNAME target did not reach Core wire payload: %+v", wire)
	}
}

func TestDNSQueryCoalescer_BoundsUnpairedMemory(t *testing.T) {
	coalescer := newDNSQueryCoalescer(time.Hour, 2)
	now := time.Now().UTC()
	for i, domain := range []string{"one.example", "two.example", "three.example"} {
		ready := coalescer.add(dnscap.Query{
			Timestamp: now, Domain: domain, QueryType: "A", Direction: "query",
			ClientIP: "192.0.2.23", ServerIP: "192.0.2.53",
		}, now.Add(time.Duration(i)*time.Millisecond))
		if i < 2 && len(ready) != 0 {
			t.Fatalf("released record before cap: %+v", ready)
		}
		if i == 2 && (len(ready) != 1 || ready[0].Domain != "one.example") {
			t.Fatalf("cap did not release oldest record: %+v", ready)
		}
	}
	if len(coalescer.unpaired) != 2 {
		t.Fatalf("unpaired memory grew past cap: %d", len(coalescer.unpaired))
	}
}

func TestPushDNSQueries_ShutdownCancelsStalledDelivery(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-requestStarted:
		default:
			close(requestStarted)
		}
		<-releaseHandler
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-dns-stop")
	queries := make(chan dnscap.Query, 1)
	queries <- dnscap.Query{Timestamp: time.Now(), Domain: "stall.example", QueryType: "A", ClientIP: "192.0.2.24", Direction: "query"}
	close(queries)
	cfg := testDNSPushConfig()
	cfg.ShutdownFlushLimit = 50 * time.Millisecond
	cfg.AttemptTimeout = time.Second
	started := time.Now()
	pushDNSQueriesWithConfig(core, queries, cfg)
	close(releaseHandler)
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("bounded shutdown took %s", elapsed)
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("delivery attempt never started before shutdown")
	}
}

// TestRegisterWithRetryReusesEnrollmentCode is the regression test for the sensor
// side of enrollment recovery (issue #44). It models a lost/failed registration
// response: the first attempt fails after the backend would have consumed the
// enrollment code, and the retry must present the SAME code so the idempotent
// backend can hand the sensor its token back — rather than discarding the code or
// switching to a fresh one.
func TestRegisterWithRetryReusesEnrollmentCode(t *testing.T) {
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))
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

// TestEnsureRegisteredValidatesEvenWithPersistedToken verifies that token presence is
// never treated as authenticated registration. The sensorRun state (not this helper)
// avoids redundant calls only after a successful Register response in this process.
func TestEnsureRegisteredValidatesEvenWithPersistedToken(t *testing.T) {
	testTokenPath(t)

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
	// A second direct validation still hits Core; a token file alone is not proof that
	// the sensor identity has not since been revoked.
	if !ensureRegistered(context.Background(), core, "192.0.2.0/24", false, nil) {
		t.Fatal("expected ensureRegistered to remain true once registered")
	}
	if registerHits != 2 {
		t.Fatalf("registration validation calls = %d, want 2", registerHits)
	}
}

func TestScanLifecycleWaitsForRegistrationThenRecovers(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-existing-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDelay := registerRetryBaseDelay
	registerRetryBaseDelay = time.Millisecond
	defer func() { registerRetryBaseDelay = oldDelay }()

	var registerHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor/register" {
			t.Errorf("unregistered lifecycle attempted %s", r.URL.Path)
			http.Error(w, "unexpected pre-registration request", http.StatusUnauthorized)
			return
		}
		hit := registerHits.Add(1)
		if hit <= 4 {
			http.Error(w, "synthetic Core startup outage", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "registered", "sensor_id": "sensor-scan-gate",
		})
	}))
	defer srv.Close()

	core, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-scan-gate"
	var scans atomic.Int32
	run := &sensorRun{
		core: core, coreURL: srv.URL, scanCIDR: "192.0.2.0/24",
		scanFn: func(context.Context, *netscan.Scanner, *client.CoreClient, string, bool, scanDeliveryConfig) error {
			scans.Add(1)
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := run.scanIfRegistered(ctx, true); err == nil {
		t.Fatal("initial scan ran after every bounded registration attempt failed")
	}
	if got := scans.Load(); got != 0 {
		t.Fatalf("initial failed registration triggered %d scan(s)", got)
	}
	// The next periodic cycle retries registration once. When Core recovers and the
	// token is persisted, that same cycle may scan safely.
	if err := run.scanIfRegistered(ctx, false); err != nil {
		t.Fatal("periodic registration recovery did not release the scan gate")
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("recovered registration triggered %d scans, want 1", got)
	}
	if got := registerHits.Load(); got != 5 {
		t.Fatalf("registration attempts = %d, want four bounded initial attempts plus one recovery", got)
	}
}

func TestPersistedRevokedTokenDoesNotBypassRegistrationAndResetRecovers(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	var registerHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor/register" {
			http.NotFound(w, r)
			return
		}
		registerHits.Add(1)
		if r.Header.Get("Authorization") == "Bearer synthetic-revoked-token" {
			http.Error(w, "revoked", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Vedetta-Enrollment-Code") != "SYNTHETIC-RESET-CODE" {
			http.Error(w, "reset code required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "registered", "sensor_id": "sensor-revoked", "auth_token": "replacement-token",
		})
	}))
	defer server.Close()

	core, err := client.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-revoked"
	var scans atomic.Int32
	run := &sensorRun{
		core: core, coreURL: server.URL, scanCIDR: "192.0.2.0/24",
		scanFn: func(context.Context, *netscan.Scanner, *client.CoreClient, string, bool, scanDeliveryConfig) error {
			scans.Add(1)
			return nil
		},
	}
	if err := run.scanIfRegistered(context.Background(), false); err == nil || !client.IsAuthorizationError(err) {
		t.Fatalf("revoked persisted token registration = %v, want authorization error", err)
	}
	if scans.Load() != 0 || run.registrationConfirmed.Load() {
		t.Fatalf("revoked token crossed scan gate: scans=%d confirmed=%v", scans.Load(), run.registrationConfirmed.Load())
	}

	// Model the documented --reset + bound reset-code restart: the old token is
	// removed before New loads state, then Core returns a replacement token.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	recovered, err := client.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	recovered.SensorID = "sensor-revoked"
	recovered.EnrollCode = "SYNTHETIC-RESET-CODE"
	run.core = recovered
	if err := run.scanIfRegistered(context.Background(), false); err != nil {
		t.Fatalf("bound reset-code recovery: %v", err)
	}
	if scans.Load() != 1 || !run.registrationConfirmed.Load() || !recovered.TokenConfigured() {
		t.Fatalf("reset recovery state: scans=%d confirmed=%v token=%v", scans.Load(), run.registrationConfirmed.Load(), recovered.TokenConfigured())
	}
	if got := registerHits.Load(); got != 2 {
		t.Fatalf("register hits = %d, want revoked attempt plus reset recovery", got)
	}
}

func TestDeliveryAuthorizationFailureClosesRegistrationGate(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-valid-then-revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	var registerHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/register":
			registerHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "registered"})
		case "/api/v1/sensor/devices":
			http.Error(w, "revoked after registration", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	core, err := client.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-late-revoke"
	run := &sensorRun{
		core: core, coreURL: server.URL, scanCIDR: "192.0.2.0/24",
		scanFn: func(ctx context.Context, _ *netscan.Scanner, core *client.CoreClient, cidr string, _ bool, cfg scanDeliveryConfig) error {
			return deliverScanResultWithConfig(ctx, core, &netscan.ScanResult{
				ScanTime: time.Now().UTC(), Hosts: []netscan.DiscoveredHost{{IPAddress: "192.0.2.10", Status: "up"}},
			}, cidr, "default", cfg)
		},
	}
	if err := run.scanIfRegistered(context.Background(), true); err == nil || !client.IsAuthorizationError(err) {
		t.Fatalf("late revoke error = %v, want authorization error", err)
	}
	if run.registrationConfirmed.Load() {
		t.Fatal("delivery 403 left the process registration gate open")
	}
	// The next periodic attempt must hit Register again instead of trusting the file.
	if err := run.scanIfRegisteredWithConfig(context.Background(), false, scanDeliveryConfig{MaxAttempts: 1, AttemptTimeout: time.Second}); err == nil {
		t.Fatal("second delivery unexpectedly succeeded")
	}
	if got := registerHits.Load(); got != 2 {
		t.Fatalf("register hits = %d, want revalidation after delivery rejection", got)
	}
}

func TestFetchWorkAuthorizationFailureIsTerminalBeforeScanning(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-revoked-work-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor/work" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "revoked", http.StatusUnauthorized)
	}))
	defer server.Close()
	core, err := client.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = runScanWithConfig(context.Background(), &netscan.Scanner{}, core, "192.0.2.0/24", false, productionScanDeliveryConfig)
	if err == nil || !client.IsAuthorizationError(err) {
		t.Fatalf("FetchWork authorization error = %v, want terminal classification", err)
	}
}

func TestServiceScanContinuesGoodQueuedWorkAfterBadPrimaryInStableOrder(t *testing.T) {
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/work":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"scan_queue": []map[string]any{{"cidr": "198.51.100.0/24", "segment": "guest"}},
				"targets":    []map[string]any{{"cidr": "203.0.113.0/24", "segment": "iot", "enabled": true}},
			})
		case "/api/v1/sensor/devices":
			var report client.DeviceReport
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			delivered.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(report.Hosts), "failed": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-scan-order")
	var order []string
	cfg := productionScanDeliveryConfig
	cfg.Scan = func(ctx context.Context, _ *netscan.Scanner, cidr string, _ bool) (*netscan.ScanResult, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		order = append(order, cidr)
		if cidr == "192.0.2.0/24" {
			return nil, errors.New("synthetic off-link primary")
		}
		now := time.Now().UTC()
		return &netscan.ScanResult{
			ScanTime: now,
			Hosts:    []netscan.DiscoveredHost{{IPAddress: strings.TrimSuffix(cidr, "0/24") + "10", Status: "up", ObservedAt: now}},
		}, nil
	}
	err := runScanWithConfig(context.Background(), &netscan.Scanner{}, core, "192.0.2.0/24", false, cfg)
	if err == nil || !strings.Contains(err.Error(), "synthetic off-link primary") {
		t.Fatalf("service aggregate error = %v, want bad primary reported after good work", err)
	}
	wantOrder := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
	if fmt.Sprint(order) != fmt.Sprint(wantOrder) {
		t.Fatalf("scan order = %v, want %v", order, wantOrder)
	}
	if got := delivered.Load(); got != 2 {
		t.Fatalf("delivered good scans = %d, want queued + recurring target", got)
	}
}

func TestServiceScanDeduplicatesByCIDRAndSegmentAndKeepsPortRequirement(t *testing.T) {
	var delivered []client.DeviceReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/work":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"scan_queue": []map[string]any{
					{"cidr": "192.0.2.0/24", "segment": "default", "scan_ports": true},
					{"cidr": "192.0.2.0/24", "segment": "guest", "scan_ports": false},
				},
				"targets": []map[string]any{
					{"cidr": "192.0.2.0/24", "segment": "guest", "scan_ports": true, "enabled": true},
				},
			})
		case "/api/v1/sensor/devices":
			var report client.DeviceReport
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			delivered = append(delivered, report)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(report.Hosts), "failed": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-scan-dedupe")

	type scanCall struct {
		cidr  string
		ports bool
	}
	var calls []scanCall
	cfg := productionScanDeliveryConfig
	cfg.Scan = func(_ context.Context, _ *netscan.Scanner, cidr string, ports bool) (*netscan.ScanResult, error) {
		calls = append(calls, scanCall{cidr: cidr, ports: ports})
		now := time.Now().UTC()
		return &netscan.ScanResult{
			ScanTime: now,
			Hosts:    []netscan.DiscoveredHost{{IPAddress: "192.0.2.10", Status: "up", ObservedAt: now}},
		}, nil
	}
	if err := runScanWithConfig(context.Background(), &netscan.Scanner{}, core, "192.0.2.0/24", false, cfg); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !calls[0].ports || !calls[1].ports {
		t.Fatalf("scan calls = %+v, want two CIDR/segment tasks with merged port coverage", calls)
	}
	if len(delivered) != 2 || delivered[0].Segment != "default" || delivered[1].Segment != "guest" {
		t.Fatalf("delivered segments = %+v, want default then guest", delivered)
	}
}

func TestOneShotScanReturnsPrimaryErrorWithoutFetchingWork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request "+r.URL.Path, http.StatusInternalServerError)
	}))
	defer server.Close()
	core := testAuthenticatedCore(t, server.URL, "sensor-oneshot-primary-error")
	calls := 0
	cfg := oneShotScanDeliveryConfig
	cfg.Scan = func(context.Context, *netscan.Scanner, string, bool) (*netscan.ScanResult, error) {
		calls++
		return nil, errors.New("synthetic one-shot scan failure")
	}
	err := runScanWithConfig(context.Background(), &netscan.Scanner{}, core, "192.0.2.0/24", false, cfg)
	if err == nil || !strings.Contains(err.Error(), "synthetic one-shot scan failure") {
		t.Fatalf("one-shot error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("one-shot scan calls = %d, want 1", calls)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("one-shot unexpectedly fetched/drained Core work: %d request(s)", got)
	}
}

func TestRunScanWithoutTokenReturnsBeforeScannerOrDelivery(t *testing.T) {
	testTokenPath(t)
	core, err := client.New("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		// A nil scanner would panic if the defensive registration gate were bypassed.
		runScan(context.Background(), nil, core, "192.0.2.0/24", false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("unregistered scan entered work/delivery instead of returning promptly")
	}
	deliveryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deliveryDone := make(chan error, 1)
	go func() {
		deliveryDone <- deliverScanResultWithConfig(deliveryCtx, core, &netscan.ScanResult{
			Hosts: []netscan.DiscoveredHost{{IPAddress: "192.0.2.62", Status: "up"}},
		}, "192.0.2.0/24", "default", scanDeliveryConfig{
			RetryBaseDelay: time.Hour, RetryMaxDelay: time.Hour, AttemptTimeout: time.Hour,
		})
	}()
	select {
	case err := <-deliveryDone:
		if err == nil || !strings.Contains(err.Error(), "not registered") {
			t.Fatalf("unregistered retained delivery error = %v, want immediate registration error", err)
		}
	case <-time.After(250 * time.Millisecond):
		cancel()
		t.Fatal("unregistered retained delivery entered its retry loop")
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
