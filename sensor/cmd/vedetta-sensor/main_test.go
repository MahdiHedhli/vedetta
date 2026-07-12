package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestSensorLoopHeartbeatsBeforeDefaultScanInterval(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "sensor-token")
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
		run.loop(ctx)
		close(done)
	}()

	select {
	case <-heartbeat:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("sensor loop did not heartbeat before its scan interval")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sensor loop did not stop after heartbeat cancellation")
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
	tokenPath := filepath.Join(t.TempDir(), "sensor-token")
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
