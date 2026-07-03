package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// setupFirewallServer builds a Server whose Enricher has the firewall_log branch
// fully wired (tag/source-IP whitelist + device cross-ref), matching production
// wiring in cmd/vedetta/main.go. It also seeds the wan_scan_noise whitelist rule
// (the inline-fallback test DB does not run migration 017).
func setupFirewallServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	enricher := dnsintel.NewEnricher(nil)
	enricher.FirewallWhitelisted = func(tags []string, sourceIP string) (string, bool) {
		return db.IsEventWhitelisted(tags, sourceIP)
	}
	enricher.DeviceByIP = func(ip string) *models.Device {
		dev, err := db.GetDeviceByIP(ip)
		if err != nil {
			return nil
		}
		return dev
	}

	// Seed the wan_scan_noise default whitelist rule (as migration 017 would).
	if _, err := db.CreateWhitelistRule(models.WhitelistRule{
		RuleID:    "wl-fw-wan-scan-rollup",
		Name:      "WAN scan noise rollup",
		TagMatch:  "wan_scan_noise",
		Category:  "firewall",
		IsDefault: true,
		Enabled:   true,
	}); err != nil {
		t.Fatalf("seed wan_scan_noise rule: %v", err)
	}

	srv := &Server{DB: db, Enricher: enricher}
	return srv, db
}

// synthFirewallEvent builds a normalized firewall_log event as the collector
// would emit it (per contracts/unifi-syslog-cef.md). All values synthetic.
func synthFirewallEvent(srcIP, action, dir, dstIP, rule string, extraTags ...string) models.Event {
	meta, _ := json.Marshal(map[string]any{
		"action":    action,
		"protocol":  "tcp",
		"src_ip":    srcIP,
		"src_port":  51234,
		"dst_ip":    dstIP,
		"dst_port":  8443,
		"direction": dir,
		"rule":      rule,
		"dialect":   "cef",
		"raw_log":   "CEF:0|Ubiquiti|UniFi Network|9.0|fwrule|Firewall Block|3|...",
	})
	tags := append([]string{"source:unifi", "fw:" + action, "dir:" + dir}, extraTags...)
	blocked := action == "block" || action == "drop" || action == "reject"
	return models.Event{
		EventType:      "firewall_log",
		Timestamp:      time.Now().UTC(),
		SourceIP:       srcIP,
		Blocked:        blocked,
		NetworkSegment: "default",
		Tags:           tags,
		Metadata:       string(meta),
	}
}

func postIngest(t *testing.T, router http.Handler, events []models.Event, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(events)
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestFirewallIngest_EndToEnd feeds a synthetic batch of normalized firewall_log
// events through handleIngest and asserts: correct tags stored, first-seen block
// scores higher than a recurring one, and a wan_scan_noise event is suppressed
// by the seeded whitelist.
func TestFirewallIngest_EndToEnd(t *testing.T) {
	srv, db := setupFirewallServer(t)
	router := NewRouter(srv)

	batch := []models.Event{
		// First-seen blocked outbound from an IoT device.
		synthFirewallEvent("192.0.2.45", "block", "out", "203.0.113.10", "IoT_Restrict"),
		// A WAN-scan rollup event that the seeded whitelist must suppress.
		func() models.Event {
			e := synthFirewallEvent("", "drop", "in", "198.51.100.2", "WAN_LOCAL", "wan_scan_noise")
			e.Metadata = `{"rollup":true,"count":1482,"dialect":"iptables"}`
			return e
		}(),
	}

	w := postIngest(t, router, batch, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("ingest: expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Recurring block (same src, dst, rule) in a second request.
	w2 := postIngest(t, router, []models.Event{
		synthFirewallEvent("192.0.2.45", "block", "out", "203.0.113.10", "IoT_Restrict"),
	}, "")
	if w2.Code != http.StatusAccepted {
		t.Fatalf("recurring ingest: expected 202, got %d", w2.Code)
	}

	res, err := db.QueryEvents(store.EventQueryParams{Type: "firewall_log"})
	if err != nil {
		t.Fatalf("query firewall events: %v", err)
	}
	if res.Total != 3 {
		t.Fatalf("expected 3 stored firewall events, got %d", res.Total)
	}

	var firstSeen, recurring, rollup *models.Event
	for i := range res.Events {
		e := &res.Events[i]
		switch {
		case containsStr(e.Tags, "wan_scan_noise"):
			rollup = e
		case containsStr(e.Tags, "new_fw_block"):
			firstSeen = e
		default:
			if e.EventType == "firewall_log" {
				recurring = e
			}
		}
	}

	if firstSeen == nil {
		t.Fatal("no first-seen (new_fw_block) event found")
	}
	if recurring == nil {
		t.Fatal("no recurring firewall event found")
	}
	if rollup == nil {
		t.Fatal("no wan_scan_noise rollup event found")
	}

	// Tags stored correctly.
	for _, want := range []string{"source:unifi", "fw:block", "dir:out"} {
		if !containsStr(firstSeen.Tags, want) {
			t.Errorf("first-seen event missing tag %q; tags=%v", want, firstSeen.Tags)
		}
	}

	// First-seen scores higher than recurring.
	if firstSeen.AnomalyScore <= recurring.AnomalyScore {
		t.Errorf("first-seen (%.2f) should score higher than recurring (%.2f)",
			firstSeen.AnomalyScore, recurring.AnomalyScore)
	}
	if firstSeen.AnomalyScore < 0.35 {
		t.Errorf("first-seen score = %.2f, want ~0.4", firstSeen.AnomalyScore)
	}

	// Rollup suppressed by the seeded whitelist → score 0 + whitelisted tag.
	if rollup.AnomalyScore != 0.0 {
		t.Errorf("wan_scan_noise rollup score = %.2f, want 0.0 (suppressed)", rollup.AnomalyScore)
	}
	if !containsStr(rollup.Tags, "whitelisted") {
		t.Errorf("suppressed rollup should carry whitelisted tag; tags=%v", rollup.Tags)
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// --- Ingest auth (T3.2) ---
//
// NOTE ON FOUNDATION: on this (canonical) branch the /ingest route is mounted
// behind auth.RequireAuth, which bypasses auth only while NO tokens exist (fresh
// install) and otherwise requires a valid Bearer token. The feature's
// VEDETTA_REQUIRE_INGEST_AUTH gate layers an additional scope requirement
// (ingest|admin) inside the handler. These tests exercise that combined model;
// the backward-compat contract ("unauthenticated batch accepted when the gate is
// unset") holds for the realistic fresh-collector case (no tokens provisioned).

func TestIngestAuth_OpenByDefault(t *testing.T) {
	// Fresh install: no tokens exist and the gate is unset → RequireAuth bypasses
	// and the handler gate is off → unauthenticated ingest is accepted.
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	w := postIngest(t, router, []models.Event{
		{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"},
	}, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("open-mode ingest: expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIngestAuth_EnforcedRequiresToken(t *testing.T) {
	t.Setenv("VEDETTA_REQUIRE_INGEST_AUTH", "1")
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	rawToken := createIngestToken(t, db)

	// Missing token → 401 (RequireAuth enforces once a token exists; the handler
	// gate would also require the ingest scope).
	w := postIngest(t, router, []models.Event{
		{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"},
	}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enforced mode without token: expected 401, got %d", w.Code)
	}

	// Valid ingest-scoped token → 202.
	w = postIngest(t, router, []models.Event{
		{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"},
	}, rawToken)
	if w.Code != http.StatusAccepted {
		t.Fatalf("enforced mode with token: expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIngestAuth_EnforcedWrongScopeRejected(t *testing.T) {
	// Gate on, an ingest token exists (so enforcement engages), but the caller
	// presents a SENSOR-scoped token → the handler's scope check returns 403.
	t.Setenv("VEDETTA_REQUIRE_INGEST_AUTH", "1")
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	_ = createIngestToken(t, db) // makes HasActiveIngestToken() true

	// Sensor-scoped token with no sensor_id (avoids the sensors FK); scope is
	// neither ingest nor admin, so the handler gate must reject it with 403.
	rawSensor, sensorTok, err := auth.GenerateToken(auth.ScopeSensor, "", "test-sensor")
	if err != nil {
		t.Fatalf("generate sensor token: %v", err)
	}
	if err := db.CreateToken(sensorTok); err != nil {
		t.Fatalf("store sensor token: %v", err)
	}

	w := postIngest(t, router, []models.Event{
		{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"},
	}, rawSensor)
	if w.Code != http.StatusForbidden {
		t.Fatalf("enforced mode with sensor-scoped token: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIngestAuth_EnforcedButNoIngestTokenStaysOpen(t *testing.T) {
	// Enforcement flag set but NO tokens exist at all → RequireAuth bypasses
	// (fresh install) and the handler gate finds no ingest token → endpoint stays
	// open. A deployment that never provisioned an ingest token keeps working.
	t.Setenv("VEDETTA_REQUIRE_INGEST_AUTH", "1")
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	w := postIngest(t, router, []models.Event{
		{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"},
	}, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("enforced-but-no-ingest-token: expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIngest_EventCap413(t *testing.T) {
	srv, _ := setupTestServer(t)
	router := NewRouter(srv)

	events := make([]models.Event, maxEventsPerIngest+1)
	for i := range events {
		events[i] = models.Event{EventType: "firewall_log", Timestamp: time.Now().UTC(), SourceHash: "h"}
	}
	w := postIngest(t, router, events, "")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap ingest: expected 413, got %d", w.Code)
	}
}

func createIngestToken(t *testing.T, db *store.DB) string {
	t.Helper()
	raw, token, err := auth.GenerateToken(auth.ScopeIngest, "", "test-ingest")
	if err != nil {
		t.Fatalf("generate ingest token: %v", err)
	}
	if err := db.CreateToken(token); err != nil {
		t.Fatalf("store ingest token: %v", err)
	}
	return raw
}
