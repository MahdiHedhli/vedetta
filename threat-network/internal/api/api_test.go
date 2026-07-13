package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/auth"
	"github.com/vedetta-network/vedetta/threat-network/internal/consensus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// uuidFor deterministically derives a valid UUIDv4 from a friendly label so the
// HTTP tests can keep readable batch-id/nonce labels while meeting the pinned
// UUIDv4 wire format (batch_id and X-Vedetta-Nonce validation, GHSA-hx86).
func uuidFor(label string) string {
	h := sha256.Sum256([]byte(label))
	h[6] = (h[6] & 0x0f) | 0x40 // version 4
	h[8] = (h[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func newTestServer(t *testing.T) (*Server, *store.DB, *httptest.Server) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewServer(db, log.New(io.Discard, "", 0))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, db, ts
}

func TestStatusEndpoint(t *testing.T) {
	_, _, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	if m["service"] != "vedetta-threat-network" || m["schema_version"].(float64) != 1 {
		t.Fatalf("unexpected status body: %v", m)
	}
	if _, ok := m["feed_items"]; !ok {
		t.Fatal("status must include feed_items count")
	}
}

func TestPublicMethodNotAllowedAdvertisesAllowedMethods(t *testing.T) {
	_, _, ts := newTestServer(t)
	tests := []struct {
		path   string
		method string
		allow  string
	}{
		{path: "/api/v1/status", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/reporters/register", method: http.MethodGet, allow: "POST"},
		{path: "/api/v1/ingest", method: http.MethodGet, allow: "POST"},
		{path: "/api/v1/feed/community", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/device-corpus/manifest", method: http.MethodPost, allow: "GET"},
		{path: "/api/v1/device-corpus/snapshot", method: http.MethodPost, allow: "GET"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, ts.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != tt.allow {
				t.Fatalf("Allow = %q, want %q", got, tt.allow)
			}
		})
	}
}

func TestDeprecatedStubs(t *testing.T) {
	_, _, ts := newTestServer(t)
	for _, path := range []string{"/api/v1/feed/top-domains", "/api/v1/feed/anomalies"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s expected 200, got %d", path, resp.StatusCode)
		}
		if resp.Header.Get("Deprecation") != "true" {
			t.Fatalf("%s missing Deprecation header", path)
		}
		resp.Body.Close()
	}
}

// registerViaAPI performs a real registration round-trip and returns id + key.
func registerViaAPI(t *testing.T, ts *httptest.Server) (id, signingKey string) {
	t.Helper()
	reqBody, _ := json.Marshal(auth.RegisterRequest{
		SchemaVersion: 1, InstallID: "11111111-1111-4111-8111-111111111111",
		VedettaVersion: "0.1.0",
		Capabilities:   []string{"known_bad_domain_hit", "high_confidence_domain_candidate", "behavior_summary"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/reporters/register", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", resp.StatusCode)
	}
	var rr auth.RegisterResponse
	json.NewDecoder(resp.Body).Decode(&rr)
	if rr.ReporterID == "" || rr.ReporterSecret == "" {
		t.Fatal("register must return id and secret")
	}
	return rr.ReporterID, auth.SigningKeyForSecret(rr.ReporterSecret)
}

// backdateReporter ages a reporter's created_at into the past so it counts toward
// consensus promotion distinctness (which excludes freshly-minted reporter_ids as
// a Sybil defense — see consensus.ReporterMaturationDelay).
func backdateReporter(t *testing.T, db *store.DB, id string) {
	t.Helper()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE reporters SET created_at = ? WHERE reporter_id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
}

func signAndPost(t *testing.T, ts *httptest.Server, id, key, nonce string, body []byte) *http.Response {
	t.Helper()
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(key, tsStr, nonce, body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "VedettaReporter "+id)
	req.Header.Set("X-Vedetta-Timestamp", tsStr)
	req.Header.Set("X-Vedetta-Nonce", nonce)
	req.Header.Set("X-Vedetta-Signature", sig)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func batchBody(batchID string) []byte {
	return []byte(fmt.Sprintf(`{
      "schema_version":1,"batch_id":%q,"generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[
        {"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
         "domain":"c2.badzone.example","etld_plus_one":"badzone.example","local_confidence":0.99,
         "local_reasons":["known_bad"],"observation_count":4,"distinct_asset_count":2,"blocked_count":4}
      ]}`, batchID))
}

func TestEndToEndRegisterIngestConsensusFeed(t *testing.T) {
	_, db, ts := newTestServer(t)

	// Two independent reporters both report the same known_bad domain.
	id1, key1 := registerViaAPI(t, ts)
	id2, key2 := registerViaAPI(t, ts)

	r1 := signAndPost(t, ts, id1, key1, uuidFor("n1"), batchBody(uuidFor("batch-1")))
	if r1.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(r1.Body)
		t.Fatalf("ingest1 expected 202, got %d: %s", r1.StatusCode, b)
	}
	var res1 map[string]any
	json.NewDecoder(r1.Body).Decode(&res1)
	r1.Body.Close()
	if res1["accepted"].(float64) != 1 || res1["duplicate"].(bool) != false {
		t.Fatalf("unexpected ingest1 result: %v", res1)
	}

	r2 := signAndPost(t, ts, id2, key2, uuidFor("n1"), batchBody(uuidFor("batch-2")))
	if r2.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest2 expected 202, got %d", r2.StatusCode)
	}
	r2.Body.Close()

	// Model established reporters: age both past the consensus maturation delay so
	// they count toward promotion. Freshly-minted reporter_ids are deliberately
	// excluded from promotion thresholds (Sybil defense); see consensus package.
	backdateReporter(t, db, id1)
	backdateReporter(t, db, id2)

	// Run consensus → the domain corroborated by 2 mature reporters promotes.
	if err := consensus.New(db).Run(); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(ts.URL + "/api/v1/feed/community")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var feedResp map[string]any
	json.NewDecoder(resp.Body).Decode(&feedResp)
	items := feedResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 promoted item, got %d", len(items))
	}
	item := items[0].(map[string]any)
	if item["advisory"].(bool) != true || item["recommended_action"].(string) != "advise" {
		t.Fatalf("feed item must be advisory-only: %v", item)
	}
	if resp.Header.Get("ETag") == "" {
		t.Fatal("feed must set ETag")
	}
}

func TestIngestReplayIdempotent(t *testing.T) {
	_, db, ts := newTestServer(t)
	id, key := registerViaAPI(t, ts)

	r1 := signAndPost(t, ts, id, key, uuidFor("nonce-a"), batchBody(uuidFor("replay-batch")))
	if r1.StatusCode != http.StatusAccepted {
		t.Fatalf("first ingest expected 202, got %d", r1.StatusCode)
	}
	r1.Body.Close()

	var before int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&before)

	// Replay the same batch_id (fresh nonce/timestamp so auth passes).
	r2 := signAndPost(t, ts, id, key, uuidFor("nonce-b"), batchBody(uuidFor("replay-batch")))
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("replay must return 200, got %d", r2.StatusCode)
	}
	var res map[string]any
	json.NewDecoder(r2.Body).Decode(&res)
	r2.Body.Close()
	if res["duplicate"].(bool) != true {
		t.Fatalf("replay must set duplicate:true, got %v", res)
	}

	var after int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&after)
	if after != before {
		t.Fatalf("replay must not re-process: %d → %d", before, after)
	}
}

func TestUnsignedIngestRejected(t *testing.T) {
	_, _, ts := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest", bytes.NewReader(batchBody(uuidFor("x"))))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned ingest expected 401, got %d", resp.StatusCode)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	_, _, ts := newTestServer(t)
	id, key := registerViaAPI(t, ts)
	body := batchBody(uuidFor("tamper"))
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	sig := auth.ComputeSignature(key, tsStr, uuidFor("n1"), body)
	// Tamper the body after signing.
	tampered := batchBody(uuidFor("tamper-CHANGED"))
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest", bytes.NewReader(tampered))
	req.Header.Set("Authorization", "VedettaReporter "+id)
	req.Header.Set("X-Vedetta-Timestamp", tsStr)
	req.Header.Set("X-Vedetta-Nonce", uuidFor("n1"))
	req.Header.Set("X-Vedetta-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body expected 401, got %d", resp.StatusCode)
	}
}

func TestPrivacyGate422OverHTTP(t *testing.T) {
	_, _, ts := newTestServer(t)
	id, key := registerViaAPI(t, ts)
	pgBID := uuidFor("pg")
	body := []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":%q,"generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[
        {"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
         "domain":"printer.local","etld_plus_one":"badzone.example","local_confidence":0.9,
         "local_reasons":["known_bad"],"observation_count":1,"distinct_asset_count":1}]}`, pgBID))
	resp := signAndPost(t, ts, id, key, uuidFor("n-pg"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("privacy violation expected 422, got %d", resp.StatusCode)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	for _, k := range []string{"error", "rule", "detail", "batch_id"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("422 body missing field %q: %v", k, m)
		}
	}
	if m["batch_id"].(string) != pgBID {
		t.Fatalf("422 body batch_id mismatch: %v", m["batch_id"])
	}
}

func TestStrictSchema422OverHTTP(t *testing.T) {
	_, _, ts := newTestServer(t)
	id, key := registerViaAPI(t, ts)
	body := []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":%q,"generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[],
      "unexpected":"x"}`, uuidFor("ss")))
	resp := signAndPost(t, ts, id, key, uuidFor("n-ss"), body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown key expected 422, got %d", resp.StatusCode)
	}
}

func TestFeed304NotModified(t *testing.T) {
	_, db, ts := newTestServer(t)
	// Seed one live item directly.
	now := time.Now().UTC()
	db.UpsertFeedItem(store.FeedItem{
		FeedID: "f1", Kind: "domain_indicator", Indicator: "x.badzone.example",
		IndicatorType: "domain", Confidence: 0.9, Severity: "high", SourcesRequired: 2,
		SourcesObserved: 3, Reasons: `["known_bad"]`,
		FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339),
		PublishedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
	})
	resp, err := http.Get(ts.URL + "/api/v1/feed/community")
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	if etag == "" {
		t.Fatal("expected ETag")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/feed/community", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", resp2.StatusCode)
	}
}

func TestRateLimitEnforced(t *testing.T) {
	db, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewServer(db, log.New(io.Discard, "", 0))
	// Shrink the feed limiter so the burst is quickly exhausted.
	s.feedLimit = NewRateLimiter(0.001, 3)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	got429 := false
	for i := 0; i < 10; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/feed/community")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			var m map[string]any
			json.NewDecoder(resp.Body).Decode(&m)
			e := m["error"].(map[string]any)
			if e["code"].(string) != "RATE_LIMIT_EXCEEDED" {
				t.Fatalf("expected RATE_LIMIT_EXCEEDED, got %v", e["code"])
			}
			if _, ok := e["retry_after_seconds"]; !ok {
				t.Fatal("429 must include retry_after_seconds")
			}
		}
		resp.Body.Close()
	}
	if !got429 {
		t.Fatal("expected a 429 after exhausting the burst")
	}
}

func TestDenylistedReporterEndToEnd(t *testing.T) {
	_, db, ts := newTestServer(t)
	id, key := registerViaAPI(t, ts)
	// Denylist via the store (mirrors the CLI admin path).
	if err := db.DenylistReporter(id, "abuse"); err != nil {
		t.Fatal(err)
	}
	resp := signAndPost(t, ts, id, key, uuidFor("n-dl"), batchBody(uuidFor("dl")))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denylisted reporter expected 403, got %d", resp.StatusCode)
	}
}

func TestDenylistExcludesFromConsensus(t *testing.T) {
	_, db, ts := newTestServer(t)
	id1, key1 := registerViaAPI(t, ts)
	id2, key2 := registerViaAPI(t, ts)
	signAndPost(t, ts, id1, key1, uuidFor("a"), batchBody(uuidFor("b1"))).Body.Close()
	signAndPost(t, ts, id2, key2, uuidFor("a"), batchBody(uuidFor("b2"))).Body.Close()

	// Denylist reporter 2 → the indicator drops to 1 distinct reporter → not promoted.
	if err := db.DenylistReporter(id2, "abuse"); err != nil {
		t.Fatal(err)
	}
	if err := consensus.New(db).Run(); err != nil {
		t.Fatal(err)
	}
	items, _, _ := db.LiveFeedItems(store.FeedQuery{Now: time.Now(), Limit: 10})
	if len(items) != 0 {
		t.Fatalf("denylisted reporter's signal must not corroborate; expected 0 items, got %d", len(items))
	}
}
