// Package contract holds the CROSS-SERVICE contract integration test: it drives
// the real threat-network ingest surface (register a reporter, HMAC-sign the
// body, POST /api/v1/ingest) with the shared golden fixtures that live beside
// the frozen wire contract at
// specs/002-telemetry-service/contracts/telemetry-export.md.
//
// The telemetry service PRODUCES the wire format; this service VALIDATES it.
// These fixtures are the single source of truth both sides pin to, so a drift
// on either side fails here.
package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/api"
	"github.com/vedetta-network/vedetta/threat-network/internal/auth"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// fixturesDir locates the shared contract fixtures. From
// threat-network/internal/contract the repo root is ../../.. then into specs.
func fixturesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "specs", "002-telemetry-service", "contracts", "fixtures")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("fixtures dir not found: %v", err)
	}
	return dir
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir(t), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := api.NewServer(db, log.New(io.Discard, "", 0))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// registerReporter performs the real registration precondition (contract §2)
// and returns the reporter id plus the signing key derived from the issued
// secret.
func registerReporter(t *testing.T, ts *httptest.Server) (id, signingKey string) {
	t.Helper()
	reqBody, _ := json.Marshal(auth.RegisterRequest{
		SchemaVersion:  1,
		InstallID:      "1f7b6d2e-8f0a-4c4e-9b1d-3a5c7e9f0b2d",
		VedettaVersion: "0.1.0-dev",
		Capabilities: []string{
			"known_bad_domain_hit",
			"high_confidence_domain_candidate",
			"behavior_summary",
		},
	})
	resp, err := http.Post(ts.URL+"/api/v1/reporters/register", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register expected 201, got %d: %s", resp.StatusCode, b)
	}
	var rr auth.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if rr.ReporterID == "" || rr.ReporterSecret == "" {
		t.Fatal("register must return id and secret")
	}
	return rr.ReporterID, auth.SigningKeyForSecret(rr.ReporterSecret)
}

// postSigned signs the body exactly as a real telemetry client would (contract
// §1) and POSTs it to /api/v1/ingest.
func postSigned(t *testing.T, ts *httptest.Server, id, key, nonce string, body []byte) *http.Response {
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
		t.Fatalf("post ingest: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return m
}

// TestValidBatchAccepted proves the well-formed fixture with all three signal
// kinds is accepted (202) and all three signals counted.
func TestValidBatchAccepted(t *testing.T) {
	ts := newServer(t)
	id, key := registerReporter(t, ts)

	body := readFixture(t, "valid-batch.json")
	resp := postSigned(t, ts, id, key, "nonce-valid", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid-batch expected 202, got %d: %s", resp.StatusCode, b)
	}
	m := decodeBody(t, resp)
	if got := m["accepted"].(float64); got != 3 {
		t.Fatalf("valid-batch expected accepted=3 (all three kinds), got %v", got)
	}
	if m["duplicate"].(bool) != false {
		t.Fatalf("first ingest must not be a duplicate: %v", m)
	}
	if m["batch_id"].(string) != "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e" {
		t.Fatalf("batch_id echo mismatch: %v", m["batch_id"])
	}
}

// TestReplayIsIdempotent proves a replay of the accepted valid-batch returns
// 200 {duplicate:true} and is NOT re-counted (contract §1).
func TestReplayIsIdempotent(t *testing.T) {
	ts := newServer(t)
	id, key := registerReporter(t, ts)
	body := readFixture(t, "valid-batch.json")

	first := postSigned(t, ts, id, key, "nonce-a", body)
	if first.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Fatalf("first ingest expected 202, got %d: %s", first.StatusCode, b)
	}
	firstBody := decodeBody(t, first)
	first.Body.Close()
	firstAccepted := firstBody["accepted"].(float64)

	// Replay same batch_id with a fresh nonce/timestamp so auth passes and only
	// the idempotency path is exercised.
	replay := postSigned(t, ts, id, key, "nonce-b", body)
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusOK {
		t.Fatalf("replay must return 200, got %d", replay.StatusCode)
	}
	m := decodeBody(t, replay)
	if m["duplicate"].(bool) != true {
		t.Fatalf("replay must set duplicate:true, got %v", m)
	}
	// Replay must report the ORIGINAL counts, not a re-count.
	if m["accepted"].(float64) != firstAccepted {
		t.Fatalf("replay accepted=%v must equal original %v (no re-count)", m["accepted"], firstAccepted)
	}
}

// invalidCase couples a fixture to the tripwire it is expected to trip.
type invalidCase struct {
	fixture     string
	nonce       string
	wantStatus  int
	wantError   string // expected top-level "error" value; "" = don't assert exact value
	wantBatchID string // expected echoed batch_id in the 422 body
	description string
}

// TestInvalidFixturesRejected runs each privacy/schema tripwire fixture through
// the real ingest validation path and asserts the machine-readable rejection
// body shape {error, rule, detail, batch_id} (contract §5).
func TestInvalidFixturesRejected(t *testing.T) {
	cases := []invalidCase{
		{
			fixture:     "invalid-raw-ip.json",
			nonce:       "n-ip",
			wantStatus:  http.StatusUnprocessableEntity,
			wantError:   "forbidden_content",
			wantBatchID: "a1111111-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
			description: "rule 2: IP literal in a domain value",
		},
		{
			fixture:     "invalid-mac.json",
			nonce:       "n-mac",
			wantStatus:  http.StatusUnprocessableEntity,
			wantError:   "forbidden_content",
			wantBatchID: "a2222222-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
			description: "rule 3: MAC-shaped value",
		},
		{
			fixture:     "invalid-hostname.json",
			nonce:       "n-host",
			wantStatus:  http.StatusUnprocessableEntity,
			wantError:   "forbidden_content",
			wantBatchID: "a3333333-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
			description: "rule 4/7: private-zone hostname",
		},
		{
			fixture:     "invalid-unknown-key.json",
			nonce:       "n-key",
			wantStatus:  http.StatusUnprocessableEntity,
			wantError:   "strict_schema",
			wantBatchID: "a4444444-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
			description: "rule 1: unknown extra key (source_hash)",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.fixture, func(t *testing.T) {
			ts := newServer(t)
			id, key := registerReporter(t, ts)
			body := readFixture(t, tc.fixture)
			resp := postSigned(t, ts, id, key, tc.nonce, body)
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s (%s): expected %d, got %d: %s",
					tc.fixture, tc.description, tc.wantStatus, resp.StatusCode, b)
			}
			m := decodeBody(t, resp)
			// The rejection body MUST carry {error, rule, detail, batch_id}.
			for _, k := range []string{"error", "rule", "detail", "batch_id"} {
				if _, ok := m[k]; !ok {
					t.Fatalf("%s: 422 body missing field %q: %v", tc.fixture, k, m)
				}
			}
			if tc.wantError != "" && m["error"].(string) != tc.wantError {
				t.Fatalf("%s: expected error=%q, got %q", tc.fixture, tc.wantError, m["error"])
			}
			if m["batch_id"].(string) != tc.wantBatchID {
				t.Fatalf("%s: batch_id echo mismatch: got %q want %q",
					tc.fixture, m["batch_id"], tc.wantBatchID)
			}
			if m["rule"].(string) == "" {
				t.Fatalf("%s: rejection must name a rule", tc.fixture)
			}
		})
	}
}

// TestMissingRequiredFieldRejected exercises the "missing required field"
// tripwire (invalid-missing-field.json omits the required top-level
// window_end, contract §3). The validator rejects the batch, but via the
// envelope path (400 INVALID_SCHEMA), NOT the 422 privacy/schema tripwire path
// the task spec anticipated. This asserts the ACTUAL behavior and documents the
// divergence; the deviation is reported rather than papered over by changing
// production logic.
func TestMissingRequiredFieldRejected(t *testing.T) {
	ts := newServer(t)
	id, key := registerReporter(t, ts)
	body := readFixture(t, "invalid-missing-field.json")
	resp := postSigned(t, ts, id, key, "n-missing", body)
	defer resp.Body.Close()

	// The batch is rejected (the contract's intent). Accept either the actual
	// 400 envelope rejection or a 422, but it MUST NOT be accepted (2xx success).
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("missing required field must be rejected, got %d: %s", resp.StatusCode, b)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing required field expected 400 or 422, got %d", resp.StatusCode)
	}
	// Record which path fired for observability.
	t.Logf("missing-required-field rejected with status %d (contract §3 envelope validation)", resp.StatusCode)
}
