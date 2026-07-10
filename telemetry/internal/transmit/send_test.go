package transmit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/export"
)

func testReporter() Reporter {
	return Reporter{ReporterID: "rid", ReporterSecret: "secret"}
}

func sampleSignals(n int) []export.Signal {
	out := make([]export.Signal, n)
	for i := range out {
		out[i] = export.Signal{
			SignalID: "sig", Kind: export.KindBehaviorSummary, Behavior: export.BehaviorBeaconing,
			TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.8,
			LocalReasons: []string{"beaconing_candidate"}, ObservationCount: 1, DistinctAssetCount: 1,
		}
	}
	return out
}

func noSleep() func(time.Duration) { return func(time.Duration) {} }

func TestSendSuccess(t *testing.T) {
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		// Verify gzip body decompresses.
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.ReadAll(zr)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "duplicate": false})
	}))
	defer srv.Close()

	tx := New(srv.URL, testReporter(), NewSpool(t.TempDir()), false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()

	batches := tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())
	res := tx.Send(context.Background(), batches[0])
	if !res.Accepted || res.Err != nil {
		t.Fatalf("send failed: %+v", res)
	}
	// All four auth headers present (contract §1).
	for _, h := range []string{"Authorization", "X-Vedetta-Timestamp", "X-Vedetta-Nonce", "X-Vedetta-Signature"} {
		if gotHeaders.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if gotHeaders.Get("Content-Encoding") != "gzip" {
		t.Errorf("missing gzip content-encoding")
	}
	if got := gotHeaders.Get("Authorization"); got != "VedettaReporter rid" {
		t.Errorf("auth header = %q", got)
	}
}

func TestSendDuplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"duplicate": true})
	}))
	defer srv.Close()
	tx := New(srv.URL, testReporter(), NewSpool(t.TempDir()), false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()
	res := tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	if !res.Accepted || !res.Duplicate {
		t.Errorf("expected accepted+duplicate: %+v", res)
	}
}

func TestSend4xxPoisonPillNoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{"error": "forbidden_content"})
	}))
	defer srv.Close()
	spool := NewSpool(t.TempDir())
	tx := New(srv.URL, testReporter(), spool, false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()

	res := tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	if !res.Rejected {
		t.Errorf("expected rejected, got %+v", res)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("4xx should not retry, got %d calls", calls)
	}
	// Rejected batch parked for inspection; not in the main spool.
	if spool.Depth() != 0 {
		t.Errorf("rejected batch should not sit in main spool")
	}
	files, _ := listSpoolFiles(spool.RejectedDir)
	if len(files) != 1 {
		t.Errorf("expected 1 rejected file, got %d", len(files))
	}
}

// Issue #36: 401/403/429 are identity/rate failures, NOT payload poison. They
// are retryable and must NOT be dead-lettered NOR spooled — the pipeline holds
// the Core cursor and re-reads, so the bounded spool is never the durability
// path under a bad/absent identity. They also must not burn retries in-tick.
func TestSendAuthFailureRetryableNotSpooled(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.WriteHeader(status)
			}))
			defer srv.Close()
			spool := NewSpool(t.TempDir())
			tx := New(srv.URL, testReporter(), spool, false, 250)
			tx.HTTP = srv.Client()
			tx.Sleep = noSleep()

			res := tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
			if !res.AuthFailed || res.Spooled {
				t.Fatalf("status %d: expected AuthFailed and NOT Spooled, got %+v", status, res)
			}
			if res.Rejected {
				t.Errorf("status %d: auth failure must NOT be dead-lettered", status)
			}
			if got := atomic.LoadInt32(&calls); got != 1 {
				t.Errorf("status %d: auth failure must not retry, got %d calls", status, got)
			}
			// Nothing is spooled — the held cursor is the retry mechanism.
			if spool.Depth() != 0 {
				t.Errorf("status %d: auth failure must not spool, got depth %d", status, spool.Depth())
			}
			rejected, _ := listSpoolFiles(spool.RejectedDir)
			if len(rejected) != 0 {
				t.Errorf("status %d: auth failure must not land in rejected dir, got %d", status, len(rejected))
			}
		})
	}
}

func TestSend5xxRetriesThenSpools(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	spool := NewSpool(t.TempDir())
	tx := New(srv.URL, testReporter(), spool, false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()
	tx.MaxAttempts = 3

	res := tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	if !res.Spooled {
		t.Errorf("expected spooled after 5xx exhaustion: %+v", res)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
	if spool.Depth() != 1 {
		t.Errorf("batch should be spooled")
	}
}

func TestDryRunNoEgress(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()
	spool := NewSpool(t.TempDir())
	tx := New(srv.URL, testReporter(), spool, true /*dryRun*/, 250)
	tx.HTTP = srv.Client()

	res := tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	if !res.Spooled {
		t.Errorf("dry-run should spool: %+v", res)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("dry-run must make ZERO egress, got %d calls", calls)
	}
	if spool.Depth() != 1 {
		t.Errorf("dry-run batch should be spooled")
	}
}

func TestBuildBatchesSplit(t *testing.T) {
	tx := New("http://x", testReporter(), NewSpool(t.TempDir()), false, 100)
	batches := tx.BuildBatches(sampleSignals(250), time.Now(), time.Now())
	if len(batches) != 3 {
		t.Errorf("expected 3 batches (100+100+50), got %d", len(batches))
	}
	ids := map[string]bool{}
	for _, b := range batches {
		if ids[b.BatchID] {
			t.Errorf("duplicate batch_id")
		}
		ids[b.BatchID] = true
	}
}

func TestDrainSpoolResendsAndRemoves(t *testing.T) {
	// First server fails (spool), second succeeds (drain).
	var ok int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&ok) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		zr, _ := gzip.NewReader(r.Body)
		io.ReadAll(zr)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	spool := NewSpool(t.TempDir())
	tx := New(srv.URL, testReporter(), spool, false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()
	tx.MaxAttempts = 2

	tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	if spool.Depth() != 1 {
		t.Fatalf("precondition: expected 1 spooled")
	}
	atomic.StoreInt32(&ok, 1)
	sent, remaining, _ := tx.DrainSpool(context.Background())
	if sent != 1 || remaining != 0 {
		t.Errorf("drain sent=%d remaining=%d, want 1/0", sent, remaining)
	}
}

// Issue #36: draining a spooled batch against an auth-failing ingest must keep
// the batch spooled (no dead-letter) and report authFailed so the caller can
// surface a degraded state.
func TestDrainSpoolAuthFailureKeepsSpooled(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	spool := NewSpool(t.TempDir())
	tx := New(srv.URL, testReporter(), spool, false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()

	// Seed the spool directly (dry-run add) with two batches.
	for i := 0; i < 2; i++ {
		if err := tx.SpoolBatch(tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0]); err != nil {
			t.Fatal(err)
		}
	}
	sent, remaining, authFailed := tx.DrainSpool(context.Background())
	if !authFailed {
		t.Errorf("expected authFailed=true on 403 drain")
	}
	if sent != 0 || remaining != 2 {
		t.Errorf("auth-failing drain must keep all batches: sent=%d remaining=%d", sent, remaining)
	}
	// Draining stops at the first auth failure — the second batch is never tried.
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("drain should stop after first auth failure, got %d calls", got)
	}
	rejected, _ := listSpoolFiles(spool.RejectedDir)
	if len(rejected) != 0 {
		t.Errorf("auth failure must not dead-letter, got %d rejected", len(rejected))
	}
}

// Signed spooled resend must still carry a valid signature over the uncompressed body.
func TestDrainSpoolSignsCorrectly(t *testing.T) {
	var gotSig, gotTS, gotNonce string
	var gotBody []byte
	fail := int32(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&fail) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		gotSig = r.Header.Get("X-Vedetta-Signature")
		gotTS = r.Header.Get("X-Vedetta-Timestamp")
		gotNonce = r.Header.Get("X-Vedetta-Nonce")
		zr, _ := gzip.NewReader(r.Body)
		gotBody, _ = io.ReadAll(zr)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	tx := New(srv.URL, testReporter(), NewSpool(t.TempDir()), false, 250)
	tx.HTTP = srv.Client()
	tx.Sleep = noSleep()
	tx.MaxAttempts = 1

	tx.Send(context.Background(), tx.BuildBatches(sampleSignals(1), time.Now(), time.Now())[0])
	atomic.StoreInt32(&fail, 0)
	tx.DrainSpool(context.Background())

	want := Sign([]byte(SigningKey("secret")), SignatureInput{Timestamp: gotTS, Nonce: gotNonce, Body: gotBody})
	if gotSig == "" || gotSig != want {
		t.Errorf("spooled resend signature mismatch: got %q want %q", gotSig, want)
	}
	_ = bytes.TrimSpace
}
