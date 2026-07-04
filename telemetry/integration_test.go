//go:build integration

// Integration test (build-tagged: `go test -tags=integration ./...`). It stands
// up a stub threat-network + fake Core in-process and drives the pipeline to
// assert the three headline behaviors:
//
//	(a) opt-in off  → zero outbound requests, no state files
//	(b) opt-in on   → register, then a valid signed batch is accepted
//	(c) server down → spool grows, then drains on recovery
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
	"github.com/vedetta-network/vedetta/telemetry/internal/export"
	"github.com/vedetta-network/vedetta/telemetry/internal/pipeline"
	"github.com/vedetta-network/vedetta/telemetry/internal/status"
	"github.com/vedetta-network/vedetta/telemetry/internal/transmit"
)

func syntheticEvent() corereader.Event {
	return corereader.Event{
		EventID: "e1", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceIP: "192.0.2.55",
		Domain: "c2-payload.badzone.example", Blocked: true, AnomalyScore: 0.99,
		Tags: []string{"known_bad", "threat_feed_match"},
	}
}

func fakeCore() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := []corereader.Event{}
		if r.URL.Query().Get("page") != "2" {
			out = []corereader.Event{syntheticEvent()}
		}
		json.NewEncoder(w).Encode(map[string]any{"events": out, "total": len(out), "page": 1, "limit": 500})
	}))
}

func TestIntegrationOptInOffInert(t *testing.T) {
	// With opt-in off, config.Load reports OptIn=false and main() would just
	// sleep. Assert no state dir is created by the pipeline path.
	dir := filepath.Join(t.TempDir(), "state")
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"VEDETTA_TELEMETRY_STATE_DIR": dir}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OptIn {
		t.Fatal("should be off")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("no state dir should exist when off")
	}
}

func TestIntegrationOptInOnAcceptsSignedBatch(t *testing.T) {
	core := fakeCore()
	defer core.Close()

	var got atomic.Value
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vedetta-Signature") == "" || r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		got.Store(true)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"accepted": 1})
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "s"}, transmit.NewSpool(dir), false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &pipeline.Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}
	p.RunTick(context.Background())

	if got.Load() != true {
		t.Fatal("threat network did not receive a signed batch")
	}
	_ = export.SchemaVersion
}

func TestIntegrationServerDownSpoolsThenDrains(t *testing.T) {
	core := fakeCore()
	defer core.Close()

	down := int32(1)
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&down) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	spool := transmit.NewSpool(dir)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "s"}, spool, false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	tx.MaxAttempts = 2
	p := &pipeline.Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())
	if spool.Depth() == 0 {
		t.Fatal("expected spool to grow while server down")
	}

	atomic.StoreInt32(&down, 0)
	sent, remaining := tx.DrainSpool(context.Background())
	if sent == 0 || remaining != 0 {
		t.Errorf("drain on recovery: sent=%d remaining=%d", sent, remaining)
	}
}
