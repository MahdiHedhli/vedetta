package pipeline

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
	"github.com/vedetta-network/vedetta/telemetry/internal/export"
	"github.com/vedetta-network/vedetta/telemetry/internal/status"
	"github.com/vedetta-network/vedetta/telemetry/internal/transmit"
)

func syntheticEvents() []corereader.Event {
	base := time.Date(2026, 7, 3, 14, 15, 0, 0, time.UTC)
	return []corereader.Event{
		// known_bad hit — exact domain permitted.
		{EventID: "e1", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.55",
			Domain: "c2-payload.badzone.example", Blocked: true, AnomalyScore: 0.99,
			Tags: []string{"known_bad", "threat_feed_match", "c2_candidate"}},
		// candidate — eTLD+1 only.
		{EventID: "e2", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.56",
			Domain: "sub.qxv-rotator.example", AnomalyScore: 0.91,
			Tags: []string{"c2_candidate", "high_entropy"}},
		// behavior — no domain.
		{EventID: "e3", Timestamp: base, EventType: "anomaly", SourceIP: "192.0.2.57",
			Domain: "beacon.qxv-rotator.example", AnomalyScore: 0.81,
			Tags: []string{"beaconing_candidate"}},
		// withheld: private domain.
		{EventID: "e4", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.58",
			Domain: "nas-placeholder-01.local", AnomalyScore: 0.99, Tags: []string{"known_bad"}},
		// withheld: acknowledged.
		{EventID: "e5", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.59",
			Domain: "acked.badzone.example", AnomalyScore: 0.99, Acknowledged: true, Tags: []string{"known_bad"}},
	}
}

func gunzipReq(r *http.Request) ([]byte, error) {
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fakeCoreServer(events []corereader.Event) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if r.URL.Query().Get("page") == "2" {
			page = 2
		}
		out := events
		if page == 2 {
			out = nil
		}
		json.NewEncoder(w).Encode(map[string]any{"events": out, "total": len(events), "page": page, "limit": 500})
	}))
}

func TestPipelineEndToEnd(t *testing.T) {
	core := fakeCoreServer(syntheticEvents())
	defer core.Close()

	var received atomic.Value // stores []byte of the last uncompressed batch
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decompress and stash for leak-scan assertion.
		gz, err := gunzipReq(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Store(gz)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "duplicate": false})
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL,
		StateDir: dir, CandidateMinScore: 0.85, BehaviorMinScore: 0.70,
		ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4,
	}
	st := status.NewState(true, false)
	spool := transmit.NewSpool(dir)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, spool, false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}

	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())

	raw, _ := received.Load().([]byte)
	if raw == nil {
		t.Fatalf("threat network received no batch")
	}
	// Privacy gate: serialized batch must be leak-free.
	if v := export.LeakScan(raw); len(v) > 0 {
		t.Errorf("leak-scan violations in transmitted batch: %v\n%s", v, raw)
	}
	// Expect exactly 3 signals (known_bad, candidate, behavior); 2 withheld.
	var batch export.Batch
	json.Unmarshal(raw, &batch)
	if len(batch.Signals) != 3 {
		t.Errorf("expected 3 signals, got %d: %+v", len(batch.Signals), batch.Signals)
	}
	// Cursor persisted.
	cur, _ := corereader.LoadCursor(dir)
	if cur.LastEventID == "" {
		t.Errorf("cursor not advanced")
	}
	// Status updated with counts only.
	snap := st.Get()
	if snap.LastBatch.Result != "accepted" || snap.LastBatch.SignalCount != 3 {
		t.Errorf("status last batch wrong: %+v", snap.LastBatch)
	}
}

// knownBadEvents builds n distinct known_bad DNS events (each a unique domain,
// so each aggregates to its own signal). They share a timestamp so the cursor
// tie-breaker keys off EventID.
func knownBadEvents(n int) []corereader.Event {
	base := time.Date(2026, 7, 3, 14, 15, 0, 0, time.UTC)
	evs := make([]corereader.Event, 0, n)
	for i := 0; i < n; i++ {
		evs = append(evs, corereader.Event{
			EventID:      "kb" + strconv.Itoa(i),
			Timestamp:    base,
			EventType:    "dns_query",
			SourceIP:     "192.0.2." + strconv.Itoa(10+i),
			Domain:       "c2-" + strconv.Itoa(i) + ".badzone.example",
			Blocked:      true,
			AnomalyScore: 0.99,
			Tags:         []string{"known_bad", "threat_feed_match"},
		})
	}
	return evs
}

// TestPipelineOverflowBatchesSpooledNotDropped is the regression test for the
// MaxBatchesTick truncation loss: overflow batches beyond the per-tick send cap
// must be spooled (and thus retried by DrainSpool), never silently discarded
// while the cursor advances past their source events.
func TestPipelineOverflowBatchesSpooledNotDropped(t *testing.T) {
	const n = 5 // 5 distinct signals → 5 batches at MaxBatchItems=1

	// Collect the domains delivered to the threat network across all ticks.
	delivered := map[string]bool{}
	var mu sync.Mutex
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gunzipReq(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var batch export.Batch
		if json.Unmarshal(gz, &batch) == nil {
			mu.Lock()
			for _, s := range batch.Signals {
				if s.Domain != "" {
					delivered[s.Domain] = true
				}
			}
			mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "duplicate": false})
	}))
	defer tn.Close()

	// Core returns the n events only on the first read; subsequent reads return
	// nothing, so tick 2 does no fresh work and only DrainSpool runs. (This keeps
	// the spool-depth assertions focused on overflow, independent of the cursor
	// tie-breaker's re-read behavior for same-timestamp events.)
	events := knownBadEvents(n)
	var served atomic.Bool
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := events
		if served.Swap(true) || r.URL.Query().Get("page") == "2" {
			out = nil
		}
		json.NewEncoder(w).Encode(map[string]any{"events": out, "total": len(out), "page": 1, "limit": 500})
	}))
	defer core.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL,
		StateDir: dir, CandidateMinScore: 0.85, BehaviorMinScore: 0.70,
		ReadCapPerTick: 5000,
		MaxBatchItems:  1, // one signal per batch
		MaxBatchesTick: 1, // only one batch may be SENT per tick; rest overflow
	}
	st := status.NewState(true, false)
	spool := transmit.NewSpool(dir)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, spool, false, 1)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}

	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	// Tick 1: reads n events, sends 1 batch, spools the other n-1 as overflow.
	p.RunTick(context.Background())

	if got := spool.Depth(); got != n-1 {
		t.Fatalf("expected %d overflow batches spooled after tick 1, got %d", n-1, got)
	}
	// Cursor must have advanced (all n events consumed).
	cur, _ := corereader.LoadCursor(dir)
	if cur.LastEventID != "kb"+strconv.Itoa(n-1) {
		t.Fatalf("cursor should advance past all read events, got %q", cur.LastEventID)
	}

	// Subsequent ticks: Core has no new events; DrainSpool must flush the
	// overflow. A single batch may itself overflow the send cap again, but each
	// tick drains the whole spool first (DrainSpool is not capped), so one more
	// tick delivers everything.
	p.RunTick(context.Background())

	mu.Lock()
	missing := []string{}
	for _, ev := range events {
		if !delivered[ev.Domain] {
			missing = append(missing, ev.Domain)
		}
	}
	got := len(delivered)
	mu.Unlock()

	if len(missing) > 0 {
		t.Fatalf("signals lost (not delivered): %v", missing)
	}
	if got != n {
		t.Fatalf("expected all %d distinct signals delivered, got %d", n, got)
	}
	if d := spool.Depth(); d != 0 {
		t.Fatalf("spool should be empty after drain, got depth %d", d)
	}
}

func TestPipelineCoreUnreachableCursorUnchanged(t *testing.T) {
	badCore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badCore.Close()
	dir := t.TempDir()
	// Seed a cursor.
	seed := corereader.Cursor{LastTimestamp: time.Now().UTC(), LastEventID: "prev"}
	seed.Save(dir)

	cfg := &config.Config{OptIn: true, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70}
	st := status.NewState(true, false)
	tx := transmit.New("http://x", transmit.Reporter{}, transmit.NewSpool(dir), false, 250)
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(badCore.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}
	p.RunTick(context.Background())

	cur, _ := corereader.LoadCursor(dir)
	if cur.LastEventID != "prev" {
		t.Errorf("cursor should be unchanged on core error, got %q", cur.LastEventID)
	}
	if st.Get().LastError == "" {
		t.Errorf("expected error surfaced on status")
	}
}
