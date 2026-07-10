package pipeline

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			MatchedIndicator: "c2-payload.badzone.example", MatchType: "domain",
			Tags: []string{"known_bad", "threat_feed_match", "c2_candidate"}},
		// candidate — eTLD+1 only.
		{EventID: "e2", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.56",
			Domain: "sub.qxv-rotator.example", AnomalyScore: 0.91,
			Tags: []string{"c2_candidate", "high_entropy"}},
		// behavior — no domain.
		{EventID: "e3", Timestamp: base, EventType: "dns_query", SourceIP: "192.0.2.57",
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
		if r.URL.Path == "/api/v1/settings/telemetry" {
			json.NewEncoder(w).Encode(map[string]any{"opt_in": true, "source": "setting", "effective": true})
			return
		}
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
	// BETA: candidate + behavior export is disabled (GHSA-hx86), so only the
	// known_bad event exports — 1 signal; the candidate, behavior, private, and
	// acknowledged events are all withheld.
	var batch export.Batch
	json.Unmarshal(raw, &batch)
	if len(batch.Signals) != 1 {
		t.Errorf("expected 1 signal (known_bad only), got %d: %+v", len(batch.Signals), batch.Signals)
	}
	// Cursor persisted.
	cur, _ := corereader.LoadCursor(dir)
	if cur.LastEventID == "" {
		t.Errorf("cursor not advanced")
	}
	// Status updated with counts only.
	snap := st.Get()
	if snap.LastBatch.Result != "accepted" || snap.LastBatch.SignalCount != 1 {
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
			EventID:          "kb" + strconv.Itoa(i),
			Timestamp:        base,
			EventType:        "dns_query",
			SourceIP:         "192.0.2." + strconv.Itoa(10+i),
			Domain:           "c2-" + strconv.Itoa(i) + ".badzone.example",
			MatchedIndicator: "c2-" + strconv.Itoa(i) + ".badzone.example",
			MatchType:        "domain",
			Blocked:          true,
			AnomalyScore:     0.99,
			Tags:             []string{"known_bad", "threat_feed_match"},
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
		if r.URL.Path == "/api/v1/settings/telemetry" {
			json.NewEncoder(w).Encode(map[string]any{"opt_in": true, "source": "setting", "effective": true})
			return
		}
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

// helper: a threat-network stub whose auth behavior is switchable at runtime.
func newIngestStub(t *testing.T, authFail *atomic.Bool, delivered *atomic.Bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authFail.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, err := gunzipReq(r); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if delivered != nil {
			delivered.Store(true)
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "duplicate": false})
	}))
}

// Issue #36: an ingest auth failure (401) must NOT dead-letter OR spool the
// batch. The events are left unconsumed in Core (the cursor is HELD), the daemon
// reports degraded, and a later tick with healthy ingest re-reads and delivers
// those events — then clears degraded. This proves no data loss under sustained
// auth failure (the bounded spool is never the durability path).
func TestPipelineIngestAuthFailHoldsCursorThenRecovers(t *testing.T) {
	core := fakeCoreServer(knownBadEvents(1))
	defer core.Close()

	var authFail, delivered atomic.Bool
	authFail.Store(true)
	tn := newIngestStub(t, &authFail, &delivered)
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	spool := transmit.NewSpool(dir)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, spool, false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	// Tick 1: ingest is auth-failing. Nothing delivered, nothing spooled, cursor HELD.
	p.RunTick(context.Background())
	if delivered.Load() {
		t.Fatal("nothing should be delivered while ingest auth-fails")
	}
	if spool.Depth() != 0 {
		t.Fatalf("auth failure must NOT spool (cursor is held instead), depth=%d", spool.Depth())
	}
	if snap := st.Get(); !snap.Degraded {
		t.Errorf("expected degraded state on ingest auth failure")
	}
	// Cursor must be HELD — the events stay unconsumed in Core for a re-read.
	if cur, _ := corereader.LoadCursor(dir); cur.LastEventID != "" {
		t.Errorf("cursor must be held (not advanced) on auth failure, got %q", cur.LastEventID)
	}

	// Tick 2: ingest recovers. Because the cursor was held, the events are re-read
	// from Core and delivered now (no spool involved).
	authFail.Store(false)
	p.RunTick(context.Background())
	if !delivered.Load() {
		t.Fatal("recovery tick must deliver the held-back events")
	}
	if cur, _ := corereader.LoadCursor(dir); cur.LastEventID == "" {
		t.Errorf("cursor should advance after successful delivery")
	}
	if snap := st.Get(); snap.Degraded {
		t.Errorf("degraded should clear after recovery: %q", snap.DegradedReason)
	}
}

// Issue #36 (2): if a derived batch cannot be durably handled (here: the auth
// failure's spool write fails because the spool path is unusable), the cursor
// MUST NOT advance past those events — they are re-read next tick, never lost.
func TestPipelineCursorHeldWhenBatchNotDurable(t *testing.T) {
	core := fakeCoreServer(knownBadEvents(1))
	defer core.Close()
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // retryable auth failure
	}))
	defer tn.Close()

	dir := t.TempDir()
	// Poison the spool: a FILE where the spool directory must live, so every
	// Spool.Add fails and the auth-failed batch cannot be durably spooled.
	if err := os.WriteFile(filepath.Join(dir, "spool"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, transmit.NewSpool(dir), false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())

	if cur, _ := corereader.LoadCursor(dir); cur.LastEventID != "" {
		t.Errorf("cursor must not advance when a batch could not be durably handled, got %q", cur.LastEventID)
	}
}

// Issue #37: when Core reports the effective telemetry opt-in as OFF, the tick
// must export NOTHING (no ingest egress) and surface the suppressed state; the
// cursor must not advance (no events consumed).
func TestPipelineCoreOptOutSuppressesExport(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/settings/telemetry" {
			json.NewEncoder(w).Encode(map[string]any{"opt_in": false, "source": "setting", "effective": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"events": knownBadEvents(1), "total": 1, "page": 1, "limit": 500})
	}))
	defer core.Close()

	var ingestCalls int32
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&ingestCalls, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	tx := transmit.New(tn.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, transmit.NewSpool(dir), false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())

	if got := atomic.LoadInt32(&ingestCalls); got != 0 {
		t.Errorf("effective opt-out must export nothing, got %d ingest calls", got)
	}
	snap := st.Get()
	if !snap.Suppressed {
		t.Errorf("suppressed state not surfaced on Core opt-out")
	}
	if cur, _ := corereader.LoadCursor(dir); cur.LastEventID != "" {
		t.Errorf("cursor must not advance when export is suppressed, got %q", cur.LastEventID)
	}
}

// GHSA-c776 (fail closed when the live opt-in can't be confirmed): a stale
// cached/persisted "true" must NEVER authorize a drain/export. Even with the env
// default ON, a leftover optin.json saying opt_in=true from an older build, and a
// pre-seeded spool, an UNREACHABLE Core must keep the daemon fully inert this
// tick: no drain, no export, cursor unchanged, suppressed. Only a LIVE read
// returning effective==true may authorize export.
func TestPipelineStaleCachedOptInDoesNotExportWhenCoreUnreachable(t *testing.T) {
	dir := t.TempDir()

	// Plant a stale on-disk opt-in "true" (the shape an older build persisted).
	// The fail-closed daemon must ignore it entirely — an unreachable Core, not a
	// cached value, governs this tick.
	if err := os.WriteFile(filepath.Join(dir, "optin.json"),
		[]byte(`{"version":1,"opt_in":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-seed the spool with a batch that WOULD be drained/exported if the daemon
	// trusted the stale "true" (the exact fail-open GHSA-c776 describes).
	seedSpool := transmit.NewSpool(dir)
	if err := seedSpool.Add("seed-batch", []byte("gz-placeholder")); err != nil {
		t.Fatal(err)
	}
	if seedSpool.Depth() != 1 {
		t.Fatalf("spool seed failed, depth=%d", seedSpool.Depth())
	}

	var ingestCalls int32
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&ingestCalls, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ingest.Close()

	// Core's settings endpoint errors → the live opt-in cannot be confirmed.
	deadCore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer deadCore.Close()

	cfg := &config.Config{OptIn: true, CoreURL: deadCore.URL, ThreatNetworkURL: ingest.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	spool := transmit.NewSpool(dir)
	tx := transmit.New(ingest.URL, transmit.Reporter{ReporterID: "rid", ReporterSecret: "secret"}, spool, false, 250)
	tx.HTTP = ingest.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(deadCore.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())

	if got := atomic.LoadInt32(&ingestCalls); got != 0 {
		t.Errorf("stale cached opt-in + unreachable Core must export nothing, got %d ingest calls", got)
	}
	if d := spool.Depth(); d != 1 {
		t.Errorf("pre-seeded spool must NOT be drained when the live opt-in is unconfirmed, depth=%d (want 1)", d)
	}
	if snap := st.Get(); !snap.Suppressed {
		t.Errorf("suppressed state not surfaced when the live opt-in cannot be confirmed")
	}
	if cur, _ := corereader.LoadCursor(dir); cur.LastEventID != "" {
		t.Errorf("cursor must not advance while suppressed, got %q", cur.LastEventID)
	}
}

// Issue #36 (3): an unregistered reporter surfaces a degraded state.
func TestPipelineUnregisteredReporterDegraded(t *testing.T) {
	core := fakeCoreServer(knownBadEvents(1))
	defer core.Close()
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250, MaxBatchesTick: 4}
	st := status.NewState(true, false)
	// Reporter with no ReporterID → unregistered.
	tx := transmit.New(tn.URL, transmit.Reporter{}, transmit.NewSpool(dir), false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	p.RunTick(context.Background())

	snap := st.Get()
	if !snap.Degraded || snap.DegradedReason != "reporter unregistered" {
		t.Errorf("expected degraded=reporter unregistered, got %+v/%q", snap.Degraded, snap.DegradedReason)
	}
}

// GHSA-c776 residual: reporter REGISTRATION is threat-network egress and must be
// gated on the effective opt-in exactly like signal export. With no persisted
// reporter identity and Core reporting effective==false, EnsureReporter must NOT
// contact the threat-network at all — no registration attempt, no egress — and
// must report "not registered". Once Core flips to effective==true, the same call
// registers.
func TestPipelineReporterRegistrationGatedOnEffectiveOptIn(t *testing.T) {
	var effective atomic.Bool // starts false → opted out

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/settings/telemetry" {
			json.NewEncoder(w).Encode(map[string]any{
				"opt_in": effective.Load(), "source": "setting", "effective": effective.Load(),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer core.Close()

	// Threat-network stub that records every registration attempt.
	var registerCalls int32
	tn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/reporters/register" {
			atomic.AddInt32(&registerCalls, 1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"reporter_id":     "11111111-2222-4333-8444-555555555555",
				"reporter_secret": "c2VjcmV0LWJhc2U2NC1leGFtcGxlLW9ubHk=",
				"config":          map[string]any{"min_upload_interval_seconds": 900, "max_batch_items": 250},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tn.Close()

	dir := t.TempDir()
	cfg := &config.Config{OptIn: true, CoreURL: core.URL, ThreatNetworkURL: tn.URL, StateDir: dir,
		CandidateMinScore: 0.85, BehaviorMinScore: 0.70, ReadCapPerTick: 5000, MaxBatchItems: 250,
		MaxBatchesTick: 4, VedettaVersion: "0.1.0-test"}
	st := status.NewState(true, false)
	// Empty reporter → no in-memory identity; no reporter.json on disk either.
	tx := transmit.New(tn.URL, transmit.Reporter{}, transmit.NewSpool(dir), false, 250)
	tx.HTTP = tn.Client()
	tx.Sleep = func(time.Duration) {}
	p := &Pipeline{Cfg: cfg, Reader: corereader.NewClient(core.URL, ""), Tx: tx,
		Salt: []byte("salt"), State: st, StateDir: dir}

	// Effective opt-OUT: registration must not be attempted (no egress).
	registered, err := p.EnsureReporter(context.Background())
	if err != nil {
		t.Fatalf("gated EnsureReporter should not error on opt-out: %v", err)
	}
	if registered {
		t.Errorf("must report not-registered while effectively opted out")
	}
	if got := atomic.LoadInt32(&registerCalls); got != 0 {
		t.Errorf("effective opt-out must attempt NO registration, got %d calls", got)
	}
	if p.Tx.Reporter.ReporterID != "" {
		t.Errorf("no reporter identity should be established while opted out")
	}

	// Admin flips the dashboard opt-IN. Now a live read confirms effective==true,
	// so the same call registers.
	effective.Store(true)
	registered, err = p.EnsureReporter(context.Background())
	if err != nil {
		t.Fatalf("registration after opt-in should succeed: %v", err)
	}
	if !registered {
		t.Errorf("expected registration once effectively opted in")
	}
	if got := atomic.LoadInt32(&registerCalls); got != 1 {
		t.Errorf("expected exactly 1 registration after opt-in, got %d", got)
	}
	if p.Tx.Reporter.ReporterID == "" {
		t.Errorf("reporter identity should be set after registration")
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
