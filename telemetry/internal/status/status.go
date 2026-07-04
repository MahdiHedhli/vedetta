// Package status exposes a localhost-bound /healthz + /status surface. The
// payload reports COUNTS and states only — never any exported signal payload
// (no domains, no per-asset data).
package status

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// LastBatch summarizes the most recent batch attempt (counts + result only).
type LastBatch struct {
	Time        string `json:"time,omitempty"`
	SignalCount int    `json:"signal_count"`
	Result      string `json:"result,omitempty"` // accepted | duplicate | spooled | rejected | error
}

// Snapshot is the JSON shape returned by /status.
type Snapshot struct {
	OptIn                  bool      `json:"opt_in"`
	DryRun                 bool      `json:"dry_run"`
	ReporterRegistered     bool      `json:"reporter_registered"`
	Cursor                 string    `json:"cursor,omitempty"`
	LastTick               string    `json:"last_tick,omitempty"`
	LastBatch              LastBatch `json:"last_batch"`
	SpoolDepth             int       `json:"spool_depth"`
	EventsSkippedMalformed int       `json:"events_skipped_malformed"`
	LastError              string    `json:"last_error,omitempty"`
}

// State is a concurrency-safe holder the tick loop updates and the HTTP surface
// reads.
type State struct {
	mu   sync.RWMutex
	snap Snapshot
	live bool // healthz: loop alive
}

// NewState builds a State seeded with opt-in/dry-run flags.
func NewState(optIn, dryRun bool) *State {
	return &State{snap: Snapshot{OptIn: optIn, DryRun: dryRun}, live: true}
}

// Update mutates the snapshot under lock.
func (s *State) Update(f func(*Snapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.snap)
}

// Get returns a copy of the current snapshot.
func (s *State) Get() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// SetLive marks the loop alive/dead for /healthz.
func (s *State) SetLive(v bool) {
	s.mu.Lock()
	s.live = v
	s.mu.Unlock()
}

func (s *State) isLive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.live
}

// Handler returns an http.Handler serving /healthz and /status.
func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.isLive() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Get())
	})
	return mux
}

// TouchTick records the last tick time.
func (s *State) TouchTick() {
	now := time.Now().UTC().Format(time.RFC3339)
	s.Update(func(sn *Snapshot) { sn.LastTick = now })
}
