// Package pipeline wires the batch reader, export gate/stripper/aggregator, and
// transmitter into a single tick. It is the orchestration seam kept out of
// cmd/telemetry so it can be unit-tested end to end.
package pipeline

import (
	"context"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
	"github.com/vedetta-network/vedetta/telemetry/internal/export"
	"github.com/vedetta-network/vedetta/telemetry/internal/idgen"
	"github.com/vedetta-network/vedetta/telemetry/internal/status"
	"github.com/vedetta-network/vedetta/telemetry/internal/transmit"
)

// Pipeline holds the collaborators for one running daemon.
type Pipeline struct {
	Cfg      *config.Config
	Reader   *corereader.Client
	Tx       *transmit.Transmitter
	Salt     []byte
	State    *status.State
	StateDir string

	// lastKnownOptIn caches the last effective opt-in successfully read from Core
	// so a transient settings-endpoint error cannot silently override an explicit
	// admin opt-out (issue #37). nil until the first successful read.
	lastKnownOptIn *bool
}

// RunTick executes one full tick: read → gate → strip → aggregate → send. It
// drains any spooled batches first. On a Core read error the cursor is left
// unchanged and the error is surfaced on /status; the tick returns nil (not
// fatal). The cursor is persisted only after all produced batches are handed to
// the transmitter (at-least-once).
func (p *Pipeline) RunTick(ctx context.Context) {
	p.State.TouchTick()

	// Issue #37: consult Core for the EFFECTIVE telemetry opt-in before doing any
	// work. If Core says opted-out, export nothing this tick (stay fully inert —
	// no drain, no read, no send) and surface it. If Core is unreachable, fall
	// back to the last value we successfully read (so a transient error can't
	// override an explicit admin opt-out), and only to the env OptIn if we have
	// never read one (issue #37).
	effective, err := p.Reader.EffectiveOptIn(ctx)
	if err != nil {
		if p.lastKnownOptIn != nil {
			effective = *p.lastKnownOptIn
		} else {
			effective = p.Cfg.OptIn
		}
	} else {
		v := effective
		p.lastKnownOptIn = &v
	}
	if !effective {
		p.State.Update(func(s *status.Snapshot) {
			s.Suppressed = true
			s.SuppressedReason = "core telemetry opt-in is off"
		})
		return
	}
	p.State.Update(func(s *status.Snapshot) { s.Suppressed = false; s.SuppressedReason = "" })

	// Drain spool before new work (best-effort). An auth/rate failure while
	// draining is surfaced as a degraded state below.
	sent, remaining, authFailing := p.Tx.DrainSpool(ctx)
	if sent > 0 || remaining > 0 {
		p.State.Update(func(s *status.Snapshot) { s.SpoolDepth = remaining })
	}
	p.setHealth(authFailing)

	cur, err := corereader.LoadCursor(p.StateDir)
	if err != nil {
		p.setError("load cursor: " + err.Error())
		return
	}

	res, err := p.Reader.Read(ctx, cur, p.Cfg.ReadCapPerTick)
	if err != nil {
		// Core unreachable: cursor unchanged, surface error, retry next tick.
		p.setError("core read: " + err.Error())
		return
	}
	if res.SkippedMalformed > 0 {
		p.State.Update(func(s *status.Snapshot) { s.EventsSkippedMalformed += res.SkippedMalformed })
	}

	// Gate + strip.
	gateCfg := export.GateConfig{
		CandidateMinScore: p.Cfg.CandidateMinScore,
		BehaviorMinScore:  p.Cfg.BehaviorMinScore,
	}
	var cands []export.ExportCandidate
	for _, ev := range res.Events {
		kind, ok := export.Eligible(ev, gateCfg)
		if !ok {
			continue
		}
		c, ok := export.Strip(ev, kind, p.Salt)
		if !ok {
			continue
		}
		cands = append(cands, c)
	}

	// Aggregate.
	sigs := export.Aggregate(cands, idgen.UUIDv4)
	export.SortSignals(sigs)

	windowStart, windowEnd := tickWindow(res.Events)

	// Nothing to send: still advance the cursor (we consumed events).
	if len(sigs) == 0 {
		p.persistCursor(res)
		return
	}

	// Build batches, then split into those we send this tick and any overflow
	// beyond MaxBatchesTick. The overflow is NOT discarded — its signals derive
	// from events we are about to advance the cursor past, so it must be durably
	// spooled and retried by DrainSpool next tick. Dropping it here would lose
	// those detections forever (never re-read, cursor already advanced).
	batches := p.Tx.BuildBatches(sigs, windowStart, windowEnd)
	var overflow []export.Batch
	if p.Cfg.MaxBatchesTick > 0 && len(batches) > p.Cfg.MaxBatchesTick {
		overflow = batches[p.Cfg.MaxBatchesTick:]
		batches = batches[:p.Cfg.MaxBatchesTick]
	}

	// cursorSafe stays true only while every derived batch is durably ACCEPTED,
	// durably SPOOLED-for-retry, or a genuine poison-pill REJECT. If any batch
	// could not be durably handled (e.g. a spool write failed on an auth failure),
	// the cursor MUST NOT advance past those events — we re-read them next tick
	// (at-least-once; the ingest dedups the ones that did land). Issue #36 (2).
	cursorSafe := true
	var lastResult string
	var totalSignals int
	for _, b := range batches {
		r := p.Tx.Send(ctx, b)
		totalSignals += len(b.Signals)
		if r.AuthFailed {
			authFailing = true
		}
		switch {
		case r.Duplicate:
			lastResult = "duplicate"
		case r.Accepted:
			lastResult = "accepted"
		case r.AuthFailed:
			// Identity/authorization/rate failure (401/403/429): the batch was NOT
			// durably delivered and is deliberately NOT spooled (the bounded spool is
			// not a durability guarantee). HOLD the cursor so these events are re-read
			// from Core next tick until the reporter is valid again (issue #36).
			lastResult = "auth-failed"
			cursorSafe = false
			p.setError("ingest auth failure (holding cursor for re-read): " + errStr(r.Err))
		case r.Rejected:
			lastResult = "rejected"
			p.setError("batch rejected: " + errStr(r.Err))
		case r.Spooled:
			lastResult = "spooled"
			if r.Err != nil {
				p.setError("spooled: " + errStr(r.Err))
			}
		default:
			// Hard failure: the batch was neither sent nor durably spooled.
			lastResult = "error"
			cursorSafe = false
			p.setError("send: " + errStr(r.Err))
		}
	}

	// Spool overflow batches so their signals survive to a later tick. Their
	// source events are about to be consumed by persistCursor, so discarding
	// here would be unrecoverable loss. If a spool write fails, the batch is lost
	// unless we hold the cursor back for a re-read.
	for _, b := range overflow {
		if err := p.Tx.SpoolBatch(b); err != nil {
			cursorSafe = false
			p.setError("spool overflow: " + err.Error())
		} else if lastResult == "" {
			lastResult = "spooled"
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	depth := p.Tx.Spool.Depth()
	p.State.Update(func(s *status.Snapshot) {
		s.LastBatch = status.LastBatch{Time: now, SignalCount: totalSignals, Result: lastResult}
		s.SpoolDepth = depth
	})
	p.setHealth(authFailing)

	// Persist the cursor ONLY when every derived batch was durably accepted or
	// safely spooled-for-retry. A hard failure holds the cursor so those events
	// are re-read next tick rather than lost (issue #36 (2)).
	if cursorSafe {
		p.persistCursor(res)
	}
}

// setHealth surfaces a degraded state when the daemon is running but not fully
// functional: the reporter is unregistered, or ingest is auth-failing
// (401/403/429). It reports state only — never any signal payload. Issue #36 (3).
func (p *Pipeline) setHealth(authFailing bool) {
	reason := ""
	switch {
	case p.Tx.Reporter.ReporterID == "":
		reason = "reporter unregistered"
	case authFailing:
		reason = "ingest auth failing"
	}
	p.State.Update(func(s *status.Snapshot) {
		s.Degraded = reason != ""
		s.DegradedReason = reason
	})
}

func (p *Pipeline) persistCursor(res *corereader.ReadResult) {
	if !res.CursorAdvanced {
		return
	}
	if err := res.NewCursor.Save(p.StateDir); err != nil {
		p.setError("save cursor: " + err.Error())
		return
	}
	c := res.NewCursor.LastTimestamp.Format(time.RFC3339)
	p.State.Update(func(s *status.Snapshot) { s.Cursor = c })
}

func (p *Pipeline) setError(msg string) {
	p.State.Update(func(s *status.Snapshot) { s.LastError = msg })
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// tickWindow computes an hour-aligned window spanning the events read this tick.
// When no events, it defaults to the current hour.
func tickWindow(events []corereader.Event) (time.Time, time.Time) {
	if len(events) == 0 {
		now := time.Now().UTC().Truncate(time.Hour)
		return now, now.Add(time.Hour)
	}
	min := events[0].Timestamp.UTC()
	max := events[0].Timestamp.UTC()
	for _, e := range events {
		t := e.Timestamp.UTC()
		if t.Before(min) {
			min = t
		}
		if t.After(max) {
			max = t
		}
	}
	start := min.Truncate(time.Hour)
	end := max.Truncate(time.Hour).Add(time.Hour)
	return start, end
}
