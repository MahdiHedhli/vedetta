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
}

// RunTick executes one full tick: read → gate → strip → aggregate → send. It
// drains any spooled batches first. On a Core read error the cursor is left
// unchanged and the error is surfaced on /status; the tick returns nil (not
// fatal). The cursor is persisted only after all produced batches are handed to
// the transmitter (at-least-once).
func (p *Pipeline) RunTick(ctx context.Context) {
	p.State.TouchTick()

	// Drain spool before new work (best-effort).
	if sent, remaining := p.Tx.DrainSpool(ctx); sent > 0 || remaining > 0 {
		p.State.Update(func(s *status.Snapshot) { s.SpoolDepth = remaining })
	}

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

	var lastResult string
	var totalSignals int
	for _, b := range batches {
		r := p.Tx.Send(ctx, b)
		totalSignals += len(b.Signals)
		switch {
		case r.Duplicate:
			lastResult = "duplicate"
		case r.Accepted:
			lastResult = "accepted"
		case r.Rejected:
			lastResult = "rejected"
			p.setError("batch rejected: " + errStr(r.Err))
		case r.Spooled:
			lastResult = "spooled"
			if r.Err != nil {
				p.setError("spooled: " + errStr(r.Err))
			}
		default:
			lastResult = "error"
			p.setError("send: " + errStr(r.Err))
		}
	}

	// Spool overflow batches so their signals survive to a later tick. Their
	// source events are about to be consumed by persistCursor, so discarding
	// here would be unrecoverable loss.
	for _, b := range overflow {
		if err := p.Tx.SpoolBatch(b); err != nil {
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

	// Persist cursor after handing everything (sent + spooled) to the transmitter.
	p.persistCursor(res)
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
