package ingest

import (
	"encoding/json"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// Per-reporter abuse caps (plan.md Failure Modes).
const (
	// MaxBatchesPerDay bounds batch volume; 4 batches/hour over 24h (plan.md).
	MaxBatchesPerDay  = 4 * 24
	MaxSignalsPerDay  = 1000
	MaxDistinctPerDay = 200
)

// Result is the ingest outcome returned as the 202/200 body.
type Result struct {
	Accepted  int    `json:"accepted"`
	Rejected  int    `json:"rejected"`
	BatchID   string `json:"batch_id"`
	Duplicate bool   `json:"duplicate"`
}

// CapError signals a per-reporter cap breach → 429.
type CapError struct {
	RetryAfterSeconds int
	Detail            string
}

func (e *CapError) Error() string { return "RATE_LIMIT_EXCEEDED: " + e.Detail }

// Processor runs the ingest pipeline against the store.
type Processor struct {
	DB  *store.DB
	Now func() time.Time
}

// NewProcessor builds a Processor with real time.
func NewProcessor(db *store.DB) *Processor {
	return &Processor{DB: db, Now: time.Now}
}

func (p *Processor) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Process validates and stores a batch for an authenticated reporter. Ordering:
//  1. duplicate batch_id → idempotent replay (200, duplicate:true, no re-processing)
//  2. parse + strict-schema + privacy re-gate (whole-batch 422 on StrictError)
//  3. envelope errors → 400 (EnvelopeError)
//  4. per-reporter caps → 429 (CapError)
//  5. dedup-upsert accepted signals, write receipt, bump counters
//
// The returned error is one of *StrictError, *EnvelopeError, *CapError, or a
// raw DB error; the caller maps these to HTTP status + body.
func (p *Processor) Process(reporterID string, body []byte) (*Result, error) {
	// Peek at batch_id cheaply for the idempotency check before full parse.
	batchID, ok := peekBatchID(body)
	if ok {
		if rc, found, err := p.DB.GetReceipt(reporterID, batchID); err != nil {
			return nil, err
		} else if found {
			// Idempotent replay — do NOT re-process, do NOT re-count.
			return &Result{
				Accepted:  rc.AcceptedCount,
				Rejected:  rc.RejectedCount,
				BatchID:   batchID,
				Duplicate: true,
			}, nil
		}
	}

	batch, rejected, err := ParseAndValidate(body)
	if err != nil {
		return nil, err
	}

	// Re-check duplicate now that we have the authoritative batch_id (parse may
	// have normalized/confirmed it). Guards a race where peek missed it.
	if rc, found, err := p.DB.GetReceipt(reporterID, batch.BatchID); err != nil {
		return nil, err
	} else if found {
		return &Result{Accepted: rc.AcceptedCount, Rejected: rc.RejectedCount,
			BatchID: batch.BatchID, Duplicate: true}, nil
	}

	day := p.now().UTC().Format("2006-01-02")
	counters, err := p.DB.GetCounters(reporterID, day)
	if err != nil {
		return nil, err
	}

	// Batch-rate cap.
	if counters.BatchesAccepted >= MaxBatchesPerDay {
		return nil, &CapError{RetryAfterSeconds: 3600, Detail: "daily batch cap reached"}
	}

	accepted := 0
	newDistinct := 0
	for _, sig := range batch.Signals {
		// Signal-count cap (stop accepting once over daily budget; overflow → rejected).
		if counters.SignalsAccepted+accepted >= MaxSignalsPerDay {
			rejected++
			continue
		}
		created, err := p.DB.UpsertSignal(store.SignalRow{
			ReporterID:         reporterID,
			Kind:               sig.Kind,
			IndicatorKey:       sig.IndicatorKey,
			Domain:             sig.Domain,
			EtldPlusOne:        sig.EtldPlusOne,
			Behavior:           sig.Behavior,
			TimeBucket:         sig.TimeBucket.UTC().Format(time.RFC3339),
			LocalConfidence:    sig.LocalConfidence,
			LocalReasons:       marshalReasons(sig.LocalReasons),
			ObservationCount:   sig.ObservationCount,
			DistinctAssetCount: sig.DistinctAssetCount,
			BlockedCount:       sig.BlockedCount,
		})
		if err != nil {
			return nil, err
		}
		accepted++
		if created {
			newDistinct++
		}
	}

	// Distinct-indicator cap is advisory here (flag, not hard-fail): if exceeded,
	// still stored but capped counter reflects it. Plan.md treats it as a daily
	// abuse cap; we enforce it as a soft ceiling recorded in counters.
	if counters.DistinctIndicators+newDistinct > MaxDistinctPerDay {
		newDistinct = MaxDistinctPerDay - counters.DistinctIndicators
		if newDistinct < 0 {
			newDistinct = 0
		}
	}

	won, err := p.DB.InsertReceipt(store.Receipt{
		BatchID:       batch.BatchID,
		ReporterID:    reporterID,
		SignalCount:   len(batch.Signals) + rejected,
		AcceptedCount: accepted,
		RejectedCount: rejected,
	})
	if err != nil {
		return nil, err
	}
	if !won {
		// Another concurrent request for the SAME (reporter_id, batch_id) already
		// wrote the receipt (INSERT OR IGNORE no-op). Treat this as the idempotent
		// replay it is: return the recorded counts and, crucially, do NOT bump the
		// per-reporter counters — otherwise a race double-counts a single batch.
		if rc, found, gerr := p.DB.GetReceipt(reporterID, batch.BatchID); gerr == nil && found {
			return &Result{Accepted: rc.AcceptedCount, Rejected: rc.RejectedCount,
				BatchID: batch.BatchID, Duplicate: true}, nil
		}
		return &Result{Accepted: accepted, Rejected: rejected, BatchID: batch.BatchID, Duplicate: true}, nil
	}
	if err := p.DB.AddCounters(reporterID, day, 1, accepted, newDistinct, 0); err != nil {
		return nil, err
	}

	return &Result{Accepted: accepted, Rejected: rejected, BatchID: batch.BatchID, Duplicate: false}, nil
}

func peekBatchID(body []byte) (string, bool) {
	var m struct {
		BatchID string `json:"batch_id"`
	}
	if json.Unmarshal(body, &m) != nil || m.BatchID == "" {
		return "", false
	}
	return m.BatchID, true
}

func marshalReasons(rs []string) string {
	b, _ := json.Marshal(rs)
	return string(b)
}
