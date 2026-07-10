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

	batch, rejected, err := ParseAndValidateAt(body, p.now())
	if err != nil {
		return nil, err
	}

	// Re-check duplicate now that we have the authoritative batch_id (parse may
	// have normalized/confirmed it). This is a cheap fast-path; PersistBatch
	// re-checks authoritatively inside the transaction.
	if rc, found, err := p.DB.GetReceipt(reporterID, batch.BatchID); err != nil {
		return nil, err
	} else if found {
		return &Result{Accepted: rc.AcceptedCount, Rejected: rc.RejectedCount,
			BatchID: batch.BatchID, Duplicate: true}, nil
	}

	day := p.now().UTC().Format("2006-01-02")

	// Build the candidate rows once, then persist the whole batch ATOMICALLY.
	// Enforcing the per-reporter caps (batch/signal/distinct-indicator) inside a
	// single transaction that also writes the rows, receipt and counters closes the
	// GHSA-7p69 non-transactional cap race: a concurrent flood of signed batches can
	// never exceed the distinct-indicator cap, because each batch's cap-check and
	// inserts are one indivisible, serialized step (see store.PersistBatch).
	rows := make([]store.SignalRow, 0, len(batch.Signals))
	for _, sig := range batch.Signals {
		rows = append(rows, store.SignalRow{
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
	}

	out, err := p.DB.PersistBatch(store.PersistBatchInput{
		ReporterID:        reporterID,
		Day:               day,
		BatchID:           batch.BatchID,
		Rows:              rows,
		ParseRejected:     rejected,
		MaxBatchesPerDay:  MaxBatchesPerDay,
		MaxSignalsPerDay:  MaxSignalsPerDay,
		MaxDistinctPerDay: MaxDistinctPerDay,
	})
	if err != nil {
		return nil, err
	}
	if out.BatchCapReached {
		return nil, &CapError{RetryAfterSeconds: 3600, Detail: "daily batch cap reached"}
	}

	return &Result{
		Accepted:  out.Accepted,
		Rejected:  out.Rejected,
		BatchID:   batch.BatchID,
		Duplicate: out.Duplicate,
	}, nil
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
