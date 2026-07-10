package store

import (
	"database/sql"
	"errors"
)

// PersistBatchInput carries one validated telemetry batch plus the per-reporter
// daily abuse caps for a single ATOMIC persist. Rows are the candidate signals
// already validated/decoded by the ingest pipeline; ParseRejected is the count of
// per-item skips the parse phase already rejected (folded into the receipt).
type PersistBatchInput struct {
	ReporterID    string
	Day           string
	BatchID       string
	Rows          []SignalRow
	ParseRejected int

	MaxBatchesPerDay  int
	MaxSignalsPerDay  int
	MaxDistinctPerDay int
}

// PersistBatchOutput reports the outcome of an atomic persist.
type PersistBatchOutput struct {
	Accepted        int
	Rejected        int
	Duplicate       bool // an existing receipt short-circuited this submission
	BatchCapReached bool // the daily batch-rate cap rejected the whole batch
}

// PersistBatch stores an authenticated batch atomically: it runs the duplicate
// check, per-reporter cap enforcement, signal upserts, receipt write and counter
// bump inside a SINGLE transaction.
//
// This closes GHSA-7p69's non-transactional distinct-indicator race. Previously
// the cap was a check-then-insert spread across separate autocommit statements:
// N concurrent signed batches from one reporter each read distinct_indicators=0
// and each stored up to MaxDistinctPerDay rows, so the DB blew past the cap
// (e.g. 20 batches × 200 = 4000 rows against a 200 cap). Here the cap is enforced
// WITHIN the transaction — the reporter's distinct stored indicators are counted
// (via an existence check on the dedup key) immediately before each insert. The
// service opens the DB with a single connection (SetMaxOpenConns(1)) and SQLite
// serializes writers, so a transaction that SELECT-counts then INSERTs holds the
// invariant: a concurrent flood serializes and can never exceed the cap.
//
// Merges into an already-stored indicator add no new distinct row and stay allowed
// even at the cap, so re-sent observations are never lost.
func (db *DB) PersistBatch(in PersistBatchInput) (PersistBatchOutput, error) {
	tx, err := db.Begin()
	if err != nil {
		return PersistBatchOutput{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Authoritative per-(reporter_id, batch_id) duplicate check inside the tx. A
	// receipt already on file means this is an idempotent replay: do not re-store,
	// do not re-count. Holding the single writer connection for the tx's whole life
	// makes this check-then-write atomic against a concurrent submission of the same
	// batch (the racer serializes behind this tx and then sees the receipt).
	var rc Receipt
	found := false
	if err := tx.QueryRow(`SELECT accepted_count, rejected_count FROM ingest_receipts
        WHERE reporter_id = ? AND batch_id = ?`, in.ReporterID, in.BatchID).
		Scan(&rc.AcceptedCount, &rc.RejectedCount); err == nil {
		found = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return PersistBatchOutput{}, err
	}
	if found {
		committed = true
		if err := tx.Commit(); err != nil {
			return PersistBatchOutput{}, err
		}
		return PersistBatchOutput{Accepted: rc.AcceptedCount, Rejected: rc.RejectedCount, Duplicate: true}, nil
	}

	// Read the reporter's daily counters WITHIN the tx (zero-valued if no row yet).
	var batchesAccepted, signalsAccepted, distinctIndicators int
	if err := tx.QueryRow(`SELECT batches_accepted, signals_accepted, distinct_indicators
        FROM reporter_counters WHERE reporter_id = ? AND day = ?`, in.ReporterID, in.Day).
		Scan(&batchesAccepted, &signalsAccepted, &distinctIndicators); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PersistBatchOutput{}, err
	}

	// Batch-rate cap → whole-batch reject (mapped to 429 by the caller). No writes.
	if batchesAccepted >= in.MaxBatchesPerDay {
		committed = true
		if err := tx.Commit(); err != nil {
			return PersistBatchOutput{}, err
		}
		return PersistBatchOutput{BatchCapReached: true}, nil
	}

	accepted := 0
	newDistinct := 0
	rejected := in.ParseRejected
	for _, s := range in.Rows {
		// Signal-count cap: stop accepting once the daily budget is exhausted.
		if signalsAccepted+accepted >= in.MaxSignalsPerDay {
			rejected++
			continue
		}
		// Distinct-indicator cap, enforced atomically. Count the reporter's distinct
		// stored indicators (existence of this dedup key) inside the tx before
		// inserting; once the budget is exhausted a signal that would create a NEW
		// distinct row is refused. Merges into an existing row are still allowed.
		if distinctIndicators+newDistinct >= in.MaxDistinctPerDay {
			exists, err := signalExists(tx, s.ReporterID, s.Kind, s.IndicatorKey, s.TimeBucket)
			if err != nil {
				return PersistBatchOutput{}, err
			}
			if !exists {
				rejected++
				continue
			}
		}
		created, err := upsertSignal(tx, s)
		if err != nil {
			return PersistBatchOutput{}, err
		}
		accepted++
		if created {
			newDistinct++
		}
	}

	// Receipt + counter bump complete the tx. We verified above that no receipt
	// existed and we hold the writer for the tx's life, so a plain INSERT is safe.
	if _, err := tx.Exec(`INSERT INTO ingest_receipts
        (batch_id, reporter_id, received_at, signal_count, accepted_count, rejected_count)
        VALUES (?, ?, ?, ?, ?, ?)`,
		in.BatchID, in.ReporterID, nowRFC3339(), len(in.Rows)+rejected, accepted, rejected); err != nil {
		return PersistBatchOutput{}, err
	}
	if _, err := tx.Exec(`INSERT INTO reporter_counters
        (reporter_id, day, batches_accepted, signals_accepted, distinct_indicators, allowlist_flags)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(reporter_id, day) DO UPDATE SET
            batches_accepted = batches_accepted + excluded.batches_accepted,
            signals_accepted = signals_accepted + excluded.signals_accepted,
            distinct_indicators = distinct_indicators + excluded.distinct_indicators`,
		in.ReporterID, in.Day, 1, accepted, newDistinct); err != nil {
		return PersistBatchOutput{}, err
	}

	committed = true
	if err := tx.Commit(); err != nil {
		return PersistBatchOutput{}, err
	}
	return PersistBatchOutput{Accepted: accepted, Rejected: rejected}, nil
}
