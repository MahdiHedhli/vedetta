package store

import (
	"database/sql"
	"errors"
	"time"
)

// Receipt is the record of a processed batch, used for idempotent replay.
type Receipt struct {
	BatchID       string
	ReporterID    string
	ReceivedAt    string
	SignalCount   int
	AcceptedCount int
	RejectedCount int
}

// GetReceipt returns the stored receipt for a (reporter_id, batch_id) pair, or
// (nil, false) if none. Idempotency is per-reporter: a receipt only short-circuits
// a resubmission from the SAME reporter. A different reporter that happens to reuse
// a batch_id must be processed independently and must never see another reporter's
// counts (cross-reporter disclosure) or be silently dropped.
func (db *DB) GetReceipt(reporterID, batchID string) (*Receipt, bool, error) {
	row := db.QueryRow(`SELECT batch_id, reporter_id, received_at, signal_count,
        accepted_count, rejected_count FROM ingest_receipts
        WHERE reporter_id = ? AND batch_id = ?`, reporterID, batchID)
	var r Receipt
	if err := row.Scan(&r.BatchID, &r.ReporterID, &r.ReceivedAt, &r.SignalCount,
		&r.AcceptedCount, &r.RejectedCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &r, true, nil
}

// InsertReceipt records a processed batch. Returns false if the batch_id already
// exists (someone raced us), true on fresh insert.
func (db *DB) InsertReceipt(r Receipt) (bool, error) {
	res, err := db.Exec(`INSERT OR IGNORE INTO ingest_receipts
        (batch_id, reporter_id, received_at, signal_count, accepted_count, rejected_count)
        VALUES (?, ?, ?, ?, ?, ?)`,
		r.BatchID, r.ReporterID, nowRFC3339(), r.SignalCount, r.AcceptedCount, r.RejectedCount)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// PurgeReceipts deletes receipts older than the cutoff.
func (db *DB) PurgeReceipts(olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM ingest_receipts WHERE received_at < ?`,
		olderThan.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
