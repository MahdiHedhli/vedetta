package store

import "time"

// RetentionResult reports how many rows each purge removed.
type RetentionResult struct {
	Signals     int64
	Receipts    int64
	Nonces      int64
	RevokedFeed int64
}

// Purge enforces retention per plan.md: signals & receipts >30d, nonces >24h,
// revoked feed_items >90d. now is injectable for tests.
func (db *DB) Purge(now time.Time) (RetentionResult, error) {
	var r RetentionResult
	var err error
	if r.Signals, err = db.PurgeSignals(now.Add(-30 * 24 * time.Hour)); err != nil {
		return r, err
	}
	if r.Receipts, err = db.PurgeReceipts(now.Add(-30 * 24 * time.Hour)); err != nil {
		return r, err
	}
	if r.Nonces, err = db.PurgeNonces(now.Add(-24 * time.Hour)); err != nil {
		return r, err
	}
	if r.RevokedFeed, err = db.PurgeRevokedFeedItems(now.Add(-90 * 24 * time.Hour)); err != nil {
		return r, err
	}
	return r, nil
}
