package store

import (
	"time"
)

// SignalRow is a stored, deduplicated per-reporter signal observation.
// Fields are counts only — no asset identifiers are ever stored.
type SignalRow struct {
	ReporterID         string
	Kind               string // telemetry-export kind
	IndicatorKey       string // exact domain | etld+1 | behavior
	Domain             string
	EtldPlusOne        string
	Behavior           string
	TimeBucket         string // RFC3339 hour-aligned
	LocalConfidence    float64
	LocalReasons       string // JSON array
	ObservationCount   int
	DistinctAssetCount int
	BlockedCount       int
}

// UpsertSignal inserts a signal or merges it into an existing row keyed by
// (reporter_id, kind, indicator_key, time_bucket). On conflict it takes the max
// confidence and sums the counts (capped by SQLite integer range; caller enforces
// wire-level caps). Returns true if a new row was created, false if merged.
//
// received_at is bumped to the merge time (the consensus window query wants
// recently-updated signals), but first_received_at is stamped ONCE at insert and
// never overwritten on merge — it is the immutable retention anchor, so a re-sent
// hour-bucket row cannot keep bumping its way past the 30-day retention.
func (db *DB) UpsertSignal(s SignalRow) (created bool, err error) {
	// Detect prior existence to report created vs merged for cap accounting.
	var existing int
	err = db.QueryRow(`SELECT COUNT(1) FROM signals
        WHERE reporter_id = ? AND kind = ? AND indicator_key = ? AND time_bucket = ?`,
		s.ReporterID, s.Kind, s.IndicatorKey, s.TimeBucket).Scan(&existing)
	if err != nil {
		return false, err
	}
	now := nowRFC3339()
	_, err = db.Exec(`INSERT INTO signals
        (reporter_id, kind, indicator_key, domain, etld_plus_one, behavior,
         time_bucket, local_confidence, local_reasons, observation_count,
         distinct_asset_count, blocked_count, received_at, first_received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(reporter_id, kind, indicator_key, time_bucket) DO UPDATE SET
            local_confidence = MAX(local_confidence, excluded.local_confidence),
            local_reasons = excluded.local_reasons,
            observation_count = observation_count + excluded.observation_count,
            distinct_asset_count = MAX(distinct_asset_count, excluded.distinct_asset_count),
            blocked_count = blocked_count + excluded.blocked_count,
            received_at = excluded.received_at`,
		// NOTE: first_received_at is intentionally absent from the DO UPDATE SET —
		// merges must preserve the original first-seen anchor.
		s.ReporterID, s.Kind, s.IndicatorKey, s.Domain, s.EtldPlusOne, s.Behavior,
		s.TimeBucket, s.LocalConfidence, s.LocalReasons, s.ObservationCount,
		s.DistinctAssetCount, s.BlockedCount, now, now)
	if err != nil {
		return false, err
	}
	return existing == 0, nil
}

// SignalExists reports whether a stored row already exists for the dedup key
// (reporter_id, kind, indicator_key, time_bucket). The ingest pipeline uses it to
// enforce the per-reporter distinct-indicator cap BEFORE persisting (GHSA-7p69):
// a signal that would create a NEW distinct row is refused once the daily budget
// is exhausted, so a single reporter/batch cannot grow storage without bound.
func (db *DB) SignalExists(reporterID, kind, indicatorKey, timeBucket string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM signals
        WHERE reporter_id = ? AND kind = ? AND indicator_key = ? AND time_bucket = ?`,
		reporterID, kind, indicatorKey, timeBucket).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// AggregateInput is one reporter's contribution for a given indicator within the
// consensus window, already reduced to the per-reporter influence cap (max conf).
type AggregateInput struct {
	Kind          string
	IndicatorKey  string
	ReporterID    string
	MaxConfidence float64
	Observations  int
	Reasons       []string
	HasKnownBad   bool
	FirstBucket   string
	LastBucket    string
	IsExactDomain bool
	Indicator     string // the human indicator string (domain / etld+1 / behavior)
}

// SignalsInWindow returns all signals with received_at >= since, optionally
// excluding a set of reporter ids (denylist). Rows are returned raw; the
// consensus package reduces them to per-reporter contributions.
func (db *DB) SignalsInWindow(since time.Time, exclude map[string]bool) ([]SignalRow, error) {
	rows, err := db.Query(`SELECT reporter_id, kind, indicator_key, domain, etld_plus_one,
        behavior, time_bucket, local_confidence, local_reasons, observation_count,
        distinct_asset_count, blocked_count
        FROM signals WHERE received_at >= ?`,
		since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignalRow
	for rows.Next() {
		var s SignalRow
		if err := rows.Scan(&s.ReporterID, &s.Kind, &s.IndicatorKey, &s.Domain,
			&s.EtldPlusOne, &s.Behavior, &s.TimeBucket, &s.LocalConfidence,
			&s.LocalReasons, &s.ObservationCount, &s.DistinctAssetCount,
			&s.BlockedCount); err != nil {
			return nil, err
		}
		if exclude != nil && exclude[s.ReporterID] {
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PurgeSignals deletes signals whose immutable first_received_at is older than
// the cutoff. Anchoring on first_received_at (not the merge-bumped received_at)
// ensures a row ages out 30 days after it was FIRST seen, even if it has been
// re-sent and merge-bumped since — so retention cannot be refreshed indefinitely.
func (db *DB) PurgeSignals(olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM signals WHERE first_received_at < ?`,
		olderThan.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
