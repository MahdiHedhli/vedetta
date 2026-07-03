package store

import (
	"time"
)

// AggregateRow is a recomputed per-indicator consensus aggregate.
type AggregateRow struct {
	Kind               string
	IndicatorKey       string
	DistinctReporters  int
	AggregateConfidence float64
	TotalObservations  int
	Reasons            string // JSON array
	HasKnownBad        bool
	FirstSeen          string
	LastSeen           string
	ComputedAt         string
}

// UpsertAggregate writes (or replaces) a signal_aggregates row.
func (db *DB) UpsertAggregate(a AggregateRow) error {
	kb := 0
	if a.HasKnownBad {
		kb = 1
	}
	_, err := db.Exec(`INSERT INTO signal_aggregates
        (kind, indicator_key, distinct_reporters, aggregate_confidence, total_observations,
         reasons, has_known_bad, first_seen, last_seen, computed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, indicator_key) DO UPDATE SET
            distinct_reporters = excluded.distinct_reporters,
            aggregate_confidence = excluded.aggregate_confidence,
            total_observations = excluded.total_observations,
            reasons = excluded.reasons,
            has_known_bad = excluded.has_known_bad,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            computed_at = excluded.computed_at`,
		a.Kind, a.IndicatorKey, a.DistinctReporters, a.AggregateConfidence, a.TotalObservations,
		a.Reasons, kb, a.FirstSeen, a.LastSeen, a.ComputedAt)
	return err
}

// FeedItem is a promoted advisory feed row.
type FeedItem struct {
	FeedID          string
	Kind            string // domain_indicator | etld1_indicator | behavior_cluster
	Indicator       string
	IndicatorType   string // domain | etld_plus_one | behavior
	Confidence      float64
	Severity        string
	SourcesRequired int
	SourcesObserved int
	Reasons         string // JSON array
	FirstSeen       string
	LastSeen        string
	PublishedAt     string
	UpdatedAt       string
	ExpiresAt       string
	RevokedAt       string // "" if not revoked
}

// GetFeedItemByIndicator looks up an existing feed item by (kind, indicator).
func (db *DB) GetFeedItemByIndicator(kind, indicator string) (*FeedItem, bool, error) {
	row := db.QueryRow(`SELECT feed_id, kind, indicator, indicator_type, confidence, severity,
        sources_required, sources_observed, reasons, first_seen, last_seen, published_at,
        updated_at, expires_at, COALESCE(revoked_at, '')
        FROM feed_items WHERE kind = ? AND indicator = ?`, kind, indicator)
	fi, err := scanFeedItem(row)
	if err != nil {
		if err == errNoFeedRow {
			return nil, false, nil
		}
		return nil, false, err
	}
	return fi, true, nil
}

// UpsertFeedItem inserts or updates a feed item keyed by (kind, indicator).
func (db *DB) UpsertFeedItem(fi FeedItem) error {
	var revoked interface{}
	if fi.RevokedAt != "" {
		revoked = fi.RevokedAt
	}
	_, err := db.Exec(`INSERT INTO feed_items
        (feed_id, kind, indicator, indicator_type, confidence, severity, sources_required,
         sources_observed, reasons, first_seen, last_seen, published_at, updated_at,
         expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, indicator) DO UPDATE SET
            confidence = excluded.confidence,
            severity = excluded.severity,
            sources_required = excluded.sources_required,
            sources_observed = excluded.sources_observed,
            reasons = excluded.reasons,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at,
            revoked_at = excluded.revoked_at`,
		fi.FeedID, fi.Kind, fi.Indicator, fi.IndicatorType, fi.Confidence, fi.Severity,
		fi.SourcesRequired, fi.SourcesObserved, fi.Reasons, fi.FirstSeen, fi.LastSeen,
		fi.PublishedAt, fi.UpdatedAt, fi.ExpiresAt, revoked)
	return err
}

// AllFeedItems returns every feed item (including revoked/expired) for lifecycle
// processing by the consensus package.
func (db *DB) AllFeedItems() ([]FeedItem, error) {
	rows, err := db.Query(`SELECT feed_id, kind, indicator, indicator_type, confidence, severity,
        sources_required, sources_observed, reasons, first_seen, last_seen, published_at,
        updated_at, expires_at, COALESCE(revoked_at, '') FROM feed_items`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedItem
	for rows.Next() {
		fi, err := scanFeedItemRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *fi)
	}
	return out, rows.Err()
}

// RevokeFeedItem marks a feed item revoked at the given time.
func (db *DB) RevokeFeedItem(feedID, revokedAt string) error {
	_, err := db.Exec(`UPDATE feed_items SET revoked_at = ?, updated_at = ? WHERE feed_id = ?`,
		revokedAt, revokedAt, feedID)
	return err
}

// FeedItemCap bounds the published feed at the top N live items ordered by
// confidence (plan.md SNR control). Anything below the cap is withheld from the
// served snapshot; the highest-confidence indicators always win a slot.
const FeedItemCap = 5000

// FeedQuery filters a live feed read.
type FeedQuery struct {
	MinConfidence float64
	Kind          string // "" = any
	AfterConf     string // cursor: confidence (formatted, see confCursor)
	AfterFeedID   string // cursor tiebreak: feed_id
	Limit         int
	Now           time.Time
}

// LiveFeedItems returns non-revoked, non-expired feed items ordered by
// (confidence DESC, feed_id ASC) — highest-confidence-first, with feed_id as a
// stable tiebreak for cursor pagination. The served feed is capped at
// FeedItemCap items by confidence: overflow below the cap is never served, so a
// flood of low-confidence promotions cannot push out higher-confidence ones.
// Returns items and the total served (capped) live count.
func (db *DB) LiveFeedItems(q FeedQuery) (items []FeedItem, total int, err error) {
	nowStr := q.Now.UTC().Format(time.RFC3339)

	// Total live count (for total_items), independent of cursor/limit, then
	// clamped to the cap so total_items never advertises more than we will serve.
	countQ := `SELECT COUNT(1) FROM feed_items WHERE revoked_at IS NULL AND expires_at > ?
        AND confidence >= ?`
	countArgs := []interface{}{nowStr, q.MinConfidence}
	if q.Kind != "" {
		countQ += ` AND kind = ?`
		countArgs = append(countArgs, q.Kind)
	}
	if err = db.QueryRow(countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total > FeedItemCap {
		total = FeedItemCap
	}

	sb := `SELECT feed_id, kind, indicator, indicator_type, confidence, severity,
        sources_required, sources_observed, reasons, first_seen, last_seen, published_at,
        updated_at, expires_at, COALESCE(revoked_at, '')
        FROM feed_items WHERE revoked_at IS NULL AND expires_at > ? AND confidence >= ?`
	args := []interface{}{nowStr, q.MinConfidence}
	if q.Kind != "" {
		sb += ` AND kind = ?`
		args = append(args, q.Kind)
	}
	// Cursor: keyset over (confidence DESC, feed_id ASC). "After" means strictly
	// past the cursor position in that order: lower confidence, or equal
	// confidence with a larger feed_id.
	if q.AfterConf != "" {
		sb += ` AND (confidence < ? OR (confidence = ? AND feed_id > ?))`
		args = append(args, q.AfterConf, q.AfterConf, q.AfterFeedID)
	}
	sb += ` ORDER BY confidence DESC, feed_id ASC`
	// Bound the served window to at most the cap (and to the page limit). The
	// caller may pass a page Limit <= FeedItemCap; the cap is the hard ceiling on
	// the whole served feed, enforced here so paging past it yields nothing.
	limit := q.Limit
	if limit <= 0 || limit > FeedItemCap {
		limit = FeedItemCap
	}
	sb += ` LIMIT ?`
	args = append(args, limit)

	rows, err := db.Query(sb, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		fi, err := scanFeedItemRows(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *fi)
	}
	return items, total, rows.Err()
}

// CountLiveFeedItems returns the number of non-revoked, non-expired items.
func (db *DB) CountLiveFeedItems(now time.Time) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM feed_items WHERE revoked_at IS NULL AND expires_at > ?`,
		now.UTC().Format(time.RFC3339)).Scan(&n)
	return n, err
}

// PurgeRevokedFeedItems deletes feed items revoked before the cutoff.
func (db *DB) PurgeRevokedFeedItems(olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM feed_items WHERE revoked_at IS NOT NULL AND revoked_at < ?`,
		olderThan.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
