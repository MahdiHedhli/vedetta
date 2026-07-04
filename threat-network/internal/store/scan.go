package store

import (
	"database/sql"
	"errors"
)

var errNoFeedRow = errors.New("no feed row")

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanFeedItemInto(s scannable) (*FeedItem, error) {
	var fi FeedItem
	err := s.Scan(&fi.FeedID, &fi.Kind, &fi.Indicator, &fi.IndicatorType, &fi.Confidence,
		&fi.Severity, &fi.SourcesRequired, &fi.SourcesObserved, &fi.Reasons, &fi.FirstSeen,
		&fi.LastSeen, &fi.PublishedAt, &fi.UpdatedAt, &fi.ExpiresAt, &fi.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &fi, nil
}

// scanFeedItem scans a single-row QueryRow result, mapping no-rows to errNoFeedRow.
func scanFeedItem(row *sql.Row) (*FeedItem, error) {
	fi, err := scanFeedItemInto(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errNoFeedRow
		}
		return nil, err
	}
	return fi, nil
}

// scanFeedItemRows scans the current row of a *sql.Rows iterator.
func scanFeedItemRows(rows *sql.Rows) (*FeedItem, error) {
	return scanFeedItemInto(rows)
}
