package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// InsertEvents writes a batch of events to the events table.
// It uses a single transaction with parameterized multi-row insert for performance.
// Returns the count of successfully inserted events.
func (db *DB) InsertEvents(events []models.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO events
			(event_id, timestamp, event_type, source_hash, domain, query_type,
			 resolved_ip, blocked, anomaly_score, tags, geo, device_vendor, network_segment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, e := range events {
		tagsJSON, _ := json.Marshal(e.Tags)
		if len(e.Tags) == 0 {
			tagsJSON = []byte("[]")
		}

		seg := e.NetworkSegment
		if seg == "" {
			seg = "default"
		}

		result, err := stmt.Exec(
			e.EventID, e.Timestamp.UTC(), e.EventType, e.SourceHash,
			nullableString(e.Domain), nullableString(e.QueryType),
			nullableString(e.ResolvedIP), e.Blocked, e.AnomalyScore,
			string(tagsJSON), nullableString(e.Geo),
			nullableString(e.DeviceVendor), seg,
		)
		if err != nil {
			continue // skip individual failures, don't abort the batch
		}
		rows, _ := result.RowsAffected()
		if rows > 0 {
			inserted++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}

	return inserted, nil
}

// EventQueryParams holds the filtering, sorting, and pagination options
// for querying events. Matches the spec in docs/schema.md.
type EventQueryParams struct {
	From     *time.Time // start of time range
	To       *time.Time // end of time range
	Type     string     // filter by event_type
	Source   string     // filter by source_hash
	Tags     []string   // filter: events must have ALL of these tags
	MinScore *float64   // minimum anomaly_score
	Domain   string     // filter by domain (exact match)
	Sort     string     // field to sort by (default: "timestamp")
	Order    string     // asc or desc (default: "desc")
	Page     int        // page number (default: 1)
	Limit    int        // results per page (default: 50, max: 500)
}

// EventQueryResult holds a page of events plus total count.
type EventQueryResult struct {
	Events []models.Event `json:"events"`
	Total  int            `json:"total"`
	Page   int            `json:"page"`
	Limit  int            `json:"limit"`
}

// QueryEvents returns events matching the given filters with pagination.
func (db *DB) QueryEvents(params EventQueryParams) (*EventQueryResult, error) {
	// Defaults
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 {
		params.Limit = 50
	}
	if params.Limit > 500 {
		params.Limit = 500
	}

	// Validate and default sort
	allowedSort := map[string]bool{
		"timestamp": true, "event_type": true, "anomaly_score": true,
		"source_hash": true, "domain": true,
	}
	if !allowedSort[params.Sort] {
		params.Sort = "timestamp"
	}
	if params.Order != "asc" {
		params.Order = "desc"
	}

	// Build WHERE clauses
	var conditions []string
	var args []any

	if params.From != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, params.From.UTC())
	}
	if params.To != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, params.To.UTC())
	}
	if params.Type != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, params.Type)
	}
	if params.Source != "" {
		conditions = append(conditions, "source_hash = ?")
		args = append(args, params.Source)
	}
	if params.Domain != "" {
		conditions = append(conditions, "domain = ?")
		args = append(args, params.Domain)
	}
	if params.MinScore != nil {
		conditions = append(conditions, "anomaly_score >= ?")
		args = append(args, *params.MinScore)
	}
	// Tag filtering: use LIKE against the JSON array string for each tag
	for _, tag := range params.Tags {
		conditions = append(conditions, "tags LIKE ?")
		args = append(args, "%\""+tag+"\"%")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM events %s", whereClause)
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	// Fetch the page
	offset := (params.Page - 1) * params.Limit
	dataQuery := fmt.Sprintf(`
		SELECT event_id, timestamp, event_type, source_hash,
		       COALESCE(domain, ''), COALESCE(query_type, ''),
		       COALESCE(resolved_ip, ''), blocked, anomaly_score,
		       COALESCE(tags, '[]'), COALESCE(geo, ''),
		       COALESCE(device_vendor, ''), COALESCE(network_segment, 'default')
		FROM events %s
		ORDER BY %s %s
		LIMIT ? OFFSET ?
	`, whereClause, params.Sort, params.Order)

	dataArgs := append(args, params.Limit, offset)
	rows, err := db.Query(dataQuery, dataArgs...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var e models.Event
		var tagsJSON string
		err := rows.Scan(
			&e.EventID, &e.Timestamp, &e.EventType, &e.SourceHash,
			&e.Domain, &e.QueryType, &e.ResolvedIP, &e.Blocked,
			&e.AnomalyScore, &tagsJSON, &e.Geo,
			&e.DeviceVendor, &e.NetworkSegment,
		)
		if err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		json.Unmarshal([]byte(tagsJSON), &e.Tags)
		if e.Tags == nil {
			e.Tags = []string{}
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	if events == nil {
		events = []models.Event{}
	}

	return &EventQueryResult{
		Events: events,
		Total:  total,
		Page:   params.Page,
		Limit:  params.Limit,
	}, nil
}

// CountEvents returns total event count.
func (db *DB) CountEvents() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

// DeleteEventsOlderThan removes events older than the given timestamp.
// Returns the number of deleted rows.
func (db *DB) DeleteEventsOlderThan(cutoff time.Time) (int64, error) {
	result, err := db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete old events: %w", err)
	}
	return result.RowsAffected()
}

// GetRetentionDays reads the configured retention period from retention_config.
func (db *DB) GetRetentionDays() (int, error) {
	var val string
	err := db.QueryRow("SELECT value FROM retention_config WHERE key = 'retention_days'").Scan(&val)
	if err != nil {
		return 90, nil // default
	}
	days := 90
	fmt.Sscanf(val, "%d", &days)
	if days < 1 {
		days = 90
	}
	return days, nil
}

// nullableString returns nil for empty strings so SQLite stores NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

