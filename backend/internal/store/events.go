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
			(event_id, timestamp, event_type, source_hash, source_ip, domain, query_type,
			 resolved_ip, blocked, anomaly_score, tags, geo, device_vendor, network_segment,
			 dns_source, threat_desc, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

		metadataStr := e.Metadata
		if metadataStr == "" {
			metadataStr = "{}"
		}

		result, err := stmt.Exec(
			e.EventID, e.Timestamp.UTC(), e.EventType, e.SourceHash,
			nullableString(e.SourceIP),
			nullableString(e.Domain), nullableString(e.QueryType),
			nullableString(e.ResolvedIP), e.Blocked, e.AnomalyScore,
			string(tagsJSON), nullableString(e.Geo),
			nullableString(e.DeviceVendor), seg,
			nullableString(e.DNSSource), nullableString(e.ThreatDesc), metadataStr,
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
		       COALESCE(source_ip, ''), COALESCE(domain, ''), COALESCE(query_type, ''),
		       COALESCE(resolved_ip, ''), blocked, anomaly_score,
		       COALESCE(tags, '[]'), COALESCE(geo, ''),
		       COALESCE(device_vendor, ''), COALESCE(network_segment, 'default'),
		       COALESCE(dns_source, ''), COALESCE(threat_desc, ''), COALESCE(metadata, '{}')
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
			&e.SourceIP, &e.Domain, &e.QueryType, &e.ResolvedIP, &e.Blocked,
			&e.AnomalyScore, &tagsJSON, &e.Geo,
			&e.DeviceVendor, &e.NetworkSegment,
			&e.DNSSource, &e.ThreatDesc, &e.Metadata,
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

// EventStats holds aggregate statistics about events.
type EventStats struct {
	TotalCount            int                    `json:"total_count"`
	ThreatCount           int                    `json:"threat_count"`           // anomaly_score > 0.5
	Last24hCount          int                    `json:"last_24h_count"`
	CountByType           map[string]int         `json:"count_by_type"`
	Top10Domains          []DomainCount          `json:"top_10_domains"`
	Top10BlockedDomains   []DomainCount          `json:"top_10_blocked_domains"`
}

// DomainCount represents a domain and its event count.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// GetEventStats returns comprehensive event statistics.
func (db *DB) GetEventStats() (*EventStats, error) {
	stats := &EventStats{
		CountByType:         make(map[string]int),
		Top10Domains:        []DomainCount{},
		Top10BlockedDomains: []DomainCount{},
	}

	// Total count
	err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&stats.TotalCount)
	if err != nil {
		return nil, fmt.Errorf("count total events: %w", err)
	}

	// Threat count (anomaly_score > 0.5)
	err = db.QueryRow("SELECT COUNT(*) FROM events WHERE anomaly_score > 0.5").Scan(&stats.ThreatCount)
	if err != nil {
		return nil, fmt.Errorf("count threats: %w", err)
	}

	// Last 24h count
	twentyFourHoursAgo := time.Now().UTC().Add(-24 * time.Hour)
	err = db.QueryRow("SELECT COUNT(*) FROM events WHERE timestamp >= ?", twentyFourHoursAgo).Scan(&stats.Last24hCount)
	if err != nil {
		return nil, fmt.Errorf("count last 24h: %w", err)
	}

	// Count by event_type
	rows, err := db.Query("SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type")
	if err != nil {
		return nil, fmt.Errorf("count by type: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			continue
		}
		stats.CountByType[eventType] = count
	}

	// Top 10 domains by query count
	rows, err = db.Query(`
		SELECT domain, COUNT(*) as cnt
		FROM events
		WHERE domain != '' AND domain IS NOT NULL
		GROUP BY domain
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("top domains: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var domain string
		var count int
		if err := rows.Scan(&domain, &count); err != nil {
			continue
		}
		stats.Top10Domains = append(stats.Top10Domains, DomainCount{Domain: domain, Count: count})
	}

	// Top 10 blocked domains
	rows, err = db.Query(`
		SELECT domain, COUNT(*) as cnt
		FROM events
		WHERE blocked = 1 AND domain != '' AND domain IS NOT NULL
		GROUP BY domain
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("top blocked domains: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var domain string
		var count int
		if err := rows.Scan(&domain, &count); err != nil {
			continue
		}
		stats.Top10BlockedDomains = append(stats.Top10BlockedDomains, DomainCount{Domain: domain, Count: count})
	}

	return stats, nil
}

// TimelineEntry represents hourly event counts.
type TimelineEntry struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// GetEventTimeline returns hourly event counts for the last 24 hours.
func (db *DB) GetEventTimeline() ([]TimelineEntry, error) {
	now := time.Now().UTC()
	twentyFourHoursAgo := now.Add(-24 * time.Hour)

	// Query returns each hour's count. SQLite groups by hour using strftime.
	rows, err := db.Query(`
		SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour, COUNT(*) as cnt
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, twentyFourHoursAgo, now)
	if err != nil {
		return nil, fmt.Errorf("timeline query: %w", err)
	}
	defer rows.Close()

	var timeline []TimelineEntry
	for rows.Next() {
		var hour string
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			continue
		}
		timeline = append(timeline, TimelineEntry{Hour: hour, Count: count})
	}

	// Ensure we return all 24 hours, filling in gaps with 0
	allHours := make([]TimelineEntry, 0, 24)
	for i := 23; i >= 0; i-- {
		hourStart := now.Add(-time.Duration(i) * time.Hour)
		hourKey := hourStart.Format("2006-01-02T15:00:00Z")

		// Check if this hour exists in results
		count := 0
		for _, entry := range timeline {
			if entry.Hour == hourKey {
				count = entry.Count
				break
			}
		}
		allHours = append(allHours, TimelineEntry{Hour: hourKey, Count: count})
	}

	return allHours, nil
}

// nullableString returns nil for empty strings so SQLite stores NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

