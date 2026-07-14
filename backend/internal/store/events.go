package store

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// InsertEvents writes a batch of events to the events table.
// It uses a single transaction with parameterized multi-row insert for performance.
// Returns the count of successfully inserted events.
//
// PIECE 2 extension: supports /ingest payloads including firewall-shaped events (per FirewallEvent
// in docs/connector-guide.md: action, protocol, src/dst IP/port, interface, direction, rule, raw_log, etc.).
// Fields without dedicated columns are stored in the metadata JSON (see /ingest handler enrichment
// which puts collector raw + received_at + extras there). No parallel table. If new columns needed
// later, use new migration file (e.g. 017_*) with additive ALTER + the guarded-ensure pattern in
// migrate() (like server_ip/services in recovery), preserving runner idempotency. Current Insert
// already has the server_ip ensure + insert from recovery. Preserves batch/tx and Pi-4 budget.
func (db *DB) InsertEvents(events []models.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	// Ensure server_ip column for richer DNS sensor data (actionability: the server/resolver
	// side of the query, complementing source_ip and dns_answers in metadata).
	// Portable pragma check + plain ALTER (no "IF NOT EXISTS" DDL) for older sqlite3 CLI compat,
	// matching the services pattern in devices.go. Column will be present for new events.
	var serverIPColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'server_ip'`).Scan(&serverIPColCount); err == nil && serverIPColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN server_ip TEXT DEFAULT ''`)
	}

	// Match-provenance columns (GHSA-hx86, migration 022). Same guarded pragma +
	// plain ALTER safety net so old DBs get the columns before this insert binds them.
	var matchedIndicatorColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'matched_indicator'`).Scan(&matchedIndicatorColCount); err == nil && matchedIndicatorColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN matched_indicator TEXT DEFAULT ''`)
	}
	var matchTypeColCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'match_type'`).Scan(&matchTypeColCount); err == nil && matchTypeColCount == 0 {
		db.Exec(`ALTER TABLE events ADD COLUMN match_type TEXT DEFAULT ''`)
	}

	// GHSA-9m7g: this is the SINGLE persistence choke point for events. Every write
	// path (HTTP /ingest, sensor DNS ingest, Pi-hole/AdGuard pollers, direct-UniFi)
	// funnels through InsertEvents, so clamping far-future timestamps here — not only
	// in the HTTP handlers — guarantees no writer can plant a forged/skewed future
	// cursor that strands all later normal events behind it. The handler clamps are
	// kept as a harmless first line of defense.
	now := time.Now().UTC()

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO events
			(event_id, timestamp, event_type, source_hash, source_ip, server_ip, domain, query_type,
			 resolved_ip, blocked, outcome, anomaly_score, tags, geo, device_vendor, network_segment,
			 dns_source, threat_desc, metadata, matched_indicator, match_type, device_id,
			 identity_confidence, identity_reason, identity_evidence, origin, sensor_id,
			 disposition, suppression_rule_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		identityEvidence := e.IdentityEvidence
		if identityEvidence == "" {
			identityEvidence = "{}"
		}
		disposition := e.Disposition
		if disposition == "" {
			disposition = "active"
		}

		result, err := stmt.Exec(
			e.EventID, clampFutureEventTimestamp(e.Timestamp, now).UTC(), e.EventType, e.SourceHash,
			nullableString(e.SourceIP), nullableString(e.ServerIP),
			nullableString(e.Domain), nullableString(e.QueryType),
			nullableString(e.ResolvedIP), e.Blocked, persistedEventOutcome(e.Outcome, e.Blocked), e.AnomalyScore,
			string(tagsJSON), nullableString(e.Geo),
			nullableString(e.DeviceVendor), seg,
			nullableString(e.DNSSource), nullableString(e.ThreatDesc), metadataStr,
			nullableString(e.MatchedIndicator), nullableString(e.MatchType),
			nullableString(e.DeviceID), e.IdentityConfidence, e.IdentityReason, identityEvidence,
			e.Origin, nullableString(e.SensorID), disposition, e.SuppressionRuleID,
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

// EnforceRetention deletes events older than retention_days (from retention_config, default 90).
// Daily job; non-blocking (WAL DELETE ok concurrent with inserts). For Pi 4 SD longevity,
// after bulk deletes run "PRAGMA incremental_vacuum;" (or periodic full VACUUM offline) to
// reclaim space without heavy IO. See research/02-log-aggregation.md.
func (db *DB) EnforceRetention() error {
	var days int
	err := db.QueryRow("SELECT CAST(value AS INTEGER) FROM retention_config WHERE key='retention_days'").Scan(&days)
	if err != nil || days <= 0 {
		days = 90
	}
	cutoff := time.Now().AddDate(0, 0, -days).UTC()
	res, err := db.Exec(`DELETE FROM events WHERE timestamp < ?
		AND event_id NOT IN (SELECT event_id FROM finding_events)`, cutoff)
	if err != nil {
		return fmt.Errorf("retention delete: %w", err)
	}
	n, _ := res.RowsAffected()
	log.Printf("Retention: deleted %d events older than %d days", n, days)
	return nil
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
	DeviceID string     // filter by stable device ID
	Origin   string     // filter by ingress adapter/origin
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

// eventOrderClause maps the public sort controls to complete, constant SQL
// fragments. Keeping request values out of the query text makes the injection
// boundary explicit to both readers and static analyzers.
func eventOrderClause(sort, order string) string {
	ascending := order == "asc"
	switch sort {
	case "event_type":
		if ascending {
			return "e.event_type ASC, e.event_id ASC"
		}
		return "e.event_type DESC, e.event_id DESC"
	case "anomaly_score":
		if ascending {
			return "e.anomaly_score ASC, e.event_id ASC"
		}
		return "e.anomaly_score DESC, e.event_id DESC"
	case "source_hash":
		if ascending {
			return "e.source_hash ASC, e.event_id ASC"
		}
		return "e.source_hash DESC, e.event_id DESC"
	case "domain":
		if ascending {
			return "e.domain ASC, e.event_id ASC"
		}
		return "e.domain DESC, e.event_id DESC"
	default:
		if ascending {
			return "e.timestamp ASC, e.event_id ASC"
		}
		return "e.timestamp DESC, e.event_id DESC"
	}
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

	orderBy := eventOrderClause(params.Sort, params.Order)

	// Build WHERE clauses
	var conditions []string
	var args []any

	if params.From != nil {
		conditions = append(conditions, "e.timestamp >= ?")
		args = append(args, params.From.UTC())
	}
	if params.To != nil {
		conditions = append(conditions, "e.timestamp <= ?")
		args = append(args, params.To.UTC())
	}
	if params.Type != "" {
		conditions = append(conditions, "e.event_type = ?")
		args = append(args, params.Type)
	}
	if params.Source != "" {
		conditions = append(conditions, "e.source_hash = ?")
		args = append(args, params.Source)
	}
	if params.Domain != "" {
		conditions = append(conditions, "e.domain = ?")
		args = append(args, params.Domain)
	}
	if params.DeviceID != "" {
		conditions = append(conditions, "COALESCE(cd.canonical_id, e.device_id, '') = ?")
		args = append(args, params.DeviceID)
	}
	if params.Origin != "" {
		conditions = append(conditions, "e.origin = ?")
		args = append(args, params.Origin)
	}
	if params.MinScore != nil {
		conditions = append(conditions, "e.anomaly_score >= ?")
		args = append(args, *params.MinScore)
	}
	// Tag filtering: use LIKE against the JSON array string for each tag
	for _, tag := range params.Tags {
		conditions = append(conditions, "e.tags LIKE ?")
		args = append(args, "%\""+tag+"\"%")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows
	const eventFromSQL = `FROM events e LEFT JOIN canonical_devices cd ON cd.root_id = e.device_id`
	countQuery := canonicalDeviceCTE + " SELECT COUNT(*) " + eventFromSQL + " " + whereClause
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	// Fetch the page
	offset := (params.Page - 1) * params.Limit
	dataQuery := canonicalDeviceCTE + `
		SELECT e.event_id, e.timestamp, e.event_type, e.source_hash,
		       COALESCE(e.source_ip, ''), COALESCE(e.server_ip, ''), COALESCE(e.domain, ''), COALESCE(e.query_type, ''),
		       COALESCE(e.resolved_ip, ''), e.blocked, COALESCE(e.outcome, 'observed'), e.anomaly_score,
		       COALESCE(e.tags, '[]'), COALESCE(e.geo, ''),
		       COALESCE(e.device_vendor, ''), COALESCE(e.network_segment, 'default'),
		       COALESCE(e.dns_source, ''), COALESCE(e.threat_desc, ''), COALESCE(e.metadata, '{}'),
		       COALESCE(e.acknowledged, FALSE), COALESCE(e.ack_reason, ''),
		       COALESCE(e.matched_indicator, ''), COALESCE(e.match_type, ''),
		       COALESCE(e.device_id, ''), COALESCE(cd.canonical_id, e.device_id, ''),
		       COALESCE(e.identity_confidence, 0),
		       COALESCE(e.identity_reason, ''), COALESCE(e.identity_evidence, '{}'),
		       COALESCE(e.origin, ''), COALESCE(e.sensor_id, ''),
		       COALESCE(e.disposition, 'active'), COALESCE(e.suppression_rule_id, '')
		` + eventFromSQL + ` ` + whereClause + `
		ORDER BY ` + orderBy + `
		LIMIT ? OFFSET ?`

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
			&e.SourceIP, &e.ServerIP, &e.Domain, &e.QueryType, &e.ResolvedIP, &e.Blocked,
			&e.Outcome, &e.AnomalyScore, &tagsJSON, &e.Geo,
			&e.DeviceVendor, &e.NetworkSegment,
			&e.DNSSource, &e.ThreatDesc, &e.Metadata,
			&e.Acknowledged, &e.AckReason,
			&e.MatchedIndicator, &e.MatchType,
			&e.DeviceID, &e.CanonicalDeviceID, &e.IdentityConfidence, &e.IdentityReason, &e.IdentityEvidence,
			&e.Origin, &e.SensorID, &e.Disposition, &e.SuppressionRuleID,
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

// CountEventsByType returns the count of events of a specific type (e.g. "dns_query").
// Useful for collection health monitoring during long-running sensor runs.
func (db *DB) CountEventsByType(eventType string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM events WHERE event_type = ?", eventType).Scan(&count)
	return count, err
}

// DeleteEventsOlderThan removes ordinary raw events older than the cutoff.
// Events supporting durable findings are retained so open and historical
// findings never turn into explanation cards with dangling evidence IDs.
// Returns the number of deleted rows.
func (db *DB) DeleteEventsOlderThan(cutoff time.Time) (int64, error) {
	result, err := db.Exec(`DELETE FROM events WHERE timestamp < ?
		AND event_id NOT IN (SELECT event_id FROM finding_events)`, cutoff.UTC())
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
	TotalCount          int            `json:"total_count"`
	ThreatCount         int            `json:"threat_count"` // anomaly_score > 0.5
	Last24hCount        int            `json:"last_24h_count"`
	CountByType         map[string]int `json:"count_by_type"`
	Top10Domains        []DomainCount  `json:"top_10_domains"`
	Top10BlockedDomains []DomainCount  `json:"top_10_blocked_domains"`
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

// maxEventFutureSkew is how far ahead of server time an event timestamp may be
// before InsertEvents treats it as clock skew or forgery and clamps it to now
// (GHSA-9m7g). Mirrors the HTTP-handler bound; kept here so EVERY writer is covered.
const maxEventFutureSkew = time.Hour

// clampFutureEventTimestamp returns ts, or now when ts is more than
// maxEventFutureSkew ahead of now. A zero ts is returned unchanged so callers can
// apply their own default.
func clampFutureEventTimestamp(ts, now time.Time) time.Time {
	if !ts.IsZero() && ts.After(now.Add(maxEventFutureSkew)) {
		return now
	}
	return ts
}

// ScrubFutureEvents repairs poisoned rows left by pre-clamp writers (GHSA-9m7g):
// on startup it clamps any existing event whose timestamp is more than
// maxEventFutureSkew ahead of server time back to now, so a forged far-future row
// written by an older build can no longer strand the telemetry cursor after an
// upgrade. Returns the number of rows repaired. Idempotent.
func (db *DB) ScrubFutureEvents() (int64, error) {
	now := time.Now().UTC()
	threshold := now.Add(maxEventFutureSkew)
	res, err := db.Exec("UPDATE events SET timestamp = ? WHERE timestamp > ?", now, threshold)
	if err != nil {
		return 0, fmt.Errorf("scrub future events: %w", err)
	}
	return res.RowsAffected()
}

// nullableString returns nil for empty strings so SQLite stores NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// persistedEventOutcome preserves Core-derived enforcement context while
// giving pre-processor callers a conservative compatibility default. A false
// blocked flag does not prove that traffic was allowed.
func persistedEventOutcome(outcome string, blocked bool) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "blocked":
		return "blocked"
	case "allowed":
		return "allowed"
	case "observed":
		return "observed"
	}
	if blocked {
		return "blocked"
	}
	return "observed"
}
