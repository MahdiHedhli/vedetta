// Package threatintel provides local threat intelligence storage and lookup.
// It manages a SQLite-backed indicator database populated from external feeds
// (abuse.ch, GreyNoise, etc.) and provides fast O(1) lookups via a Bloom filter.
package threatintel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// Indicator represents a single threat intelligence indicator.
type Indicator struct {
	Value      string    `json:"value"`      // domain, IP, JA3 hash, URL
	Type       string    `json:"type"`       // domain, ipv4, ipv6, ja3, url, hash
	Source     string    `json:"source"`     // urlhaus, feodotracker, sslbl, greynoise
	Confidence float64   `json:"confidence"` // 0.0–1.0
	Tags       []string  `json:"tags"`       // c2, malware_distribution, phishing
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	TTLHours   int       `json:"ttl_hours"`
}

// LookupResult is returned by Lookup when an indicator matches.
type LookupResult struct {
	Found      bool
	Indicator  *Indicator
	IsStale    bool    // True if the indicator's TTL has expired
	Confidence float64 // Adjusted confidence (reduced if stale)
}

// ThreatIntelDB manages the local threat indicator database.
type ThreatIntelDB struct {
	db    *sql.DB
	bloom *BloomFilter
}

// NewThreatIntelDB wraps an existing sql.DB connection (the same vedetta.db)
// and initializes the Bloom filter from existing indicators.
func NewThreatIntelDB(db *sql.DB) (*ThreatIntelDB, error) {
	tid := &ThreatIntelDB{
		db:    db,
		bloom: NewBloomFilter(200000, 7), // ~500KB for 100K indicators, 0.1% FP rate
	}

	// Load existing indicators into the Bloom filter
	if err := tid.rebuildBloom(); err != nil {
		log.Printf("threatintel: bloom rebuild skipped (table may not exist yet): %v", err)
	}

	return tid, nil
}

// Lookup checks if an indicator value exists in the threat database.
// It first checks the Bloom filter for O(1) rejection of non-matches,
// then queries SQLite for confirmed matches.
func (t *ThreatIntelDB) Lookup(value string) LookupResult {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return LookupResult{}
	}

	// Fast path: Bloom filter says "definitely not present"
	if !t.bloom.MayContain(value) {
		return LookupResult{}
	}

	// Slow path: confirm with SQLite (Bloom filter has false positives)
	row := t.db.QueryRow(`
		SELECT indicator, type, source, confidence, tags, first_seen, last_seen, ttl_hours
		FROM threat_indicators
		WHERE indicator = ?
		ORDER BY confidence DESC
		LIMIT 1
	`, value)

	var ind Indicator
	var tagsJSON string
	var firstSeenStr, lastSeenStr string
	err := row.Scan(&ind.Value, &ind.Type, &ind.Source, &ind.Confidence,
		&tagsJSON, &firstSeenStr, &lastSeenStr, &ind.TTLHours)
	if err != nil {
		return LookupResult{} // Not found (Bloom false positive)
	}

	// Parse timestamps from TEXT columns (sqlite3 driver doesn't auto-parse TEXT→time.Time)
	ind.FirstSeen, _ = parseTimestamp(firstSeenStr)
	ind.LastSeen, _ = parseTimestamp(lastSeenStr)

	json.Unmarshal([]byte(tagsJSON), &ind.Tags)
	if ind.Tags == nil {
		ind.Tags = []string{}
	}

	// Check staleness
	isStale := time.Since(ind.LastSeen) > time.Duration(ind.TTLHours)*time.Hour
	confidence := ind.Confidence
	if isStale {
		confidence *= 0.5 // Demote stale indicators
	}

	return LookupResult{
		Found:      true,
		Indicator:  &ind,
		IsStale:    isStale,
		Confidence: confidence,
	}
}

// BulkImport inserts or updates a batch of indicators from a feed source.
// Uses INSERT OR REPLACE to update existing indicators from the same source.
func (t *ThreatIntelDB) BulkImport(indicators []Indicator) (int, error) {
	if len(indicators) == 0 {
		return 0, nil
	}

	tx, err := t.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO threat_indicators
			(indicator, type, source, confidence, tags, first_seen, last_seen, ttl_hours)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	imported := 0
	now := time.Now().UTC()
	for _, ind := range indicators {
		value := strings.ToLower(strings.TrimSpace(ind.Value))
		if value == "" {
			continue
		}

		tagsJSON, _ := json.Marshal(ind.Tags)
		if ind.Tags == nil {
			tagsJSON = []byte("[]")
		}

		firstSeen := ind.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = now
		}
		lastSeen := ind.LastSeen
		if lastSeen.IsZero() {
			lastSeen = now
		}
		ttl := ind.TTLHours
		if ttl == 0 {
			ttl = 168 // 7 days default
		}

		_, err := stmt.Exec(value, ind.Type, ind.Source, ind.Confidence,
			string(tagsJSON), firstSeen, lastSeen, ttl)
		if err != nil {
			continue
		}

		t.bloom.Add(value)
		imported++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	return imported, nil
}

// PurgeExpired removes indicators whose TTL has expired and they haven't
// been refreshed. Returns the count of deleted indicators.
func (t *ThreatIntelDB) PurgeExpired() (int64, error) {
	result, err := t.db.Exec(`
		DELETE FROM threat_indicators
		WHERE datetime(last_seen, '+' || ttl_hours || ' hours') < datetime('now')
	`)
	if err != nil {
		return 0, fmt.Errorf("purge expired: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		// Rebuild Bloom filter after purge
		t.rebuildBloom()
	}
	return deleted, nil
}

// Stats returns counts of indicators by source.
func (t *ThreatIntelDB) Stats() (map[string]int, error) {
	rows, err := t.db.Query(`
		SELECT source, COUNT(*) FROM threat_indicators GROUP BY source
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var source string
		var count int
		rows.Scan(&source, &count)
		stats[source] = count
	}
	return stats, rows.Err()
}

// rebuildBloom reconstructs the Bloom filter from all indicators in the DB.
func (t *ThreatIntelDB) rebuildBloom() error {
	rows, err := t.db.Query("SELECT indicator FROM threat_indicators")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Create a fresh Bloom filter
	bloom := NewBloomFilter(200000, 7)
	count := 0
	for rows.Next() {
		var value string
		rows.Scan(&value)
		bloom.Add(value)
		count++
	}

	t.bloom = bloom
	if count > 0 {
		log.Printf("threatintel: Bloom filter rebuilt with %d indicators", count)
	}
	return rows.Err()
}

// parseTimestamp tries multiple formats that mattn/go-sqlite3 may use
// when writing time.Time to a TEXT column.
func parseTimestamp(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999+00:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05+00:00",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp: %q", s)
}
