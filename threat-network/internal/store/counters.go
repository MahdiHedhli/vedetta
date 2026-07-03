package store

// Counters holds a reporter's daily accounting used for abuse caps.
type Counters struct {
	ReporterID         string
	Day                string
	BatchesAccepted    int
	SignalsAccepted    int
	DistinctIndicators int
	AllowlistFlags     int
}

// GetCounters returns the counters row for (reporter, day), zero-valued if none.
func (db *DB) GetCounters(reporterID, day string) (Counters, error) {
	row := db.QueryRow(`SELECT batches_accepted, signals_accepted, distinct_indicators,
        allowlist_flags FROM reporter_counters WHERE reporter_id = ? AND day = ?`,
		reporterID, day)
	c := Counters{ReporterID: reporterID, Day: day}
	err := row.Scan(&c.BatchesAccepted, &c.SignalsAccepted, &c.DistinctIndicators, &c.AllowlistFlags)
	if err != nil {
		// No row yet → zero counters.
		return Counters{ReporterID: reporterID, Day: day}, nil
	}
	return c, nil
}

// AddCounters atomically increments the daily counters for a reporter, creating
// the row if needed.
func (db *DB) AddCounters(reporterID, day string, batches, signals, distinctIndicators, allowlistFlags int) error {
	_, err := db.Exec(`INSERT INTO reporter_counters
        (reporter_id, day, batches_accepted, signals_accepted, distinct_indicators, allowlist_flags)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(reporter_id, day) DO UPDATE SET
            batches_accepted = batches_accepted + excluded.batches_accepted,
            signals_accepted = signals_accepted + excluded.signals_accepted,
            distinct_indicators = distinct_indicators + excluded.distinct_indicators,
            allowlist_flags = allowlist_flags + excluded.allowlist_flags`,
		reporterID, day, batches, signals, distinctIndicators, allowlistFlags)
	return err
}
