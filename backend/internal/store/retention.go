package store

import (
	"log"
	"time"
)

// StartRetentionEnforcer runs a background goroutine that deletes events
// older than the configured retention period. It runs once on startup and
// then every 24 hours. Call the returned stop function to shut it down.
func (db *DB) StartRetentionEnforcer() func() {
	ticker := time.NewTicker(24 * time.Hour)
	done := make(chan struct{})

	// Run immediately on startup, then every tick
	go func() {
		db.enforceRetention()
		for {
			select {
			case <-ticker.C:
				db.enforceRetention()
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		close(done)
	}
}

func (db *DB) enforceRetention() {
	days, err := db.GetRetentionDays()
	if err != nil {
		log.Printf("Retention: failed to read config: %v", err)
		return
	}

	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	deleted, err := db.DeleteEventsOlderThan(cutoff)
	if err != nil {
		log.Printf("Retention: failed to delete old events: %v", err)
		return
	}

	if deleted > 0 {
		log.Printf("Retention: deleted %d events older than %d days", deleted, days)
	}
}
