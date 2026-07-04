package corereader

import (
	"path/filepath"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
)

// Cursor tracks the poll position into Core's event stream. It is persisted so a
// restart resumes without re-reading everything. The tie-breaker (LastEventID)
// disambiguates events sharing the same timestamp: on resume we skip events at
// exactly LastTimestamp whose ID we already processed.
type Cursor struct {
	Version       int       `json:"version"`
	LastTimestamp time.Time `json:"last_timestamp"`
	LastEventID   string    `json:"last_event_id"`
}

const cursorFile = "cursor.json"

// LoadCursor reads the cursor from the state dir. A missing or corrupt file
// yields a zero cursor (start from the beginning) with no error.
func LoadCursor(stateDir string) (Cursor, error) {
	var c Cursor
	found, err := config.ReadJSONFile(filepath.Join(stateDir, cursorFile), &c)
	if err != nil {
		return Cursor{}, err
	}
	if !found {
		return Cursor{Version: config.StateFileVersion}, nil
	}
	if err := config.CheckVersion(cursorFile, c.Version); err != nil {
		// Newer than we understand: restart from scratch rather than misread.
		return Cursor{Version: config.StateFileVersion}, nil
	}
	return c, nil
}

// Save persists the cursor atomically (0644 — cursor is not a secret).
func (c Cursor) Save(stateDir string) error {
	c.Version = config.StateFileVersion
	return config.WriteJSONFile(filepath.Join(stateDir, cursorFile), c, 0o644)
}

// Advance updates the cursor to the last event of a fully processed page.
func (c Cursor) Advance(ev Event) Cursor {
	return Cursor{
		Version:       config.StateFileVersion,
		LastTimestamp: ev.Timestamp.UTC(),
		LastEventID:   ev.EventID,
	}
}

// After reports whether ev is strictly after the cursor position. Events at
// exactly LastTimestamp are only "after" if their ID differs AND we treat the
// stored ID as the last-seen — so the exact LastEventID is filtered out. This is
// the at-least-once tie-breaker: duplicates are bounded, none are lost.
func (c Cursor) After(ev Event) bool {
	t := ev.Timestamp.UTC()
	if c.LastTimestamp.IsZero() {
		return true
	}
	if t.After(c.LastTimestamp) {
		return true
	}
	if t.Equal(c.LastTimestamp) {
		// Same instant: skip the exact event we last recorded; keep others.
		return ev.EventID != c.LastEventID
	}
	return false
}
