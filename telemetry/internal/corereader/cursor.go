package corereader

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
)

// Cursor tracks the poll position into Core's event stream. Core's `from`
// filter is inclusive, so every event ID consumed at LastTimestamp is retained
// as the exact tie-breaker cohort. LastEventID remains for compatibility with
// cursor files written by older releases; new readers migrate it into
// SeenEventIDs when that field is absent.
type Cursor struct {
	Version       int       `json:"version"`
	LastTimestamp time.Time `json:"last_timestamp"`
	LastEventID   string    `json:"last_event_id"`
	SeenEventIDs  []string  `json:"seen_event_ids,omitempty"`
}

const cursorFile = "cursor.json"

// maxCursorTimestampCohort bounds both the persisted cursor and its in-memory
// lookup set. More than 50,000 events at one exact timestamp is far beyond the
// expected LAN workload. If it occurs, Read fails visibly and holds the prior
// cursor rather than silently losing an event or replaying a partial cohort.
const maxCursorTimestampCohort = 50_000

// cursorFutureSkew bounds how far ahead of the local clock a persisted cursor
// timestamp may sit before we treat it as bogus. A cursor dated beyond this is
// impossible for any real Core event to be "after" (After() would reject every
// event forever), so telemetry would silently stop exporting until a human
// noticed. Such a value only appears via clock skew at write time, a corrupted
// write, or a hand-edited/hostile state file that survives an upgrade — the
// GHSA-9m7g "future-dated cursor strands telemetry" path.
const cursorFutureSkew = time.Hour

// nowUTC is overridable in tests so the future-skew guard is deterministic.
var nowUTC = func() time.Time { return time.Now().UTC() }

// LoadCursor reads the cursor from the state dir. A missing or corrupt file
// yields a zero cursor (start from the beginning) with no error. A persisted
// cursor whose timestamp is implausibly in the future (beyond cursorFutureSkew)
// is likewise reset to zero rather than trusted: keeping it would strand
// telemetry forever (GHSA-9m7g), whereas resetting re-reads from a sane point
// (at-least-once dedup absorbs any bounded replay).
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
	if !c.LastTimestamp.IsZero() && c.LastTimestamp.After(nowUTC().Add(cursorFutureSkew)) {
		// Future-dated beyond tolerated skew: invalid. Reset so telemetry resumes
		// from a sane point instead of being stranded forever (GHSA-9m7g).
		return Cursor{Version: config.StateFileVersion}, nil
	}
	return normalizeCursor(c)
}

// Save persists the cursor atomically (0644 — cursor is not a secret).
func (c Cursor) Save(stateDir string) error {
	normalized, err := normalizeCursor(c)
	if err != nil {
		return err
	}
	normalized.Version = config.StateFileVersion
	return config.WriteJSONFile(filepath.Join(stateDir, cursorFile), normalized, 0o644)
}

// Advance returns a cursor that includes ev. At a newer timestamp the prior
// cohort can be discarded; at the current timestamp ev is added to the exact
// seen-ID set. An over-cap cohort returns an error so callers hold the previous
// durable cursor rather than accepting replay or loss.
func (c Cursor) Advance(ev Event) (Cursor, error) {
	watermark, err := newCursorWatermark(c)
	if err != nil {
		return c, err
	}
	if err := watermark.advance(ev); err != nil {
		return c, err
	}
	return watermark.snapshot(), nil
}

// After reports whether ev is beyond the cursor watermark. At LastTimestamp an
// event is new only when its ID is absent from the complete persisted cohort.
func (c Cursor) After(ev Event) bool {
	watermark, err := newCursorWatermark(c)
	return err == nil && watermark.after(ev)
}

// normalizeCursor canonicalizes the optional v1 cohort extension. A legacy
// file has only LastEventID; treating that ID as the initial one-element cohort
// preserves its old durable position while allowing other equal-time events to
// be consumed once and recorded on the next save.
func normalizeCursor(c Cursor) (Cursor, error) {
	c.Version = config.StateFileVersion
	if c.LastTimestamp.IsZero() {
		c.LastEventID = ""
		c.SeenEventIDs = nil
		return c, nil
	}
	c.LastTimestamp = c.LastTimestamp.UTC()
	c.LastEventID = strings.TrimSpace(c.LastEventID)

	seen := make(map[string]struct{}, len(c.SeenEventIDs)+1)
	ids := make([]string, 0, len(c.SeenEventIDs)+1)
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, id := range c.SeenEventIDs {
		add(id)
	}
	add(c.LastEventID)
	if len(ids) > maxCursorTimestampCohort {
		return Cursor{}, fmt.Errorf("cursor timestamp cohort exceeds bounded maximum of %d event IDs", maxCursorTimestampCohort)
	}
	sort.Strings(ids)
	c.SeenEventIDs = ids
	if c.LastEventID == "" && len(ids) > 0 {
		c.LastEventID = ids[len(ids)-1]
	}
	return c, nil
}

// cursorWatermark is the efficient per-read form of Cursor. The persisted form
// stays a deterministic JSON slice, while ingestion uses an O(1) membership set
// across page boundaries.
type cursorWatermark struct {
	cursor Cursor
	seen   map[string]struct{}
}

func newCursorWatermark(c Cursor) (*cursorWatermark, error) {
	normalized, err := normalizeCursor(c)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(normalized.SeenEventIDs))
	for _, id := range normalized.SeenEventIDs {
		seen[id] = struct{}{}
	}
	return &cursorWatermark{cursor: normalized, seen: seen}, nil
}

func (w *cursorWatermark) after(ev Event) bool {
	id := strings.TrimSpace(ev.EventID)
	if id == "" || ev.Timestamp.IsZero() {
		return false
	}
	t := ev.Timestamp.UTC()
	if w.cursor.LastTimestamp.IsZero() || t.After(w.cursor.LastTimestamp) {
		return true
	}
	if t.Before(w.cursor.LastTimestamp) {
		return false
	}
	_, exists := w.seen[id]
	return !exists
}

func (w *cursorWatermark) advance(ev Event) error {
	if !w.after(ev) {
		return nil
	}
	id := strings.TrimSpace(ev.EventID)
	t := ev.Timestamp.UTC()
	if w.cursor.LastTimestamp.IsZero() || t.After(w.cursor.LastTimestamp) {
		w.cursor.LastTimestamp = t
		w.cursor.LastEventID = id
		w.cursor.SeenEventIDs = []string{id}
		w.seen = map[string]struct{}{id: {}}
		return nil
	}
	if len(w.seen) >= maxCursorTimestampCohort {
		return fmt.Errorf("cursor timestamp %s exceeds bounded maximum of %d event IDs",
			w.cursor.LastTimestamp.Format(time.RFC3339Nano), maxCursorTimestampCohort)
	}
	w.seen[id] = struct{}{}
	w.cursor.SeenEventIDs = append(w.cursor.SeenEventIDs, id)
	w.cursor.LastEventID = id
	return nil
}

func (w *cursorWatermark) snapshot() Cursor {
	result := w.cursor
	result.SeenEventIDs = append([]string(nil), result.SeenEventIDs...)
	sort.Strings(result.SeenEventIDs)
	return result
}
