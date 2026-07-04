package corereader

import (
	"context"
	"time"
)

// ReadResult is the outcome of one tick's read from Core.
type ReadResult struct {
	Events           []Event
	NewCursor        Cursor
	CursorAdvanced   bool
	SkippedMalformed int
}

// pageSize is the per-request page limit (Core caps at 500).
const pageSize = 500

// Read pulls new events since the cursor, paging until drained or the per-tick
// read cap is hit. It filters events already at/behind the cursor (tie-breaker)
// and advances the cursor only across events it actually returns — the caller is
// expected to persist NewCursor after fully processing the returned events
// (at-least-once). On any Core error the cursor is left unchanged so the tick
// can be retried next interval with no data loss.
func (c *Client) Read(ctx context.Context, cur Cursor, readCap int) (*ReadResult, error) {
	res := &ReadResult{NewCursor: cur}
	page := 1
	for len(res.Events) < readCap {
		limit := pageSize
		if remaining := readCap - len(res.Events); remaining < limit {
			limit = remaining
		}
		fp, err := c.FetchPage(ctx, cur.LastTimestamp, page, limit)
		if err != nil {
			return nil, err
		}
		res.SkippedMalformed += fp.SkippedMalformed
		if len(fp.Events) == 0 {
			break
		}
		for _, ev := range fp.Events {
			if !cur.After(ev) {
				continue // already processed (tie-breaker / inclusive from)
			}
			res.Events = append(res.Events, ev)
			res.NewCursor = res.NewCursor.Advance(ev)
			res.CursorAdvanced = true
			if len(res.Events) >= readCap {
				break
			}
		}
		// If the server returned fewer than we asked for, we've drained.
		if len(fp.Events) < limit {
			break
		}
		page++
	}
	return res, nil
}

// TimeNow is overridable in tests.
var TimeNow = func() time.Time { return time.Now().UTC() }
