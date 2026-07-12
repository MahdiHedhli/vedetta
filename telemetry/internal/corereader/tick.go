package corereader

import (
	"context"
	"fmt"
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
// read cap is hit. The request page size is constant for the whole traversal so
// Core's offset pagination cannot overlap or skip rows when the final remaining
// output capacity is smaller than a page. The watermark tracks every ID at its
// inclusive timestamp across those pages. On any Core or watermark error the
// caller receives no result and therefore leaves the durable cursor unchanged.
func (c *Client) Read(ctx context.Context, cur Cursor, readCap int) (*ReadResult, error) {
	res := &ReadResult{NewCursor: cur}
	if readCap <= 0 {
		return res, nil
	}
	watermark, err := newCursorWatermark(cur)
	if err != nil {
		return nil, fmt.Errorf("load cursor watermark: %w", err)
	}
	res.NewCursor = watermark.snapshot()
	limit := pageSize
	if readCap < limit {
		limit = readCap
	}
	page := 1
	for len(res.Events) < readCap {
		fp, err := c.FetchPage(ctx, cur.LastTimestamp, page, limit)
		if err != nil {
			return nil, err
		}
		res.SkippedMalformed += fp.SkippedMalformed
		if fp.Received == 0 {
			break
		}
		for _, ev := range fp.Events {
			if !watermark.after(ev) {
				continue // already processed (inclusive timestamp cohort)
			}
			if err := watermark.advance(ev); err != nil {
				return nil, fmt.Errorf("advance cursor watermark: %w", err)
			}
			res.Events = append(res.Events, ev)
			res.CursorAdvanced = true
			if len(res.Events) >= readCap {
				break
			}
		}
		// If the server returned fewer than we asked for, we've drained.
		// Use the raw record count: malformed records still occupy page slots.
		if fp.Received < limit {
			break
		}
		page++
	}
	res.NewCursor = watermark.snapshot()
	return res, nil
}

// TimeNow is overridable in tests.
var TimeNow = func() time.Time { return time.Now().UTC() }
