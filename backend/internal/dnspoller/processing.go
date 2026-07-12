package dnspoller

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/processing"
)

func processPollerEvents(ctx context.Context, processor *processing.Processor, events []models.Event, origin string) (inserted, duplicates, findingEvents int, err error) {
	if processor == nil {
		return 0, 0, 0, errors.New("event processor is not available")
	}
	sortPollerEventsOldestFirst(events)
	now := time.Now().UTC()
	envelopes := make([]processing.IngressEnvelope, 0, len(events))
	for _, event := range events {
		envelopes = append(envelopes, processing.IngressEnvelope{Event: event, Origin: origin, ReceivedAt: now})
	}
	for _, result := range processor.ProcessBatch(ctx, envelopes) {
		if result.Err != nil {
			if err == nil {
				err = result.Err
			}
			continue
		}
		if result.Duplicate {
			duplicates++
		} else if result.Inserted {
			inserted++
		} else if err == nil {
			err = errors.New("processor returned no disposition")
		}
		if len(result.FindingIDs) > 0 {
			findingEvents++
		}
	}
	return inserted, duplicates, findingEvents, err
}

// Poller APIs return newest-first snapshots. Stateful detectors (especially
// beacon intervals and public->private rebinding) require observation order, so
// normalize every adapter batch before it enters the unified processor. Stable
// sorting preserves upstream occurrence ordinals among equal timestamps.
func sortPollerEventsOldestFirst(events []models.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}
