package api

import (
	"context"
	"errors"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/processing"
)

type processSummary struct {
	Inserted   int
	Duplicates int
	Failed     int
	FirstError error
	Results    []processing.ProcessRecordResult
}

// processEvents is the HTTP adapter boundary for the unified processor. Parsing
// and authentication remain route-specific; normalization, identity, detection,
// suppression, and persistence do not.
func (s *Server) processEvents(ctx context.Context, events []models.Event, origin, sensorID string) processSummary {
	summary := processSummary{Results: []processing.ProcessRecordResult{}}
	if len(events) == 0 {
		return summary
	}
	if s.Processor == nil {
		summary.Failed = len(events)
		summary.FirstError = errors.New("event processor is not available")
		return summary
	}

	receivedAt := time.Now().UTC()
	envelopes := make([]processing.IngressEnvelope, 0, len(events))
	for _, event := range events {
		envelopes = append(envelopes, processing.IngressEnvelope{
			Event: event, Origin: origin, SensorID: sensorID, ReceivedAt: receivedAt,
		})
	}
	summary.Results = s.Processor.ProcessBatch(ctx, envelopes)
	for _, result := range summary.Results {
		switch {
		case result.Err != nil:
			summary.Failed++
			if summary.FirstError == nil {
				summary.FirstError = result.Err
			}
		case result.Duplicate:
			summary.Duplicates++
		case result.Inserted:
			summary.Inserted++
		default:
			summary.Failed++
			if summary.FirstError == nil {
				summary.FirstError = errors.New("processor returned no disposition")
			}
		}
	}
	return summary
}
