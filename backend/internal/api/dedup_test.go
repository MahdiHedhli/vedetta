package api

import (
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// The sensor emits an event for both the query packet and the response packet of
// the same DNS lookup. deduplicateGatewayEchoes collapses them (same domain +
// query type, same client SourceIP, within 2s). The survivor must be the
// answer-bearing (response) event — or at least end up carrying its answers —
// regardless of ordering.
func TestDeduplicateGatewayEchoes_KeepsAnswerBearingEvent(t *testing.T) {
	now := time.Now().UTC()

	queryEvt := models.Event{
		EventID:   "query-1",
		Timestamp: now,
		EventType: "dns_query",
		SourceIP:  "192.168.1.25",
		ServerIP:  "192.168.1.53",
		Domain:    "example.com",
		QueryType: "A",
	}
	responseEvt := models.Event{
		EventID:    "response-1",
		Timestamp:  now.Add(50 * time.Millisecond),
		EventType:  "dns_query",
		SourceIP:   "192.168.1.25",
		ServerIP:   "192.168.1.53",
		Domain:     "example.com",
		QueryType:  "A",
		ResolvedIP: "93.184.216.34",
		Metadata:   `{"dns_answers":["93.184.216.34"]}`,
	}

	orderings := map[string][]models.Event{
		"query_first":    {queryEvt, responseEvt},
		"response_first": {responseEvt, queryEvt},
	}

	for name, events := range orderings {
		t.Run(name, func(t *testing.T) {
			result := deduplicateGatewayEchoes(events)
			if len(result) != 1 {
				t.Fatalf("expected query+response pair collapsed to 1 event, got %d", len(result))
			}
			kept := result[0]
			if kept.ResolvedIP != "93.184.216.34" {
				t.Fatalf("kept event lost ResolvedIP: %+v", kept)
			}
			if !strings.Contains(kept.Metadata, "dns_answers") {
				t.Fatalf("kept event lost dns_answers metadata: %q", kept.Metadata)
			}
			if kept.ServerIP == "" {
				t.Fatalf("kept event lost ServerIP: %+v", kept)
			}
		})
	}
}

// When the client IP looks like a gateway (.1/.254 heuristic), all events in the
// group are classified as gateway echoes. The survivor must still be the
// answer-bearing event, not blindly the first one.
func TestDeduplicateGatewayEchoes_GatewayClientPrefersAnswers(t *testing.T) {
	now := time.Now().UTC()

	events := []models.Event{
		{
			EventID:   "query-1",
			Timestamp: now,
			EventType: "dns_query",
			SourceIP:  "192.168.1.1",
			Domain:    "example.com",
			QueryType: "A",
		},
		{
			EventID:    "response-1",
			Timestamp:  now.Add(50 * time.Millisecond),
			EventType:  "dns_query",
			SourceIP:   "192.168.1.1",
			Domain:     "example.com",
			QueryType:  "A",
			ResolvedIP: "93.184.216.34",
			Metadata:   `{"dns_answers":["93.184.216.34"]}`,
		},
	}

	result := deduplicateGatewayEchoes(events)
	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	if result[0].ResolvedIP != "93.184.216.34" {
		t.Fatalf("expected answer-bearing event to survive, got %+v", result[0])
	}
}

// Metadata from a discarded duplicate must be merged into the kept event when
// the kept event has other metadata keys (e.g. process) but no answers.
func TestDeduplicateGatewayEchoes_MergesMetadataKeys(t *testing.T) {
	now := time.Now().UTC()

	events := []models.Event{
		{
			EventID:   "query-1",
			Timestamp: now,
			EventType: "dns_query",
			SourceIP:  "192.168.1.25",
			Domain:    "example.com",
			QueryType: "A",
			Metadata:  `{"process":"curl"}`,
		},
		{
			EventID:    "response-1",
			Timestamp:  now.Add(50 * time.Millisecond),
			EventType:  "dns_query",
			SourceIP:   "192.168.1.1",
			Domain:     "example.com",
			QueryType:  "A",
			ResolvedIP: "93.184.216.34",
			Metadata:   `{"dns_answers":["93.184.216.34"]}`,
		},
	}

	result := deduplicateGatewayEchoes(events)
	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	kept := result[0]
	// Non-gateway event (query-1) is kept, but response answers must be merged in.
	if !strings.Contains(kept.Metadata, "dns_answers") || !strings.Contains(kept.Metadata, "process") {
		t.Fatalf("expected merged metadata with both keys, got %q", kept.Metadata)
	}
	if kept.ResolvedIP != "93.184.216.34" {
		t.Fatalf("expected ResolvedIP merged into kept event, got %+v", kept)
	}
}

// Events outside the 2-second window must not be collapsed.
func TestDeduplicateGatewayEchoes_OutsideWindowKeepsAll(t *testing.T) {
	now := time.Now().UTC()

	events := []models.Event{
		{
			EventID:   "a",
			Timestamp: now,
			EventType: "dns_query",
			SourceIP:  "192.168.1.25",
			Domain:    "example.com",
			QueryType: "A",
		},
		{
			EventID:   "b",
			Timestamp: now.Add(10 * time.Second),
			EventType: "dns_query",
			SourceIP:  "192.168.1.25",
			Domain:    "example.com",
			QueryType: "A",
		},
	}

	result := deduplicateGatewayEchoes(events)
	if len(result) != 2 {
		t.Fatalf("expected 2 events outside dedup window, got %d", len(result))
	}
}
