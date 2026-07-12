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
			SourceIP:  "192.0.2.25",
			ServerIP:  "192.0.2.53",
			Domain:    "example.com",
			QueryType: "A",
			Metadata:  `{"process":"curl"}`,
		},
		{
			EventID:    "response-1",
			Timestamp:  now.Add(50 * time.Millisecond),
			EventType:  "dns_query",
			SourceIP:   "192.0.2.25",
			ServerIP:   "192.0.2.53",
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
	// The response event survives, but query-side process context must be merged.
	if !strings.Contains(kept.Metadata, "dns_answers") || !strings.Contains(kept.Metadata, "process") {
		t.Fatalf("expected merged metadata with both keys, got %q", kept.Metadata)
	}
	if kept.ResolvedIP != "93.184.216.34" {
		t.Fatalf("expected ResolvedIP merged into kept event, got %+v", kept)
	}
}

func TestDeduplicateGatewayEchoes_PreservesDistinctClientsAndResolvers(t *testing.T) {
	now := time.Now().UTC()
	base := models.Event{Timestamp: now, EventType: "dns_query", Domain: "shared.example", QueryType: "A"}

	distinctClients := []models.Event{base, base}
	distinctClients[0].EventID, distinctClients[0].SourceIP, distinctClients[0].ServerIP = "client-a", "192.0.2.21", "192.0.2.53"
	distinctClients[1].EventID, distinctClients[1].SourceIP, distinctClients[1].ServerIP = "client-b", "192.0.2.22", "192.0.2.53"
	distinctClients[1].ResolvedIP = "198.51.100.20"
	if got := deduplicateGatewayEchoes(distinctClients); len(got) != 2 {
		t.Fatalf("distinct clients collapsed into %d events", len(got))
	}

	distinctResolvers := []models.Event{base, base}
	distinctResolvers[0].EventID, distinctResolvers[0].SourceIP, distinctResolvers[0].ServerIP = "resolver-a", "192.0.2.21", "192.0.2.53"
	distinctResolvers[1].EventID, distinctResolvers[1].SourceIP, distinctResolvers[1].ServerIP = "resolver-b", "192.0.2.21", "192.0.2.54"
	distinctResolvers[1].ResolvedIP = "198.51.100.20"
	if got := deduplicateGatewayEchoes(distinctResolvers); len(got) != 2 {
		t.Fatalf("distinct resolvers collapsed into %d events", len(got))
	}
}

func TestDeduplicateGatewayEchoes_PreservesRepeatedSameDirectionPackets(t *testing.T) {
	now := time.Now().UTC()
	base := models.Event{
		Timestamp: now, EventType: "dns_query", SourceIP: "192.0.2.21",
		ServerIP: "192.0.2.53", Domain: "repeat.example", QueryType: "A",
	}

	queries := []models.Event{base, base}
	queries[0].EventID, queries[1].EventID = "query-a", "query-b"
	if got := deduplicateGatewayEchoes(queries); len(got) != 2 {
		t.Fatalf("two query packets collapsed into %d events", len(got))
	}

	responses := []models.Event{base, base}
	responses[0].EventID, responses[1].EventID = "response-a", "response-b"
	responses[0].ResolvedIP = "198.51.100.20"
	responses[1].ResolvedIP = "198.51.100.20"
	if got := deduplicateGatewayEchoes(responses); len(got) != 2 {
		t.Fatalf("two response packets collapsed into %d events", len(got))
	}
}

func TestDeduplicateGatewayEchoes_ExplicitDirectionsPairAnswerlessResponse(t *testing.T) {
	now := time.Now().UTC()
	query := models.Event{
		EventID: "nxdomain-query", Timestamp: now, EventType: "dns_query",
		SourceIP: "192.0.2.25", ServerIP: "192.0.2.53", Domain: "missing.example", QueryType: "A",
		Metadata: `{"dns_direction":"query","process":"synthetic-resolver"}`,
	}
	response := models.Event{
		EventID: "nxdomain-response", Timestamp: now.Add(20 * time.Millisecond), EventType: "dns_query",
		SourceIP: "192.0.2.25", ServerIP: "192.0.2.53", Domain: "missing.example", QueryType: "A",
		Metadata: `{"dns_direction":"response","dns_response_code":"NXDOMAIN"}`,
	}
	got := deduplicateGatewayEchoes([]models.Event{query, response})
	if len(got) != 1 {
		t.Fatalf("explicit answerless query/response pair produced %d events", len(got))
	}
	if got[0].EventID != "nxdomain-response" {
		t.Fatalf("response did not survive answerless pairing: %+v", got[0])
	}
	for _, material := range []string{"dns_response_code", "NXDOMAIN", "process", "synthetic-resolver"} {
		if !strings.Contains(got[0].Metadata, material) {
			t.Fatalf("merged answerless response lost %q: %s", material, got[0].Metadata)
		}
	}
}

func TestDeduplicateGatewayEchoes_ExplicitSameDirectionNeverPairs(t *testing.T) {
	now := time.Now().UTC()
	base := models.Event{
		Timestamp: now, EventType: "dns_query", SourceIP: "192.0.2.26", ServerIP: "192.0.2.53",
		Domain: "repeat-explicit.example", QueryType: "A", ResolvedIP: "198.51.100.26",
		Metadata: `{"dns_direction":"response","dns_answers":["198.51.100.26"]}`,
	}
	a, b := base, base
	a.EventID = "explicit-response-a"
	b.EventID = "explicit-response-b"
	b.Timestamp = now.Add(10 * time.Millisecond)
	if got := deduplicateGatewayEchoes([]models.Event{a, b}); len(got) != 2 {
		t.Fatalf("same-direction explicit responses collapsed into %d events", len(got))
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
