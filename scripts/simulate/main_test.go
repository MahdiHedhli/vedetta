package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIngestPayloadIncludesStableReplayBoundary(t *testing.T) {
	observedAt := time.Date(2026, time.July, 13, 12, 30, 0, 0, time.UTC)
	payload := ingestPayload(SimEvent{
		EventID:    "synthetic-event-1",
		Timestamp:  observedAt,
		EventType:  "dns_query",
		Domain:     "example.test",
		ResolvedIP: "192.0.2.44",
	})

	if got := payload["event_id"]; got != "synthetic-event-1" {
		t.Fatalf("event_id = %v, want stable upstream identity", got)
	}
	if got, ok := payload["timestamp"].(time.Time); !ok || !got.Equal(observedAt) {
		t.Fatalf("timestamp = %#v, want %s", payload["timestamp"], observedAt)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decoded["event_id"] == "" || decoded["timestamp"] == "" {
		t.Fatalf("serialized payload lacks replay boundary: %s", encoded)
	}
}

func TestNewIngestRequestUsesConfiguredIngestCredential(t *testing.T) {
	req, err := newIngestRequest("http://localhost:8080/api/v1/ingest", []byte(`[]`), "  synthetic-token  ")
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer synthetic-token" {
		t.Fatalf("Authorization = %q, want bearer ingest credential", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}
