package dnspoller

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/processing"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func TestAdGuardQueryToEventPreservesEveryAnswer(t *testing.T) {
	poller := &AdGuardPoller{}
	event := poller.adguardQueryToEvent(AdGuardQuery{
		Time:     time.Unix(1_700_000_000, 0),
		Client:   "192.0.2.10",
		Question: AdGuardQuestion{Name: "lookup.example", Type: "A"},
		Answer: []AdGuardAnswer{
			{Type: "CNAME", Value: "edge.example"},
			{Type: "A", Value: "198.51.100.66"},
		},
		OriginalAnswer: []AdGuardAnswer{{Type: "A", Value: "203.0.113.7"}},
		Reason:         "FilteredBlackList",
		Rules:          []AdGuardRule{{FilterListID: 42, Text: "synthetic-rule"}},
	})
	if event == nil {
		t.Fatal("expected event")
	}
	if event.ResolvedIP != "edge.example" {
		t.Fatalf("legacy resolved_ip = %q", event.ResolvedIP)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	want := []any{"edge.example", "198.51.100.66"}
	if got := metadata["dns_answers"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("dns_answers = %#v, want %#v", got, want)
	}
	if got := metadata["dns_original_answers"]; !reflect.DeepEqual(got, []any{"203.0.113.7"}) {
		t.Fatalf("dns_original_answers = %#v", got)
	}
}

func TestPiHoleQueryToEventPreservesCNAMEAndResponseContext(t *testing.T) {
	poller := &Poller{}
	event := poller.piHoleQueryToEvent(PiHoleQuery{
		Timestamp:   1_700_000_000,
		QueryType:   "A",
		Domain:      "lookup.example",
		ClientIP:    "192.0.2.11",
		Status:      4,
		ReplyType:   5,
		ReplyTime:   12,
		CNAMETarget: "edge.example",
		RegexID:     "synthetic-rule",
	})
	if event == nil {
		t.Fatal("expected event")
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if got := metadata["dns_answers"]; !reflect.DeepEqual(got, []any{"edge.example"}) {
		t.Fatalf("dns_answers = %#v", got)
	}
	if metadata["pihole_regex_id"] != "synthetic-rule" {
		t.Fatalf("regex evidence missing: %#v", metadata)
	}
}

func TestPiHoleQueryToEventUsesReplayStableDistinctIDs(t *testing.T) {
	poller := &Poller{}
	query := PiHoleQuery{
		Timestamp: 1_700_000_000, QueryType: "A", Domain: "Replay.Example.", ClientIP: "192.0.2.11",
		Status: 2, DNSSEC: 1, ReplyType: 4, ReplyTime: 12, CNAMETarget: "Edge.Example.",
	}
	first := poller.piHoleQueryToEvent(query)
	second := poller.piHoleQueryToEvent(query)
	if first.EventID != second.EventID {
		t.Fatalf("Pi-hole replay IDs differ: %q != %q", first.EventID, second.EventID)
	}
	query.ReplyTime++
	if changed := poller.piHoleQueryToEvent(query); changed.EventID == first.EventID {
		t.Fatal("distinct Pi-hole upstream material collided")
	}
}

func TestPiHoleOccurrenceOrdinalPreservesIdenticalSameTimestampQueries(t *testing.T) {
	query := PiHoleQuery{
		Timestamp: 1_700_000_000, QueryType: "A", Domain: "duplicate.example",
		ClientIP: "192.0.2.11", Status: 2, ReplyType: 4, ReplyTime: 12,
	}
	firstSnapshot := []PiHoleQuery{query, query}
	secondSnapshot := []PiHoleQuery{query, query}
	assignPiHoleOccurrences(firstSnapshot)
	assignPiHoleOccurrences(secondSnapshot)
	if piHoleEventID(firstSnapshot[0]) == piHoleEventID(firstSnapshot[1]) {
		t.Fatal("identical same-timestamp Pi-hole occurrences collided")
	}
	for index := range firstSnapshot {
		if piHoleEventID(firstSnapshot[index]) != piHoleEventID(secondSnapshot[index]) {
			t.Fatalf("occurrence %d was not replay-stable", index)
		}
	}
}

func TestAdGuardQueryToEventUsesReplayStableNormalizedIDs(t *testing.T) {
	poller := &AdGuardPoller{}
	query := AdGuardQuery{
		Time: time.Unix(1_700_000_000, 123).UTC(), Client: "192.0.2.10", ClientID: "client-1",
		Question: AdGuardQuestion{Name: "Replay.Example.", Type: "a", Class: "in"},
		Answer: []AdGuardAnswer{
			{Type: "CNAME", Value: "Edge.Example.", TTL: 30},
			{Type: "A", Value: "198.51.100.66", TTL: 30},
		},
		Rules: []AdGuardRule{{FilterListID: 2, Text: "rule-b"}, {FilterListID: 1, Text: "rule-a"}}, Reason: "Processed", FilterID: 7,
	}
	first := poller.adguardQueryToEvent(query)
	query.Answer[0], query.Answer[1] = query.Answer[1], query.Answer[0]
	query.Rules[0], query.Rules[1] = query.Rules[1], query.Rules[0]
	second := poller.adguardQueryToEvent(query)
	if first.EventID != second.EventID {
		t.Fatalf("normalized AdGuard replay IDs differ: %q != %q", first.EventID, second.EventID)
	}
	query.FilterID++
	if changed := poller.adguardQueryToEvent(query); changed.EventID == first.EventID {
		t.Fatal("distinct AdGuard upstream material collided")
	}
}

func TestAdGuardOccurrenceOrdinalPreservesIdenticalSameTimestampQueries(t *testing.T) {
	query := AdGuardQuery{
		Time: time.Unix(1_700_000_000, 123).UTC(), Client: "192.0.2.10",
		Question: AdGuardQuestion{Name: "duplicate.example", Type: "A", Class: "IN"},
	}
	first, second := query, query
	second.Occurrence = 1
	if adGuardEventID(first) == adGuardEventID(second) {
		t.Fatal("identical same-timestamp AdGuard occurrences collided")
	}
	if adGuardEventID(first) != adGuardEventID(query) {
		t.Fatal("AdGuard occurrence zero was not replay-stable")
	}
}

func TestPollerEventsAreStableSortedOldestFirst(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	events := []models.Event{
		{EventID: "newest", Timestamp: base.Add(2 * time.Second)},
		{EventID: "tie-first", Timestamp: base.Add(time.Second)},
		{EventID: "oldest", Timestamp: base},
		{EventID: "tie-second", Timestamp: base.Add(time.Second)},
	}
	sortPollerEventsOldestFirst(events)
	want := []string{"oldest", "tie-first", "tie-second", "newest"}
	for index, event := range events {
		if event.EventID != want[index] {
			t.Fatalf("order[%d]=%q, want %q; events=%+v", index, event.EventID, want[index], events)
		}
	}
}

func TestProcessPollerEventsFeedsStatefulDetectorsChronologically(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "poller-order.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	enricher := dnsintel.NewEnricher(nil)
	enricher.SetAdvancedDNSHuntingProfile(dnsintel.AdvancedDNSHuntingProfile{Enabled: true, Rebinding: true})
	processor := processing.NewProcessor(db, enricher)
	base := time.Now().UTC().Add(-time.Minute)

	// AdGuard and Pi-hole commonly return newest-first. If that order reached the
	// rebinding detector, private->public would hide the public->private change.
	events := []models.Event{
		{EventID: "private-later", Timestamp: base.Add(time.Second), EventType: "dns_query", SourceHash: "stable", Domain: "ordering.example", ResolvedIP: "192.168.1.20"},
		{EventID: "public-earlier", Timestamp: base, EventType: "dns_query", SourceHash: "stable", Domain: "ordering.example", ResolvedIP: "198.51.100.20"},
	}
	inserted, duplicates, _, err := processPollerEvents(context.Background(), processor, events, "adguard")
	if err != nil || inserted != 2 || duplicates != 0 {
		t.Fatalf("process result inserted=%d duplicates=%d err=%v", inserted, duplicates, err)
	}
	result, err := db.QueryEvents(store.EventQueryParams{Domain: "ordering.example"})
	if err != nil || result.Total != 2 {
		t.Fatalf("query events total=%d err=%v", result.Total, err)
	}
	for _, event := range result.Events {
		if event.EventID == "private-later" {
			for _, tag := range event.Tags {
				if tag == "dns_rebinding" {
					return
				}
			}
			t.Fatalf("private event missed chronological rebinding detection: %+v", event)
		}
	}
	t.Fatal("private event not persisted")
}

func TestAdGuardWatermarkUsesOnlyCommittedUpstreamTimeAndOverlapsBoundary(t *testing.T) {
	watermark := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

	// A no-new snapshot must retain the upstream watermark. Advancing it to the
	// later Core wall clock would skip the next skewed/snapshot-race record.
	latestAdvance := watermark.Add(time.Hour)
	selected, next := adGuardQueriesSince([]AdGuardQuery{{Time: watermark.Add(-time.Second)}}, watermark, latestAdvance)
	if len(selected) != 0 || !next.Equal(watermark) {
		t.Fatalf("old-only snapshot selected=%d next=%s, want 0/%s", len(selected), next, watermark)
	}

	betweenSnapshotAndCoreNow := AdGuardQuery{Time: watermark.Add(time.Second)}
	selected, next = adGuardQueriesSince([]AdGuardQuery{betweenSnapshotAndCoreNow}, next, latestAdvance)
	if len(selected) != 1 || !next.Equal(betweenSnapshotAndCoreNow.Time) {
		t.Fatalf("record after upstream watermark was skipped: selected=%d next=%s", len(selected), next)
	}

	// Include the boundary because distinct AdGuard rows can share a timestamp;
	// deterministic event IDs make replaying an already-seen row a safe no-op.
	selected, next = adGuardQueriesSince([]AdGuardQuery{{Time: next}}, next, latestAdvance)
	if len(selected) != 1 || !next.Equal(betweenSnapshotAndCoreNow.Time) {
		t.Fatalf("watermark boundary was not overlapped: selected=%d next=%s", len(selected), next)
	}

	// A broken upstream clock must not strand the cursor. The record is still
	// selected for clamped persistence, but it cannot advance the watermark.
	future := AdGuardQuery{Time: watermark.Add(24 * time.Hour)}
	selected, afterFuture := adGuardQueriesSince([]AdGuardQuery{future}, next, latestAdvance)
	if len(selected) != 1 || !afterFuture.Equal(next) {
		t.Fatalf("future record poisoned watermark: selected=%d next=%s", len(selected), afterFuture)
	}
}
