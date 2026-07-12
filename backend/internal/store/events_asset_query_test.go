package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func insertEventQueryDevice(t *testing.T, db *DB, deviceID, ipAddress, macAddress string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address)
		VALUES (?, ?, ?, ?, ?)`, deviceID, now, now, ipAddress, macAddress); err != nil {
		t.Fatalf("insert device %s: %v", deviceID, err)
	}
}

func TestProcessedPassiveOutcomeRoundTrip(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	const deviceA = "asset-outcome-a"
	insertEventQueryDevice(t, db, deviceA, "192.0.2.10", "00:00:5E:00:53:10")
	now := time.Now().UTC()
	evidenceID := "evidence-passive-observed"

	result, err := db.PersistProcessedEvent(ctx, ProcessedEventRecord{
		Event: models.Event{
			EventID: "event-passive-observed", Timestamp: now, EventType: "dns_query",
			SourceHash: "source-passive", Domain: "passive.example", Outcome: "observed",
			Tags: []string{"known_bad"}, Metadata: `{}`,
		},
		DeviceID:           deviceA,
		IdentityConfidence: 0.95,
		IdentityReason:     "stable evidence",
		IdentityEvidence:   json.RawMessage(`{}`),
		Origin:             "sensor_dns",
		Disposition:        models.DispositionActive,
		Evidence: []models.DetectionEvidence{{
			EvidenceID: evidenceID, Detector: "threat_intelligence", Category: "command_and_control",
			ObservableType: "domain", ObservableValue: "passive.example", ThreatSource: "test",
			SourceConfidence: 0.9, Rationale: "test IOC", ScoreContribution: 0.8,
			Outcome: "observed", CreatedAt: now,
		}},
		Findings: []models.FindingCandidate{{
			FindingKey: "passive-observed-key", DeviceID: deviceA, Detector: "threat_intelligence",
			Category: "command_and_control", PrimaryObservableType: "domain", PrimaryObservable: "passive.example",
			ObservedAt: now, Score: 0.8, Priority: models.PriorityHigh, Outcome: "observed",
			Reason: "test IOC", RecommendedAction: "investigate", Disposition: models.DispositionActive,
			EvidenceIDs: []string{evidenceID},
		}},
	})
	if err != nil || !result.Inserted || len(result.FindingIDs) != 1 {
		t.Fatalf("PersistProcessedEvent = %+v, err=%v", result, err)
	}

	page, err := db.QueryEvents(EventQueryParams{DeviceID: deviceA})
	if err != nil || page.Total != 1 || len(page.Events) != 1 {
		t.Fatalf("QueryEvents = %+v, err=%v", page, err)
	}
	if event := page.Events[0]; event.Outcome != "observed" || event.DeviceID != deviceA || event.CanonicalDeviceID != deviceA {
		t.Fatalf("event projection = %+v, want observed/raw A/canonical A", event)
	}

	merge, err := db.MergeDevices(ctx, deviceA, insertMergeTarget(t, db), "same test asset", "test-admin")
	if err != nil {
		t.Fatalf("merge devices: %v", err)
	}
	supporting, err := db.FindingSupportingEvents(ctx, result.FindingIDs[0], 10, 0)
	if err != nil || len(supporting) != 1 {
		t.Fatalf("FindingSupportingEvents = %+v, err=%v", supporting, err)
	}
	if event := supporting[0]; event.Outcome != "observed" || event.DeviceID != deviceA || event.CanonicalDeviceID != merge.TargetDeviceID {
		t.Fatalf("supporting event projection = %+v, want observed/raw A/canonical target", event)
	}
}

func insertMergeTarget(t *testing.T, db *DB) string {
	t.Helper()
	const deviceB = "asset-outcome-b"
	insertEventQueryDevice(t, db, deviceB, "192.0.2.11", "00:00:5E:00:53:11")
	return deviceB
}

func TestQueryEventsCanonicalDeviceFilterAndUndo(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	const (
		deviceA = "asset-query-a"
		deviceB = "asset-query-b"
	)
	insertEventQueryDevice(t, db, deviceA, "192.0.2.20", "00:00:5E:00:53:20")
	insertEventQueryDevice(t, db, deviceB, "192.0.2.21", "00:00:5E:00:53:21")

	inserted, err := db.InsertEvents([]models.Event{{
		EventID: "event-query-merge", Timestamp: time.Now().UTC(), EventType: "firewall_log",
		SourceHash: "source-query", DeviceID: deviceA, Origin: "collector", Outcome: "allowed",
	}})
	if err != nil || inserted != 1 {
		t.Fatalf("InsertEvents inserted=%d err=%v", inserted, err)
	}

	before, err := db.QueryEvents(EventQueryParams{})
	if err != nil || before.Total != 1 || len(before.Events) != 1 {
		t.Fatalf("direct QueryEvents before merge = %+v, err=%v", before, err)
	}
	if event := before.Events[0]; event.DeviceID != deviceA || event.CanonicalDeviceID != deviceA || event.Outcome != "allowed" {
		t.Fatalf("before merge = %+v, want raw/canonical A and allowed", event)
	}

	merge, err := db.MergeDevices(ctx, deviceA, deviceB, "same test asset", "test-admin")
	if err != nil {
		t.Fatalf("merge devices: %v", err)
	}
	after, err := db.QueryEvents(EventQueryParams{DeviceID: deviceB})
	if err != nil || after.Total != 1 || len(after.Events) != 1 {
		t.Fatalf("QueryEvents(device B) = %+v, err=%v", after, err)
	}
	if event := after.Events[0]; event.DeviceID != deviceA || event.CanonicalDeviceID != deviceB {
		t.Fatalf("after merge = %+v, want raw A/canonical B", event)
	}
	oldID, err := db.QueryEvents(EventQueryParams{DeviceID: deviceA})
	if err != nil || oldID.Total != 0 {
		t.Fatalf("QueryEvents(old device A) = %+v, err=%v; want no canonical matches", oldID, err)
	}
	direct, err := db.QueryEvents(EventQueryParams{})
	if err != nil || direct.Total != 1 || direct.Events[0].DeviceID != deviceA || direct.Events[0].CanonicalDeviceID != deviceB {
		t.Fatalf("direct QueryEvents after merge = %+v, err=%v", direct, err)
	}

	if _, err := db.UndoDeviceMerge(ctx, merge.ActionID, "incorrect merge", "test-admin"); err != nil {
		t.Fatalf("undo merge: %v", err)
	}
	restored, err := db.QueryEvents(EventQueryParams{DeviceID: deviceA})
	if err != nil || restored.Total != 1 || len(restored.Events) != 1 {
		t.Fatalf("QueryEvents(device A) after undo = %+v, err=%v", restored, err)
	}
	if event := restored.Events[0]; event.DeviceID != deviceA || event.CanonicalDeviceID != deviceA {
		t.Fatalf("after undo = %+v, want raw/canonical A", event)
	}
	noLongerTarget, err := db.QueryEvents(EventQueryParams{DeviceID: deviceB})
	if err != nil || noLongerTarget.Total != 0 {
		t.Fatalf("QueryEvents(device B) after undo = %+v, err=%v", noLongerTarget, err)
	}
	direct, err = db.QueryEvents(EventQueryParams{})
	if err != nil || direct.Total != 1 || direct.Events[0].DeviceID != deviceA || direct.Events[0].CanonicalDeviceID != deviceA {
		t.Fatalf("direct QueryEvents after undo = %+v, err=%v", direct, err)
	}
}

func TestQueryEventsPaginationIsStableForEqualTimestamps(t *testing.T) {
	db := testDB(t)
	observedAt := time.Unix(1_700_000_000, 0).UTC()
	events := []models.Event{}
	for _, id := range []string{"event-page-a", "event-page-b", "event-page-c"} {
		events = append(events, models.Event{
			EventID: id, Timestamp: observedAt, EventType: "dns_query", SourceHash: "source-page",
		})
	}
	if inserted, err := db.InsertEvents(events); err != nil || inserted != 3 {
		t.Fatalf("InsertEvents inserted=%d err=%v", inserted, err)
	}

	first, err := db.QueryEvents(EventQueryParams{Sort: "timestamp", Order: "desc", Page: 1, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.QueryEvents(EventQueryParams{Sort: "timestamp", Order: "desc", Page: 2, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || len(second.Events) != 1 ||
		first.Events[0].EventID != "event-page-c" || first.Events[1].EventID != "event-page-b" ||
		second.Events[0].EventID != "event-page-a" {
		t.Fatalf("unstable equal-timestamp pages: first=%v second=%v", eventIDs(first.Events), eventIDs(second.Events))
	}
}

func eventIDs(events []models.Event) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
}
