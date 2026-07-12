package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func processedFixture(eventID, findingKey string, observedAt time.Time, score float64, blocked bool) ProcessedEventRecord {
	evidenceID := "evidence-" + eventID
	return ProcessedEventRecord{
		Event: models.Event{
			EventID: eventID, Timestamp: observedAt, EventType: "dns_query",
			SourceHash: "source-fixture", Domain: "badzone.example",
			Blocked: blocked, AnomalyScore: score, Tags: []string{"known_bad"}, Metadata: `{}`,
		},
		IdentityEvidence: json.RawMessage(`{}`),
		Origin:           "test",
		Disposition:      models.DispositionActive,
		Evidence: []models.DetectionEvidence{{
			EvidenceID: evidenceID, EventID: eventID, Detector: "threat_intelligence",
			Category: "command_and_control", ObservableType: "domain", ObservableValue: "badzone.example",
			ThreatSource: "fixture", SourceConfidence: score, Rationale: "fixture IOC",
			ScoreContribution: score, Outcome: map[bool]string{true: "blocked", false: "allowed"}[blocked],
			CreatedAt: observedAt,
		}},
		Findings: []models.FindingCandidate{{
			FindingKey: findingKey, FallbackIdentity: "source:fixture", Detector: "threat_intelligence",
			Category: "command_and_control", PrimaryObservableType: "domain", PrimaryObservable: "badzone.example",
			ObservedAt: observedAt, Score: score, Priority: priorityForScore(score), Blocked: blocked,
			Outcome: map[bool]string{true: "blocked", false: "allowed"}[blocked],
			Reason:  "fixture IOC", RecommendedAction: "isolate", Disposition: models.DispositionActive,
			EvidenceIDs: []string{evidenceID},
		}},
	}
}

func processedOutcomeFixture(eventID, findingKey string, observedAt time.Time, outcome string) ProcessedEventRecord {
	record := processedFixture(eventID, findingKey, observedAt, 0.7, outcome == "blocked")
	record.Event.Outcome = outcome
	record.Evidence[0].Outcome = outcome
	record.Findings[0].Outcome = outcome
	record.Findings[0].Blocked = outcome == "blocked"
	return record
}

func TestPersistProcessedEventDuplicateDoesNotIncrementFinding(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	record := processedFixture("event-1", "stable-key", time.Now().UTC(), 0.7, false)

	first, err := db.PersistProcessedEvent(ctx, record)
	if err != nil || !first.Inserted || first.Duplicate || len(first.FindingIDs) != 1 {
		t.Fatalf("first persist = %+v, err=%v", first, err)
	}
	second, err := db.PersistProcessedEvent(ctx, record)
	if err != nil || second.Inserted || !second.Duplicate {
		t.Fatalf("duplicate persist = %+v, err=%v", second, err)
	}

	finding, err := db.GetFinding(ctx, first.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if finding.OccurrenceCount != 1 || finding.AllowedCount != 1 || finding.BlockedCount != 0 {
		t.Fatalf("duplicate changed aggregate: %+v", finding)
	}
	var evidenceCount, eventCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM event_detection_evidence`).Scan(&evidenceCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&eventCount)
	if evidenceCount != 1 || eventCount != 1 {
		t.Fatalf("events=%d evidence=%d, want 1/1", eventCount, evidenceCount)
	}
}

func TestQueryFindingsCapsExpandedPrefixAtSafeBetaBound(t *testing.T) {
	db := testDB(t)
	result, err := db.QueryFindings(t.Context(), FindingQueryParams{
		ActiveOnly: true,
		Page:       1,
		Limit:      MaxFindingQueryLimit + 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Limit != MaxFindingQueryLimit || result.Page != 1 || result.Total != 0 || len(result.Findings) != 0 {
		t.Fatalf("bounded prefix = %+v, want page 1 limit %d", result, MaxFindingQueryLimit)
	}
}

func TestFindingUsesLatestEventTimeIdentityConfidence(t *testing.T) {
	db := testDB(t)
	now := time.Now().UTC()
	const deviceID = "asset-tentative"
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address)
		VALUES (?, ?, ?, ?, ?)`, deviceID, now, now, "192.0.2.90", "00:00:5E:00:53:90"); err != nil {
		t.Fatal(err)
	}
	record := processedFixture("event-tentative", "finding-tentative", now, 0.8, false)
	record.DeviceID = deviceID
	record.IdentityConfidence = 0.42
	record.IdentityReason = "unique_unscoped_address_binding"
	record.Findings[0].DeviceID = deviceID
	record.Findings[0].FallbackIdentity = ""
	result, err := db.PersistProcessedEvent(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := db.GetFinding(t.Context(), result.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if finding.IdentityConfidence != 0.42 || finding.IdentityReason != "unique_unscoped_address_binding" || !finding.NeedsIdentification {
		t.Fatalf("finding event-time identity = %+v", finding)
	}
}

func TestPersistProcessedEventAggregatesMaximumAndOutcome(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	first, err := db.PersistProcessedEvent(ctx, processedFixture("event-a", "aggregate-key", base, 0.4, true))
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.PersistProcessedEvent(ctx, processedFixture("event-b", "aggregate-key", base.Add(time.Minute), 0.9, false))
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingIDs[0] != second.FindingIDs[0] {
		t.Fatalf("related events created different findings: %v / %v", first.FindingIDs, second.FindingIDs)
	}
	finding, err := db.GetFinding(ctx, first.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if finding.OccurrenceCount != 2 || finding.MaximumScore != 0.9 || finding.CurrentPriority != models.PriorityCritical {
		t.Fatalf("bad aggregate: %+v", finding)
	}
	if finding.AllowedCount != 1 || finding.BlockedCount != 1 || finding.Outcome != "mixed" {
		t.Fatalf("bad outcome aggregate: %+v", finding)
	}
}

func TestPersistProcessedEventEveryMixedOutcomePairIsMixed(t *testing.T) {
	for _, pair := range [][2]string{{"allowed", "blocked"}, {"allowed", "observed"}, {"blocked", "observed"}} {
		t.Run(pair[0]+"_and_"+pair[1], func(t *testing.T) {
			db := testDB(t)
			base := time.Now().UTC().Add(-time.Hour)
			key := "mixed-" + pair[0] + "-" + pair[1]
			first, err := db.PersistProcessedEvent(t.Context(), processedOutcomeFixture("mixed-a-"+key, key, base, pair[0]))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.PersistProcessedEvent(t.Context(), processedOutcomeFixture("mixed-b-"+key, key, base.Add(time.Minute), pair[1])); err != nil {
				t.Fatal(err)
			}
			finding, err := db.GetFinding(t.Context(), first.FindingIDs[0])
			if err != nil {
				t.Fatal(err)
			}
			if finding.Outcome != "mixed" {
				t.Fatalf("%s + %s outcome = %q, want mixed: %+v", pair[0], pair[1], finding.Outcome, finding)
			}
		})
	}
}

func TestMixedOutcomeSurvivesResolvedEvidenceAndReopenPaths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		delayed    bool
		wantStatus models.FindingStatus
	}{
		{name: "resolved historical evidence", delayed: true, wantStatus: models.FindingStatusResolved},
		{name: "within-window recurrence", delayed: false, wantStatus: models.FindingStatusOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testDB(t)
			base := time.Now().UTC().Add(-2 * time.Hour)
			first, err := db.PersistProcessedEvent(t.Context(), processedOutcomeFixture("path-first-"+tc.name, "path-key-"+tc.name, base, "blocked"))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.UpdateFindingStatus(t.Context(), first.FindingIDs[0], models.FindingStatusResolved, "fixture closed", "tester"); err != nil {
				t.Fatal(err)
			}
			observedAt := base.Add(time.Hour)
			if tc.delayed {
				observedAt = base.Add(time.Minute)
			} else if _, err := db.Exec(`UPDATE findings SET resolved_at = ? WHERE finding_id = ?`, base.Add(30*time.Minute), first.FindingIDs[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := db.PersistProcessedEvent(t.Context(), processedOutcomeFixture("path-second-"+tc.name, "path-key-"+tc.name, observedAt, "observed")); err != nil {
				t.Fatal(err)
			}
			finding, err := db.GetFinding(t.Context(), first.FindingIDs[0])
			if err != nil {
				t.Fatal(err)
			}
			if finding.Outcome != "mixed" || finding.Status != tc.wantStatus {
				t.Fatalf("finding = %+v, want mixed/%s", finding, tc.wantStatus)
			}
		})
	}
}

func TestDelayedActiveEventDoesNotRegressCurrentFindingProjection(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	newer := processedFixture("projection-newer", "projection-key", now, 0.8, true)
	newer.Findings[0].Disposition = models.DispositionSuppressed
	newer.Findings[0].SuppressionRuleID = "newer-rule"
	created, err := db.PersistProcessedEvent(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	older := processedFixture("projection-older", "projection-key", now.Add(-time.Hour), 0.6, false)
	if _, err := db.PersistProcessedEvent(ctx, older); err != nil {
		t.Fatal(err)
	}
	finding, err := db.GetFinding(ctx, created.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !finding.LastSeen.Equal(now) || finding.LastEventID != "projection-newer" ||
		finding.Disposition != models.DispositionSuppressed || finding.SuppressionRuleID != "newer-rule" || finding.OccurrenceCount != 2 {
		t.Fatalf("delayed event regressed current projection: %+v", finding)
	}
}

func TestFindingRecurrenceReopensThenCreatesGeneration(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-20 * 24 * time.Hour)
	first, err := db.PersistProcessedEvent(ctx, processedFixture("recurrence-1", "recurrence-key", base, 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	firstID := first.FindingIDs[0]
	if err := db.UpdateFindingStatus(ctx, firstID, models.FindingStatusResolved, "contained", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET resolved_at = ? WHERE finding_id = ?`, base.Add(24*time.Hour), firstID); err != nil {
		t.Fatal(err)
	}

	within, err := db.PersistProcessedEvent(ctx, processedFixture("recurrence-2", "recurrence-key", base.Add(2*24*time.Hour), 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	if within.FindingIDs[0] != firstID {
		t.Fatalf("within-window recurrence created a new generation: %v", within.FindingIDs)
	}
	reopened, _ := db.GetFinding(ctx, firstID)
	if reopened.Status != models.FindingStatusOpen || reopened.OccurrenceCount != 2 || reopened.ResolvedAt != nil {
		t.Fatalf("finding was not reopened correctly: %+v", reopened)
	}
	if err := db.UpdateFindingStatus(ctx, firstID, models.FindingStatusResolved, "contained again", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET resolved_at = ? WHERE finding_id = ?`, base.Add(3*24*time.Hour), firstID); err != nil {
		t.Fatal(err)
	}

	after, err := db.PersistProcessedEvent(ctx, processedFixture("recurrence-3", "recurrence-key", base.Add(10*24*time.Hour), 0.8, true))
	if err != nil {
		t.Fatal(err)
	}
	if after.FindingIDs[0] == firstID {
		t.Fatal("recurrence after seven quiet days reused the old generation")
	}
	newFinding, err := db.GetFinding(ctx, after.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if newFinding.Generation != 2 || newFinding.PreviousFindingID != firstID {
		t.Fatalf("bad new generation: %+v", newFinding)
	}
}

func TestDelayedPreResolutionEventDoesNotReopenFinding(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-2 * time.Hour)
	first, err := db.PersistProcessedEvent(ctx, processedFixture("delayed-first", "delayed-key", base, 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	findingID := first.FindingIDs[0]
	if err := db.UpdateFindingStatus(ctx, findingID, models.FindingStatusResolved, "review complete", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PersistProcessedEvent(ctx, processedFixture("delayed-late-arrival", "delayed-key", base.Add(10*time.Minute), 0.8, true)); err != nil {
		t.Fatal(err)
	}
	finding, err := db.GetFinding(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != models.FindingStatusResolved || finding.OccurrenceCount != 2 || finding.Generation != 1 {
		t.Fatalf("delayed historical evidence reopened the incident: %+v", finding)
	}
	var generations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE finding_key = 'delayed-key'`).Scan(&generations); err != nil {
		t.Fatal(err)
	}
	if generations != 1 {
		t.Fatalf("delayed event created %d generations", generations)
	}
}

func TestDelayedEventTargetsHistoricalGenerationNotLatest(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-30 * 24 * time.Hour)
	first, err := db.PersistProcessedEvent(ctx, processedFixture("history-gen1", "history-key", base, 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	gen1 := first.FindingIDs[0]
	if err := db.UpdateFindingStatus(ctx, gen1, models.FindingStatusResolved, "closed one", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET resolved_at = ? WHERE finding_id = ?`, base.Add(time.Hour), gen1); err != nil {
		t.Fatal(err)
	}
	second, err := db.PersistProcessedEvent(ctx, processedFixture("history-gen2", "history-key", base.Add(10*24*time.Hour), 0.8, false))
	if err != nil {
		t.Fatal(err)
	}
	gen2 := second.FindingIDs[0]
	if gen2 == gen1 {
		t.Fatal("expected second generation")
	}
	if err := db.UpdateFindingStatus(ctx, gen2, models.FindingStatusResolved, "closed two", "tester"); err != nil {
		t.Fatal(err)
	}

	delayed, err := db.PersistProcessedEvent(ctx, processedFixture("history-delayed", "history-key", base.Add(30*time.Minute), 0.6, true))
	if err != nil || len(delayed.FindingIDs) != 1 || delayed.FindingIDs[0] != gen1 {
		t.Fatalf("delayed historical event linked to %+v err=%v, want gen1", delayed, err)
	}
	one, _ := db.GetFinding(ctx, gen1)
	two, _ := db.GetFinding(ctx, gen2)
	if one.OccurrenceCount != 2 || two.OccurrenceCount != 1 || two.FirstSeen.Before(base.Add(10*24*time.Hour)) {
		t.Fatalf("generation counts/timeline corrupted: gen1=%+v gen2=%+v", one, two)
	}
}

func TestDelayedEventAfterQuietBoundaryMovesNextGenerationFirstSeen(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-30 * 24 * time.Hour)
	first, err := db.PersistProcessedEvent(ctx, processedFixture("boundary-gen1", "boundary-key", base, 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	gen1 := first.FindingIDs[0]
	if err := db.UpdateFindingStatus(ctx, gen1, models.FindingStatusResolved, "closed", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET resolved_at = ? WHERE finding_id = ?`, base.Add(time.Hour), gen1); err != nil {
		t.Fatal(err)
	}
	second, err := db.PersistProcessedEvent(ctx, processedFixture("boundary-gen2", "boundary-key", base.Add(10*24*time.Hour), 0.8, false))
	if err != nil {
		t.Fatal(err)
	}
	gen2 := second.FindingIDs[0]
	if gen2 == gen1 {
		t.Fatal("expected second generation")
	}

	delayedAt := base.Add(8 * 24 * time.Hour)
	delayed, err := db.PersistProcessedEvent(ctx, processedFixture("boundary-delayed", "boundary-key", delayedAt, 0.6, true))
	if err != nil || len(delayed.FindingIDs) != 1 || delayed.FindingIDs[0] != gen2 {
		t.Fatalf("delayed recurrence linked to %+v err=%v, want gen2", delayed, err)
	}
	one, _ := db.GetFinding(ctx, gen1)
	two, _ := db.GetFinding(ctx, gen2)
	if one.OccurrenceCount != 1 || two.OccurrenceCount != 2 || !two.FirstSeen.Equal(delayedAt) {
		t.Fatalf("recurrence boundary corrupted generations: gen1=%+v gen2=%+v", one, two)
	}
}

func TestFindingSuppressionIsImmediateAuditedAndReversible(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	created, err := db.PersistProcessedEvent(ctx, processedFixture(
		"suppression-event", "suppression-key", time.Now().UTC(), 0.8, false))
	if err != nil {
		t.Fatal(err)
	}
	findingID := created.FindingIDs[0]
	if _, err := db.SuppressFinding(ctx, findingID, "", "tester"); err != ErrFindingSuppressionReasonRequired {
		t.Fatalf("empty reason error = %v", err)
	}
	rule, err := db.SuppressFinding(ctx, findingID, "Expected lab traffic", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Detector != "threat_intelligence" || rule.ObservableType != "domain" ||
		rule.ObservableValue != "badzone.example" || rule.FallbackIdentity != "source:fixture" || !rule.Active {
		t.Fatalf("typed rule = %+v", rule)
	}
	finding, err := db.GetFinding(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Disposition != models.DispositionSuppressed || finding.SuppressionRuleID != rule.RuleID ||
		finding.Status != models.FindingStatusOpen || finding.OccurrenceCount != 1 {
		t.Fatalf("suppression mutated incident/evidence state: %+v", finding)
	}

	affected, err := db.DeactivateFindingSuppression(ctx, rule.RuleID, "tester")
	if err != nil || affected != 1 {
		t.Fatalf("deactivate affected=%d err=%v", affected, err)
	}
	finding, _ = db.GetFinding(ctx, findingID)
	if finding.Disposition != models.DispositionActive || finding.SuppressionRuleID != "" || finding.OccurrenceCount != 1 {
		t.Fatalf("unsuppress mutated evidence or failed disposition: %+v", finding)
	}
	rules, err := db.ListFindingSuppressionRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Active {
		t.Fatalf("rules = %+v err=%v", rules, err)
	}
	var history, events, evidence int
	_ = db.QueryRow(`SELECT COUNT(*) FROM finding_suppression_history WHERE rule_id = ?`, rule.RuleID).Scan(&history)
	_ = db.QueryRow(`SELECT COUNT(*) FROM finding_events WHERE finding_id = ?`, findingID).Scan(&events)
	_ = db.QueryRow(`SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?`, findingID).Scan(&evidence)
	if history != 2 || events != 1 || evidence != 1 {
		t.Fatalf("audit/evidence counts history=%d events=%d evidence=%d", history, events, evidence)
	}
}

func TestPersistProcessedEventConcurrentSingleActiveFinding(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const workers = 20
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	base := time.Now().UTC()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := db.PersistProcessedEvent(context.Background(), processedFixture(
				"concurrent-"+string(rune('A'+i)), "concurrent-key", base.Add(time.Duration(i)*time.Second), 0.6, false))
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent persist: %v", err)
		}
	}
	var active, occurrences int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(occurrence_count), 0) FROM findings WHERE finding_key = ? AND status <> 'resolved'`, "concurrent-key").Scan(&active, &occurrences); err != nil {
		t.Fatal(err)
	}
	if active != 1 || occurrences != workers {
		t.Fatalf("active=%d occurrences=%d, want 1/%d", active, occurrences, workers)
	}
}

func TestProcessedEventRollsBackWhenEvidenceFails(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	seed := processedFixture("seed", "seed-key", time.Now().UTC(), 0.7, false)
	if _, err := db.PersistProcessedEvent(ctx, seed); err != nil {
		t.Fatal(err)
	}
	record := processedFixture("must-rollback", "rollback-key", time.Now().UTC(), 0.7, false)
	record.Evidence[0].EvidenceID = seed.Evidence[0].EvidenceID // primary-key violation after event insert
	if _, err := db.PersistProcessedEvent(ctx, record); err == nil {
		t.Fatal("expected evidence insert to fail")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_id = 'must-rollback'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("event survived a failed atomic evidence insert")
	}
}

func TestFindingEvidenceIsIsolatedAcrossMultiFindingEvent(t *testing.T) {
	db := testDB(t)
	now := time.Now().UTC()
	record := processedFixture("multi-finding-event", "domain-key", now, 0.8, false)
	record.Evidence = append(record.Evidence, models.DetectionEvidence{
		EvidenceID: "evidence-ip", EventID: record.Event.EventID, Detector: "threat_intelligence",
		Category: "command_and_control", ObservableType: "destination_ip", ObservableValue: "198.51.100.44",
		ThreatSource: "feodotracker", SourceConfidence: 0.9, ScoreContribution: 0.9,
		Rationale: "fixture IP IOC", Outcome: "allowed", CreatedAt: now,
	})
	record.Findings = append(record.Findings, models.FindingCandidate{
		FindingKey: "ip-key", FallbackIdentity: "source:fixture", Detector: "threat_intelligence",
		Category: "command_and_control", PrimaryObservableType: "destination_ip", PrimaryObservable: "198.51.100.44",
		ObservedAt: now, Score: 0.9, Priority: models.PriorityCritical, Reason: "fixture IP IOC",
		RecommendedAction: "isolate", Disposition: models.DispositionActive, EvidenceIDs: []string{"evidence-ip"},
	})
	result, err := db.PersistProcessedEvent(context.Background(), record)
	if err != nil || len(result.FindingIDs) != 2 {
		t.Fatalf("persist = %+v err=%v", result, err)
	}
	for _, findingID := range result.FindingIDs {
		finding, err := db.GetFinding(context.Background(), findingID)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := db.FindingEvidence(context.Background(), findingID)
		if err != nil || len(evidence) != 1 {
			t.Fatalf("finding %s evidence=%+v err=%v", findingID, evidence, err)
		}
		if evidence[0].ObservableType != finding.PrimaryObservableType || evidence[0].ObservableValue != finding.PrimaryObservable {
			t.Fatalf("finding %s received unrelated evidence: finding=%+v evidence=%+v", findingID, finding, evidence)
		}
	}
}

func TestRetentionPreservesEventsSupportingDurableFindings(t *testing.T) {
	db := testDB(t)
	old := time.Now().UTC().Add(-120 * 24 * time.Hour)
	result, err := db.PersistProcessedEvent(context.Background(), processedFixture("retained-finding-event", "retained-key", old, 0.8, false))
	if err != nil || len(result.FindingIDs) != 1 {
		t.Fatalf("persist finding event = %+v err=%v", result, err)
	}
	if _, err := db.InsertEvents([]models.Event{{
		EventID: "ordinary-old-event", Timestamp: old, EventType: "dns_query", SourceHash: "ordinary", Metadata: `{}`,
	}}); err != nil {
		t.Fatal(err)
	}
	deleted, err := db.DeleteEventsOlderThan(time.Now().UTC().Add(-90 * 24 * time.Hour))
	if err != nil || deleted != 1 {
		t.Fatalf("retention deleted=%d err=%v, want only ordinary event", deleted, err)
	}
	evidence, err := db.FindingEvidence(context.Background(), result.FindingIDs[0])
	if err != nil || len(evidence) != 1 {
		t.Fatalf("durable finding lost evidence: %+v err=%v", evidence, err)
	}
	var retained int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_id = 'retained-finding-event'`).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("supporting event retained=%d err=%v", retained, err)
	}
}

func TestResolveRequiresReasonAndDoesNotMutateEvent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	result, err := db.PersistProcessedEvent(ctx, processedFixture("immutable-event", "lifecycle-key", time.Now().UTC(), 0.7, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateFindingStatus(ctx, result.FindingIDs[0], models.FindingStatusResolved, "", "tester"); err != ErrResolutionReasonRequired {
		t.Fatalf("missing reason error = %v", err)
	}
	if err := db.UpdateFindingStatus(ctx, result.FindingIDs[0], models.FindingStatusResolved, "reviewed", "tester"); err != nil {
		t.Fatal(err)
	}
	var acknowledged bool
	var ackReason string
	if err := db.QueryRow(`SELECT acknowledged, COALESCE(ack_reason, '') FROM events WHERE event_id = 'immutable-event'`).Scan(&acknowledged, &ackReason); err != nil {
		t.Fatal(err)
	}
	if acknowledged || ackReason != "" {
		t.Fatalf("finding lifecycle mutated event: acknowledged=%v reason=%q", acknowledged, ackReason)
	}
}

func TestFindingReadsFollowReversibleDeviceRedirect(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"device-source", "device-target"} {
		if _, err := db.Exec(`INSERT INTO devices
			(device_id, first_seen, last_seen, ip_address, mac_address, segment)
			VALUES (?, ?, ?, ?, ?, 'default')`, id, now, now, "192.0.2.10", "00:00:5E:00:53:01"); err != nil {
			t.Fatal(err)
		}
	}
	record := processedFixture("redirect-event", "redirect-finding", now, 0.8, false)
	record.DeviceID = "device-source"
	record.Findings[0].DeviceID = "device-source"
	created, err := db.PersistProcessedEvent(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	findingID := created.FindingIDs[0]
	if _, err := db.Exec(`UPDATE devices SET merged_into_device_id = ? WHERE device_id = ?`, "device-target", "device-source"); err != nil {
		t.Fatal(err)
	}
	// Future processor events use the canonical target in their finding key. The
	// store must aggregate them into the already-open source-family finding.
	afterMerge := processedFixture("redirect-event-after-merge", "different-target-key", now.Add(time.Minute), 0.9, true)
	afterMerge.DeviceID = "device-target"
	afterMerge.Findings[0].DeviceID = "device-target"
	afterMergeResult, err := db.PersistProcessedEvent(ctx, afterMerge)
	if err != nil || len(afterMergeResult.FindingIDs) != 1 || afterMergeResult.FindingIDs[0] != findingID {
		t.Fatalf("canonical event duplicated merged finding: %+v err=%v", afterMergeResult, err)
	}

	finding, err := db.GetFinding(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.DeviceID != "device-source" || finding.CanonicalDeviceID != "device-target" {
		t.Fatalf("detail did not preserve raw/canonical identity: %+v", finding)
	}
	list, err := db.QueryFindings(ctx, FindingQueryParams{DeviceID: "device-target"})
	if err != nil || list.Total != 1 || list.Findings[0].DeviceID != "device-source" || list.Findings[0].CanonicalDeviceID != "device-target" {
		t.Fatalf("canonical target filter = %+v, err=%v", list, err)
	}
	sourceList, err := db.QueryFindings(ctx, FindingQueryParams{DeviceID: "device-source"})
	if err != nil || sourceList.Total != 0 {
		t.Fatalf("hidden source filter returned %+v, err=%v", sourceList, err)
	}
	events, err := db.FindingSupportingEvents(ctx, findingID, 10, 0)
	if err != nil || len(events) != 2 ||
		events[0].DeviceID != "device-target" || events[0].CanonicalDeviceID != "device-target" ||
		events[1].DeviceID != "device-source" || events[1].CanonicalDeviceID != "device-target" {
		t.Fatalf("supporting event canonical device = %+v, err=%v", events, err)
	}
	var rawFindingDevice, rawEventDevice string
	if err := db.QueryRow(`SELECT device_id FROM findings WHERE finding_id = ?`, findingID).Scan(&rawFindingDevice); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT device_id FROM events WHERE event_id = 'redirect-event'`).Scan(&rawEventDevice); err != nil {
		t.Fatal(err)
	}
	if rawFindingDevice != "device-source" || rawEventDevice != "device-source" {
		t.Fatalf("read projection rewrote history: finding=%q event=%q", rawFindingDevice, rawEventDevice)
	}

	// Recursive projection: A -> B -> C must filter, count, and navigate as C.
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, segment)
		VALUES ('device-final', ?, ?, '192.0.2.12', '00:00:5E:00:53:03', 'default')`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE devices SET merged_into_device_id = 'device-final' WHERE device_id = 'device-target'`); err != nil {
		t.Fatal(err)
	}
	finding, err = db.GetFinding(ctx, findingID)
	if err != nil || finding.DeviceID != "device-source" || finding.CanonicalDeviceID != "device-final" || finding.OccurrenceCount != 2 {
		t.Fatalf("recursive finding projection = %+v err=%v", finding, err)
	}
	finalList, err := db.QueryFindings(ctx, FindingQueryParams{DeviceID: "device-final"})
	if err != nil || finalList.Total != 1 {
		t.Fatalf("recursive canonical filter = %+v err=%v", finalList, err)
	}
	stats, err := db.GetFindingStats(ctx, 7*24*time.Hour)
	if err != nil || stats.AffectedDevices != 1 {
		t.Fatalf("recursive affected-device count = %+v err=%v", stats, err)
	}

	// Beta split is exact merge undo: clearing the redirect restores the source
	// everywhere without rewriting historical event/finding rows.
	if _, err := db.Exec(`UPDATE devices SET merged_into_device_id = NULL WHERE device_id = ?`, "device-source"); err != nil {
		t.Fatal(err)
	}
	finding, err = db.GetFinding(ctx, findingID)
	if err != nil || finding.DeviceID != "device-source" || finding.CanonicalDeviceID != "device-source" {
		t.Fatalf("split did not restore source projection: %+v, err=%v", finding, err)
	}
}
