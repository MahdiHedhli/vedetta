package processing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

func TestRecommendedActionDoesNotClaimAggregateEnforcementOutcome(t *testing.T) {
	action := recommendedAction(models.DetectionEvidence{Detector: "threat_intelligence"})
	if strings.Contains(strings.ToLower(action), "was blocked") || strings.Contains(strings.ToLower(action), "was allowed") {
		t.Fatalf("per-event enforcement leaked into durable finding action: %q", action)
	}
}

func TestNewProcessorNormalizesTypedNilDependencies(t *testing.T) {
	var typedNil *dnsintel.Enricher
	processor := NewProcessor(nil, typedNil)
	if processor.enricher != nil || processor.threats != nil {
		t.Fatalf("typed nil dependencies survived: enricher=%v threats=%v", processor.enricher, processor.threats)
	}
	processor = NewProcessor(nil, dnsintel.NewEnricher(nil))
	if processor.threats != nil {
		t.Fatalf("typed nil ThreatDB survived: %v", processor.threats)
	}
}

type captureStore struct {
	records []store.ProcessedEventRecord
	result  store.PersistProcessedResult
	err     error
}

func (s *captureStore) ProcessedEventExists(context.Context, string) (bool, error) {
	return false, nil
}

func (s *captureStore) PersistProcessedEvent(_ context.Context, record store.ProcessedEventRecord) (store.PersistProcessedResult, error) {
	s.records = append(s.records, record)
	result := s.result
	result.EventID = record.Event.EventID
	if result.FindingIDs == nil {
		for _, finding := range record.Findings {
			result.FindingIDs = append(result.FindingIDs, finding.FindingKey)
		}
	}
	if !result.Duplicate {
		result.Inserted = true
	}
	return result, s.err
}

type statefulTestStore struct {
	mu              sync.Mutex
	persisted       map[string]bool
	records         []store.ProcessedEventRecord
	failures        map[string]int
	blockEventID    string
	persistEntered  chan struct{}
	persistRelease  chan struct{}
	persistEnterOne sync.Once
}

func newStatefulTestStore() *statefulTestStore {
	return &statefulTestStore{persisted: map[string]bool{}, failures: map[string]int{}}
}

func (s *statefulTestStore) ProcessedEventExists(_ context.Context, eventID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persisted[eventID], nil
}

func (s *statefulTestStore) PersistProcessedEvent(ctx context.Context, record store.ProcessedEventRecord) (store.PersistProcessedResult, error) {
	if record.Event.EventID == s.blockEventID && s.persistEntered != nil && s.persistRelease != nil {
		s.persistEnterOne.Do(func() { close(s.persistEntered) })
		select {
		case <-s.persistRelease:
		case <-ctx.Done():
			return store.PersistProcessedResult{EventID: record.Event.EventID}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persisted[record.Event.EventID] {
		return store.PersistProcessedResult{EventID: record.Event.EventID, Duplicate: true}, nil
	}
	if s.failures[record.Event.EventID] > 0 {
		s.failures[record.Event.EventID]--
		return store.PersistProcessedResult{EventID: record.Event.EventID}, errors.New("synthetic persistence failure")
	}
	s.persisted[record.Event.EventID] = true
	s.records = append(s.records, record)
	return store.PersistProcessedResult{EventID: record.Event.EventID, Inserted: true}, nil
}

func (s *statefulTestStore) record(eventID string) (store.ProcessedEventRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Event.EventID == eventID {
			return record, true
		}
	}
	return store.ProcessedEventRecord{}, false
}

type countingEnricher struct{ calls atomic.Int64 }

func (e *countingEnricher) Enrich(*models.Event) { e.calls.Add(1) }

func TestConcurrentExactReplayMutatesDetectorOnce(t *testing.T) {
	db := newStatefulTestStore()
	enricher := &countingEnricher{}
	processor := newProcessorWithStore(db, enricher)
	event := models.Event{EventID: "concurrent-replay", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "stable", Domain: "replay.example"}

	const workers = 32
	results := make(chan ProcessRecordResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: "sensor_dns"}})[0]
		}()
	}
	wg.Wait()
	close(results)
	inserted, duplicates := 0, 0
	for result := range results {
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if result.Inserted {
			inserted++
		}
		if result.Duplicate {
			duplicates++
		}
	}
	if inserted != 1 || duplicates != workers-1 || enricher.calls.Load() != 1 {
		t.Fatalf("inserted=%d duplicates=%d enrich_calls=%d", inserted, duplicates, enricher.calls.Load())
	}
}

func TestFailedPersistenceDoesNotConsumeRebindingOrFirewallFirstSeen(t *testing.T) {
	now := time.Now().UTC()
	t.Run("rebinding", func(t *testing.T) {
		db := newStatefulTestStore()
		db.failures["private"] = 1
		enricher := dnsintel.NewEnricher(nil)
		enricher.SetAdvancedDNSHuntingProfile(dnsintel.AdvancedDNSHuntingProfile{Enabled: true, Rebinding: true})
		processor := newProcessorWithStore(db, enricher, WithClock(func() time.Time { return now }))
		public := models.Event{EventID: "public", Timestamp: now, EventType: "dns_query", SourceHash: "stable", Domain: "rebind.example", ResolvedIP: "198.51.100.20"}
		if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: public, Origin: "sensor_dns"}})[0]; result.Err != nil || !result.Inserted {
			t.Fatalf("seed public result = %+v", result)
		}
		private := models.Event{EventID: "private", Timestamp: now.Add(time.Second), EventType: "dns_query", SourceHash: "stable", Domain: "rebind.example", ResolvedIP: "192.168.1.20"}
		if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: private, Origin: "sensor_dns"}})[0]; result.Err == nil {
			t.Fatal("synthetic failed persistence unexpectedly succeeded")
		}
		if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: private, Origin: "sensor_dns"}})[0]; result.Err != nil || !result.Inserted {
			t.Fatalf("retry result = %+v", result)
		}
		record, ok := db.record("private")
		if !ok || !hasAnyTag(record.Event.Tags, "dns_rebinding") {
			t.Fatalf("failed attempt consumed rebinding transition: %+v", record.Event)
		}
	})

	t.Run("firewall_first_seen", func(t *testing.T) {
		db := newStatefulTestStore()
		db.failures["firewall"] = 1
		processor := newProcessorWithStore(db, dnsintel.NewEnricher(nil), WithClock(func() time.Time { return now }))
		event := models.Event{EventID: "firewall", Timestamp: now, EventType: "firewall_log", SourceHash: "stable", SourceIP: "192.0.2.10", Blocked: true,
			Metadata: `{"action":"block","direction":"out","dst_ip":"203.0.113.10","rule":"synthetic"}`}
		if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: "collector"}})[0]; result.Err == nil {
			t.Fatal("synthetic failed persistence unexpectedly succeeded")
		}
		if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: "collector"}})[0]; result.Err != nil || !result.Inserted {
			t.Fatalf("retry result = %+v", result)
		}
		record, ok := db.record("firewall")
		if !ok || !hasAnyTag(record.Event.Tags, "new_fw_block") {
			t.Fatalf("failed attempt consumed first-seen transition: %+v", record.Event)
		}
	})
}

func TestFailedEventRollbackCannotOverwriteConcurrentDistinctCommit(t *testing.T) {
	now := time.Now().UTC()
	db := newStatefulTestStore()
	db.failures["failed-first"] = 1
	db.blockEventID = "failed-first"
	db.persistEntered = make(chan struct{})
	db.persistRelease = make(chan struct{})
	processor := newProcessorWithStore(db, dnsintel.NewEnricher(nil), WithClock(func() time.Time { return now }))
	makeEvent := func(id string, offset time.Duration) models.Event {
		return models.Event{EventID: id, Timestamp: now.Add(offset), EventType: "firewall_log", SourceHash: "stable", SourceIP: "192.0.2.10", Blocked: true,
			Metadata: `{"action":"block","direction":"out","dst_ip":"203.0.113.10","rule":"shared-tuple"}`}
	}

	failedResult := make(chan ProcessRecordResult, 1)
	go func() {
		failedResult <- processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: makeEvent("failed-first", 0), Origin: "collector"}})[0]
	}()
	<-db.persistEntered
	distinctResult := make(chan ProcessRecordResult, 1)
	go func() {
		distinctResult <- processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: makeEvent("distinct-commit", time.Second), Origin: "collector"}})[0]
	}()
	close(db.persistRelease)
	if result := <-failedResult; result.Err == nil {
		t.Fatalf("failed event result = %+v", result)
	}
	if result := <-distinctResult; result.Err != nil || !result.Inserted {
		t.Fatalf("distinct event result = %+v", result)
	}
	distinct, ok := db.record("distinct-commit")
	if !ok || !hasAnyTag(distinct.Event.Tags, "new_fw_block") {
		t.Fatalf("distinct commit did not retain first-seen state: %+v", distinct.Event)
	}

	if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: makeEvent("failed-first", 2*time.Second), Origin: "collector"}})[0]; result.Err != nil || !result.Inserted {
		t.Fatalf("retry failed event = %+v", result)
	}
	retry, ok := db.record("failed-first")
	if !ok || hasAnyTag(retry.Event.Tags, "new_fw_block") {
		t.Fatalf("rollback overwrote the concurrent distinct commit: %+v", retry.Event)
	}
}

type lookupMap map[string]threatintel.LookupResult

func (m lookupMap) Lookup(value string) threatintel.LookupResult { return m[value] }

type multiLookup struct {
	values map[string][]threatintel.LookupResult
}

func (m multiLookup) Lookup(value string) threatintel.LookupResult {
	if values := m.values[value]; len(values) > 0 {
		return values[0]
	}
	return threatintel.LookupResult{}
}

func (m multiLookup) LookupAll(value string) []threatintel.LookupResult {
	return append([]threatintel.LookupResult(nil), m.values[value]...)
}

type overwriteEnricher struct{}

func (overwriteEnricher) Enrich(event *models.Event) {
	// Models the legacy DNS behavior that overwrites Metadata. Strong TI found by
	// the processor must survive this and caller source metadata must be restored.
	event.Metadata = `{"detections":{"dga":{"score":0.4}}}`
	event.Tags = []string{"dga_candidate"}
	event.AnomalyScore = 0.4
}

func TestCommunityReasonsCannotForgeCoreHeuristicFinding(t *testing.T) {
	now := time.Now().UTC()
	community := &threatintel.Indicator{
		Value: "ordinary.badzone.example", Type: "domain", Source: "vedetta-community", Confidence: 0.95,
		Tags:     []string{"indicator_scope:exact", "dga_candidate", "tunneling_candidate", "beaconing_candidate"},
		LastSeen: now, TTLHours: 24,
	}
	store := &captureStore{}
	lookup := multiLookup{values: map[string][]threatintel.LookupResult{
		"ordinary.badzone.example": {{Found: true, Indicator: community, Confidence: 0.95}},
	}}
	processor := newProcessorWithStore(store, dnsintel.NewEnricher(nil),
		WithThreatLookup(lookup), WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "community-reason-forgery", Timestamp: now, EventType: "dns_query",
		SourceHash: "stable", Domain: "ordinary.badzone.example",
	}}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(store.records) != 1 || len(store.records[0].Findings) != 0 {
		t.Fatalf("community reasons created actionable findings: %+v", store.records)
	}
	for _, item := range store.records[0].Evidence {
		if item.Detector != "threat_intelligence" {
			t.Fatalf("community reason became Core detector evidence: %+v", store.records[0].Evidence)
		}
	}
}

func TestCommunityReasonCannotEraseGenuineCoreHeuristicFinding(t *testing.T) {
	now := time.Now().UTC()
	community := &threatintel.Indicator{
		Value: "asdfjklqwerty.com", Type: "domain", Source: "vedetta-community", Confidence: 0.95,
		Tags:     []string{"indicator_scope:exact", "dga_candidate"},
		LastSeen: now, TTLHours: 24,
	}
	db := &captureStore{}
	lookup := multiLookup{values: map[string][]threatintel.LookupResult{
		"asdfjklqwerty.com": {{Found: true, Indicator: community, Confidence: 0.95}},
	}}
	enricher := dnsintel.NewEnricher(nil)
	enricher.SetAdvancedDNSHuntingProfile(dnsintel.AdvancedDNSHuntingProfile{Enabled: true, DGANXDomain: true})
	// Isolate the community-vs-Core evidence contract from the burst threshold;
	// dedicated dnsintel tests cover the production five-domain correlation.
	enricher.NXDomainBurst.MinDistinctDomains = 1
	processor := newProcessorWithStore(db, enricher,
		WithThreatLookup(lookup), WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "community-reason-collision", Timestamp: now, EventType: "dns_query",
		SourceHash: "stable", Domain: "asdfjklqwerty.com",
		Metadata: `{"dns_direction":"response","dns_response_code":"NXDOMAIN"}`,
	}}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(db.records) != 1 || len(db.records[0].Findings) != 1 || db.records[0].Findings[0].Detector != "dga" {
		t.Fatalf("feed reason erased genuine DGA finding: %+v", db.records)
	}
	for _, item := range db.records[0].Evidence {
		if item.Detector == "dga" {
			return
		}
	}
	t.Fatalf("genuine DGA evidence missing: %+v", db.records[0].Evidence)
}

func TestExtractObservablesIncludesAllAnswersAndFirewallFields(t *testing.T) {
	event := models.Event{
		Domain: "Example.COM.", ResolvedIP: "192.0.2.10",
		Metadata: `{"dns_answers":["192.0.2.10","198.51.100.44","Alias.Example."],"dst_ip":"203.0.113.9","dst_port":8443,"protocol":"TCP","url":"HTTPS://Example.COM/path"}`,
	}
	values := ExtractObservables(event)
	want := map[string]bool{
		"domain\x00example.com":           true,
		"destination_ip\x00192.0.2.10":    true,
		"destination_ip\x00198.51.100.44": true,
		"cname\x00alias.example":          true,
		"destination_ip\x00203.0.113.9":   true,
		"destination_port\x008443":        true,
		"protocol\x00tcp":                 true,
		"url\x00https://example.com/path": true,
	}
	for _, value := range values {
		delete(want, value.Type+"\x00"+value.Value)
	}
	if len(want) != 0 {
		t.Fatalf("missing observables: %v; got %+v", want, values)
	}
}

func TestProcessorChecksEveryDNSAnswerAndPreservesSourceMetadata(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	indicator := &threatintel.Indicator{
		Value: "198.51.100.44", Type: "ipv4", Source: "feodotracker", Confidence: 0.9,
		Tags: []string{"c2"}, FirstSeen: now.Add(-24 * time.Hour), LastSeen: now, TTLHours: 24,
	}
	db := &captureStore{}
	processor := newProcessorWithStore(db, overwriteEnricher{},
		WithThreatLookup(lookupMap{"198.51.100.44": {Found: true, Indicator: indicator, Confidence: 0.9}}),
		WithClock(func() time.Time { return now }),
		WithSourceHasher(SourceHasherFunc(func(context.Context, string) (string, error) { return "core-hmac", nil })),
		WithIdentityResolver(IdentityResolverFunc(func(context.Context, models.Event, IdentityContext) (IdentityResolution, error) {
			return IdentityResolution{DeviceID: "device-1", Confidence: 0.9, Reason: "temporal_address", Evidence: json.RawMessage(`{"binding":"test"}`)}, nil
		})),
	)
	results := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{
			EventID: "all-answers", Timestamp: now, EventType: "dns_query", SourceHash: "forged",
			SourceIP: "192.0.2.20", Domain: "ordinary.example",
			ResolvedIP: "192.0.2.30", Metadata: `{"dns_answers":["192.0.2.30","198.51.100.44"],"process":"browser","_vedetta":{"forged":true}}`,
		},
		Origin: "sensor_dns", SensorID: "sensor-1", ReceivedAt: now,
		SourceMeta: map[string]any{"transport": "etw"},
	}})
	if len(results) != 1 || results[0].Err != nil || !results[0].Inserted {
		t.Fatalf("result = %+v", results)
	}
	if len(db.records) != 1 {
		t.Fatalf("persisted %d records", len(db.records))
	}
	record := db.records[0]
	if record.Event.SourceHash != "core-hmac" {
		t.Fatalf("Core did not replace caller hash: %q", record.Event.SourceHash)
	}
	if record.Event.AnomalyScore != 0.9 || !hasAnyTag(record.Event.Tags, "known_bad") {
		t.Fatalf("strong IOC was lost around enricher: %+v", record.Event)
	}
	matched := false
	for _, evidence := range record.Evidence {
		if evidence.Detector == "threat_intelligence" && evidence.ObservableValue == "198.51.100.44" && evidence.ThreatSource == "feodotracker" && evidence.SourceConfidence == 0.9 {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("second DNS answer did not produce typed TI evidence: %+v", record.Evidence)
	}
	if len(record.Findings) < 2 { // one IOC plus deterministic DGA from the fake enricher
		t.Fatalf("expected IOC and DGA findings, got %+v", record.Findings)
	}
	meta := decodeObject(record.Event.Metadata)
	if meta["process"] != "browser" {
		t.Fatalf("source metadata was replaced: %s", record.Event.Metadata)
	}
	core := mapValue(meta["_vedetta"])
	source := mapValue(core["source"])
	if source["transport"] != "etw" || source["caller_reserved_namespace"] == nil {
		t.Fatalf("namespaced source metadata incomplete: %s", record.Event.Metadata)
	}
}

func TestProcessorSuppressionChangesDispositionNotEvidence(t *testing.T) {
	now := time.Now().UTC()
	indicator := &threatintel.Indicator{Value: "bad.example", Type: "domain", Source: "urlhaus", Confidence: 0.8, LastSeen: now, TTLHours: 24}
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil,
		WithThreatLookup(lookupMap{"bad.example": {Found: true, Indicator: indicator, Confidence: 0.8}}),
		WithSuppressionEvaluator(SuppressionEvaluatorFunc(func(context.Context, SuppressionInput) (SuppressionDecision, error) {
			return SuppressionDecision{Suppressed: true, RuleID: "rule-1", Reason: "operator policy"}, nil
		})),
		WithClock(func() time.Time { return now }),
	)
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "suppressed", Timestamp: now, EventType: "dns_query", SourceHash: "stable", Domain: "bad.example",
	}}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if record.Disposition != models.DispositionSuppressed || record.SuppressionRuleID != "rule-1" {
		t.Fatalf("bad disposition: %+v", record)
	}
	if len(record.Evidence) != 1 || len(record.Findings) != 1 || record.Findings[0].Disposition != models.DispositionSuppressed {
		t.Fatalf("suppression erased evidence/finding: evidence=%+v findings=%+v", record.Evidence, record.Findings)
	}
}

func TestTypedSuppressionIsScopedToMatchingFinding(t *testing.T) {
	now := time.Now().UTC()
	indicator := &threatintel.Indicator{
		Value: "bad.example", Type: "domain", Source: "urlhaus", Confidence: 0.85,
		Tags: []string{"malware_distribution"}, LastSeen: now, TTLHours: 24,
	}
	db := &captureStore{}
	processor := newProcessorWithStore(db, overwriteEnricher{},
		WithThreatLookup(lookupMap{"bad.example": {Found: true, Indicator: indicator, Confidence: 0.85}}),
		WithSuppressionEvaluator(SuppressionEvaluatorFunc(func(_ context.Context, input SuppressionInput) (SuppressionDecision, error) {
			decision := SuppressionDecision{Evidence: map[string]SuppressionMatch{}}
			for _, item := range input.Evidence {
				if item.Detector == "dga" {
					decision.Evidence[item.EvidenceID] = SuppressionMatch{RuleID: "suppress-dga", Reason: "known test generator"}
				}
			}
			return decision, nil
		})),
		WithClock(func() time.Time { return now }),
	)
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "scoped-suppression", Timestamp: now, EventType: "dns_query", SourceHash: "stable", Domain: "bad.example",
	}}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(db.records) != 1 || len(db.records[0].Findings) != 2 {
		t.Fatalf("findings = %+v", db.records)
	}
	for _, finding := range db.records[0].Findings {
		switch finding.Detector {
		case "dga":
			if finding.Disposition != models.DispositionSuppressed || finding.SuppressionRuleID != "suppress-dga" {
				t.Fatalf("DGA finding not suppressed: %+v", finding)
			}
		case "threat_intelligence":
			if finding.Disposition != models.DispositionActive {
				t.Fatalf("unrelated IOC inherited suppression: %+v", finding)
			}
		}
	}
	if db.records[0].Disposition != models.DispositionActive {
		t.Fatalf("mixed event disposition = %q, want active", db.records[0].Disposition)
	}
}

func TestCommunityEvidenceRequiresCorroboration(t *testing.T) {
	evidence := []models.DetectionEvidence{{Detector: "threat_intelligence", ThreatSource: "vedetta-community", ScoreContribution: 0.9}}
	markFindingEligibility(evidence)
	if evidence[0].CreatesFinding {
		t.Fatal("community-only advisory evidence created a finding")
	}
	evidence = append(evidence, models.DetectionEvidence{Detector: "dga", ScoreContribution: 0.4})
	markFindingEligibility(evidence)
	if evidence[0].CreatesFinding || !evidence[1].CreatesFinding {
		t.Fatalf("community evidence drove priority instead of remaining corroboration: %+v", evidence)
	}
}

func TestIngressOutcomeDoesNotTreatMissingBlockedAsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		event    models.Event
		envelope IngressEnvelope
		want     string
	}{
		{name: "passive sensor query", event: models.Event{EventType: "dns_query"}, envelope: IngressEnvelope{Origin: "sensor_dns"}, want: "observed"},
		{name: "generic collector query", event: models.Event{EventType: "dns_query"}, envelope: IngressEnvelope{Origin: "collector"}, want: "observed"},
		{name: "pihole explicit pass", event: models.Event{EventType: "dns_query"}, envelope: IngressEnvelope{Origin: "pihole"}, want: "allowed"},
		{name: "adguard explicit block", event: models.Event{EventType: "dns_query", Blocked: true}, envelope: IngressEnvelope{Origin: "adguard"}, want: "blocked"},
		{name: "firewall allow", event: models.Event{EventType: "firewall_log", Metadata: `{"action":"allow"}`}, envelope: IngressEnvelope{Origin: "unifi_rest"}, want: "allowed"},
		{name: "firewall unknown", event: models.Event{EventType: "firewall_log", Metadata: `{}`}, envelope: IngressEnvelope{Origin: "collector"}, want: "observed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveIngressOutcome(tt.event, tt.envelope); got != tt.want {
				t.Fatalf("outcome = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCommunityETLDMatchesObservedSubdomainWithoutBroadeningExactFeeds(t *testing.T) {
	now := time.Now().UTC()
	community := &threatintel.Indicator{
		Value: "badzone.example", Type: "domain", Source: "vedetta-community", Confidence: 0.9,
		Tags: []string{"indicator_scope:etld_plus_one", "cross_reporter_match"}, LastSeen: now, TTLHours: 24,
	}
	curatedExact := &threatintel.Indicator{
		Value: "otherzone.example", Type: "domain", Source: "urlhaus", Confidence: 0.9,
		Tags: []string{"malware_distribution"}, LastSeen: now, TTLHours: 24,
	}
	lookup := multiLookup{values: map[string][]threatintel.LookupResult{
		"badzone.example":   {{Found: true, Indicator: community, Confidence: 0.9}},
		"otherzone.example": {{Found: true, Indicator: curatedExact, Confidence: 0.9}},
	}}

	communityEvidence := threatIntelEvidence(lookup, models.Event{EventID: "community-subdomain"},
		[]models.Observable{{Type: ObservableDomain, Value: "c2.badzone.example"}}, now)
	if len(communityEvidence) != 1 || communityEvidence[0].ObservableValue != "c2.badzone.example" {
		t.Fatalf("eTLD+1 community match = %+v", communityEvidence)
	}
	curatedEvidence := threatIntelEvidence(lookup, models.Event{EventID: "exact-subdomain"},
		[]models.Observable{{Type: ObservableDomain, Value: "c2.otherzone.example"}}, now)
	if len(curatedEvidence) != 0 {
		t.Fatalf("exact-domain feed was incorrectly broadened to subtree: %+v", curatedEvidence)
	}
}

func TestUnknownUnresolvedEventsDoNotCollapse(t *testing.T) {
	envelope := IngressEnvelope{Origin: "collector"}
	one, _ := findingIdentity(models.Event{EventID: "one", SourceHash: "unknown"}, IdentityResolution{}, envelope)
	two, _ := findingIdentity(models.Event{EventID: "two", SourceHash: "unknown"}, IdentityResolution{}, envelope)
	if one == two {
		t.Fatalf("unknown unresolved events shared identity %q", one)
	}
}

func TestProcessorClampsFutureTimestampBeforeFindingAndPersistence(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil, WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{EventID: "future", EventType: "dns_query", SourceHash: "stable",
			Timestamp: now.Add(24 * time.Hour), Domain: "fixture.example"},
		Origin: "test", ReceivedAt: now,
	}})[0]
	if result.Err != nil || len(db.records) != 1 {
		t.Fatalf("process result=%+v records=%d", result, len(db.records))
	}
	if !db.records[0].Event.Timestamp.Equal(now) {
		t.Fatalf("future timestamp survived processor: %s", db.records[0].Event.Timestamp)
	}
}

func TestProcessorRejectsForgedCoreDetectorAndContextTags(t *testing.T) {
	now := time.Now().UTC()
	owned := []string{
		"known_bad", "c2", "dga", "dga_candidate", "dns_tunnel", "beaconing",
		"dns_rebinding", "dns_bypass", "ips", "new_fw_block", "whitelisted",
		"known_good_context", "vedetta_self", "new_device", "very_new_device", "iot_context",
		"eol_router", "known_exploited", "risky_device_fw_block", "fw:block", "dir:out",
	}
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil, WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{
			EventID: "forged-tags", EventType: "dns_query", Timestamp: now, SourceHash: "stable",
			Domain: "ordinary.example", Tags: append(owned, "operator:keep"), AnomalyScore: 1,
			DeviceVendor: "Forged Vendor", ThreatDesc: "forged rationale",
			MatchedIndicator: "forged.example", MatchType: "domain",
			DeviceID: "forged-device", IdentityConfidence: 1, IdentityReason: "forged",
			IdentityEvidence: `{"forged":true}`, Origin: "forged-origin", SensorID: "forged-sensor",
			Disposition: "suppressed", SuppressionRuleID: "forged-rule",
			Metadata: `{"threat_db":{"confidence":1,"indicator":"forged.example","source":"urlhaus"}}`,
		},
		Origin: "collector", ReceivedAt: now,
	}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if len(record.Evidence) != 0 || len(record.Findings) != 0 || record.Event.AnomalyScore != 0 {
		t.Fatalf("forged verdict survived: event=%+v evidence=%+v findings=%+v", record.Event, record.Evidence, record.Findings)
	}
	for _, tag := range owned {
		if hasAnyTag(record.Event.Tags, tag) {
			t.Fatalf("Core-owned tag %q survived: %v", tag, record.Event.Tags)
		}
	}
	if !hasAnyTag(record.Event.Tags, "operator:keep") || record.Event.DeviceVendor != "" || record.Event.ThreatDesc != "" || record.Event.MatchType != "" ||
		record.Event.DeviceID != "" || record.Event.IdentityConfidence != 0 || record.Event.Origin != "collector" || record.Event.SensorID != "" {
		t.Fatalf("bad sanitized event: %+v", record.Event)
	}
	meta := decodeObject(record.Event.Metadata)
	core := mapValue(meta["_vedetta"])
	source := mapValue(core["source"])
	if source["ingress_tags"] == nil || source["ingress_core_fields"] == nil {
		t.Fatalf("sanitized caller material was not retained as source audit: %s", record.Event.Metadata)
	}
}

func TestGenericOriginsCannotForgeIPS(t *testing.T) {
	now := time.Now().UTC()
	for _, origin := range []string{"collector", "sensor_dns", "pihole", "adguard"} {
		t.Run(origin, func(t *testing.T) {
			db := &captureStore{}
			processor := newProcessorWithStore(db, nil, WithClock(func() time.Time { return now }))
			result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
				Event: models.Event{EventID: "forged-ips-" + origin, EventType: "firewall_log", Timestamp: now,
					SourceHash: "stable", Tags: []string{"ips"}, Metadata: `{"dialect":"rest","ips_severity":3,"dst_ip":"203.0.113.20"}`},
				Origin: origin, ReceivedAt: now,
			}})[0]
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			record := db.records[0]
			if hasAnyTag(record.Event.Tags, "ips") || len(record.Evidence) != 0 || len(record.Findings) != 0 {
				t.Fatalf("origin %s forged IPS: event=%+v evidence=%+v findings=%+v", origin, record.Event, record.Evidence, record.Findings)
			}
		})
	}
}

func TestTrustedUniFiRESTPreservesValidatedIPS(t *testing.T) {
	now := time.Now().UTC()
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil, WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{EventID: "trusted-ips", EventType: "firewall_log", Timestamp: now,
			SourceHash: "stable", Tags: []string{"ips"},
			Metadata: `{"dialect":"rest","ips_severity":3,"dst_ip":"203.0.113.20","rule":"Synthetic IPS signature"}`},
		Origin: "unifi_rest", ReceivedAt: now,
	}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if !hasAnyTag(record.Event.Tags, "ips") || record.Event.AnomalyScore != 1 || len(record.Evidence) != 1 || len(record.Findings) != 1 {
		t.Fatalf("trusted IPS was not preserved: event=%+v evidence=%+v findings=%+v", record.Event, record.Evidence, record.Findings)
	}
	if record.Evidence[0].Detector != "ips" || record.Findings[0].Priority != models.PriorityCritical {
		t.Fatalf("bad IPS evidence/finding: %+v / %+v", record.Evidence[0], record.Findings[0])
	}

	// The internal origin alone is insufficient; malformed Core shape is rejected.
	badDB := &captureStore{}
	bad := newProcessorWithStore(badDB, nil, WithClock(func() time.Time { return now }))
	badResult := bad.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{EventID: "bad-shape", EventType: "firewall_log", Timestamp: now,
			SourceHash: "stable", Tags: []string{"ips"}, Metadata: `{"dialect":"cef","ips_severity":3,"dst_ip":"203.0.113.20"}`},
		Origin: "unifi_rest", ReceivedAt: now,
	}})[0]
	if badResult.Err != nil || len(badDB.records[0].Evidence) != 0 {
		t.Fatalf("malformed internal IPS shape accepted: result=%+v record=%+v", badResult, badDB.records[0])
	}
}

type contextEnricher struct{}

func (contextEnricher) Enrich(event *models.Event) {
	event.Tags = appendUniqueString(event.Tags, "dga_candidate")
	event.AnomalyScore = 0.4
	event.ThreatDesc = "Core deterministic DGA"
	event.Metadata = `{"detections":{"dga":{"score":0.4,"label":"fixture"}}}`
}

func TestDeviceContextParityAcrossOrigins(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	db := &captureStore{}
	processor := newProcessorWithStore(db, contextEnricher{},
		WithClock(func() time.Time { return now }),
		WithIdentityResolver(IdentityResolverFunc(func(context.Context, models.Event, IdentityContext) (IdentityResolution, error) {
			return IdentityResolution{DeviceID: "device-context", Confidence: 0.95, Reason: "stable_identity", Evidence: json.RawMessage(`{}`)}, nil
		})),
		WithDeviceContextResolver(DeviceContextResolverFunc(func(context.Context, string, time.Time) (DeviceContext, error) {
			return DeviceContext{DeviceID: "device-context", Vendor: "Fixture Vendor", DeviceType: "camera",
				Model: "FixtureCam", Segment: "iot", RiskCategory: "eol_eos", EOLRisk: true,
				FirstSeen: now.Add(-30 * time.Minute), IsNew: true, IsVeryNew: true,
				IdentityConfidence: 0.95, IdentityStatus: "identified"}, nil
		})),
	)
	origins := []string{"sensor_dns", "pihole", "adguard", "collector", "unifi_rest"}
	envelopes := make([]IngressEnvelope, 0, len(origins))
	for _, origin := range origins {
		envelopes = append(envelopes, IngressEnvelope{Event: models.Event{
			EventID: "context-" + origin, EventType: "dns_query", Timestamp: now, SourceHash: "stable",
			Domain: "fixture.example", DeviceVendor: "caller-forged", Tags: []string{"known_exploited"},
		}, Origin: origin, ReceivedAt: now})
	}
	results := processor.ProcessBatch(context.Background(), envelopes)
	for i, result := range results {
		if result.Err != nil {
			t.Fatalf("origin %s: %v", origins[i], result.Err)
		}
		record := db.records[i]
		if record.Event.DeviceVendor != "Fixture Vendor" || record.Event.NetworkSegment != "default" {
			t.Fatalf("origin %s context fields differ: %+v", origins[i], record.Event)
		}
		for _, tag := range []string{"new_device", "very_new_device", "eol_router", "iot_context", "new_device_context", "eol_device_context"} {
			if !hasAnyTag(record.Event.Tags, tag) {
				t.Fatalf("origin %s missing context tag %s: %v", origins[i], tag, record.Event.Tags)
			}
		}
		if len(record.Evidence) != 1 {
			t.Fatalf("origin %s evidence=%+v", origins[i], record.Evidence)
		}
		var context DeviceContext
		if err := json.Unmarshal(record.Evidence[0].DeviceContext, &context); err != nil || context.DeviceID != "device-context" || context.DeviceType != "camera" || context.RiskCategory != "eol_eos" {
			t.Fatalf("origin %s evidence context=%s err=%v", origins[i], record.Evidence[0].DeviceContext, err)
		}
	}
}

func TestFirstSeenFirewallEvidenceDoesNotCreateFinding(t *testing.T) {
	now := time.Now().UTC()
	db := &captureStore{}
	processor := newProcessorWithStore(db, dnsintel.NewEnricher(nil), WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{
		Event: models.Event{EventID: "ordinary-first-block", EventType: "firewall_log", Timestamp: now,
			SourceHash: "stable", SourceIP: "192.0.2.10", Blocked: true,
			Metadata: `{"action":"block","direction":"out","protocol":"tcp","dst_ip":"203.0.113.10","rule":"ordinary"}`},
		Origin: "collector", ReceivedAt: now,
	}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if len(record.Evidence) != 1 || record.Evidence[0].Detector != "firewall_first_seen" || len(record.Findings) != 0 {
		t.Fatalf("first seen became actionable: evidence=%+v findings=%+v", record.Evidence, record.Findings)
	}
}

func TestCommunityConfidenceCannotEclipseTrustedSource(t *testing.T) {
	now := time.Now().UTC()
	community := &threatintel.Indicator{Value: "shared.example", Type: "domain", Source: "vedetta-community", Confidence: 0.95, Tags: []string{"community"}, LastSeen: now, TTLHours: 24}
	trusted := &threatintel.Indicator{Value: "shared.example", Type: "domain", Source: "urlhaus", Confidence: 0.85, Tags: []string{"malware"}, LastSeen: now, TTLHours: 24}
	lookup := multiLookup{values: map[string][]threatintel.LookupResult{"shared.example": {
		{Found: true, Indicator: community, Confidence: 0.95},
		{Found: true, Indicator: trusted, Confidence: 0.85},
	}}}
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil, WithThreatLookup(lookup), WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "multi-source", EventType: "dns_query", Timestamp: now, SourceHash: "stable", Domain: "shared.example",
	}, Origin: "sensor_dns", ReceivedAt: now}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if len(record.Evidence) != 2 || len(record.Findings) != 1 {
		t.Fatalf("multi-source evidence/finding = %+v / %+v", record.Evidence, record.Findings)
	}
	if record.Findings[0].Score != 0.85 || record.Event.AnomalyScore != 0.85 || record.Event.MatchedIndicator != "shared.example" ||
		!hasAnyTag(record.Event.Tags, "known_bad") || !hasAnyTag(record.Event.Tags, "community_advisory") {
		t.Fatalf("community eclipsed trusted source: event=%+v finding=%+v", record.Event, record.Findings[0])
	}
}

func TestCommunityOnlyRemainsLowPriorityAdvisory(t *testing.T) {
	now := time.Now().UTC()
	indicator := &threatintel.Indicator{Value: "advisory.example", Type: "domain", Source: "vedetta-community", Confidence: 0.95, Tags: []string{"c2"}, LastSeen: now, TTLHours: 24}
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil, WithThreatLookup(lookupMap{"advisory.example": {
		Found: true, Indicator: indicator, Confidence: 0.95,
	}}), WithClock(func() time.Time { return now }))
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: models.Event{
		EventID: "community-only", EventType: "dns_query", Timestamp: now, SourceHash: "stable", Domain: "advisory.example",
	}, Origin: "sensor_dns", ReceivedAt: now}})[0]
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := db.records[0]
	if len(record.Evidence) != 1 || len(record.Findings) != 0 || record.Event.AnomalyScore > 0.20 || !hasAnyTag(record.Event.Tags, "community_advisory") || hasAnyTag(record.Event.Tags, "known_bad", "c2") {
		t.Fatalf("community-only match masqueraded as confirmed: event=%+v evidence=%+v findings=%+v", record.Event, record.Evidence, record.Findings)
	}
}
