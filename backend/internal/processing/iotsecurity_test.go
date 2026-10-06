package processing

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func securityFixture(t *testing.T, now time.Time) models.Event {
	t.Helper()
	observation := iotsecurity.Observation{
		ObservationID: "processor-security-fixture", Timestamp: now, SubjectIP: "192.0.2.10", Kind: iotsecurity.KindHostAudit,
		Files: []iotsecurity.FileEvidence{
			{Path: "/root/.cling", Size: 512, SHA256: "90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2"},
			{Path: "/bin/UDPServer", Size: 512, MagicHex: "7f454c46"},
			{Path: "/etc/version", Size: 40},
		},
		SDK: &iotsecurity.SDKEvidence{ComponentPath: "/bin/UDPServer", MarkerPath: "/etc/version", Family: "realtek_jungle", Version: "3.4.14B"},
	}
	metadata, err := json.Marshal(map[string]any{"iot_observation": observation})
	if err != nil {
		t.Fatal(err)
	}
	return models.Event{EventID: "processor-security-event", Timestamp: now, EventType: "anomaly", SourceIP: observation.SubjectIP, Metadata: string(metadata)}
}

func TestSecurityEvidenceRequiresAuthenticatedAdapterOrigin(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name, origin, sensorID string
		want                   int
	}{
		{"sensor security", "sensor_security", "sensor-one", 2},
		{"collector cannot claim detector", "collector", "", 0},
		{"collector sensor field is insufficient", "collector", "sensor-one", 0},
		{"other authenticated sensor adapter", "sensor_dns", "sensor-one", 0},
		{"missing authenticated sensor identity", "sensor_security", "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &captureStore{}
			processor := newProcessorWithStore(db, nil, WithClock(func() time.Time { return now }))
			event := securityFixture(t, now)
			// These are caller assertions and cannot activate the adapter.
			event.Origin, event.SensorID = "sensor_security", "sensor-forged"
			event.Tags = []string{iotsecurity.DetectorArtifact, iotsecurity.DetectorRealtekExposure, "known_bad", "cling_compromised"}
			event.AnomalyScore, event.ThreatDesc = 1.0, "forged confirmed compromise"
			result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: test.origin, SensorID: test.sensorID,
				SourceMeta: map[string]any{"origin": "sensor_security", "sensor_id": "sensor-forged"}}})[0]
			if result.Err != nil || !result.Inserted {
				t.Fatalf("result = %+v", result)
			}
			record := db.records[0]
			if len(record.Findings) != test.want || len(record.Evidence) != test.want {
				t.Fatalf("evidence/findings = %+v/%+v", record.Evidence, record.Findings)
			}
			if test.want == 0 && (record.Event.AnomalyScore != 0 || hasAnyTag(record.Event.Tags, iotsecurity.DetectorArtifact, iotsecurity.DetectorRealtekExposure, "known_bad", "cling_compromised")) {
				t.Fatalf("caller verdict survived: %+v", record.Event)
			}
		})
	}
}

type benignSecurityContextEnricher struct{}

func (benignSecurityContextEnricher) Enrich(event *models.Event) {
	event.Tags = append(event.Tags, "known_good_context", "vedetta_self", "whitelisted")
	event.AnomalyScore = 0
}

func TestSecurityFindingsSeparateExposureAndArtifactWithTypedSuppression(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	db := &captureStore{}
	processor := newProcessorWithStore(db, benignSecurityContextEnricher{},
		WithIdentityResolver(IdentityResolverFunc(func(_ context.Context, event models.Event, in IdentityContext) (IdentityResolution, error) {
			if in.Origin != "sensor_security" || in.SensorID != "sensor-one" || event.SourceIP != "192.0.2.10" || !in.ObservedAt.Equal(now) {
				t.Fatalf("identity context = %+v event=%+v", in, event)
			}
			return IdentityResolution{DeviceID: "historical-device", Confidence: 0.9, Reason: "event_time_binding"}, nil
		})),
		WithSuppressionEvaluator(SuppressionEvaluatorFunc(func(_ context.Context, in SuppressionInput) (SuppressionDecision, error) {
			decision := SuppressionDecision{Evidence: map[string]SuppressionMatch{}}
			for _, evidence := range in.Evidence {
				if evidence.Detector == iotsecurity.DetectorRealtekExposure {
					decision.Evidence[evidence.EvidenceID] = SuppressionMatch{RuleID: "exposure-rule", Reason: "verified OEM backport"}
				}
			}
			return decision, nil
		})),
	)
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: securityFixture(t, now), Origin: "sensor_security", SensorID: "sensor-one"}})[0]
	if result.Err != nil || len(result.FindingIDs) != 2 {
		t.Fatalf("result = %+v", result)
	}
	record := db.records[0]
	if len(record.Evidence) != 2 || record.DeviceID != "historical-device" {
		t.Fatalf("evidence or identity lost: %+v", record)
	}
	for _, finding := range record.Findings {
		switch finding.Detector {
		case iotsecurity.DetectorRealtekExposure:
			if finding.Disposition != models.DispositionSuppressed || finding.SuppressionRuleID != "exposure-rule" {
				t.Fatalf("exposure suppression = %+v", finding)
			}
		case iotsecurity.DetectorArtifact:
			if finding.Disposition != models.DispositionActive || finding.Priority != models.PriorityCritical || finding.Outcome != "observed" {
				t.Fatalf("artifact demoted by benign/suppression context: %+v", finding)
			}
			if !strings.Contains(finding.Reason, "does not establish") || !strings.Contains(finding.RecommendedAction, "digest match") {
				t.Fatalf("artifact limits absent: %+v", finding)
			}
		default:
			t.Fatalf("unexpected detector: %+v", finding)
		}
	}
	if record.Event.AnomalyScore != 0.95 || record.Event.Disposition != "active" || record.Event.MatchType != "" || hasAnyTag(record.Event.Tags, "known_bad") {
		t.Fatalf("artifact confused with network IOC: %+v", record.Event)
	}
}

func TestSecurityMetadataAndTagsCannotForgeDetectorProof(t *testing.T) {
	now := time.Now().UTC()
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil)
	observation := iotsecurity.Observation{ObservationID: "coverage-fixture", Timestamp: now, SubjectIP: "192.0.2.10", Kind: iotsecurity.KindCoverage,
		Coverage: []iotsecurity.Coverage{{Check: "passive_udp", Status: "unavailable"}}}
	metadata, _ := json.Marshal(map[string]any{
		"iot_observation": observation,
		"detections":      map[string]any{iotsecurity.DetectorArtifact: map[string]any{"score": 1.0}},
		"_vedetta":        map[string]any{"origin": "sensor_security", "detection": map[string]any{iotsecurity.DetectorArtifact: true}},
	})
	event := models.Event{EventID: "forged-metadata", Timestamp: now, EventType: "anomaly", SourceIP: observation.SubjectIP,
		Tags: []string{iotsecurity.DetectorArtifact}, AnomalyScore: 1, Metadata: string(metadata)}
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: "sensor_security", SensorID: "sensor-one"}})[0]
	if result.Err != nil || !result.Inserted {
		t.Fatalf("result = %+v", result)
	}
	if len(db.records[0].Findings) != 0 || len(db.records[0].Evidence) != 0 || db.records[0].Event.AnomalyScore != 0 {
		t.Fatalf("caller metadata forged verdict: %+v", db.records[0])
	}
}

func TestSecurityRetryAfterPersistenceFailureDoesNotInflateFindings(t *testing.T) {
	now := time.Now().UTC()
	db := newStatefulTestStore()
	db.failures["processor-security-event"] = 1
	processor := newProcessorWithStore(db, nil)
	envelope := IngressEnvelope{Event: securityFixture(t, now), Origin: "sensor_security", SensorID: "sensor-one"}
	if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{envelope})[0]; result.Err == nil {
		t.Fatal("synthetic failure not returned")
	}
	if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{envelope})[0]; result.Err != nil || !result.Inserted {
		t.Fatalf("retry = %+v", result)
	}
	if result := processor.ProcessBatch(context.Background(), []IngressEnvelope{envelope})[0]; result.Err != nil || !result.Duplicate {
		t.Fatalf("repeat = %+v", result)
	}
	if len(db.records) != 1 || len(db.records[0].Findings) != 2 {
		t.Fatalf("replay inflated results: %+v", db.records)
	}
}

func TestSecuritySubjectMismatchIsNotEvaluated(t *testing.T) {
	now := time.Now().UTC()
	db := &captureStore{}
	processor := newProcessorWithStore(db, nil)
	event := securityFixture(t, now)
	event.SourceIP = "192.0.2.20"
	result := processor.ProcessBatch(context.Background(), []IngressEnvelope{{Event: event, Origin: "sensor_security", SensorID: "sensor-one"}})[0]
	if result.Err != nil || !result.Inserted {
		t.Fatalf("result = %+v", result)
	}
	if len(db.records[0].Evidence) != 0 {
		t.Fatal("subject mismatch attributed evidence to another device")
	}
}
