package processing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

type ProcessorOption func(*Processor)

func WithIdentityResolver(resolver IdentityResolver) ProcessorOption {
	return func(processor *Processor) { processor.identity = resolver }
}

func WithSuppressionEvaluator(evaluator SuppressionEvaluator) ProcessorOption {
	return func(processor *Processor) { processor.suppression = evaluator }
}

func WithThreatLookup(lookup ThreatLookup) ProcessorOption {
	return func(processor *Processor) { processor.threats = lookup }
}

func WithSourceHasher(hasher SourceHasher) ProcessorOption {
	return func(processor *Processor) { processor.sourceHasher = hasher }
}

func WithDeviceContextResolver(resolver DeviceContextResolver) ProcessorOption {
	return func(processor *Processor) { processor.deviceContext = resolver }
}

func WithClock(clock func() time.Time) ProcessorOption {
	return func(processor *Processor) {
		if clock != nil {
			processor.now = clock
		}
	}
}

type processedEventStore interface {
	ProcessedEventExists(context.Context, string) (bool, error)
	PersistProcessedEvent(context.Context, store.ProcessedEventRecord) (store.PersistProcessedResult, error)
}

const maxEventFutureSkew = time.Hour

// Processor is the single normalization, resolution, detection, suppression,
// and persistence path for production event ingestion.
type Processor struct {
	store         processedEventStore
	enricher      EventEnricher
	identity      IdentityResolver
	suppression   SuppressionEvaluator
	threats       ThreatLookup
	sourceHasher  SourceHasher
	deviceContext DeviceContextResolver
	now           func() time.Time
	// mutationMu is the in-process idempotency reservation. It serializes the
	// second existence check, stateful enrichment, and persistence, so two
	// concurrent deliveries cannot both mutate detector state before one wins
	// the database uniqueness race.
	mutationMu sync.Mutex
}

func NewProcessor(db *store.DB, enricher EventEnricher, options ...ProcessorOption) *Processor {
	if concrete, ok := enricher.(*dnsintel.Enricher); ok {
		// A Server assembled in tests or reduced-function startup may contain a
		// typed nil pointer. Once stored in EventEnricher the interface itself is
		// non-nil; normalize it here to preserve the old nil guard semantics.
		if concrete == nil {
			enricher = nil
		} else {
			concrete.EnsureDefaults()
		}
	}
	processor := &Processor{enricher: enricher, now: func() time.Time { return time.Now().UTC() }}
	if db != nil {
		processor.store = db
		processor.sourceHasher = db
		processor.identity = StoreIdentityResolver{DB: db}
		processor.suppression = StoreSuppressionEvaluator{DB: db}
		processor.deviceContext = StoreDeviceContextResolver{DB: db}
	}
	// Reuse the existing in-process TI index while extracting every observable.
	if concrete, ok := enricher.(*dnsintel.Enricher); ok && concrete != nil && concrete.ThreatDB != nil {
		processor.threats = concrete.ThreatDB
	}
	for _, option := range options {
		option(processor)
	}
	return processor
}

// newProcessorWithStore is intentionally package-private; tests use it to
// prove normalization and partial-batch behavior without SQLite.
func newProcessorWithStore(db processedEventStore, enricher EventEnricher, options ...ProcessorOption) *Processor {
	processor := &Processor{store: db, enricher: enricher, now: func() time.Time { return time.Now().UTC() }}
	for _, option := range options {
		option(processor)
	}
	return processor
}

func (processor *Processor) ProcessBatch(ctx context.Context, envelopes []IngressEnvelope) []ProcessRecordResult {
	results := make([]ProcessRecordResult, len(envelopes))
	for i := range envelopes {
		if err := ctx.Err(); err != nil {
			results[i] = ProcessRecordResult{EventID: envelopes[i].Event.EventID, FindingIDs: []string{}, Err: err}
			continue
		}
		results[i] = processor.processRecord(ctx, envelopes[i])
	}
	return results
}

func (processor *Processor) processRecord(ctx context.Context, envelope IngressEnvelope) ProcessRecordResult {
	now := processor.now().UTC()
	event := envelope.Event
	if event.EventID == "" {
		event.EventID = uuid.NewString()
	}
	result := ProcessRecordResult{EventID: event.EventID, FindingIDs: []string{}}
	if processor.store == nil {
		result.Err = errors.New("event store is required")
		return result
	}
	exists, err := processor.store.ProcessedEventExists(ctx, event.EventID)
	if err != nil {
		result.Err = err
		return result
	}
	if exists {
		result.Duplicate = true
		return result
	}
	if envelope.ReceivedAt.IsZero() {
		envelope.ReceivedAt = now
	}
	normalizeEvent(&event, envelope.ReceivedAt)
	// Core owns this pseudonym whenever a raw local source address is present.
	// Never let a caller choose a forged grouping key, and replace legacy hashes
	// derived from a shared fallback salt. A supplied hash is retained only when
	// the source address is unavailable.
	if event.SourceIP != "" && processor.sourceHasher != nil {
		hash, err := processor.sourceHasher.SourceHash(ctx, event.SourceIP)
		if err != nil {
			result.Err = err
			return result
		}
		if hash != "" {
			event.SourceHash = hash
		}
	}
	if event.SourceHash == "" {
		event.SourceHash = "unknown"
	}
	trustedIPS := sanitizeIngressEvent(&event, &envelope)
	event.Outcome = deriveIngressOutcome(event, envelope)
	envelope.Event = event

	// Preserve adapter and original event metadata before legacy enrichment.
	originalMeta := decodeObject(event.Metadata)
	combinedMeta := cloneObject(originalMeta)
	for key, value := range envelope.SourceMeta {
		if _, exists := combinedMeta[key]; !exists {
			combinedMeta[key] = value
		}
	}
	event.Metadata = marshalStableObject(combinedMeta)

	identity := IdentityResolution{Evidence: json.RawMessage("{}")}
	if processor.identity != nil {
		resolved, err := processor.identity.ResolveEventIdentity(ctx, event, IdentityContext{
			Origin: envelope.Origin, SensorID: envelope.SensorID,
			Segment: event.NetworkSegment, ObservedAt: event.Timestamp, SourceMeta: envelope.SourceMeta,
		})
		if err != nil {
			result.Err = err
			return result
		}
		identity = resolved
		identity.Confidence = clampScore(identity.Confidence)
		if len(identity.Evidence) == 0 {
			identity.Evidence = json.RawMessage("{}")
		}
	}
	event.DeviceID = identity.DeviceID
	event.IdentityConfidence = identity.Confidence
	event.IdentityReason = identity.Reason
	event.IdentityEvidence = string(identity.Evidence)
	event.Origin = strings.TrimSpace(envelope.Origin)
	event.SensorID = strings.TrimSpace(envelope.SensorID)

	observables := ExtractObservables(event)
	// Strong IOC evaluation is deliberately complete before any device or benign
	// context is applied. Context can explain or suppress; it cannot erase or
	// demote this evidence.
	strongEvidence := threatIntelEvidence(processor.threats, event, observables, now)
	deviceContext := DeviceContext{}
	if identity.DeviceID != "" && processor.deviceContext != nil {
		resolvedContext, err := processor.deviceContext.ResolveDeviceContext(ctx, identity.DeviceID, event.Timestamp)
		if err != nil {
			result.Err = err
			return result
		}
		deviceContext = resolvedContext
		applyDeviceContext(&event, deviceContext)
	}

	// Reserve the stateful section and re-check after acquiring it. The first
	// lookup above makes ordinary retries cheap; this check is what closes the
	// concurrent-delivery race before Beacon/Rebinding/FirewallFirstSeen mutate.
	processor.mutationMu.Lock()
	defer processor.mutationMu.Unlock()

	enrichEvent := func(*models.Event) {}
	commitState := func() {}
	rollbackState := func() {}
	if processor.enricher != nil {
		enrichEvent = processor.enricher.Enrich
		if transactional, ok := processor.enricher.(TransactionalEventEnricher); ok {
			enrichEvent, commitState, rollbackState = transactional.BeginEventState(event)
		}
	}
	stateFinalized := false
	defer func() {
		if !stateFinalized {
			rollbackState()
		}
	}()

	exists, err = processor.store.ProcessedEventExists(ctx, event.EventID)
	if err != nil {
		result.Err = err
		return result
	}
	if exists {
		result.Duplicate = true
		return result
	}

	metadataBeforeEnrichment := event.Metadata
	enrichEvent(&event)
	enrichedMeta := decodeObject(event.Metadata)
	detectionMeta := map[string]any{}
	if event.Metadata != metadataBeforeEnrichment {
		// dnsintel writes its authoritative detector output beneath `detections`.
		// Never interpret caller-owned lookalike root keys as detector provenance.
		detectionMeta = mapValue(enrichedMeta["detections"])
	}
	// Capture algorithm evidence while both halves of its Core-owned proof are
	// present: the detector metadata and its tag. Feed tags are stripped next so
	// they cannot forge a detector, but a feed reason with the same spelling must
	// not erase a genuine detector result either.
	heuristics := heuristicEvidence(event, detectionMeta, now)
	stripThreatEvidenceTags(&event, strongEvidence)
	if event.EventType == "firewall_log" && hasAnyTag(event.Tags, "new_fw_block") {
		meta := decodeObject(event.Metadata)
		detectionMeta["firewall"] = map[string]any{
			"score": event.AnomalyScore, "action": meta["action"], "rule": meta["rule"],
		}
	}
	applyTrustedIPS(&event, trustedIPS, detectionMeta)
	// Firewall/IPS detector metadata is synthesized only after untrusted feed tags
	// have been removed. Re-evaluate and deduplicate so those paths are included
	// without allowing a feed reason to manufacture them.
	heuristics = deduplicateEvidence(append(heuristics, heuristicEvidence(event, detectionMeta, now)...))
	evidence := deduplicateEvidence(append(strongEvidence, heuristics...))
	markFindingEligibility(evidence)
	attachDeviceContext(evidence, deviceContext)
	applyPostDetectionContext(&event, deviceContext, evidence)
	finalizeEventVerdict(&event, evidence)

	decision := SuppressionDecision{}
	if processor.suppression != nil {
		var err error
		_, fallbackIdentity := findingIdentity(event, identity, envelope)
		decision, err = processor.suppression.EvaluateSuppression(ctx, SuppressionInput{
			Event: event, DeviceID: identity.DeviceID, FallbackIdentity: fallbackIdentity, Origin: envelope.Origin,
			SensorID: envelope.SensorID, Evidence: evidence, Observables: observables,
		})
		if err != nil {
			result.Err = err
			return result
		}
	}
	disposition, eventSuppressionRuleID := eventSuppressionDisposition(decision, evidence)
	event.Disposition = string(disposition)
	event.SuppressionRuleID = eventSuppressionRuleID

	event.Metadata = finalMetadata(originalMeta, envelope, detectionMeta, identity, deviceContext, decision)
	findings := findingCandidates(event, identity, envelope, evidence, decision)
	persisted, err := processor.store.PersistProcessedEvent(ctx, store.ProcessedEventRecord{
		Event: event, DeviceID: identity.DeviceID, IdentityConfidence: identity.Confidence,
		IdentityReason: identity.Reason, IdentityEvidence: identity.Evidence,
		Origin: strings.TrimSpace(envelope.Origin), SensorID: strings.TrimSpace(envelope.SensorID),
		Disposition: disposition, SuppressionRuleID: eventSuppressionRuleID,
		Evidence: evidence, Findings: findings,
	})
	if err != nil {
		result.Err = err
		return result
	}
	if persisted.Inserted {
		commitState()
		stateFinalized = true
	}
	result.FindingIDs = persisted.FindingIDs
	result.Inserted = persisted.Inserted
	result.Duplicate = persisted.Duplicate
	return result
}

func normalizeEvent(event *models.Event, receivedAt time.Time) {
	event.EventType = strings.ToLower(strings.TrimSpace(event.EventType))
	event.Domain = normalizeObservable(ObservableDomain, event.Domain)
	event.QueryType = strings.ToUpper(strings.TrimSpace(event.QueryType))
	if event.Timestamp.IsZero() {
		event.Timestamp = receivedAt.UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
		if event.Timestamp.After(receivedAt.UTC().Add(maxEventFutureSkew)) {
			event.Timestamp = receivedAt.UTC()
		}
	}
	if event.NetworkSegment == "" {
		event.NetworkSegment = "default"
	}
	if event.Tags == nil {
		event.Tags = []string{}
	}
	event.AnomalyScore = clampScore(event.AnomalyScore)
}

func finalMetadata(original map[string]any, envelope IngressEnvelope, detection map[string]any, identity IdentityResolution, deviceContext DeviceContext, suppression SuppressionDecision) string {
	result := cloneObject(original)
	source := cloneObject(envelope.SourceMeta)
	if callerReserved, exists := result["_vedetta"]; exists {
		// A caller cannot populate Core's namespace, but its value remains available
		// as immutable source evidence instead of being silently discarded.
		source["caller_reserved_namespace"] = callerReserved
	}
	core := map[string]any{
		"origin":      strings.TrimSpace(envelope.Origin),
		"sensor_id":   strings.TrimSpace(envelope.SensorID),
		"received_at": envelope.ReceivedAt.UTC().Format(time.RFC3339Nano),
		"source":      source,
		"detection":   detection,
		"identity": map[string]any{
			"device_id": identity.DeviceID, "confidence": identity.Confidence, "reason": identity.Reason,
		},
		"device_context": deviceContext,
		"disposition": map[string]any{
			"suppressed": suppression.Suppressed || len(suppression.Evidence) > 0,
			"rule_id":    suppression.RuleID, "reason": suppression.Reason,
			"typed_evidence_matches": len(suppression.Evidence),
		},
	}
	result["_vedetta"] = core
	return marshalStableObject(result)
}

func eventSuppressionDisposition(decision SuppressionDecision, evidence []models.DetectionEvidence) (models.FindingDisposition, string) {
	if decision.Suppressed {
		return models.DispositionSuppressed, decision.RuleID
	}
	actionable := 0
	suppressed := 0
	ruleID := ""
	for _, item := range evidence {
		if !item.CreatesFinding {
			continue
		}
		actionable++
		if match, ok := decision.Evidence[item.EvidenceID]; ok {
			suppressed++
			if ruleID == "" {
				ruleID = match.RuleID
			}
		}
	}
	if actionable > 0 && suppressed == actionable {
		return models.DispositionSuppressed, ruleID
	}
	return models.DispositionActive, ""
}
