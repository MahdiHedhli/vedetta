// Package processing owns the single event-processing contract used by every
// production ingestion adapter.
package processing

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

type IngressEnvelope struct {
	Event      models.Event
	Origin     string
	SensorID   string
	ReceivedAt time.Time
	SourceMeta map[string]any
}

type ProcessRecordResult struct {
	EventID    string   `json:"event_id"`
	FindingIDs []string `json:"finding_ids"`
	Inserted   bool     `json:"inserted"`
	Duplicate  bool     `json:"duplicate"`
	Err        error    `json:"-"`
}

// IdentityResolution is authoritative only when returned by the configured
// timestamp-aware resolver. Adapters cannot set these values directly.
type IdentityResolution struct {
	DeviceID   string
	Confidence float64
	Reason     string
	Evidence   json.RawMessage
}

type IdentityContext struct {
	Origin     string
	SensorID   string
	Segment    string
	ObservedAt time.Time
	SourceMeta map[string]any
}

type IdentityResolver interface {
	ResolveEventIdentity(context.Context, models.Event, IdentityContext) (IdentityResolution, error)
}

type IdentityResolverFunc func(context.Context, models.Event, IdentityContext) (IdentityResolution, error)

func (f IdentityResolverFunc) ResolveEventIdentity(ctx context.Context, event models.Event, in IdentityContext) (IdentityResolution, error) {
	return f(ctx, event, in)
}

type SuppressionInput struct {
	Event            models.Event
	DeviceID         string
	FallbackIdentity string
	Origin           string
	SensorID         string
	Evidence         []models.DetectionEvidence
	Observables      []models.Observable
}

type SuppressionDecision struct {
	// Suppressed is reserved for legacy event-wide rules. Typed finding rules are
	// recorded per evidence ID so one detector cannot hide an unrelated finding
	// emitted by the same raw event.
	Suppressed bool
	RuleID     string
	Reason     string
	Evidence   map[string]SuppressionMatch
}

type SuppressionMatch struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

type SuppressionEvaluator interface {
	EvaluateSuppression(context.Context, SuppressionInput) (SuppressionDecision, error)
}

type SuppressionEvaluatorFunc func(context.Context, SuppressionInput) (SuppressionDecision, error)

func (f SuppressionEvaluatorFunc) EvaluateSuppression(ctx context.Context, in SuppressionInput) (SuppressionDecision, error) {
	return f(ctx, in)
}

// EventEnricher is satisfied by dnsintel.Enricher and makes the processor easy
// to test with deterministic enrichers.
type EventEnricher interface {
	Enrich(*models.Event)
}

// TransactionalEventEnricher lets a stateful detector hold its mutation guard
// from checkpoint through durable persistence. The returned enrich function is
// the guarded variant; exactly one of commit or rollback must be called.
type TransactionalEventEnricher interface {
	BeginEventState(models.Event) (enrich func(*models.Event), commit func(), rollback func())
}

type ThreatLookup interface {
	Lookup(string) threatintel.LookupResult
}

// ThreatLookupAll is optional for compatibility, but production ThreatIntelDB
// implements it so one source cannot eclipse another source for the same IOC.
type ThreatLookupAll interface {
	LookupAll(string) []threatintel.LookupResult
}

type SourceHasher interface {
	SourceHash(context.Context, string) (string, error)
}

type SourceHasherFunc func(context.Context, string) (string, error)

func (f SourceHasherFunc) SourceHash(ctx context.Context, value string) (string, error) {
	return f(ctx, value)
}

// DeviceContext is a privacy-bounded, Core-owned projection used for scoring
// explanations. It intentionally excludes IP, MAC, hostname, notes, and other
// sensitive identity values.
type DeviceContext struct {
	DeviceID           string    `json:"device_id,omitempty"`
	Vendor             string    `json:"vendor,omitempty"`
	DeviceType         string    `json:"device_type,omitempty"`
	Model              string    `json:"model,omitempty"`
	Segment            string    `json:"segment,omitempty"`
	RiskCategory       string    `json:"risk_category,omitempty"`
	RiskModel          string    `json:"risk_model,omitempty"`
	EOLRisk            bool      `json:"eol_risk"`
	FirstSeen          time.Time `json:"first_seen,omitempty"`
	IsNew              bool      `json:"is_new"`
	IsVeryNew          bool      `json:"is_very_new"`
	IdentityConfidence float64   `json:"identity_confidence"`
	IdentityStatus     string    `json:"identity_status,omitempty"`
}

type DeviceContextResolver interface {
	ResolveDeviceContext(context.Context, string, time.Time) (DeviceContext, error)
}

type DeviceContextResolverFunc func(context.Context, string, time.Time) (DeviceContext, error)

func (f DeviceContextResolverFunc) ResolveDeviceContext(ctx context.Context, deviceID string, observedAt time.Time) (DeviceContext, error) {
	return f(ctx, deviceID, observedAt)
}
