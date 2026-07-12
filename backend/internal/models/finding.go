package models

import (
	"encoding/json"
	"time"
)

// FindingStatus is the operator-controlled lifecycle state of a finding.
// Suppression is deliberately represented separately by FindingDisposition.
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusInvestigating FindingStatus = "investigating"
	FindingStatusResolved      FindingStatus = "resolved"
)

// Priority is derived once from detection evidence and is not reduced merely
// because the observed traffic was blocked.
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// FindingDisposition controls whether a finding is presented as actionable.
// It never removes the event, detector evidence, or finding/event relationship.
type FindingDisposition string

const (
	DispositionActive     FindingDisposition = "active"
	DispositionSuppressed FindingDisposition = "suppressed"
)

// Observable is a normalized value that a detector can evaluate. Value is
// local operator evidence and is never exported merely by persisting it here.
type Observable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DetectionEvidence is the immutable, typed explanation of one detector result.
// Context and Details are bounded JSON objects populated by Core, not trusted
// verdict material copied directly from an ingest caller.
type DetectionEvidence struct {
	EvidenceID        string          `json:"evidence_id" db:"evidence_id"`
	EventID           string          `json:"event_id" db:"event_id"`
	Detector          string          `json:"detector" db:"detector"`
	Category          string          `json:"category" db:"category"`
	ObservableType    string          `json:"observable_type" db:"observable_type"`
	ObservableValue   string          `json:"observable_value" db:"observable_value"`
	ThreatSource      string          `json:"threat_source,omitempty" db:"threat_source"`
	SourceConfidence  float64         `json:"source_confidence" db:"source_confidence"`
	FeedFreshness     *time.Time      `json:"feed_freshness,omitempty" db:"feed_freshness"`
	FeedStale         bool            `json:"feed_stale" db:"feed_stale"`
	Rationale         string          `json:"rationale" db:"rationale"`
	ScoreContribution float64         `json:"score_contribution" db:"score_contribution"`
	Outcome           string          `json:"outcome" db:"outcome"` // allowed | blocked | observed
	DeviceContext     json.RawMessage `json:"device_context,omitempty" db:"device_context"`
	Details           json.RawMessage `json:"details,omitempty" db:"details"`
	CreatedAt         time.Time       `json:"created_at" db:"created_at"`

	// CreatesFinding is an internal processor decision. It is intentionally not
	// persisted as detector evidence because threshold policy can evolve.
	CreatesFinding bool `json:"-" db:"-"`
}

// Finding is the durable incident-like aggregation presented to operators.
type Finding struct {
	FindingID         string `json:"finding_id" db:"finding_id"`
	FindingKey        string `json:"finding_key" db:"finding_key"`
	Generation        int    `json:"generation" db:"generation"`
	PreviousFindingID string `json:"previous_finding_id,omitempty" db:"previous_finding_id"`
	DeviceID          string `json:"device_id,omitempty" db:"device_id"`
	// CanonicalDeviceID follows an audited soft-merge redirect for operator
	// navigation. DeviceID remains the historical identity stored on the finding.
	CanonicalDeviceID string `json:"canonical_device_id,omitempty" db:"-"`
	// IdentityConfidence and IdentityReason describe the event-time association
	// on the finding's latest supporting event. They deliberately do not borrow
	// the device's mutable current confidence.
	IdentityConfidence    float64            `json:"identity_confidence" db:"-"`
	IdentityReason        string             `json:"identity_reason,omitempty" db:"-"`
	NeedsIdentification   bool               `json:"needs_identification" db:"-"`
	FallbackIdentity      string             `json:"fallback_identity,omitempty" db:"fallback_identity"`
	Detector              string             `json:"detector" db:"detector"`
	Category              string             `json:"category" db:"category"`
	PrimaryObservableType string             `json:"primary_observable_type" db:"primary_observable_type"`
	PrimaryObservable     string             `json:"primary_observable" db:"primary_observable"`
	FirstSeen             time.Time          `json:"first_seen" db:"first_seen"`
	LastSeen              time.Time          `json:"last_seen" db:"last_seen"`
	OccurrenceCount       int64              `json:"occurrence_count" db:"occurrence_count"`
	MaximumScore          float64            `json:"maximum_score" db:"maximum_score"`
	CurrentPriority       Priority           `json:"current_priority" db:"current_priority"`
	AllowedCount          int64              `json:"allowed_count" db:"allowed_count"`
	BlockedCount          int64              `json:"blocked_count" db:"blocked_count"`
	ObservedCount         int64              `json:"observed_count" db:"observed_count"`
	Outcome               string             `json:"outcome" db:"outcome"`
	Status                FindingStatus      `json:"status" db:"status"`
	Reason                string             `json:"reason" db:"reason"`
	RecommendedAction     string             `json:"recommended_action" db:"recommended_action"`
	LastEventID           string             `json:"last_event_id" db:"last_event_id"`
	Evidence              json.RawMessage    `json:"evidence" db:"evidence"`
	Disposition           FindingDisposition `json:"disposition" db:"disposition"`
	SuppressionRuleID     string             `json:"suppression_rule_id,omitempty" db:"suppression_rule_id"`
	CreatedAt             time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at" db:"updated_at"`
	ResolvedAt            *time.Time         `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolutionReason      string             `json:"resolution_reason,omitempty" db:"resolution_reason"`
}

// FindingCandidate is the processor-to-store contract for updating one durable
// finding from an accepted event. The store owns generation and recurrence.
type FindingCandidate struct {
	FindingKey            string
	DeviceID              string
	FallbackIdentity      string
	Detector              string
	Category              string
	PrimaryObservableType string
	PrimaryObservable     string
	ObservedAt            time.Time
	Score                 float64
	Priority              Priority
	Blocked               bool
	Outcome               string
	Reason                string
	RecommendedAction     string
	Disposition           FindingDisposition
	SuppressionRuleID     string
	EvidenceIDs           []string
}

// FindingEvent preserves the complete many-to-many relationship between
// findings and immutable supporting events.
type FindingEvent struct {
	FindingID string    `json:"finding_id" db:"finding_id"`
	EventID   string    `json:"event_id" db:"event_id"`
	LinkedAt  time.Time `json:"linked_at" db:"linked_at"`
}

// FindingStatusHistory is an append-only audit row for lifecycle transitions,
// including automatic recurrence reopen operations.
type FindingStatusHistory struct {
	HistoryID  string        `json:"history_id" db:"history_id"`
	FindingID  string        `json:"finding_id" db:"finding_id"`
	FromStatus FindingStatus `json:"from_status" db:"from_status"`
	ToStatus   FindingStatus `json:"to_status" db:"to_status"`
	Reason     string        `json:"reason" db:"reason"`
	Actor      string        `json:"actor" db:"actor"`
	ChangedAt  time.Time     `json:"changed_at" db:"changed_at"`
}

// FindingSuppressionRule is an exact, typed policy derived from an operator's
// finding action. Deactivation preserves the rule and its audit history.
type FindingSuppressionRule struct {
	RuleID           string    `json:"rule_id" db:"rule_id"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
	Detector         string    `json:"detector" db:"detector"`
	ObservableType   string    `json:"observable_type" db:"observable_type"`
	ObservableValue  string    `json:"observable_value" db:"observable_value"`
	DeviceID         string    `json:"device_id,omitempty" db:"device_id"`
	FallbackIdentity string    `json:"fallback_identity,omitempty" db:"fallback_identity"`
	Reason           string    `json:"reason" db:"reason"`
	Active           bool      `json:"active" db:"active"`
}
