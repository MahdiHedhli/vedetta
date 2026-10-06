package processing

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// sensorSecurityEvidence is reachable only with the server-selected adapter
// origin and authenticated sensor context. Caller-owned metadata, tags, and even
// a collector's claimed origin never enable these detectors.
func sensorSecurityEvidence(event *models.Event, envelope IngressEnvelope, originalMeta map[string]any, detectorMeta map[string]any, now time.Time) []models.DetectionEvidence {
	if envelope.Origin != "sensor_security" || strings.TrimSpace(envelope.SensorID) == "" || event.EventType != "anomaly" {
		return nil
	}
	raw, err := json.Marshal(originalMeta["iot_observation"])
	if err != nil {
		return nil
	}
	var observation iotsecurity.Observation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observation) != nil || iotsecurity.ValidateObservation(observation) != nil ||
		!net.ParseIP(observation.SubjectIP).Equal(net.ParseIP(event.SourceIP)) || observation.Timestamp.After(envelope.ReceivedAt.Add(maxEventFutureSkew)) {
		return nil
	}
	detections := iotsecurity.Evaluate(observation)
	evidence := make([]models.DetectionEvidence, 0, len(detections))
	bestScore := -1.0
	for _, detection := range detections {
		details, err := json.Marshal(detection.Details)
		if err != nil {
			continue
		}
		event.Tags = appendUniqueString(event.Tags, detection.Detector)
		if detection.Score > bestScore {
			bestScore = detection.Score
			event.ThreatDesc = detection.Rationale
		}
		// Metadata is a Core-owned projection; detailed independent records below
		// retain every digest/path even when a detector emits more than one item.
		detectorMeta[detection.Detector] = detection.Details
		evidence = append(evidence, models.DetectionEvidence{
			EvidenceID: uuid.NewString(), EventID: event.EventID,
			Detector: detection.Detector, Category: detection.Category,
			ObservableType: detection.ObservableType, ObservableValue: detection.ObservableValue,
			SourceConfidence: detection.Confidence, Rationale: detection.Rationale,
			ScoreContribution: detection.Score, Outcome: eventOutcome(*event),
			Details: details, CreatedAt: now,
		})
	}
	return evidence
}
