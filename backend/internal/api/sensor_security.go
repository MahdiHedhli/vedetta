package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/eventid"
	"github.com/vedetta-network/vedetta/backend/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

type sensorSecurityRequest struct {
	SensorID     string                    `json:"sensor_id"`
	Observations []iotsecurity.Observation `json:"observations"`
}

// handleSensorSecurity accepts observation facts only. Authentication chooses
// the sensor and adapter origin; clients cannot submit verdicts or device IDs.
func (s *Server) handleSensorSecurity(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, iotsecurity.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var body sensorSecurityRequest
	err := decoder.Decode(&body)
	if err == nil {
		var trailing any
		if trailingErr := decoder.Decode(&trailing); !errors.Is(trailingErr, io.EOF) {
			if trailingErr != nil {
				err = trailingErr
			} else {
				err = errors.New("multiple JSON values")
			}
		}
	}
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]any{"error": "invalid or oversized security observation JSON"})
		return
	}
	if strings.TrimSpace(body.SensorID) == "" || body.Observations == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sensor_id and observations are required"})
		return
	}
	sensorID, ok := s.requireAuthenticatedSensorID(w, r, body.SensorID, r.Header.Get("X-Sensor-ID"))
	if !ok {
		return
	}
	if err := iotsecurity.ValidateBatch(body.Observations); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	for _, observation := range body.Observations {
		if observation.Timestamp.After(now.Add(maxTimestampSkew)) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "observation timestamp exceeds permitted future clock skew"})
			return
		}
	}

	events := make([]models.Event, 0, len(body.Observations))
	for _, observation := range body.Observations {
		metadata, err := json.Marshal(map[string]any{"iot_observation": observation})
		if err != nil {
			// Validated observations contain only JSON-safe, bounded fields.
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid security observation"})
			return
		}
		events = append(events, models.Event{
			EventID:   sensorSecurityEventID(sensorID, observation.ObservationID),
			Timestamp: observation.Timestamp.UTC(), EventType: "anomaly",
			SourceIP:       net.ParseIP(observation.SubjectIP).String(),
			NetworkSegment: "default", Tags: []string{}, Metadata: string(metadata),
		})
	}
	// All records passed validation before any event is sent to the processor.
	// Event IDs depend only on authenticated sensor and occurrence ID: altered
	// content under a previously accepted ID cannot create a second occurrence.
	summary := s.processEvents(r.Context(), events, "sensor_security", sensorID)
	response := map[string]any{
		"accepted": summary.Inserted, "duplicates": summary.Duplicates, "failed": summary.Failed,
	}
	healthID := "sensor_security:" + sensorID
	if summary.Failed > 0 {
		_ = s.DB.MarkCollectionError(r.Context(), healthID, "sensor_security", "Sensor security "+sensorID, "security observation processing failed", now)
		response["error"] = "security observation persistence failed; retry the same observation IDs"
		writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}
	_ = s.DB.TouchSensor(sensorID)
	_ = s.DB.MarkCollectionSuccess(r.Context(), healthID, "sensor_security", "Sensor security "+sensorID, int64(summary.Inserted+summary.Duplicates), now)
	writeJSON(w, http.StatusOK, response)
}

func sensorSecurityEventID(sensorID, observationID string) string {
	return eventid.Deterministic("sensor_security", sensorID, time.Time{}, struct {
		ObservationID string `json:"observation_id"`
	}{ObservationID: observationID})
}
