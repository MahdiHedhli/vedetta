package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// sensorRegistrationResponse returns the one-time bearer credential minted during initial sensor bootstrap.
// auth_token is only populated when Core creates a new sensor-scoped token; authenticated re-registration
// updates sensor metadata without repeating the secret.
type sensorRegistrationResponse struct {
	Status       string `json:"status"`
	SensorID     string `json:"sensor_id"`
	AuthToken    string `json:"auth_token,omitempty"`
	TokenID      string `json:"token_id,omitempty"`
	TokenWarning string `json:"token_warning,omitempty"`
}

func (s *Server) requireAuthenticatedSensorID(w http.ResponseWriter, r *http.Request, ids ...string) (string, bool) {
	reportedSensorID, err := canonicalSensorID(ids...)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return "", false
	}

	token := auth.GetTokenFromContext(r)
	if token == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing authenticated sensor token"})
		return "", false
	}
	if token.Scope != auth.ScopeSensor {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "sensor scope required"})
		return "", false
	}
	if token.SensorID == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "sensor token is not bound to a sensor_id"})
		return "", false
	}
	if reportedSensorID != "" && token.SensorID != reportedSensorID {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "token does not match sensor_id"})
		return "", false
	}

	return token.SensorID, true
}

func canonicalSensorID(ids ...string) (string, error) {
	var sensorID string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if sensorID == "" {
			sensorID = id
			continue
		}
		if sensorID != id {
			return "", fmt.Errorf("conflicting sensor_id values in request")
		}
	}
	return sensorID, nil
}
