package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

var errInvalidReadOnlySensorCredential = errors.New("invalid read-only sensor credential")

func (s *Server) readOnlySensorToken(r *http.Request) (*auth.Token, error) {
	if s.DB == nil {
		return nil, fmt.Errorf("database not available")
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
		return nil, auth.ErrInvalidAuthorizationHeader
	}
	token, err := s.DB.GetTokenByHash(auth.HashToken(strings.TrimSpace(parts[1])))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errInvalidReadOnlySensorCredential
	}
	if err != nil {
		return nil, fmt.Errorf("look up sensor token: %w", err)
	}
	if token.Revoked {
		return nil, errInvalidReadOnlySensorCredential
	}
	return token, nil
}

// validateReadOnlySensorRequest enforces the same identity lifecycle as normal
// sensor authorization without touching api_tokens.last_used. Every caller error
// intentionally collapses to one sentinel so the endpoint cannot be used as a
// token/sensor existence oracle; database failures remain distinguishable for a
// generic service-unavailable response.
func (s *Server) validateReadOnlySensorRequest(r *http.Request) error {
	token, err := s.readOnlySensorToken(r)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAuthorizationHeader) || errors.Is(err, auth.ErrMissingAuthorizationHeader) {
			return errInvalidReadOnlySensorCredential
		}
		return err
	}
	reportedSensorID, err := canonicalSensorID(r.Header.Get("X-Sensor-ID"))
	if err != nil || reportedSensorID == "" || token.Scope != auth.ScopeSensor || token.SensorID == "" || token.SensorID != reportedSensorID {
		return errInvalidReadOnlySensorCredential
	}
	active, err := s.DB.SensorActive(token.SensorID)
	if err != nil {
		return fmt.Errorf("verify sensor identity: %w", err)
	}
	if !active {
		return errInvalidReadOnlySensorCredential
	}
	return nil
}

// sensorRegistrationResponse returns the one-time bearer credential minted during initial sensor bootstrap.
// auth_token is only populated when Core creates a new sensor-scoped token; authenticated re-registration
// updates sensor metadata without repeating the secret.
type sensorRegistrationResponse struct {
	Status        string `json:"status"`
	SensorID      string `json:"sensor_id"`
	AuthToken     string `json:"auth_token,omitempty"`
	TokenID       string `json:"token_id,omitempty"`
	TokenWarning  string `json:"token_warning,omitempty"`
	DeliveryEpoch string `json:"delivery_epoch,omitempty"`
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
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return "", false
	}
	active, err := s.DB.SensorActive(token.SensorID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to verify sensor identity"})
		return "", false
	}
	if !active {
		// Defense in depth for legacy/manual token rows: removal remains effective
		// even if a sensor credential exists outside the provisioning path.
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "sensor identity is not active"})
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
