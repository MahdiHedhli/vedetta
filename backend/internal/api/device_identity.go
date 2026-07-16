package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func (s *Server) handleListDeviceMerges(w http.ResponseWriter, r *http.Request) {
	actions, err := s.DB.ListActiveDeviceMerges(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list device merge audit"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleConfirmDeviceIdentity(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	var body struct {
		Evidence   store.DeviceIdentityEvidenceInput `json:"evidence"`
		Segment    string                            `json:"segment"`
		SensorID   string                            `json:"sensor_id"`
		Reason     string                            `json:"reason"`
		ObservedAt *time.Time                        `json:"observed_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	kind := strings.ToLower(strings.TrimSpace(body.Evidence.Type))
	if !operatorIdentityEvidenceType(kind) || strings.TrimSpace(body.Evidence.Value) == "" || len(body.Evidence.Value) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "a supported identity evidence type and value are required"})
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "confirmation reason is required"})
		return
	}
	body.Evidence.Type = kind
	body.Evidence.Source = "operator"
	observedAt := time.Now().UTC()
	if body.ObservedAt != nil {
		observedAt = body.ObservedAt.UTC()
	}
	action, err := s.DB.ConfirmDeviceIdentity(r.Context(), deviceID, body.Evidence,
		body.Segment, body.SensorID, requestActor(r), body.Reason, observedAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"action": action})
}

func (s *Server) handleMergeDevices(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SourceDeviceID string `json:"source_device_id"`
		TargetDeviceID string `json:"target_device_id"`
		Reason         string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.SourceDeviceID) == "" || strings.TrimSpace(body.TargetDeviceID) == "" || strings.TrimSpace(body.Reason) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "source_device_id, target_device_id, and reason are required"})
		return
	}
	action, err := s.DB.MergeDevices(r.Context(), body.SourceDeviceID, body.TargetDeviceID, body.Reason, requestActor(r))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"action": action})
}

func (s *Server) handleUndoDeviceMerge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "split reason is required"})
		return
	}
	action, err := s.DB.UndoDeviceMerge(r.Context(), chi.URLParam(r, "actionID"), body.Reason, requestActor(r))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"action": action})
}

func operatorIdentityEvidenceType(kind string) bool {
	switch kind {
	case "dhcp_client_id", "dhcp_option_55", "ssdp_uuid", "ssdp_device_type",
		"mdns_name", "mdns_service", "hostname", "mac":
		return true
	default:
		return false
	}
}

func sensorIdentityEvidenceType(kind string) bool {
	if operatorIdentityEvidenceType(kind) {
		return true
	}
	switch kind {
	case "mdns_txt_model", "mdns_txt_vendor", "mdns_txt_id", "ssdp_server_token":
		return true
	default:
		return false
	}
}
