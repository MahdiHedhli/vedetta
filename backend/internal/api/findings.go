package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}
	q := r.URL.Query()
	params := store.FindingQueryParams{
		DeviceID: q.Get("device_id"), Page: positiveInt(q.Get("page"), 1), Limit: positiveInt(q.Get("limit"), 50),
	}
	if raw := strings.ToLower(strings.TrimSpace(q.Get("status"))); raw != "" {
		if raw == "active" {
			params.ActiveOnly = true
		} else {
			params.Status = models.FindingStatus(raw)
			if params.Status != models.FindingStatusOpen && params.Status != models.FindingStatusInvestigating && params.Status != models.FindingStatusResolved {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid finding status"})
				return
			}
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(q.Get("priority"))); raw != "" {
		params.Priority = models.Priority(raw)
		if params.Priority != models.PriorityCritical && params.Priority != models.PriorityHigh && params.Priority != models.PriorityMedium && params.Priority != models.PriorityLow {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid priority"})
			return
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(q.Get("disposition"))); raw != "" {
		params.Disposition = models.FindingDisposition(raw)
		if params.Disposition != models.DispositionActive && params.Disposition != models.DispositionSuppressed {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid disposition"})
			return
		}
	}

	result, err := s.DB.QueryFindings(r.Context(), params)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not query findings"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "findingID")
	finding, err := s.DB.GetFinding(r.Context(), id)
	if errors.Is(err, store.ErrFindingNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "finding not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load finding"})
		return
	}
	evidenceLimit := positiveInt(r.URL.Query().Get("evidence_limit"), 100)
	evidenceOffset := nonNegativeInt(r.URL.Query().Get("evidence_offset"), 0)
	evidence, err := s.DB.FindingEvidencePage(r.Context(), id, evidenceLimit, evidenceOffset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load finding evidence"})
		return
	}
	history, err := s.DB.FindingStatusHistory(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load finding history"})
		return
	}
	limit := positiveInt(r.URL.Query().Get("event_limit"), 100)
	offset := nonNegativeInt(r.URL.Query().Get("event_offset"), 0)
	events, err := s.DB.FindingSupportingEvents(r.Context(), id, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load supporting events"})
		return
	}
	evidenceTotal, _ := s.DB.CountFindingEvidence(r.Context(), id)
	eventTotal, _ := s.DB.CountFindingEvents(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{
		"finding": finding, "evidence": evidence, "status_history": history,
		"evidence_total": evidenceTotal, "evidence_limit": evidenceLimit, "evidence_offset": evidenceOffset,
		"supporting_events": events, "supporting_event_total": eventTotal,
		"supporting_event_limit": limit, "supporting_event_offset": offset,
	})
}

func (s *Server) handleFindingStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.DB.GetFindingStats(r.Context(), 7*24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not calculate finding stats"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	id := chi.URLParam(r, "findingID")
	err := s.DB.UpdateFindingStatus(r.Context(), id, models.FindingStatus(strings.ToLower(strings.TrimSpace(body.Status))), body.Reason, requestActor(r))
	switch {
	case errors.Is(err, store.ErrFindingNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "finding not found"})
		return
	case errors.Is(err, store.ErrInvalidFindingStatus), errors.Is(err, store.ErrResolutionReasonRequired):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not update finding"})
		return
	}
	finding, err := s.DB.GetFinding(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "finding updated but could not be reloaded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": finding})
}

func (s *Server) handleSuppressFinding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	findingID := chi.URLParam(r, "findingID")
	rule, err := s.DB.SuppressFinding(r.Context(), findingID, body.Reason, requestActor(r))
	switch {
	case errors.Is(err, store.ErrFindingNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "finding not found"})
		return
	case errors.Is(err, store.ErrFindingSuppressionReasonRequired):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not suppress finding"})
		return
	}
	finding, err := s.DB.GetFinding(r.Context(), findingID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "finding suppressed but could not be reloaded"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"finding": finding, "rule": rule})
}

func (s *Server) handleListFindingSuppressions(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DB.ListFindingSuppressionRules(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list finding suppression rules"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleDeleteFindingSuppression(w http.ResponseWriter, r *http.Request) {
	affected, err := s.DB.DeactivateFindingSuppression(r.Context(), chi.URLParam(r, "ruleID"), requestActor(r))
	if errors.Is(err, store.ErrFindingSuppressionNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "finding suppression rule not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not deactivate finding suppression"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deactivated": true, "affected_findings": affected})
}

type detectionHealthActor struct {
	ID          string     `json:"id,omitempty"`
	Name        string     `json:"name"`
	State       string     `json:"state"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	EventCount  *int64     `json:"event_count,omitempty"`
	ItemCount   *int       `json:"item_count,omitempty"`
	Error       string     `json:"error,omitempty"`
}

func (s *Server) handleDetectionHealth(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}
	stored, err := s.DB.ListCollectionSourceHealth(r.Context(), 5*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read collection health"})
		return
	}
	sourceMap := map[string]detectionHealthActor{}
	for _, source := range stored {
		count := source.ItemCount
		sourceMap[source.SourceID] = detectionHealthActor{
			ID: source.SourceID, Name: firstNonEmptyString(source.DisplayName, source.SourceID),
			State: source.Status, LastAttempt: source.LastAttempt, LastSuccess: source.LastSuccess,
			EventCount: &count, Error: source.Error,
		}
	}
	// Sensor work polling proves the process can reach Core, but it cannot prove
	// packet capture or event delivery is healthy. Until the sensor commits its
	// first event batch, expose it as initializing rather than letting a heartbeat
	// produce a misleading green empty state.
	if sensors, listErr := s.DB.ListSensors(); listErr == nil {
		now := time.Now().UTC()
		for _, sensor := range sensors {
			last := sensor.LastSeen.UTC()
			state := "healthy"
			if last.IsZero() {
				state = "initializing"
			} else if now.Sub(last) > store.SensorOnlineWindow {
				state = "stale"
			}
			var attempt *time.Time
			if !last.IsZero() {
				attempt = &last
			}
			id := "sensor:" + sensor.SensorID
			heartbeat := detectionHealthActor{
				ID: "sensor:" + sensor.SensorID, Name: "Sensor " + sensor.Hostname,
				State: state, LastAttempt: attempt,
			}
			if persisted, ok := sourceMap[id]; ok {
				// A live work-poll heartbeat proves the sensor process is reachable;
				// it does not prove that its most recent event batch committed. Preserve
				// the worse of transport/heartbeat and persisted processing health.
				sourceMap[id] = mergeDetectionHealthActors(persisted, heartbeat)
			} else {
				if heartbeat.State == "healthy" {
					heartbeat.State = "initializing"
				}
				sourceMap[id] = heartbeat
			}
		}
	}
	if s.Firewall != nil {
		now := time.Now().UTC()
		for _, connector := range s.Firewall.ListNamed() {
			health := connector.Health
			state := "healthy"
			switch {
			case health.LastError != "" || !health.Connected:
				state = "error"
			case health.LastPoll.IsZero():
				state = "initializing"
			case now.Sub(health.LastPoll) > 3*time.Minute:
				state = "stale"
			}
			last := health.LastPoll.UTC()
			var success *time.Time
			if !last.IsZero() {
				success = &last
			}
			count := health.EventCount
			sourceMap["firewall:"+connector.Name] = detectionHealthActor{
				ID: "firewall:" + connector.Name, Name: connector.Name + " firewall",
				State: state, LastSuccess: success, EventCount: &count, Error: health.LastError,
			}
		}
	}
	sources := make([]detectionHealthActor, 0, len(sourceMap))
	for _, source := range sourceMap {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })

	feeds := []detectionHealthActor{}
	if s.FeedHealth == nil {
		feeds = append(feeds, detectionHealthActor{Name: "Threat intelligence", State: "error", Error: "feed scheduler unavailable"})
	} else {
		for _, feed := range s.FeedHealth.Status() {
			count := feed.ItemCount
			feeds = append(feeds, detectionHealthActor{
				ID: feed.Name, Name: feed.Name, State: feed.State, LastAttempt: feed.LastAttempt,
				LastSuccess: feed.LastSuccess, ItemCount: &count, Error: feed.LastError,
			})
		}
	}

	state := aggregateDetectionHealth(sources, feeds)
	// Avoid MAX(timestamp): SQLite drops the declared TIMESTAMP type through an
	// aggregate and the driver returns a string that cannot scan into NullTime.
	var lastEvent time.Time
	lastEventErr := s.DB.QueryRowContext(r.Context(), `SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1`).Scan(&lastEvent)
	var lastEventAt any
	if lastEventErr == nil {
		lastEventAt = lastEvent.UTC()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state": state, "last_event_at": lastEventAt, "sources": sources, "feeds": feeds,
	})
}

func aggregateDetectionHealth(sources, feeds []detectionHealthActor) string {
	if len(sources) == 0 {
		return "initializing"
	}
	if len(feeds) == 0 {
		return "error"
	}
	worst := "healthy"
	for _, actor := range append(append([]detectionHealthActor{}, sources...), feeds...) {
		state := normalizedDetectionHealthState(actor.State)
		if detectionHealthStateRank(state) > detectionHealthStateRank(worst) {
			worst = state
		}
	}
	return worst
}

func mergeDetectionHealthActors(persisted, heartbeat detectionHealthActor) detectionHealthActor {
	persisted.State = normalizedDetectionHealthState(persisted.State)
	heartbeat.State = normalizedDetectionHealthState(heartbeat.State)
	if detectionHealthStateRank(persisted.State) >= detectionHealthStateRank(heartbeat.State) {
		// Keep the processing timestamps/error/count, but prefer the current sensor
		// label so renames do not leave a stale display name behind.
		persisted.ID = heartbeat.ID
		persisted.Name = heartbeat.Name
		return persisted
	}
	// The heartbeat is worse (normally stale). Retain the last committed batch
	// diagnostics without replacing the process heartbeat timestamp.
	heartbeat.EventCount = persisted.EventCount
	heartbeat.LastSuccess = persisted.LastSuccess
	if heartbeat.LastAttempt == nil {
		heartbeat.LastAttempt = persisted.LastAttempt
	}
	return heartbeat
}

func normalizedDetectionHealthState(state string) string {
	state = strings.ToLower(strings.TrimSpace(state))
	switch state {
	case "healthy", "initializing", "stale", "error", "unauthorized":
		return state
	default:
		return "error"
	}
}

func detectionHealthStateRank(state string) int {
	switch normalizedDetectionHealthState(state) {
	case "healthy":
		return 0
	case "initializing":
		return 1
	case "stale":
		return 2
	case "error":
		return 3
	case "unauthorized":
		return 4
	default:
		return 3
	}
}

func requestActor(r *http.Request) string {
	if token := auth.GetTokenFromContext(r); token != nil && token.TokenID != "" {
		return "token:" + token.TokenID
	}
	return "bootstrap-admin"
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	if token := auth.GetTokenFromContext(r); token != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"scope": token.Scope, "authenticated": true, "can_admin": token.Scope == auth.ScopeAdmin,
		})
		return
	}
	// RequireRead permits the bootstrap window only while no active admin exists.
	writeJSON(w, http.StatusOK, map[string]any{
		"scope": "bootstrap", "authenticated": false, "can_admin": false,
	})
}

func positiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func nonNegativeInt(raw string, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "Source"
}
