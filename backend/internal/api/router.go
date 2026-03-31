package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// Server holds dependencies for all API handlers.
type Server struct {
	DB          *store.DB
	Scheduler   *discovery.Scheduler
	Enricher    *dnsintel.Enricher
	ScanQueue   *ScanQueue
	ActivityLog *ActivityLog
}

// NewRouter creates the main API router with all routes mounted.
func NewRouter(srv *Server) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/healthz"))

	frontendDir := os.Getenv("VEDETTA_FRONTEND_DIR")
	if frontendDir == "" {
		frontendDir = "./frontend/dist"
	}

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/status", srv.handleStatus)
		r.Get("/events", srv.handleEvents)
		r.Get("/events/stats", srv.handleEventStats)
		r.Get("/events/timeline", srv.handleEventTimeline)
		r.Post("/ingest", srv.handleIngest)

		// Device discovery
		r.Get("/devices", srv.handleListDevices)
		r.Get("/devices/new", srv.handleNewDevices)

		// Scanning
		r.Post("/scan", srv.handleTriggerScan)
		r.Get("/scan/status", srv.handleScanStatus)
		r.Get("/scan/subnets", srv.handleDetectSubnets)
		r.Put("/scan/cidr", srv.handleSetDefaultCIDR)

		// Custom scan targets
		r.Get("/scan/targets", srv.handleListTargets)
		r.Post("/scan/targets", srv.handleCreateTarget)
		r.Delete("/scan/targets/{targetID}", srv.handleDeleteTarget)
		r.Put("/scan/targets/{targetID}/toggle", srv.handleToggleTarget)
		r.Post("/scan/targets/{targetID}/scan", srv.handleScanTarget)

		// Sensor ingest (native sensors push data to Core)
		r.Post("/sensor/register", srv.handleSensorRegister)
		r.Post("/sensor/devices", srv.handleSensorDevices)
		r.Get("/sensor/list", srv.handleSensorList)
		r.Get("/sensor/work", srv.handleSensorWork)
		r.Put("/sensor/{sensorID}/primary", srv.handleSetPrimarySensor)

		// Activity log
		r.Get("/logs", srv.handleLogs)
	})

	// Static file server for the React frontend
	fileServer := http.FileServer(http.Dir(frontendDir))
	r.Handle("/*", fileServer)

	return r
}

// --- Status ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	deviceCount := 0
	sensorCount := 0
	eventCount := 0
	if s.DB != nil {
		deviceCount, _ = s.DB.CountDevices()
		eventCount, _ = s.DB.CountEvents()
		if sensors, err := s.DB.ListSensors(); err == nil {
			sensorCount = len(sensors)
		}
	}

	scanStatus := discovery.ScanStatus{}
	defaultCIDR := ""
	if s.Scheduler != nil {
		scanStatus = s.Scheduler.Status()
		defaultCIDR = s.Scheduler.DefaultCIDR()
	}

	// Fall back to the primary sensor's CIDR if no local scheduler
	if defaultCIDR == "" && s.DB != nil {
		if primary, err := s.DB.GetPrimarySensor(); err == nil {
			defaultCIDR = primary.CIDR
		} else if sensors, err := s.DB.ListSensors(); err == nil && len(sensors) > 0 {
			defaultCIDR = sensors[0].CIDR // fallback: most recent sensor
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      "0.1.0-dev",
		"service":      "vedetta-core",
		"device_count": deviceCount,
		"event_count":  eventCount,
		"sensor_count": sensorCount,
		"scan":         scanStatus,
		"default_cidr": defaultCIDR,
	})
}

// --- Event Ingest ---

// Allowed event types (matches the CHECK constraint in 001_init.sql).
var allowedEventTypes = map[string]bool{
	"dns_query":      true,
	"nmap_discovery": true,
	"firewall_log":   true,
	"anomaly":        true,
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	// Read body (limit to 10MB to prevent abuse)
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to read body"})
		return
	}

	// Parse: accept both a single event object and an array of events.
	// Also handle Fluent Bit's HTTP output format: array of [timestamp, record] pairs.
	var events []models.Event

	// Try array first
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty body"})
		return
	}

	if trimmed[0] == '[' {
		// Could be an array of events or Fluent Bit [timestamp, record] pairs
		var rawArray []json.RawMessage
		if err := json.Unmarshal(body, &rawArray); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON array"})
			return
		}

		for _, raw := range rawArray {
			// Try as a normal event object
			var evt models.Event
			if err := json.Unmarshal(raw, &evt); err == nil && evt.EventType != "" {
				events = append(events, evt)
				continue
			}

			// Try as Fluent Bit [timestamp, record] pair
			var pair []json.RawMessage
			if err := json.Unmarshal(raw, &pair); err == nil && len(pair) == 2 {
				var evt models.Event
				if err := json.Unmarshal(pair[1], &evt); err == nil && evt.EventType != "" {
					events = append(events, evt)
				}
			}
		}
	} else if trimmed[0] == '{' {
		// Single event object
		var evt models.Event
		if err := json.Unmarshal(body, &evt); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON object"})
			return
		}
		events = append(events, evt)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "expected JSON object or array"})
		return
	}

	// Validate and assign defaults
	accepted := make([]models.Event, 0, len(events))
	rejected := 0
	for _, e := range events {
		// Validate event_type
		if !allowedEventTypes[e.EventType] {
			rejected++
			continue
		}

		// Assign event_id if missing
		if e.EventID == "" {
			e.EventID = uuid.New().String()
		}

		// Assign timestamp if missing or zero
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}

		// Default source_hash
		if e.SourceHash == "" {
			e.SourceHash = "unknown"
		}

		// Clamp anomaly_score
		if e.AnomalyScore < 0 {
			e.AnomalyScore = 0
		}
		if e.AnomalyScore > 1 {
			e.AnomalyScore = 1
		}

		// Default tags
		if e.Tags == nil {
			e.Tags = []string{}
		}

		// Default network_segment
		if e.NetworkSegment == "" {
			e.NetworkSegment = "default"
		}

		accepted = append(accepted, e)
	}

	// Enrich events with threat intelligence and DNS detection
	if s.Enricher != nil {
		for i := range accepted {
			s.Enricher.Enrich(&accepted[i])
		}
	}

	// Insert
	inserted, err := s.DB.InsertEvents(accepted)
	if err != nil {
		log.Printf("Ingest error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":    "insert failed",
			"accepted": 0,
			"rejected": len(events),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": inserted,
		"rejected": rejected + (len(accepted) - inserted),
	})
}

// --- Event Query ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	q := r.URL.Query()
	params := store.EventQueryParams{
		Type:   q.Get("type"),
		Source: q.Get("source"),
		Domain: q.Get("domain"),
		Sort:   q.Get("sort"),
		Order:  q.Get("order"),
	}

	// Time range
	if from := q.Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			params.From = &t
		}
	}
	if to := q.Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			params.To = &t
		}
	}

	// Tags
	if tags := q.Get("tags"); tags != "" {
		params.Tags = strings.Split(tags, ",")
	}

	// Min score
	if ms := q.Get("min_score"); ms != "" {
		if score, err := strconv.ParseFloat(ms, 64); err == nil {
			params.MinScore = &score
		}
	}

	// Pagination
	if p := q.Get("page"); p != "" {
		params.Page, _ = strconv.Atoi(p)
	}
	if l := q.Get("limit"); l != "" {
		params.Limit, _ = strconv.Atoi(l)
	}

	result, err := s.DB.QueryEvents(params)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// CSV export
	if q.Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=events.csv")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("event_id,timestamp,event_type,source_hash,domain,query_type,resolved_ip,blocked,anomaly_score,tags,geo,device_vendor,network_segment\n"))
		for _, e := range result.Events {
			tagsStr := strings.Join(e.Tags, ";")
			line := strings.Join([]string{
				e.EventID, e.Timestamp.Format(time.RFC3339), e.EventType, e.SourceHash,
				e.Domain, e.QueryType, e.ResolvedIP, strconv.FormatBool(e.Blocked),
				strconv.FormatFloat(e.AnomalyScore, 'f', 4, 64), tagsStr, e.Geo,
				e.DeviceVendor, e.NetworkSegment,
			}, ",")
			w.Write([]byte(line + "\n"))
		}
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// --- Event Stats and Timeline ---

func (s *Server) handleEventStats(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	stats, err := s.DB.GetEventStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleEventTimeline(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	timeline, err := s.DB.GetEventTimeline()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	if timeline == nil {
		timeline = []store.TimelineEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"timeline": timeline,
	})
}

// --- Device Discovery ---

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	devices, err := s.DB.ListDevices()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"total":   len(devices),
	})
}

func (s *Server) handleNewDevices(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	since := 24 * time.Hour
	devices, err := s.DB.GetNewDevices(since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"total":   len(devices),
		"since":   since.String(),
	})
}

// --- Scanning ---

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if s.Scheduler != nil {
		// Built-in scanner available (nmap in Docker)
		status := s.Scheduler.Status()
		if status.Running {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "scan already in progress"})
			return
		}
		s.Scheduler.RunNow()
		writeJSON(w, http.StatusAccepted, map[string]any{"message": "scan triggered"})
		return
	}

	// No built-in scanner; queue for sensor pickup
	if s.ScanQueue == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}

	// Queue all enabled targets for the next sensor pickup
	if s.DB != nil {
		if targets, err := s.DB.GetEnabledScanTargets(); err == nil && len(targets) > 0 {
			for _, target := range targets {
				s.ScanQueue.Enqueue(target.CIDR, target.Segment, target.ScanPorts)
			}
			s.logInfo("scan", fmt.Sprintf("Queued %d scan targets for next sensor pickup", len(targets)))
			writeJSON(w, http.StatusAccepted, map[string]any{
				"message": fmt.Sprintf("queued %d targets for next sensor pickup", len(targets)),
			})
			return
		}
	}

	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error": "no default CIDR configured and no targets enabled; please create a scan target",
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if s.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}
	writeJSON(w, http.StatusOK, s.Scheduler.Status())
}

func (s *Server) handleDetectSubnets(w http.ResponseWriter, r *http.Request) {
	subnets, err := discovery.DetectSubnets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subnets":          subnets,
		"inside_container": discovery.IsInsideDocker(),
	})
}

func (s *Server) handleSetDefaultCIDR(w http.ResponseWriter, r *http.Request) {
	if s.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}

	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil || body.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cidr required"})
		return
	}

	s.Scheduler.SetDefaultCIDR(body.CIDR)
	writeJSON(w, http.StatusOK, map[string]any{"default_cidr": body.CIDR})
}

// --- Custom Scan Targets ---

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	targets, err := s.DB.ListScanTargets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"targets": targets,
		"total":   len(targets),
	})
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	var body struct {
		Name      string `json:"name"`
		CIDR      string `json:"cidr"`
		Segment   string `json:"segment"`
		ScanPorts bool   `json:"scan_ports"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.Name == "" || body.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name and cidr required"})
		return
	}
	if body.Segment == "" {
		body.Segment = "default"
	}

	target, err := s.DB.CreateScanTarget(body.Name, body.CIDR, body.Segment, body.ScanPorts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	s.logInfo("scan", fmt.Sprintf("Scan target created: %s (%s) segment=%s", body.Name, body.CIDR, body.Segment))
	writeJSON(w, http.StatusCreated, target)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	targetID := chi.URLParam(r, "targetID")
	if err := s.DB.DeleteScanTarget(targetID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleToggleTarget(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	targetID := chi.URLParam(r, "targetID")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	if err := s.DB.ToggleScanTarget(targetID, body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}

func (s *Server) handleScanTarget(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	targetID := chi.URLParam(r, "targetID")

	// Look up the target
	targets, err := s.DB.ListScanTargets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	var target *models.ScanTarget
	for i := range targets {
		if targets[i].TargetID == targetID {
			target = &targets[i]
			break
		}
	}

	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "target not found"})
		return
	}

	// If built-in scanner is available, use it
	if s.Scheduler != nil {
		status := s.Scheduler.Status()
		if status.Running {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "scan already in progress"})
			return
		}
		s.Scheduler.RunTarget(target.CIDR, target.Segment, target.ScanPorts)
	} else if s.ScanQueue != nil {
		// No built-in scanner; queue for sensor pickup
		s.ScanQueue.Enqueue(target.CIDR, target.Segment, target.ScanPorts)
	} else {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"message": "scan queued",
		"target":  target.Name,
		"cidr":    target.CIDR,
	})
}

// --- Sensor Ingest ---

func (s *Server) handleSensorRegister(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	var body struct {
		SensorID  string `json:"sensor_id"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		CIDR      string `json:"cidr"`
		Version   string `json:"version"`
		IsPrimary bool   `json:"is_primary"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.SensorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sensor_id required"})
		return
	}

	sensor := models.Sensor{
		SensorID:  body.SensorID,
		Hostname:  body.Hostname,
		OS:        body.OS,
		Arch:      body.Arch,
		CIDR:      body.CIDR,
		Version:   body.Version,
		IsPrimary: body.IsPrimary,
	}

	if err := s.DB.RegisterSensor(sensor); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	log.Printf("Sensor registered: %s (%s/%s) scanning %s", body.SensorID, body.OS, body.Arch, body.CIDR)
	s.logInfo("sensor", fmt.Sprintf("Sensor registered: %s (%s/%s) scanning %s", body.SensorID, body.OS, body.Arch, body.CIDR))
	writeJSON(w, http.StatusOK, map[string]any{"status": "registered", "sensor_id": body.SensorID})
}

func (s *Server) handleSensorDevices(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	var body struct {
		SensorID string `json:"sensor_id"`
		CIDR     string `json:"cidr"`
		Segment  string `json:"segment"`
		Hosts    []struct {
			IPAddress  string `json:"ip_address"`
			MACAddress string `json:"mac_address"`
			Hostname   string `json:"hostname"`
			Vendor     string `json:"vendor"`
			OpenPorts  []int  `json:"open_ports"`
			Status     string `json:"status"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	if body.Segment == "" {
		body.Segment = "default"
	}

	// Touch the sensor's last_seen
	if body.SensorID != "" {
		s.DB.TouchSensor(body.SensorID)
	}

	// Upsert each discovered host
	now := time.Now()
	newCount := 0
	for _, h := range body.Hosts {
		host := discovery.DiscoveredHost{
			IPAddress:  h.IPAddress,
			MACAddress: h.MACAddress,
			Hostname:   h.Hostname,
			Vendor:     h.Vendor,
			OpenPorts:  h.OpenPorts,
			Status:     h.Status,
		}
		isNew, err := s.DB.UpsertDevice(host, now, body.Segment)
		if err != nil {
			log.Printf("Failed to upsert device %s from sensor %s: %v", h.IPAddress, body.SensorID, err)
			continue
		}
		if isNew {
			newCount++
			log.Printf("New device [%s] via sensor %s: %s (%s)", body.Segment, body.SensorID, h.IPAddress, h.MACAddress)
		}
	}

	log.Printf("Sensor %s reported %d hosts (%d new) from %s", body.SensorID, len(body.Hosts), newCount, body.CIDR)
	s.logInfo("scan", fmt.Sprintf("Sensor %s reported %d hosts (%d new) from %s [%s]", body.SensorID, len(body.Hosts), newCount, body.CIDR, body.Segment))
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":    len(body.Hosts),
		"new_devices": newCount,
	})
}

func (s *Server) handleSensorList(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	sensors, err := s.DB.ListSensors()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sensors": sensors,
		"total":   len(sensors),
	})
}

func (s *Server) handleSensorWork(w http.ResponseWriter, r *http.Request) {
	sensorID := r.Header.Get("X-Sensor-ID")
	response := map[string]any{
		"scan_queue": []ScanRequest{},
		"targets":    []models.ScanTarget{},
	}

	// Drain pending scan requests
	var queuedScans []ScanRequest
	if s.ScanQueue != nil {
		queuedScans = s.ScanQueue.Drain()
		response["scan_queue"] = queuedScans
	}

	// Get enabled scan targets for auto-scanning
	var targetCount int
	if s.DB != nil {
		targets, err := s.DB.GetEnabledScanTargets()
		if err == nil {
			response["targets"] = targets
			targetCount = len(targets)
		}
	}

	if len(queuedScans) > 0 || targetCount > 0 {
		s.logInfo("sensor", fmt.Sprintf("Sensor %s fetched work: %d queued scans, %d targets", sensorID, len(queuedScans), targetCount))
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSetPrimarySensor(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	sensorID := chi.URLParam(r, "sensorID")
	if sensorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sensor_id required"})
		return
	}

	if err := s.DB.SetPrimarySensor(sensorID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	log.Printf("Primary sensor changed to: %s", sensorID)
	writeJSON(w, http.StatusOK, map[string]any{"primary": sensorID})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	var entries []LogEntry
	if s.ActivityLog != nil {
		entries = s.ActivityLog.Recent(limit)
	}
	if entries == nil {
		entries = []LogEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"logs": entries})
}

// logActivity is a nil-safe helper.
func (s *Server) logInfo(category, message string) {
	if s.ActivityLog != nil {
		s.ActivityLog.Info(category, message)
	}
}

func (s *Server) logWarn(category, message string) {
	if s.ActivityLog != nil {
		s.ActivityLog.Warn(category, message)
	}
}

func (s *Server) logError(category, message string) {
	if s.ActivityLog != nil {
		s.ActivityLog.Error(category, message)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
