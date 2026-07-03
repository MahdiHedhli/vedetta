package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/vedetta-network/vedetta/backend/internal/auth"
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
	sensorRegistrationLimiter := newIPRateLimiter(5, time.Minute)

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
		r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":    "0.1.0-dev",
				"build_time": "2026-03-31T00:00:00Z",
				"routes":     []string{"/suppression", "/whitelist", "/events/{eventID}/ack", "/devices/{deviceID}"},
			})
		})
		r.Get("/events", srv.handleEvents)
		r.Get("/events/stats", srv.handleEventStats)
		r.Get("/events/timeline", srv.handleEventTimeline)
		r.Post("/ingest", srv.handleIngest)

		// Device discovery (reads are public for convenience during alpha; writes protected)
		r.Get("/devices", srv.handleListDevices)
		r.Get("/devices/new", srv.handleNewDevices)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Put("/devices/{deviceID}", srv.handleUpdateDevice)
		})

		// Event acknowledgment and suppression — protected (user intent / configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Put("/events/{eventID}/ack", srv.handleAckEvent)
			r.Delete("/events/{eventID}/ack", srv.handleUnackEvent)
			r.Get("/suppression", srv.handleListSuppression)
			r.Post("/suppression", srv.handleCreateSuppression)
			r.Delete("/suppression/{ruleID}", srv.handleDeleteSuppression)
		})

		// Known-traffic whitelist — protected (user configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Get("/whitelist", srv.handleListWhitelist)
			r.Post("/whitelist", srv.handleCreateWhitelist)
			r.Put("/whitelist/{ruleID}", srv.handleToggleWhitelist)
			r.Delete("/whitelist/{ruleID}", srv.handleDeleteWhitelist)
			r.Post("/whitelist/seed", srv.handleSeedWhitelist)
		})

		// Scanning & scan targets — protected (active scanning + configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Post("/scan", srv.handleTriggerScan)
			r.Put("/scan/cidr", srv.handleSetDefaultCIDR)
			r.Get("/scan/targets", srv.handleListTargets)
			r.Post("/scan/targets", srv.handleCreateTarget)
			r.Delete("/scan/targets/{targetID}", srv.handleDeleteTarget)
			r.Put("/scan/targets/{targetID}/toggle", srv.handleToggleTarget)
			r.Post("/scan/targets/{targetID}/scan", srv.handleScanTarget)
		})
		// Read-only scan status and subnet detection remain public for convenience
		r.Get("/scan/status", srv.handleScanStatus)
		r.Get("/scan/subnets", srv.handleDetectSubnets)

		// Authentication and token management
		r.Get("/auth/setup-status", srv.handleSetupStatus)
		r.Post("/auth/tokens", srv.handleCreateToken)

		// Token management (list/revoke) requires admin scope once auth is configured.
		// Bootstrap mode allows the first admin token to be created via POST above.
		r.Route("/auth", func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Get("/tokens", srv.handleListTokens)
			r.Delete("/tokens/{tokenID}", srv.handleRevokeToken)
		})

		// Sensor ingest (native sensors push data to Core)
		r.Route("/sensor", func(r chi.Router) {
			r.With(sensorRegistrationLimiter.Middleware).Post("/register", srv.handleSensorRegister)
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireStrictAuth(srv.DB))
				r.Use(auth.RequireExactScope(auth.ScopeSensor))
				r.Post("/devices", srv.handleSensorDevices)
				r.Post("/dns", srv.handleSensorDNS)
				r.Get("/work", srv.handleSensorWork)
			})

			// Dashboard-facing sensor management routes — now protected with admin auth.
			// In bootstrap mode (no tokens yet) they remain open for first-run setup.
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireAdmin(srv.DB))
				r.Get("/list", srv.handleSensorList)
				r.Put("/{sensorID}/primary", srv.handleSetPrimarySensor)
			})
		})

		// Activity log (protected — can contain operational details)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin(srv.DB))
			r.Get("/logs", srv.handleLogs)
		})

		// Simulation endpoints temporarily disabled while fixing sensor auth (will re-enable later)
		// if os.Getenv("VEDETTA_ALLOW_SIMULATION") == "true" { ... }
	})

	return r
}

// --- Simulation Handlers (only active when VEDETTA_ALLOW_SIMULATION=true) ---

type SimulateDNSRequest struct {
	Queries []struct {
		Domain      string `json:"domain"`
		QueryType   string `json:"query_type"`
		ClientIP    string `json:"client_ip"`
		ResponseIP  string `json:"response_ip"`
		Blocked     bool   `json:"blocked"`
		DeviceVendor string `json:"device_vendor,omitempty"`
		NetworkSegment string `json:"network_segment,omitempty"`
	} `json:"queries"`
}

func (s *Server) handleSimulateDNS(w http.ResponseWriter, r *http.Request) {
	var req SimulateDNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	var events []models.Event
	now := time.Now().UTC()

	for _, q := range req.Queries {
		event := models.Event{
			EventID:        uuid.New().String(),
			Timestamp:      now,
			EventType:      "dns_query",
			SourceHash:     "simulated-" + q.ClientIP,
			SourceIP:       q.ClientIP,
			Domain:         q.Domain,
			QueryType:      q.QueryType,
			ResolvedIP:     q.ResponseIP,
			Blocked:        q.Blocked,
			AnomalyScore:   0,
			Tags:           []string{},
			DeviceVendor:   q.DeviceVendor,
			NetworkSegment: q.NetworkSegment,
			DNSSource:      "simulation",
		}
		events = append(events, event)
	}

	if s.Enricher != nil {
		for i := range events {
			s.Enricher.Enrich(&events[i])
		}
	}

	inserted, err := s.DB.InsertEvents(events)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "insert failed", "details": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": inserted,
		"events":   events,
	})
}

type SimulateDevicesRequest struct {
	Devices []struct {
		IPAddress  string `json:"ip_address"`
		MACAddress string `json:"mac_address"`
		Hostname   string `json:"hostname"`
		Vendor     string `json:"vendor"`
		Segment    string `json:"segment"`
	} `json:"devices"`
}

func (s *Server) handleSimulateDevices(w http.ResponseWriter, r *http.Request) {
	var req SimulateDevicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	now := time.Now().UTC()
	inserted := 0

	for _, d := range req.Devices {
		host := discovery.DiscoveredHost{
			IPAddress:  d.IPAddress,
			MACAddress: d.MACAddress,
			Hostname:   d.Hostname,
			Vendor:     d.Vendor,
		}
		_, err := s.DB.UpsertDevice(host, now, d.Segment)
		if err == nil {
			inserted++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": inserted,
		"total":    len(req.Devices),
	})
}

// --- Status ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	deviceCount := 0
	sensorCount := 0
	eventCount := 0
	dnsEventCount := 0
	if s.DB != nil {
		deviceCount, _ = s.DB.CountDevices()
		eventCount, _ = s.DB.CountEvents()
		if sensors, err := s.DB.ListSensors(); err == nil {
			sensorCount = len(sensors)
		}
		// Collection health for long-running sensor validation
		dnsEventCount, _ = s.DB.CountEventsByType("dns_query")
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

	// Collection health summary for long-running sensor validation
	collectionHealth := map[string]any{
		"dns_events_received": dnsEventCount,
		"has_data":            dnsEventCount > 0,
	}

	// Real device inventory stats (for SNR / real-data monitoring)
	if s.DB != nil {
		new48h, _ := s.DB.CountDevicesNewSince(48 * time.Hour)
		iotCount, _ := s.DB.CountDevicesBySegment("iot")
		lastDevUpdate, _ := s.DB.GetLastDeviceUpdate()
		collectionHealth["device_count"] = deviceCount
		collectionHealth["new_devices_48h"] = new48h
		collectionHealth["iot_devices"] = iotCount
		if !lastDevUpdate.IsZero() {
			collectionHealth["last_device_update"] = lastDevUpdate.UTC().Format(time.RFC3339)
			collectionHealth["device_baseline_age_hours"] = time.Since(lastDevUpdate).Hours()
		}
	}

	// Beaconing detector state (for SNR observability during real collection)
	if s.Enricher != nil {
		collectionHealth["beacon_tracked_pairs"] = s.Enricher.BeaconEntryCount()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"version":           "0.1.0-dev",
		"service":           "vedetta-core",
		"device_count":      deviceCount,
		"event_count":       eventCount,
		"sensor_count":      sensorCount,
		"scan":              scanStatus,
		"default_cidr":      defaultCIDR,
		"collection_health": collectionHealth,
	})
}

// --- Event Ingest ---

// Allowed event types (matches the CHECK constraint in 001_init.sql).
var allowedEventTypes = map[string]bool{
	"dns_query":              true,
	"encrypted_dns_detected": true,
	"nmap_discovery":         true,
	"firewall_log":           true,
	"anomaly":                true,
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
		w.Write([]byte("event_id,timestamp,event_type,source_hash,source_ip,server_ip,domain,query_type,resolved_ip,blocked,anomaly_score,tags,geo,device_vendor,network_segment,dns_source,threat_desc,dns_answers,process\n"))
		for _, e := range result.Events {
			tagsStr := strings.Join(e.Tags, ";")
			answersStr := ""
			processStr := ""
			if e.Metadata != "" {
				var m map[string]any
				if json.Unmarshal([]byte(e.Metadata), &m) == nil {
					if ans, ok := m["dns_answers"].([]interface{}); ok {
						strs := []string{}
						for _, a := range ans {
							if s, ok := a.(string); ok {
								strs = append(strs, s)
							}
						}
						answersStr = strings.Join(strs, ";")
					}
					if p, ok := m["process"].(string); ok {
						processStr = p
					}
				}
			}
			line := strings.Join([]string{
				e.EventID, e.Timestamp.Format(time.RFC3339), e.EventType, e.SourceHash,
				e.SourceIP, e.ServerIP, e.Domain, e.QueryType, e.ResolvedIP, strconv.FormatBool(e.Blocked),
				strconv.FormatFloat(e.AnomalyScore, 'f', 4, 64), tagsStr, e.Geo,
				e.DeviceVendor, e.NetworkSegment, e.DNSSource, e.ThreatDesc, answersStr, processStr,
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
		Name         string `json:"name"`
		CIDR         string `json:"cidr"`
		Segment      string `json:"segment"`
		ScanPorts    bool   `json:"scan_ports"`
		DNSCapture   bool   `json:"dns_capture"`
		DNSInterface string `json:"dns_interface"`
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

	target, err := s.DB.CreateScanTarget(body.Name, body.CIDR, body.Segment, body.ScanPorts, body.DNSCapture, body.DNSInterface)
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
		SensorID   string          `json:"sensor_id"`
		Hostname   string          `json:"hostname"`
		OS         string          `json:"os"`
		Arch       string          `json:"arch"`
		CIDR       string          `json:"cidr"`
		Version    string          `json:"version"`
		IsPrimary  bool            `json:"is_primary"`
		Interfaces json.RawMessage `json:"interfaces"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 10240)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.SensorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sensor_id required"})
		return
	}

	existingToken, err := s.DB.HasActiveSensorToken(body.SensorID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check sensor token state"})
		return
	}

	var presentedToken *auth.Token
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		presentedToken, err = auth.ValidateAuthorizationHeader(s.DB, authHeader)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}
		if presentedToken.Scope != auth.ScopeSensor {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "sensor scope required"})
			return
		}
		if presentedToken.SensorID != body.SensorID {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "token does not match sensor_id"})
			return
		}
	}
	if existingToken && presentedToken == nil {
		// Recovery mode: user ran --reset on sensor side.
		// Revoke old tokens and force generation of a new one.
		log.Printf("Sensor %s re-registering without token (recovery mode) — revoking old tokens and issuing new one", body.SensorID)
		_ = s.DB.DeleteTokensBySensor(body.SensorID)
		existingToken = false  // force new token generation
	}

	// Store interfaces as JSON string
	interfacesStr := ""
	if len(body.Interfaces) > 0 {
		interfacesStr = string(body.Interfaces)
	}

	sensor := models.Sensor{
		SensorID:   body.SensorID,
		Hostname:   body.Hostname,
		OS:         body.OS,
		Arch:       body.Arch,
		CIDR:       body.CIDR,
		Version:    body.Version,
		IsPrimary:  body.IsPrimary,
		Interfaces: interfacesStr,
	}

	if err := s.DB.RegisterSensor(sensor); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	response := sensorRegistrationResponse{
		Status:   "registered",
		SensorID: body.SensorID,
	}
	if !existingToken {
		rawToken, token, err := auth.GenerateToken(auth.ScopeSensor, body.SensorID, "auto-generated-registration")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to generate sensor auth token"})
			return
		}
		if err := s.DB.CreateToken(token); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to store sensor auth token"})
			return
		}

		response.AuthToken = rawToken
		response.TokenID = token.TokenID
		response.TokenWarning = "save this token now — it will not be displayed again"
		log.Printf("Sensor token generated: %s (label: %s)", token.TokenID, token.Label)
	}

	log.Printf("Sensor registered: %s (%s/%s) scanning %s", body.SensorID, body.OS, body.Arch, body.CIDR)
	s.logInfo("sensor", fmt.Sprintf("Sensor registered: %s (%s/%s) scanning %s", body.SensorID, body.OS, body.Arch, body.CIDR))
	writeJSON(w, http.StatusOK, response)
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
			IPAddress       string   `json:"ip_address"`
			MACAddress      string   `json:"mac_address"`
			Hostname        string   `json:"hostname"`
			Vendor          string   `json:"vendor"`
			OpenPorts       []int    `json:"open_ports"`
			Status          string   `json:"status"`
			Model           string   `json:"model,omitempty"`
			Services        []string `json:"services,omitempty"`
			DiscoverySource string   `json:"discovery_source,omitempty"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	sensorID, ok := s.requireAuthenticatedSensorID(w, r, body.SensorID, r.Header.Get("X-Sensor-ID"))
	if !ok {
		return
	}
	body.SensorID = sensorID

	if body.Segment == "" {
		body.Segment = "default"
	}

	// Touch the sensor's last_seen
	if body.SensorID != "" {
		s.DB.TouchSensor(body.SensorID)
	}

	log.Printf("Sensor %s reported %d devices", body.SensorID, len(body.Hosts))

	// Upsert each discovered host
	now := time.Now()
	newCount := 0
	for _, h := range body.Hosts {
		host := discovery.DiscoveredHost{
			IPAddress:       h.IPAddress,
			MACAddress:      h.MACAddress,
			Hostname:        h.Hostname,
			Vendor:          h.Vendor,
			OpenPorts:       h.OpenPorts,
			Status:          h.Status,
			Model:           h.Model,
			Services:        h.Services,
			DiscoverySource: h.DiscoverySource,
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
	sensorID, ok := s.requireAuthenticatedSensorID(w, r, r.Header.Get("X-Sensor-ID"))
	if !ok {
		return
	}

	// Keep sensor last_seen fresh on work requests
	s.DB.TouchSensor(sensorID)
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

// deduplicateGatewayEchoes removes duplicate DNS events caused by gateway/DNS forwarder
// echoing the same query. Groups events by (domain, queryType) within a 2-second window
// and keeps only the event that is NOT from a gateway IP (ends in .1 or .254).
// Tags deduplicated events with "deduplicated" so users know dedup occurred.
func deduplicateGatewayEchoes(events []models.Event) []models.Event {
	if len(events) <= 1 {
		return events
	}

	type groupKey struct {
		domain    string
		queryType string
	}

	// Group events by (domain, queryType)
	groups := make(map[groupKey][]*models.Event)
	for i := range events {
		key := groupKey{domain: events[i].Domain, queryType: events[i].QueryType}
		groups[key] = append(groups[key], &events[i])
	}

	isGatewayIP := func(ip string) bool {
		// Check if IP ends in .1 or .254 (common gateway addresses)
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			if parts[3] == "1" || parts[3] == "254" {
				return true
			}
		}
		return false
	}

	// Process each group and deduplicate
	var result []models.Event
	dedupCount := 0

	for _, groupEvents := range groups {
		if len(groupEvents) <= 1 {
			// No duplicates in this group
			result = append(result, *groupEvents[0])
			continue
		}

		// Check if events are within 2-second window
		minTime := groupEvents[0].Timestamp
		maxTime := groupEvents[0].Timestamp
		for _, evt := range groupEvents {
			if evt.Timestamp.Before(minTime) {
				minTime = evt.Timestamp
			}
			if evt.Timestamp.After(maxTime) {
				maxTime = evt.Timestamp
			}
		}

		timeDiff := maxTime.Sub(minTime).Seconds()
		if timeDiff > 2 {
			// Events are outside 2-second window, keep all
			for _, evt := range groupEvents {
				result = append(result, *evt)
			}
			continue
		}

		// A dedup group typically contains both the query packet and the response
		// packet of the same lookup (the sensor emits an event for each). Only the
		// response carries answers (ResolvedIP / dns_answers metadata). When picking
		// the survivor we must prefer the answer-bearing event, otherwise the entire
		// answers feature is silently defeated by dedup.
		hasAnswerData := func(evt *models.Event) bool {
			return evt.ResolvedIP != "" || strings.Contains(evt.Metadata, "dns_answers")
		}

		// Find event that is NOT from a gateway IP, preferring one with answer data.
		var nonGatewayEvent *models.Event
		for _, evt := range groupEvents {
			if isGatewayIP(evt.SourceIP) {
				continue
			}
			if nonGatewayEvent == nil || (!hasAnswerData(nonGatewayEvent) && hasAnswerData(evt)) {
				nonGatewayEvent = evt
			}
		}

		// Keep the non-gateway event; if all are gateway IPs, prefer an
		// answer-bearing one, falling back to the first.
		var kept *models.Event
		if nonGatewayEvent != nil {
			kept = nonGatewayEvent
		} else {
			kept = groupEvents[0]
			for _, evt := range groupEvents {
				if hasAnswerData(evt) {
					kept = evt
					break
				}
			}
		}
		dedupCount += len(groupEvents) - 1

		// Merge answer-bearing fields from discarded duplicates into the kept event
		// so no resolution info is lost regardless of which event survived.
		for _, evt := range groupEvents {
			if evt == kept {
				continue
			}
			if kept.ResolvedIP == "" && evt.ResolvedIP != "" {
				kept.ResolvedIP = evt.ResolvedIP
			}
			if kept.ServerIP == "" && evt.ServerIP != "" {
				kept.ServerIP = evt.ServerIP
			}
			if evt.Metadata != "" && evt.Metadata != kept.Metadata {
				merged := map[string]any{}
				_ = json.Unmarshal([]byte(evt.Metadata), &merged)
				if kept.Metadata != "" {
					keptMeta := map[string]any{}
					if err := json.Unmarshal([]byte(kept.Metadata), &keptMeta); err == nil {
						for k, v := range keptMeta {
							merged[k] = v // kept event wins on conflicting keys
						}
					}
				}
				if len(merged) > 0 {
					if b, err := json.Marshal(merged); err == nil {
						kept.Metadata = string(b)
					}
				}
			}
		}

		// Tag the kept event as deduplicated
		if len(groupEvents) > 1 {
			// appendUnique inline: add "deduplicated" if not already present
			found := false
			for _, tag := range kept.Tags {
				if tag == "deduplicated" {
					found = true
					break
				}
			}
			if !found {
				kept.Tags = append(kept.Tags, "deduplicated")
			}
		}
		result = append(result, *kept)
	}

	if dedupCount > 0 {
		log.Printf("Deduplication: removed %d gateway echo events from batch", dedupCount)
	}

	return result
}

func (s *Server) handleSensorDNS(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	var body struct {
		SensorID string `json:"sensor_id"`
		Queries  []struct {
			Timestamp  int64    `json:"timestamp"` // unix millis or seconds (auto-detected for compat)
			Domain     string   `json:"domain"`
			QueryType  string   `json:"query_type"`
			ClientIP   string   `json:"client_ip"`
			ResponseIP string   `json:"response_ip,omitempty"`
			ServerIP   string   `json:"server_ip,omitempty"`
			Blocked    bool     `json:"blocked"`
			Source     string   `json:"source"`
			Answers    []string `json:"answers,omitempty"` // resolved destinations from sensor (for actionability)
			Process    string   `json:"process,omitempty"` // originating process hint (if sensor has local visibility)
		} `json:"queries"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 5<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	sensorID, ok := s.requireAuthenticatedSensorID(w, r, body.SensorID, r.Header.Get("X-Sensor-ID"))
	if !ok {
		return
	}
	body.SensorID = sensorID

	// Keep sensor last_seen fresh on DNS data (important for long-running collection observability)
	s.DB.TouchSensor(sensorID)

	log.Printf("Sensor %s sent %d DNS queries", sensorID, len(body.Queries))

	if len(body.Queries) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": 0})
		return
	}

	// Get install salt for source_hash
	installSalt := os.Getenv("VEDETTA_INSTALL_SALT")
	if installSalt == "" {
		installSalt = "vedetta-install-salt" // fallback
	}

	// Convert DNS queries to Events
	events := make([]models.Event, 0, len(body.Queries))
	for _, q := range body.Queries {
		if q.Domain == "" || q.ClientIP == "" {
			continue // skip invalid queries
		}

		// Generate event ID
		eventID := uuid.New().String()

		// Compute source_hash as HMAC-SHA256(clientIP, installSalt)
		h := hmac.New(sha256.New, []byte(installSalt))
		h.Write([]byte(q.ClientIP))
		sourceHash := hex.EncodeToString(h.Sum(nil))

		// Timestamp: support millis (preferred for precision) or legacy seconds
		var ts time.Time
		if q.Timestamp > 1_000_000_000_000 { // millis
			ts = time.UnixMilli(q.Timestamp).UTC()
		} else {
			ts = time.Unix(q.Timestamp, 0).UTC()
		}

		event := models.Event{
			EventID:        eventID,
			Timestamp:      ts,
			EventType:      "dns_query",
			SourceHash:     sourceHash,
			SourceIP:       q.ClientIP,
			ServerIP:       q.ServerIP,
			Domain:         q.Domain,
			QueryType:      q.QueryType,
			ResolvedIP:     q.ResponseIP,
			Blocked:        q.Blocked,
			AnomalyScore:   0.0,
			Tags:           []string{},
			Geo:            "",
			DeviceVendor:   "",
			NetworkSegment: "default",
			DNSSource:      q.Source,
		}

		// Store answers (resolved destinations) in metadata for actionability.
		// This helps users see what the query actually resolved to without extra lookups.
		if len(q.Answers) > 0 {
			m := map[string]any{}
			if event.Metadata != "" {
				_ = json.Unmarshal([]byte(event.Metadata), &m)
			}
			m["dns_answers"] = q.Answers
			if b, err := json.Marshal(m); err == nil {
				event.Metadata = string(b)
			}
			// Also surface first answer in ResolvedIP for backward/ simple views
			if event.ResolvedIP == "" {
				event.ResolvedIP = q.Answers[0]
			}
		}

		if q.Process != "" {
			m := map[string]any{}
			if event.Metadata != "" {
				_ = json.Unmarshal([]byte(event.Metadata), &m)
			}
			m["process"] = q.Process
			if b, err := json.Marshal(m); err == nil {
				event.Metadata = string(b)
			}
		}

		// SNR-05: Enrich with passive device discovery context.
		// This adds high-value signal (vendor, device type, segment) to DNS events,
		// dramatically helping reduce false positive noise ("beaconing from new IoT device"
		// is very different from "from my laptop").
		if dev, err := s.DB.GetDeviceByIP(q.ClientIP); err == nil && dev != nil {
			if dev.Vendor != "" {
				event.DeviceVendor = dev.Vendor
			}
			if dev.Segment != "" {
				event.NetworkSegment = dev.Segment
			}

			// SNR-11: Detect new devices (first seen in last 48 hours)
			// Suspicious DNS from brand new devices is higher risk.
			// Use the minimum first_seen across all records for this IP to avoid
			// spurious "new_device" tags on established machines that have duplicate
			// records (with different first_seen values) from mixed discovery sources.
			effectiveFirstSeen := dev.FirstSeen
			if s.DB != nil {
				if minSeen, err := s.DB.GetMinFirstSeenForIP(q.ClientIP); err == nil && !minSeen.IsZero() && minSeen.Before(effectiveFirstSeen) {
					effectiveFirstSeen = minSeen
				}
			}
			if !effectiveFirstSeen.IsZero() {
				age := time.Since(effectiveFirstSeen)
				if age < 48*time.Hour {
					found := false
					for _, t := range event.Tags {
						if t == "new_device" {
							found = true
							break
						}
					}
					if !found {
						event.Tags = append(event.Tags, "new_device")
					}
				}
				if age < 1*time.Hour {
					// Extra tag for extremely new devices (< 1 hour)
					found := false
					for _, t := range event.Tags {
						if t == "very_new_device" {
							found = true
							break
						}
					}
					if !found {
						event.Tags = append(event.Tags, "very_new_device")
					}
				}
			}

			// Risk tagging for known exploitable / EOL / high-risk IoT devices.
			// Generalized from the original IC3 AVrecon work (migration 016).
			// We map categories to tags for downstream scoring and UI:
			//   eol_eos       -> "eol_router" (kept for compat + specific IC3 boost)
			//   high_risk_iot -> "high_risk_iot"
			//   known_exploited -> "known_exploited"
			if dev.EOLRisk || dev.RiskCategory != "" {
				category := dev.RiskCategory
				if category == "" && dev.EOLRisk {
					category = "eol_eos"
				}

				tag := ""
				switch category {
				case "eol_eos":
					tag = "eol_router"
				case "high_risk_iot":
					tag = "high_risk_iot"
				case "known_exploited":
					tag = "known_exploited"
				}

				if tag != "" {
					found := false
					for _, t := range event.Tags {
						if t == tag {
							found = true
							break
						}
					}
					if !found {
						event.Tags = append(event.Tags, tag)
					}
				}
			}
		}

		events = append(events, event)
	}

	if len(events) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": 0})
		return
	}

	// Deduplicate gateway echoes before enrichment
	events = deduplicateGatewayEchoes(events)

	// Enrich events
	if s.Enricher != nil {
		for i := range events {
			s.Enricher.Enrich(&events[i])
		}
	}

	// Insert into database
	inserted, err := s.DB.InsertEvents(events)
	if err != nil {
		log.Printf("Sensor DNS ingest error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "insert failed"})
		return
	}

	s.logInfo("ingest", fmt.Sprintf("Sensor %s ingested %d DNS queries", sensorID, inserted))
	writeJSON(w, http.StatusOK, map[string]any{"accepted": inserted})
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

// --- Device Update ---

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing device ID"})
		return
	}

	var body struct {
		CustomName string `json:"custom_name"`
		Notes      string `json:"notes"`
		Segment    string `json:"segment"`
		DeviceType string `json:"device_type,omitempty"`
		OSFamily   string `json:"os_family,omitempty"`
		OSVersion  string `json:"os_version,omitempty"`
		Model      string `json:"model,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	if err := s.DB.UpdateDeviceMeta(deviceID, body.CustomName, body.Notes, body.Segment); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Update device fingerprint fields if provided (device correction)
	if body.DeviceType != "" || body.OSFamily != "" || body.OSVersion != "" || body.Model != "" {
		if err := s.DB.UpdateDeviceFingerprint(deviceID, body.DeviceType, body.OSFamily, body.OSVersion, body.Model); err != nil {
			log.Printf("Failed to update device fingerprint: %v", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Event Acknowledgment ---

func (s *Server) handleAckEvent(w http.ResponseWriter, r *http.Request) {
	eventID := chi.URLParam(r, "eventID")
	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)

	if err := s.DB.AcknowledgeEvent(eventID, body.Reason); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUnackEvent(w http.ResponseWriter, r *http.Request) {
	eventID := chi.URLParam(r, "eventID")
	if err := s.DB.UnacknowledgeEvent(eventID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Suppression Rules ---

func (s *Server) handleListSuppression(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DB.ListSuppressionRules()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleCreateSuppression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string   `json:"domain"`
		SourceIP string   `json:"source_ip"`
		Tags     []string `json:"tags"`
		Reason   string   `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	rule, err := s.DB.CreateSuppressionRule(body.Domain, body.SourceIP, body.Tags, body.Reason)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")
	if err := s.DB.DeleteSuppressionRule(ruleID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DB.ListWhitelistRules()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleCreateWhitelist(w http.ResponseWriter, r *http.Request) {
	var body models.WhitelistRule
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	rule, err := s.DB.CreateWhitelistRule(body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleToggleWhitelist(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	if err := s.DB.UpdateWhitelistRule(ruleID, body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleID")
	if err := s.DB.DeleteWhitelistRule(ruleID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSeedWhitelist(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.SeedDefaultWhitelistRules(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
