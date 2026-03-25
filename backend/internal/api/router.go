package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// Server holds dependencies for all API handlers.
type Server struct {
	DB        *store.DB
	Scheduler *discovery.Scheduler
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
	})

	// Static file server for the React frontend
	fileServer := http.FileServer(http.Dir(frontendDir))
	r.Handle("/*", fileServer)

	return r
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	deviceCount := 0
	if s.DB != nil {
		deviceCount, _ = s.DB.CountDevices()
	}

	scanStatus := discovery.ScanStatus{}
	defaultCIDR := ""
	if s.Scheduler != nil {
		scanStatus = s.Scheduler.Status()
		defaultCIDR = s.Scheduler.DefaultCIDR()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      "0.1.0-dev",
		"service":      "vedetta-backend",
		"device_count": deviceCount,
		"scan":         scanStatus,
		"default_cidr": defaultCIDR,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"events": []any{},
		"total":  0,
		"page":   1,
	})
}

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
	if s.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}

	status := s.Scheduler.Status()
	if status.Running {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "scan already in progress"})
		return
	}

	s.Scheduler.RunNow()
	writeJSON(w, http.StatusAccepted, map[string]any{"message": "scan triggered"})
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
	writeJSON(w, http.StatusOK, map[string]any{"subnets": subnets})
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
	if s.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scanner not available"})
		return
	}

	status := s.Scheduler.Status()
	if status.Running {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "scan already in progress"})
		return
	}

	targetID := chi.URLParam(r, "targetID")

	// Look up the target
	targets, err := s.DB.ListScanTargets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	for _, t := range targets {
		if t.TargetID == targetID {
			s.Scheduler.RunTarget(t.CIDR, t.Segment, t.ScanPorts)
			writeJSON(w, http.StatusAccepted, map[string]any{
				"message": "scan triggered",
				"target":  t.Name,
				"cidr":    t.CIDR,
			})
			return
		}
	}

	writeJSON(w, http.StatusNotFound, map[string]any{"error": "target not found"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
