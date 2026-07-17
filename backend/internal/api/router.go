package api

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/firewall"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/processing"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
	"github.com/vedetta-network/vedetta/backend/internal/updatecheck"
)

// Server holds dependencies for all API handlers.
type Server struct {
	DB          *store.DB
	Scheduler   *discovery.Scheduler
	Enricher    *dnsintel.Enricher
	ScanQueue   *ScanQueue
	ActivityLog *ActivityLog
	Firewall    *firewall.Manager
	Enroll      *EnrollmentStore
	Processor   *processing.Processor
	FeedHealth  FeedHealthProvider
	Readiness   *ReadinessMonitor

	// UpdateChecker serves the read-only release-availability status for the dashboard's
	// update notifier. Optional (nil disables the notice).
	UpdateChecker *updatecheck.Checker

	// SetupCode is the single-use first-admin bootstrap code (GHSA-6cmx). It is set
	// at boot ONLY while no active admin token exists, and is cleared once the first
	// admin is minted. While set, minting the first admin (and revoking tokens during
	// bootstrap) requires the X-Vedetta-Setup-Code header. Guarded by setupMu.
	SetupCode string
	setupMu   sync.Mutex
}

// FeedHealthProvider keeps detection-health routing testable without starting
// network download goroutines. threatintel.FeedScheduler satisfies it.
type FeedHealthProvider interface {
	Status() []threatintel.FeedHealth
}

// checkSetupCode reports whether provided matches the server-held bootstrap setup
// code, using a constant-time compare. Returns false if no code is set (i.e. once
// the first admin exists and the code has been cleared).
func (s *Server) checkSetupCode(provided string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.SetupCode == "" {
		return false
	}
	provided = strings.TrimSpace(provided)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.SetupCode)) == 1
}

// clearSetupCode consumes the bootstrap setup code (single-use). Safe to call more
// than once.
func (s *Server) clearSetupCode() {
	s.setupMu.Lock()
	s.SetupCode = ""
	s.setupMu.Unlock()
}

// consumeSetupCode atomically verifies AND clears the single-use bootstrap setup
// code under one lock. Exactly ONE caller presenting the correct code gets true;
// every concurrent or later caller gets false. Use this (never a separate check +
// later clear) for first-admin creation so a concurrent replay cannot mint two
// admins (GHSA-6cmx).
func (s *Server) consumeSetupCode(provided string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.SetupCode == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(provided)), []byte(s.SetupCode)) != 1 {
		return false
	}
	s.SetupCode = "" // consume — single use
	return true
}

// needsSetupCode reports whether a bootstrap setup code is currently active.
func (s *Server) needsSetupCode() bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.SetupCode != ""
}

// NewRouter creates the main API router with all routes mounted.
func NewRouter(srv *Server) http.Handler {
	r := chi.NewRouter()
	if srv.Enroll == nil {
		srv.Enroll = NewEnrollmentStore()
	}
	if srv.Processor == nil && srv.DB != nil {
		srv.Processor = processing.NewProcessor(srv.DB, srv.Enricher)
	}
	if srv.Readiness == nil && srv.DB != nil {
		srv.Readiness = NewReadinessMonitor(srv.DB)
	}
	sensorRegistrationLimiter := newIPRateLimiter(5, time.Minute)
	sensorAuthCheckLimiter := newIPRateLimiter(sensorAuthCheckRequestsPerMinute, time.Minute)

	// Outermost middleware: stamp anti-clickjacking / anti-sniffing headers on
	// every response, including the dashboard SPA and health probes (GHSA-69jp).
	r.Use(securityHeaders)

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// /healthz stays a pure liveness probe: middleware.Heartbeat answers 200 without
	// ever touching the DB, proving only that HTTP is up. Anything already pointed at
	// it keeps working unchanged.
	r.Use(middleware.Heartbeat("/healthz"))

	// /readyz is the REAL readiness probe (see ReadinessMonitor): it exercises the
	// store, checks the schema migration head, and returns the cached integrity result,
	// so a behind/half-migrated/corrupt DB reads NOT ready. Public and unauthenticated
	// like /healthz and /version — it exposes only readiness state and the schema
	// version, no network or inventory data. The compose healthcheck targets this.
	// Registered UNCONDITIONALLY: with no DB there is no monitor, and a probe must see
	// 503 "not ready", never 404. Both GET and HEAD are served — chi does not fall back
	// HEAD→GET on its own, and HEAD-based probers (GNU wget --spider, curl -I) would
	// otherwise get 405. (BusyBox wget --spider issues GET, but don't depend on that.)
	readyz := func(w http.ResponseWriter, r *http.Request) {
		if srv.Readiness == nil {
			writeReadyz(w, http.StatusServiceUnavailable, "database not configured", nil)
			return
		}
		srv.Readiness.handleReadyz(w, r)
	}
	r.Get("/readyz", readyz)
	r.Head("/readyz", readyz)

	frontendDir := os.Getenv("VEDETTA_FRONTEND_DIR")
	if frontendDir == "" {
		frontendDir = "./frontend/dist"
	}

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// /version stays public: it exposes only a static version/build string
		// (no network or inventory data) and is used as an unauthenticated
		// build probe, like /healthz.
		r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"version":    "0.1.0-dev",
				"build_time": "2026-03-31T00:00:00Z",
				"routes":     []string{"/suppression", "/whitelist", "/events/{eventID}/ack", "/devices/{deviceID}"},
			})
		})

		// Read-only dashboard/query endpoints (beta-gate B6). These expose device
		// inventory, DNS/firewall events, and network status, so once an active
		// admin token exists they require AT LEAST read scope (admin implies read;
		// a read token qualifies). During bootstrap (no admin yet) RequireRead lets
		// them through so first-run setup and the onboarding wizard still work.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRead(srv.DB))
			r.Get("/status", srv.handleStatus)
			r.Get("/events", srv.handleEvents)
			r.Get("/events/stats", srv.handleEventStats)
			r.Get("/events/timeline", srv.handleEventTimeline)
			r.Get("/findings", srv.handleFindings)
			r.Get("/findings/stats", srv.handleFindingStats)
			r.Get("/findings/{findingID}", srv.handleFindingDetail)
			r.Get("/finding-suppressions", srv.handleListFindingSuppressions)
			r.Get("/health/detection", srv.handleDetectionHealth)
			r.Get("/update-status", srv.handleUpdateStatus)
			r.Get("/auth/session", srv.handleAuthSession)
			// Telemetry opt-in is a read-scope read: the telemetry daemon polls it
			// each tick with its read token to decide whether to export (issue #37).
			r.Get("/settings/telemetry", srv.handleGetTelemetrySetting)
		})

		// Persisting the telemetry opt-in is an admin action (dashboard control).
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Put("/settings/telemetry", srv.handlePutTelemetrySetting)
		})

		// Ingest endpoint for the Fluent Bit log collector (Pi-hole DNS + firewall syslog).
		// Auth: bootstrap-open until any token exists; afterward only ingest scope
		// (or admin, which implies it) may write collector records. Native sensors
		// use /sensor/* and cannot cross this trust boundary to pre-seed collector IDs.
		// /ingest is for external log sources (collector); /sensor/* is for the native
		// vedetta-sensor binary -- they share InsertEvents.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAuth(srv.DB))
			r.Use(auth.RequireScopeOrBootstrap(auth.ScopeIngest))
			r.Post("/ingest", srv.handleIngest)
		})

		// Device discovery reads now require read scope once an admin exists
		// (they expose the LAN device inventory). Writes remain admin-only.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRead(srv.DB))
			r.Get("/devices", srv.handleListDevices)
			r.Get("/devices/new", srv.handleNewDevices)
			r.Get("/device-merges", srv.handleListDeviceMerges)
		})
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Put("/devices/{deviceID}", srv.handleUpdateDevice)
			r.Post("/devices/{deviceID}/confirm", srv.handleConfirmDeviceIdentity)
			r.Post("/devices/merge", srv.handleMergeDevices)
			r.Post("/devices/consolidate-mac-owners", srv.handleConsolidateMACOwners)
			r.Post("/device-merges/{actionID}/split", srv.handleUndoDeviceMerge)
		})

		// Finding lifecycle changes are incident state, not raw-event mutation.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Patch("/findings/{findingID}/status", srv.handleFindingStatus)
			r.Post("/findings/{findingID}/suppress", srv.handleSuppressFinding)
			r.Delete("/finding-suppressions/{ruleID}", srv.handleDeleteFindingSuppression)
		})

		// Event acknowledgment and suppression — protected (user intent / configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Put("/events/{eventID}/ack", srv.handleAckEvent)
			r.Delete("/events/{eventID}/ack", srv.handleUnackEvent)
			r.Get("/suppression", srv.handleListSuppression)
			r.Post("/suppression", srv.handleCreateSuppression)
			r.Delete("/suppression/{ruleID}", srv.handleDeleteSuppression)
		})

		// Known-traffic whitelist — protected (user configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Get("/whitelist", srv.handleListWhitelist)
			r.Post("/whitelist", srv.handleCreateWhitelist)
			r.Put("/whitelist/{ruleID}", srv.handleToggleWhitelist)
			r.Delete("/whitelist/{ruleID}", srv.handleDeleteWhitelist)
			r.Post("/whitelist/seed", srv.handleSeedWhitelist)
		})

		// Scanning & scan targets — protected (active scanning + configuration)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Post("/scan", srv.handleTriggerScan)
			r.Put("/scan/cidr", srv.handleSetDefaultCIDR)
			r.Get("/scan/targets", srv.handleListTargets)
			r.Post("/scan/targets", srv.handleCreateTarget)
			r.Delete("/scan/targets/{targetID}", srv.handleDeleteTarget)
			r.Put("/scan/targets/{targetID}/toggle", srv.handleToggleTarget)
			r.Post("/scan/targets/{targetID}/scan", srv.handleScanTarget)
		})
		// Read-only scan status and subnet detection expose network topology
		// (detected local subnets), so they require read scope once an admin
		// exists. Open during bootstrap so the setup wizard can detect subnets.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRead(srv.DB))
			r.Get("/scan/status", srv.handleScanStatus)
			r.Get("/scan/subnets", srv.handleDetectSubnets)
		})

		// Authentication and token management
		r.Get("/auth/setup-status", srv.handleSetupStatus)

		// Token management requires admin scope once auth is configured. RequireAdmin
		// bootstraps when zero tokens exist (so the FIRST admin token is creatable
		// with no auth) and, once any token exists, requires a valid admin bearer AND
		// populates the auth scope in the request context. Registering /auth/tokens
		// POST here (rather than bare, outside any middleware) is the BUG-2 fix:
		// previously the handler's GetScopeFromContext returned "" for every request
		// because no middleware ever set it, so once >=1 token existed no second token
		// could ever be minted even with a valid admin bearer.
		r.Route("/auth", func(r chi.Router) {
			// First-admin creation must work during bootstrap (self-gated by the
			// single-use setup code inside the handler); RequireAdmin bootstrap-passes
			// ONLY here. Listing/revoking tokens are strictly admin — never open
			// pre-admin (GHSA-6cmx).
			r.With(auth.RequireAdmin(srv.DB)).Post("/tokens", srv.handleCreateToken)
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireStrictAdmin(srv.DB))
				r.Get("/tokens", srv.handleListTokens)
				r.Delete("/tokens/{tokenID}", srv.handleRevokeToken)
			})
		})

		// Admin mints a short-lived, single-use code to enroll a NEW sensor once
		// admin auth exists (beta-gate B1a).
		r.With(auth.RequireStrictAdmin(srv.DB)).Post("/enrollment-codes", srv.handleGenerateEnrollmentCode)

		// Sensor ingest (native sensors push data to Core)
		r.Route("/sensor", func(r chi.Router) {
			r.With(sensorRegistrationLimiter.Middleware).Post("/register", srv.handleSensorRegister)
			// Auth check deliberately uses its handler's read-only token validation.
			// The normal auth middleware updates api_tokens.last_used, which would make
			// this diagnostic GET mutate Core state.
			// noStore wraps the limiter as well as the handler so every credential
			// response, including an early 429, is explicitly non-cacheable.
			r.With(noStore, sensorAuthCheckLimiter.Middleware).Get("/auth-check", srv.handleSensorAuthCheck)
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireStrictAuth(srv.DB))
				r.Use(auth.RequireExactScope(auth.ScopeSensor))
				r.Post("/heartbeat", srv.handleSensorHeartbeat)
				r.Post("/devices", srv.handleSensorDevices)
				r.Post("/dns", srv.handleSensorDNS)
				r.Get("/work", srv.handleSensorWork)
			})

			// Dashboard-facing sensor management routes — now protected with admin auth.
			// In bootstrap mode (no tokens yet) they remain open for first-run setup.
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireStrictAdmin(srv.DB))
				r.Get("/list", srv.handleSensorList)
				r.Put("/{sensorID}/primary", srv.handleSetPrimarySensor)
				r.Delete("/{sensorID}", srv.handleDeleteSensor)
			})
		})

		// Activity log (protected — can contain operational details)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireStrictAdmin(srv.DB))
			r.Get("/logs", srv.handleLogs)
			// Firewall connector health (spec 001, T4.4) — admin-only.
			r.Get("/connectors", srv.handleListConnectors)
		})

		// Simulation endpoints temporarily disabled while fixing sensor auth (will re-enable later)
		// if os.Getenv("VEDETTA_ALLOW_SIMULATION") == "true" { ... }
	})

	return r
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// --- Simulation Handlers (only active when VEDETTA_ALLOW_SIMULATION=true) ---

type SimulateDNSRequest struct {
	Queries []struct {
		Domain         string `json:"domain"`
		QueryType      string `json:"query_type"`
		ClientIP       string `json:"client_ip"`
		ResponseIP     string `json:"response_ip"`
		Blocked        bool   `json:"blocked"`
		DeviceVendor   string `json:"device_vendor,omitempty"`
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

	summary := s.processEvents(r.Context(), events, "simulation", "")
	if summary.Failed > 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "processing failed", "details": summary.FirstError.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":   summary.Inserted + summary.Duplicates,
		"inserted":   summary.Inserted,
		"duplicates": summary.Duplicates,
		"events":     events,
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

	// Machine-credential health (issue #34): surface the effective collector-ingest
	// and telemetry-read credential state so operators can diagnose a 403 from the
	// API, not only from the startup logs. "configured" reflects the compose env
	// secret; "active" reflects a usable non-revoked token of that scope actually
	// existing in the DB; "collision" flags the identical-secret case that would
	// leave only one scope provisioned.
	ingestCfg, readCfg, collision := MachineCredentialState()
	machineCreds := map[string]any{
		"ingest_token_configured": ingestCfg,
		"read_token_configured":   readCfg,
		"collision":               collision,
	}
	if s.DB != nil {
		if present, err := s.DB.HasActiveIngestToken(); err == nil {
			machineCreds["ingest_token_active"] = present
		}
		if present, err := s.DB.HasActiveReadToken(); err == nil {
			machineCreds["read_token_active"] = present
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":              "ok",
		"version":             "0.1.0-dev",
		"service":             "vedetta-core",
		"device_count":        deviceCount,
		"event_count":         eventCount,
		"sensor_count":        sensorCount,
		"scan":                scanStatus,
		"default_cidr":        defaultCIDR,
		"collection_health":   collectionHealth,
		"machine_credentials": machineCreds,
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
	markCollectorError := func(message string) {
		if err := s.DB.MarkCollectionError(r.Context(), "collector", "push", "Collector/syslog", message, time.Now().UTC()); err != nil {
			log.Printf("Mark collector health error: %v", err)
		}
	}

	// Ingest auth (spec 001, FR-8) is enforced at the MIDDLEWARE layer: the route is
	// wrapped in auth.RequireAuth (see NewRouter), whose bootstrap-bypass semantics
	// are the single source of truth — while zero tokens exist the endpoint is open
	// for first-run setup, and once ANY token exists a valid Bearer token is required
	// unconditionally. There is therefore no per-handler VEDETTA_REQUIRE_INGEST_AUTH
	// toggle here: an earlier in-handler check keyed on that env var was dead code (it
	// could never make ingest MORE permissive than the middleware already allowed) and
	// its "optional by default" comment was misleading, so both were removed (BUG-5).
	// The middleware admits admin/ingest tokens (and the zero-token bootstrap
	// window) on /ingest. Read and sensor credentials cannot cross this boundary.

	// Read body (limit to 10MB to prevent abuse)
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		markCollectorError("failed to read collector request body")
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to read body"})
		return
	}

	// Parse: accept both a single event object and an array of events.
	// Also handle Fluent Bit's HTTP output format: array of [timestamp, record] pairs.
	var events []models.Event
	received := 0
	decodeRejected := 0
	ignored := 0 // No Core-side ignorable record classes are currently documented.

	// Try array first
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		markCollectorError("empty collector request body")
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty body"})
		return
	}

	if trimmed[0] == '[' {
		// Could be an array of events or Fluent Bit [timestamp, record] pairs
		var rawArray []json.RawMessage
		if err := json.Unmarshal(body, &rawArray); err != nil {
			markCollectorError("invalid collector JSON array")
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON array"})
			return
		}
		received = len(rawArray)

		for _, raw := range rawArray {
			// To preserve ALL top-level fields from the collector record (e.g. raw_log, and any action/protocol/src_ip etc
			// if the collector or future filters emit them at top level), unmarshal the record to map first.
			// Then lift non-Event (or all collector) keys into metadata so PIECE 3 json_extract filters can find them.
			// Known Event fields are still populated via the struct unmarshal for compatibility.
			record := map[string]any{}
			_ = json.Unmarshal(raw, &record)

			// Try as normal event object (for the known fields)
			var evt models.Event
			if err := json.Unmarshal(raw, &evt); err == nil && evt.EventType != "" {
				// Lift top-level non-Event / collector fields into metadata
				if evt.Metadata == "" {
					evt.Metadata = "{}"
				}
				var meta map[string]any
				if json.Unmarshal([]byte(evt.Metadata), &meta) != nil || meta == nil {
					meta = map[string]any{}
				}
				for k, v := range record {
					if k == "metadata" {
						// merge any existing metadata sub-object
						if sub, ok := v.(map[string]any); ok {
							for sk, sv := range sub {
								meta[sk] = sv
							}
						}
						continue
					}
					// lift the top-level key (raw_log, action, protocol, src_ip, etc if present at top)
					meta[k] = v
				}
				b, _ := json.Marshal(meta)
				evt.Metadata = string(b)
				events = append(events, evt)
				continue
			}

			// Try as Fluent Bit [timestamp, record] pair
			var pair []json.RawMessage
			if err := json.Unmarshal(raw, &pair); err == nil && len(pair) == 2 {
				recMap := map[string]any{}
				_ = json.Unmarshal(pair[1], &recMap)
				var evt models.Event
				if err := json.Unmarshal(pair[1], &evt); err == nil && evt.EventType != "" {
					// Fluent Bit's pair protocol carries record time outside the record.
					// Preserve it before deriving a replay-stable ID.
					if evt.Timestamp.IsZero() {
						evt.Timestamp = parseCollectorTimestamp(pair[0])
					}
					if evt.Metadata == "" {
						evt.Metadata = "{}"
					}
					var meta map[string]any
					if json.Unmarshal([]byte(evt.Metadata), &meta) != nil || meta == nil {
						meta = map[string]any{}
					}
					for k, v := range recMap {
						if k == "metadata" {
							if sub, ok := v.(map[string]any); ok {
								for sk, sv := range sub {
									meta[sk] = sv
								}
							}
							continue
						}
						meta[k] = v
					}
					b, _ := json.Marshal(meta)
					evt.Metadata = string(b)
					events = append(events, evt)
					continue
				}
			}

			// Documented collector noise is dropped by the collector transform before
			// HTTP. Core therefore has no intentionally ignorable payload shape: an
			// unrecognized top-level item is malformed and must be accounted for as
			// rejected rather than silently proving collection health.
			decodeRejected++
		}
	} else if trimmed[0] == '{' {
		received = 1
		// Single event object
		recMap := map[string]any{}
		_ = json.Unmarshal(body, &recMap)
		var evt models.Event
		if err := json.Unmarshal(body, &evt); err != nil {
			markCollectorError("invalid collector JSON object")
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON object"})
			return
		}
		// Lift top-level collector fields to metadata
		if evt.Metadata == "" {
			evt.Metadata = "{}"
		}
		var meta map[string]any
		if json.Unmarshal([]byte(evt.Metadata), &meta) != nil || meta == nil {
			meta = map[string]any{}
		}
		for k, v := range recMap {
			if k == "metadata" {
				if sub, ok := v.(map[string]any); ok {
					for sk, sv := range sub {
						meta[sk] = sv
					}
				}
				continue
			}
			meta[k] = v
		}
		b, _ := json.Marshal(meta)
		evt.Metadata = string(b)
		events = append(events, evt)
	} else {
		markCollectorError("collector payload is not a JSON object or array")
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "expected JSON object or array"})
		return
	}

	// The 10MB body limit is the request bound. Do not reject a decoded chunk by
	// record count: Fluent Bit retries the same chunk rather than splitting it,
	// so a count-based 413 eventually discards otherwise valid security events.

	// Validate and assign defaults
	accepted := make([]models.Event, 0, len(events))
	rejected := decodeRejected
	missingIdentity := 0
	for _, e := range events {
		// Validate event_type
		if !allowedEventTypes[e.EventType] {
			rejected++
			continue
		}

		upstreamEventID := strings.TrimSpace(e.EventID)
		// A record with neither upstream ID nor time has no replay boundary: two
		// real identical occurrences and one retry are indistinguishable. Reject it
		// instead of collapsing every future occurrence onto a zero-time UUID.
		if e.Timestamp.IsZero() && upstreamEventID == "" {
			rejected++
			missingIdentity++
			continue
		}
		// Core owns the database key. Namespace every collector ID by normalized
		// record material even when the caller supplied an upstream identifier, so
		// an ingest principal cannot collide with sensor/poller/UniFi trust domains.
		e.EventID = deterministicCollectorEventID(e, upstreamEventID)

		// An upstream ID is a stable replay boundary when its source omitted time;
		// timestamp the accepted observation at receipt without putting wall clock
		// into its deterministic ID.
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}

		// GHSA-9m7g: never persist a far-future timestamp. Telemetry uses the event
		// Timestamp as its cursor, so a forged/skewed future event would strand all
		// later normal events behind it. Clamp anything beyond a small skew to now.
		e.Timestamp = clampFutureTimestamp(e.Timestamp, time.Now().UTC())

		// Core owns source_hash. Collector callers provide raw local identity via
		// source_ip; accepting a caller-selected pseudonym would permit forged
		// device grouping and can accidentally persist a raw IP in the hash field.
		e.SourceHash = ""

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

		// Server-side received_at default in metadata (for actionability/audit).
		if e.Metadata == "" {
			e.Metadata = "{}"
		}
		var meta map[string]any
		if json.Unmarshal([]byte(e.Metadata), &meta) != nil || meta == nil {
			meta = map[string]any{}
		}
		if _, has := meta["received_at"]; !has {
			meta["received_at"] = time.Now().UTC().Format(time.RFC3339)
		}
		// For collector payloads (firewall_log from modify filter + syslog parser), the raw record
		// fields (action/protocol/src-dst etc or full syslog) are emitted at top level in the JSON record.
		// Since direct unmarshal to Event drops unknowns, for ingest we preserve the full original record
		// shape in metadata so PIECE 2 can store firewall details without dedicated columns (or via future migration).
		// (Note: full raw capture would require map-based parse of the record before Event unmarshal;
		// here we ensure at least received_at and that any pre-set metadata from collector is kept.
		// Tests use payloads matching collector output + explicit metadata for extras.)
		b, _ := json.Marshal(meta)
		e.Metadata = string(b)

		accepted = append(accepted, e)
	}

	// Normalize, resolve, detect, suppress, and persist through the same path as
	// every sensor and connector. A bad record does not roll back its siblings.
	summary := s.processEvents(r.Context(), accepted, "collector", "")
	if summary.Failed > 0 {
		log.Printf("Ingest processing failures: %d (first: %v)", summary.Failed, summary.FirstError)
	}
	processed := summary.Inserted + summary.Duplicates
	totalRejected := rejected + summary.Failed
	if summary.Failed > 0 {
		markCollectorError("event processing failed")
	} else if processed == 0 {
		markCollectorError(fmt.Sprintf("collector batch contained no accepted events (received=%d rejected=%d ignored=%d)", received, totalRejected, ignored))
	} else if err := s.DB.MarkCollectionSuccess(r.Context(), "collector", "push", "Collector/syslog", int64(processed), time.Now().UTC()); err != nil {
		log.Printf("Mark collector health success: %v", err)
	}

	status := http.StatusAccepted
	if summary.Failed > 0 {
		// Fluent Bit retries only non-2xx responses. Successfully committed
		// siblings remain safe because missing upstream IDs are deterministic.
		status = http.StatusInternalServerError
	} else if processed == 0 {
		// A decoded request with no usable records is semantically malformed. A
		// non-2xx response makes Fluent Bit retain/retry the batch, while collector
		// health remains visibly failed instead of claiming a healthy empty source.
		status = http.StatusUnprocessableEntity
	}
	response := map[string]any{
		"received":               received,
		"accepted":               processed,
		"inserted":               summary.Inserted,
		"duplicates":             summary.Duplicates,
		"rejected":               totalRejected,
		"ignored":                ignored,
		"failed":                 summary.Failed,
		"missing_event_identity": missingIdentity,
	}
	if processed == 0 && summary.Failed == 0 {
		response["error"] = "collector batch contained no accepted events"
	}
	writeJSON(w, status, response)
}

// --- Event Query ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	q := r.URL.Query()
	params := store.EventQueryParams{
		Type:     q.Get("type"),
		Source:   q.Get("source"),
		Domain:   q.Get("domain"),
		DeviceID: q.Get("device_id"),
		Origin:   q.Get("origin"),
		Sort:     q.Get("sort"),
		Order:    q.Get("order"),
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
		writeEventsCSV(w, result.Events)
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

	// BUG-4: return an empty JSON array, never null, when there are no devices.
	if devices == nil {
		devices = []models.Device{}
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

	// BUG-4: return an empty JSON array, never null, when there are no new devices.
	if devices == nil {
		devices = []models.Device{}
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

	// Queue all enabled targets for the next sensor pickup (re-validated at serve
	// time so a planted/invalid target is never dispatched to the sensor, Issue #7).
	if s.DB != nil {
		if targets, err := s.servableScanTargets(); err == nil && len(targets) > 0 {
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

	// GHSA-c5gj: reject anything that isn't a clean scan target before it can reach nmap.
	cidr := strings.TrimSpace(body.CIDR)
	if err := discovery.ValidateScanTarget(cidr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	s.Scheduler.SetDefaultCIDR(cidr)
	writeJSON(w, http.StatusOK, map[string]any{"default_cidr": cidr})
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
	// GHSA-c5gj: the CIDR is ultimately handed to nmap, so validate it before it is
	// persisted as a scan target.
	body.CIDR = strings.TrimSpace(body.CIDR)
	if err := discovery.ValidateScanTarget(body.CIDR); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
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

	// Issue #44: idempotent enrollment recovery. Core consumes the single-use code
	// and mints the sensor's only raw bearer BEFORE this response reaches the sensor.
	// If that first response is lost, the code is spent and the token exists, so a
	// normal retry lands in the "already enrolled" 401 branch below and the sensor is
	// stranded forever. If the SAME code was already redeemed for THIS sensor_id and
	// we still remember the minted token (within the code's TTL), return that same
	// raw token now — before any of the state checks — so the sensor recovers without
	// admin intervention. Bound to sensor_id, so a DIFFERENT caller replaying the code
	// gets nothing (single-use preserved).
	enrollCode := r.Header.Get("X-Vedetta-Enrollment-Code")
	if s.Enroll != nil {
		if rawToken, tokenID, ok := s.Enroll.LookupRedemption(enrollCode, body.SensorID); ok {
			// Only replay the remembered token if it is STILL ACTIVE. If the sensor was
			// reset (or its token otherwise revoked) after this code was first redeemed,
			// the remembered token is dead — returning it would tell a retrying sensor it
			// re-enrolled while handing back a credential that will not authenticate.
			// When the remembered token is gone/revoked, fall through to the normal flow,
			// which surfaces the correct next step (present a fresh reset code).
			if tok, terr := s.DB.GetTokenByID(tokenID); terr == nil && tok != nil && !tok.Revoked {
				// Refresh sensor metadata and re-check the exact credential atomically.
				// A concurrent admin removal must win cleanly instead of this replay
				// returning a token for (or resurrecting) a tombstoned identity.
				interfacesStr := ""
				if len(body.Interfaces) > 0 {
					interfacesStr = string(body.Interfaces)
				}
				refreshErr := s.DB.RefreshSensorWithActiveToken(models.Sensor{
					SensorID:   body.SensorID,
					Hostname:   body.Hostname,
					OS:         body.OS,
					Arch:       body.Arch,
					CIDR:       body.CIDR,
					Version:    body.Version,
					IsPrimary:  body.IsPrimary,
					Interfaces: interfacesStr,
				}, tokenID)
				if refreshErr == nil {
					deliveryEpoch, epochErr := s.DB.IssueARPCacheDeliveryEpoch(body.SensorID)
					if epochErr != nil {
						log.Printf("Sensor %s delivery-session issue failed: %v", body.SensorID, epochErr)
						// The bearer was already committed and is the only recoverable copy.
						// Return it even when the optional ARP-cache delivery session cannot
						// be issued; an empty epoch keeps cache evidence provisional until a
						// later registration succeeds instead of stranding the sensor.
						deliveryEpoch = ""
					}
					log.Printf("Sensor %s re-registered via idempotent enrollment replay — returning existing token %s", body.SensorID, tokenID)
					writeJSON(w, http.StatusOK, sensorRegistrationResponse{
						Status:        "registered",
						SensorID:      body.SensorID,
						AuthToken:     rawToken,
						TokenID:       tokenID,
						TokenWarning:  "save this token now — it will not be displayed again",
						DeliveryEpoch: deliveryEpoch,
					})
					return
				}
				if !errors.Is(refreshErr, store.ErrSensorRemoved) &&
					!errors.Is(refreshErr, store.ErrSensorTokenInactive) &&
					!errors.Is(refreshErr, store.ErrSensorNotFound) {
					log.Printf("Sensor %s idempotent replay refresh failed: %v", body.SensorID, refreshErr)
					writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to refresh sensor registration"})
					return
				}
			}
			log.Printf("Sensor %s replayed a redeemed code whose token is no longer active — falling through to normal enrollment", body.SensorID)
		}
	}

	// Branch on sensor IDENTITY existence (row present), NOT active-token existence:
	// once an admin revokes a sensor its row remains, and a generic new-sensor code
	// must not be able to re-enroll that id (which would defeat the revocation).
	sensorExists, err := s.DB.SensorExists(body.SensorID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check sensor identity state"})
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
		switch presentedToken.Scope {
		case auth.ScopeAdmin:
			// An admin may enroll or reset any sensor (authenticated sensor reset).
		case auth.ScopeSensor:
			if presentedToken.SensorID != body.SensorID {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "token does not match sensor_id"})
				return
			}
		default:
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "sensor or admin scope required"})
			return
		}
	}

	// consumedEnrollCode is the enrollment code (if any) this registration spends,
	// recorded after the token is minted so a lost-response retry is idempotent
	// (Issue #44). resetExisting is set when we must revoke the sensor's current
	// active token and mint a fresh one (admin reset, or a bound reset code) — the
	// actual revoke+mint happens atomically in ProvisionSensorToken below.
	consumedEnrollCode := ""
	resetExisting := false
	reactivationActor := ""

	if sensorExists {
		// This sensor IDENTITY already exists — whether its token is currently active
		// OR was revoked by an admin. Re-registration MUST be authenticated to THIS
		// sensor: sensor_ids are hostname-os-arch and therefore guessable, so a generic
		// new-sensor code must never claim or reactivate an existing identity — that
		// would let anyone holding a 15-minute generic code undo an admin revocation or
		// hijack a guessable id (beta-gate B1a). Reset/reactivation is authenticated.
		switch {
		case presentedToken != nil && presentedToken.Scope == auth.ScopeAdmin:
			// Admin-initiated reset/reactivation.
			log.Printf("Sensor %s reset by admin token %s — revoking any old token, issuing a new one", body.SensorID, presentedToken.TokenID)
			resetExisting = true
			reactivationActor = "token:" + presentedToken.TokenID
		case presentedToken != nil:
			// A valid (therefore active) matching sensor token: metadata refresh; keep
			// the existing credential (no reissue).
		case s.Enroll != nil && s.Enroll.ConsumeReset(enrollCode, body.SensorID):
			// RECOVERY / REACTIVATION (#44, B1a): a sensor whose local token was lost
			// (`--reset`, a lost enrollment response, a Core restart, local corruption) OR
			// whose token an admin revoked re-enrolls by presenting a fresh admin-minted
			// RESET code BOUND to this exact sensor_id (POST /enrollment-codes with
			// {"sensor_id":...}). A generic new-sensor code is REFUSED here, so possession
			// of any enrollment code cannot revoke/impersonate a guessable sensor_id or
			// resurrect a revoked one. Single-use: the code is spent by ConsumeReset.
			log.Printf("Sensor %s reset via a bound enrollment code — revoking any old token, issuing a new one", body.SensorID)
			resetExisting = true
			consumedEnrollCode = enrollCode
			reactivationActor = "bound-reset-code"
		default:
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "sensor_id already exists (it may be actively enrolled, or have been revoked by an admin). A generic new-sensor code cannot claim or reactivate an existing sensor. Present its current sensor token, an admin token, or an admin-minted RESET code bound to this sensor_id (POST /api/v1/enrollment-codes with {\"sensor_id\":\"...\"}). Two devices sharing hostname/OS/arch also collide here — give one a distinct hostname.",
			})
			return
		}
	}

	// New-identity enrollment gate: once an admin exists, registering a brand-new
	// sensor (no existing row) requires an admin bearer or a valid single-use
	// enrollment code — otherwise any unauthenticated LAN host could mint a sensor
	// token and push forged data (beta-gate B1a). During bootstrap (no admin yet)
	// the first sensor may enroll with the one-time setup code.
	if !sensorExists {
		hasAdmin, aerr := s.DB.HasActiveAdminToken()
		if aerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check admin state"})
			return
		}
		isAdmin := presentedToken != nil && presentedToken.Scope == auth.ScopeAdmin
		switch {
		case !hasAdmin:
			// Bootstrap: no admin exists yet. A brand-new sensor may enroll ONLY with
			// the one-time setup code printed to Core's logs, so a LAN peer cannot grab
			// a persistent sensor bearer before setup completes (GHSA-6cmx). This is a
			// non-consuming check; the code is consumed only by first-admin creation.
			if !s.checkSetupCode(r.Header.Get("X-Vedetta-Setup-Code")) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "sensor enrollment during setup requires the X-Vedetta-Setup-Code printed in Core's logs",
				})
				return
			}
		case !isAdmin:
			// Brand-new identity (sensorExists is false here, so this never runs for a
			// reset — no double-consume). A generic code, or a code bound to this new
			// sensor_id, is accepted.
			if s.Enroll == nil || !s.Enroll.ConsumeNewSensor(enrollCode, body.SensorID) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "new sensor enrollment requires an admin token or a valid enrollment code (an admin can mint one via POST /api/v1/enrollment-codes)",
				})
				return
			}
			// Remember which code this enrollment consumed so, once the token is minted
			// below, a lost-response retry is idempotent (Issue #44).
			consumedEnrollCode = enrollCode
		}
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

	response := sensorRegistrationResponse{
		Status:   "registered",
		SensorID: body.SensorID,
	}

	// Mint a fresh token for a brand-new identity or an authorized reset; otherwise
	// (a matching sensor token was presented) just refresh metadata and keep the
	// existing credential.
	if !sensorExists || resetExisting {
		rawToken, token, err := auth.GenerateToken(auth.ScopeSensor, body.SensorID, "auto-generated-registration")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to generate sensor auth token"})
			return
		}
		// Atomic: enforce the new-vs-reset identity precondition, (on reset) revoke the
		// current active token, write the sensor row, and insert the new token in ONE
		// transaction. The partial unique index means a racing reset/registration for
		// the same sensor_id leaves only ONE active token (beta-gate B1a).
		if err := s.DB.ProvisionSensorTokenWithActor(sensor, token, resetExisting, reactivationActor); err != nil {
			log.Printf("Sensor %s token provisioning failed: %v", body.SensorID, err)
			switch {
			case errors.Is(err, store.ErrSensorExists):
				// A concurrent request created this identity between our check and the tx.
				writeJSON(w, http.StatusConflict, map[string]any{
					"error": "sensor_id already exists; a generic new-sensor code cannot claim it — use an admin-minted reset code bound to this sensor_id",
				})
			case errors.Is(err, store.ErrSensorNotFound):
				writeJSON(w, http.StatusConflict, map[string]any{
					"error": "sensor_id no longer exists to reset; retry as a new enrollment",
				})
			default:
				writeJSON(w, http.StatusConflict, map[string]any{
					"error": "could not provision sensor token; a concurrent registration for this sensor_id may be in progress — retry",
				})
			}
			return
		}

		response.AuthToken = rawToken
		response.TokenID = token.TokenID
		response.TokenWarning = "save this token now — it will not be displayed again"
		log.Printf("Sensor token generated: %s (label: %s)", token.TokenID, token.Label)

		// Issue #44: remember the (code -> raw token + sensor_id) so a sensor that
		// loses THIS response can present the same code and get the same token back
		// instead of a permanent 401. The memory expires with the code's TTL.
		if consumedEnrollCode != "" && s.Enroll != nil {
			s.Enroll.RecordRedemption(consumedEnrollCode, body.SensorID, rawToken, token.TokenID)
		}
	} else if err := s.DB.RefreshSensorWithActiveToken(sensor, presentedToken.TokenID); err != nil {
		// Metadata refresh only (matching sensor token, no reissue).
		log.Printf("Sensor %s metadata refresh failed: %v", body.SensorID, err)
		if errors.Is(err, store.ErrSensorRemoved) || errors.Is(err, store.ErrSensorTokenInactive) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "sensor is no longer active; use an admin-minted reset code bound to this sensor_id to reactivate it",
			})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to refresh sensor registration"})
		}
		return
	}
	deliveryEpoch, err := s.DB.IssueARPCacheDeliveryEpoch(body.SensorID)
	if err != nil {
		log.Printf("Sensor %s delivery-session issue failed: %v", body.SensorID, err)
		// Registration/token persistence has already committed. Withholding a
		// freshly minted raw bearer here would make the credential unrecoverable.
		// Empty means ARP-cache evidence remains provisional/fail-closed.
		deliveryEpoch = ""
	}
	response.DeliveryEpoch = deliveryEpoch

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
		SensorID string    `json:"sensor_id"`
		CIDR     string    `json:"cidr"`
		Segment  string    `json:"segment"`
		ScanTime time.Time `json:"scan_time"`
		Hosts    []struct {
			IPAddress        string    `json:"ip_address"`
			MACAddress       string    `json:"mac_address"`
			Hostname         string    `json:"hostname"`
			Vendor           string    `json:"vendor"`
			OpenPorts        []int     `json:"open_ports"`
			Status           string    `json:"status"`
			ObservedAt       time.Time `json:"observed_at,omitempty"`
			DeliveryEpoch    string    `json:"delivery_epoch,omitempty"`
			DeliverySequence uint64    `json:"delivery_sequence,omitempty"`
			// Extended for actionability (model/services/discovery_source from passive sensor).
			// These will be populated in JSON decode; copy to DiscoveredHost only after L4 updates the type.
			Model            string   `json:"model,omitempty"`
			Services         []string `json:"services,omitempty"`
			FriendlyName     string   `json:"friendly_name,omitempty"` // spec 004: optional human-friendly name (mDNS/SSDP). Additive; old sensors omit it.
			DiscoverySource  string   `json:"discovery_source,omitempty"`
			IdentityEvidence []struct {
				Type       string  `json:"type"`
				Value      string  `json:"value"`
				Source     string  `json:"source,omitempty"`
				Confidence float64 `json:"confidence,omitempty"`
				Sensitive  bool    `json:"sensitive,omitempty"`
			} `json:"identity_evidence,omitempty"`
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

	// Upsert each discovered host, tracking REAL successes and failures.
	// BUG-3: previously this always reported accepted == len(hosts) and swallowed
	// every store error, so the API returned 200 "accepted:N" even when every
	// upsert failed. Now we count what actually persisted and reflect it.
	now := time.Now().UTC()
	// Normalize implausibly future clocks before any device write. The store keeps
	// the first mapping by authenticated sensor and exact upstream timestamp, so a
	// partial 207 replay cannot turn identical evidence into a newer observation.
	// Correct-clock timestamps remain exact. A short forward continuation of a
	// durable future-clock epoch retains its offset after entering the skew window
	// only while upstream progress still tracks server receipt time; a backward or
	// partial NTP correction is deliberately left raw. Future cohorts keep their
	// relative ordering, including request-local cohorts that straddle the skew
	// cutoff and would otherwise invert under independent classification.
	upstreamTimes := make([]time.Time, 0, len(body.Hosts)+1)
	upstreamTimes = append(upstreamTimes, body.ScanTime)
	for _, host := range body.Hosts {
		upstreamTimes = append(upstreamTimes, host.ObservedAt)
	}
	normalizedTimes, err := s.DB.NormalizeSensorReportTimes(
		r.Context(), body.SensorID, upstreamTimes, now, maxTimestampSkew,
	)
	if err != nil {
		log.Printf("Failed to normalize device report timestamps from sensor %s: %v", body.SensorID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to normalize sensor report timestamps"})
		return
	}
	normalizeReportTime := func(ts time.Time) time.Time {
		if ts.IsZero() {
			return ts
		}
		ts = ts.UTC()
		if normalized, ok := normalizedTimes[ts.Format(time.RFC3339Nano)]; ok {
			return normalized
		}
		// Every non-zero request timestamp was included above. Keep a safe fallback
		// if that invariant changes in a future additive payload.
		return clampFutureTimestamp(ts, now)
	}
	observedAt := normalizeReportTime(body.ScanTime)
	if observedAt.IsZero() {
		observedAt = now
	}
	hostObservedTimes := make([]time.Time, len(body.Hosts))
	for i, host := range body.Hosts {
		hostObservedTimes[i] = observedAt
		if !host.ObservedAt.IsZero() {
			hostObservedTimes[i] = normalizeReportTime(host.ObservedAt)
		}
	}

	// One authenticated sensor report is one observation generation. Collapse
	// equal-time cache conflicts before the first store write so input ordering
	// cannot fuse A and only afterward discover B/blank for the same scoped IP.
	// Current sensors already emit one pre-classified state per IP; this boundary
	// also keeps legacy/additive payloads fail-closed.
	type cacheGenerationKey struct {
		ip         string
		observedAt time.Time
		epoch      string
		sequence   uint64
	}
	normalizeIP := func(raw string) string {
		if ip := net.ParseIP(strings.TrimSpace(raw)).To4(); ip != nil &&
			!ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() {
			return ip.String()
		}
		return ""
	}
	normalizeMAC := func(raw string) string {
		mac, err := net.ParseMAC(strings.TrimSpace(raw))
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return ""
		}
		allZero, allBroadcast := true, true
		for _, octet := range mac {
			allZero = allZero && octet == 0
			allBroadcast = allBroadcast && octet == 0xff
		}
		if allZero || allBroadcast {
			return ""
		}
		return strings.ToUpper(mac.String())
	}
	// Delivery epochs are untrusted request fields until they are tied to this sensor in
	// Core's issuance ledger. Classify every candidate before the first device write so
	// arbitrary strings cannot split one equal-time conflict into attacker-chosen keys.
	issuedEpochs := make(map[string]bool)
	checkedEpochs := make(map[string]struct{})
	for _, host := range body.Hosts {
		source := strings.ToLower(strings.TrimSpace(host.DiscoverySource))
		if source != "arp_cache" && source != "arp" {
			continue
		}
		epoch := strings.TrimSpace(host.DeliveryEpoch)
		if epoch == "" || len(epoch) > 64 || host.DeliverySequence == 0 || host.DeliverySequence > uint64(1<<63-1) {
			continue
		}
		if _, checked := checkedEpochs[epoch]; checked {
			continue
		}
		checkedEpochs[epoch] = struct{}{}
		issued, err := s.DB.HasARPCacheDeliveryEpoch(body.SensorID, epoch)
		if err != nil {
			log.Printf("Failed to classify ARP delivery epoch from sensor %s: %v", body.SensorID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to classify sensor delivery epoch"})
			return
		}
		issuedEpochs[epoch] = issued
	}
	cacheKey := func(index int, ipAddress, deliveryEpoch string, deliverySequence uint64) cacheGenerationKey {
		key := cacheGenerationKey{ip: normalizeIP(ipAddress), observedAt: hostObservedTimes[index]}
		epoch := strings.TrimSpace(deliveryEpoch)
		if issuedEpochs[epoch] && deliverySequence > 0 && deliverySequence <= uint64(1<<63-1) {
			key.observedAt = time.Time{}
			key.epoch = epoch
			key.sequence = deliverySequence
		}
		return key
	}
	cacheValues := make(map[cacheGenerationKey]string)
	cacheAmbiguous := make(map[cacheGenerationKey]struct{})
	for i, host := range body.Hosts {
		source := strings.ToLower(strings.TrimSpace(host.DiscoverySource))
		if source != "arp_cache" && source != "arp" {
			continue
		}
		key := cacheKey(i, host.IPAddress, host.DeliveryEpoch, host.DeliverySequence)
		mac := normalizeMAC(host.MACAddress)
		if previous, exists := cacheValues[key]; exists {
			if previous == "" || mac == "" || previous != mac {
				cacheAmbiguous[key] = struct{}{}
			}
		} else {
			cacheValues[key] = mac
		}
	}
	newCount := 0
	accepted := 0
	failed := 0
	protocolConflicts := 0
	staleReplays := 0
	for hostIndex, h := range body.Hosts {
		identityEvidence := make([]discovery.IdentityEvidence, 0, len(h.IdentityEvidence))
		for i, evidence := range h.IdentityEvidence {
			if i >= 32 {
				break
			}
			kind := strings.ToLower(strings.TrimSpace(evidence.Type))
			if !sensorIdentityEvidenceType(kind) || strings.TrimSpace(evidence.Value) == "" || len(evidence.Value) > 512 {
				continue
			}
			identityEvidence = append(identityEvidence, discovery.IdentityEvidence{
				Type: kind, Value: evidence.Value, Source: evidence.Source,
				Confidence: evidence.Confidence, Sensitive: evidence.Sensitive,
			})
		}
		host := discovery.DiscoveredHost{
			IPAddress:        h.IPAddress,
			MACAddress:       h.MACAddress,
			Hostname:         h.Hostname,
			Vendor:           h.Vendor,
			OpenPorts:        h.OpenPorts,
			Status:           h.Status,
			ObservedAt:       h.ObservedAt,
			Model:            h.Model,
			Services:         h.Services,
			FriendlyName:     h.FriendlyName,
			DiscoverySource:  h.DiscoverySource,
			IdentityEvidence: identityEvidence,
		}
		hostObservedAt := hostObservedTimes[hostIndex]
		source := strings.ToLower(strings.TrimSpace(h.DiscoverySource))
		if source == "arp_cache" || source == "arp" {
			key := cacheKey(hostIndex, h.IPAddress, h.DeliveryEpoch, h.DeliverySequence)
			if _, ambiguous := cacheAmbiguous[key]; ambiguous {
				host.MACAddress = ""
			}
		}
		host.ObservedAt = hostObservedAt
		isNew, err := s.DB.ObserveDevice(store.DeviceObservation{
			Host: host, Segment: body.Segment, SensorID: body.SensorID,
			ObservedAt: hostObservedAt, DeliveryEpoch: h.DeliveryEpoch,
			DeliverySequence: h.DeliverySequence,
		})
		if err != nil {
			if errors.Is(err, store.ErrARPCacheDeliveryMutation) {
				// The immutable batch was already accepted under this scoped
				// generation. Acknowledge the changed duplicate as permanently
				// processed so the sensor does not retry it forever. Aggregate the
				// warning below rather than logging attacker-controlled host values.
				accepted++
				protocolConflicts++
				continue
			}
			if errors.Is(err, store.ErrARPCacheDeliveryStale) {
				// A newer accepted sequence or process epoch makes every older
				// generation terminal. Do not let the stale payload create weak
				// provisional evidence, and do not make the sensor retry it.
				accepted++
				staleReplays++
				continue
			}
			failed++
			log.Printf("Failed to upsert device %s from sensor %s: %v", h.IPAddress, body.SensorID, err)
			continue
		}
		accepted++
		if isNew {
			newCount++
			log.Printf("New device [%s] via sensor %s: %s (%s)", body.Segment, body.SensorID, h.IPAddress, h.MACAddress)
		}
	}

	if protocolConflicts > 0 {
		log.Printf("Sensor %s sent %d contradictory immutable ARP cache delivery generations; acknowledged without changing stored identity", body.SensorID, protocolConflicts)
	}
	if staleReplays > 0 {
		log.Printf("Sensor %s replayed %d superseded ARP cache delivery generations; acknowledged without creating projections", body.SensorID, staleReplays)
	}
	log.Printf("Sensor %s reported %d hosts (%d accepted, %d failed, %d new, %d protocol conflicts, %d stale replays) from %s", body.SensorID, len(body.Hosts), accepted, failed, newCount, protocolConflicts, staleReplays, body.CIDR)
	s.logInfo("scan", fmt.Sprintf("Sensor %s reported %d hosts (%d accepted, %d failed, %d new, %d protocol conflicts, %d stale replays) from %s [%s]", body.SensorID, len(body.Hosts), accepted, failed, newCount, protocolConflicts, staleReplays, body.CIDR, body.Segment))

	resp := map[string]any{
		"accepted":    accepted,
		"failed":      failed,
		"new_devices": newCount,
	}
	if protocolConflicts > 0 {
		resp["protocol_conflicts"] = protocolConflicts
	}
	if staleReplays > 0 {
		resp["stale_replays"] = staleReplays
	}

	// If we had hosts to store but every single one failed, this is a server-side
	// persistence failure — do not lie with a 200. Report 500 so the sensor retries.
	if len(body.Hosts) > 0 && accepted == 0 {
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	// Some (but not all) failed → 207-style partial success signalled in the body.
	if failed > 0 {
		resp["status"] = "partial"
		writeJSON(w, http.StatusMultiStatus, resp)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSensorList(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	sensors, removed, err := s.DB.ListSensorPartitions()
	if err != nil {
		log.Printf("List sensors failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to list sensors"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"removed_sensors": removed,
		"removed_total":   len(removed),
		"sensors":         sensors,
		"total":           len(sensors),
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
		// Re-validate at the serve point (Issue #7): never hand an invalid target to
		// the root-running sensor, even if one slipped past write-time validation.
		targets, err := s.servableScanTargets()
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

// handleSensorHeartbeat keeps process reachability independent from the much
// slower network-scan cadence. It deliberately records only sensor last_seen:
// detection health still requires a successfully committed event batch before
// it can claim capture is healthy.
func (s *Server) handleSensorHeartbeat(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}
	sensorID, ok := s.requireAuthenticatedSensorID(w, r, r.Header.Get("X-Sensor-ID"))
	if !ok {
		return
	}
	if err := s.DB.TouchSensor(sensorID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not record sensor heartbeat"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSensorAuthCheck validates that the caller still holds the active credential
// bound to its sensor identity. Unlike heartbeat it deliberately performs no database
// write, does not refresh last_seen/status, and does not drain queued work. Installers
// and diagnostics use this endpoint to distinguish a valid persisted token from a
// revoked one without making a stopped sensor appear online.
func (s *Server) handleSensorAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}
	err := s.validateReadOnlySensorRequest(r)
	if errors.Is(err, errInvalidReadOnlySensorCredential) {
		// Keep the response generic: callers must not be able to enumerate token IDs,
		// revocation state, or sensor identities through this diagnostic surface.
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or revoked sensor token"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "sensor authentication temporarily unavailable"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		if errors.Is(err, store.ErrSensorNotFound) || errors.Is(err, store.ErrSensorRemoved) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "sensor not found"})
		} else {
			log.Printf("Set primary sensor %s failed: %v", sensorID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to set primary sensor"})
		}
		return
	}

	log.Printf("Primary sensor changed to: %s", sensorID)
	writeJSON(w, http.StatusOK, map[string]any{"primary": sensorID})
}

// handleDeleteSensor tombstones a sensor and revokes only its sensor credential.
// Its identity and history remain, so returning requires a fresh bound reset code.
// The current primary can't be removed; another active sensor must be promoted.
func (s *Server) handleDeleteSensor(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	sensorID := chi.URLParam(r, "sensorID")
	if sensorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sensor_id required"})
		return
	}

	actorTokenID := ""
	if token := auth.GetTokenFromContext(r); token != nil {
		actorTokenID = token.TokenID
	}
	removedAt, err := s.DB.RemoveSensor(sensorID, actorTokenID, "removed by operator")
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSensorNotFound):
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "sensor not found"})
		case errors.Is(err, store.ErrLastPrimarySensor):
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "cannot remove the primary sensor; make another sensor primary first"})
		default:
			log.Printf("Remove sensor %s failed: %v", sensorID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to remove sensor"})
		}
		return
	}

	log.Printf("Sensor removed: %s", sensorID)
	s.logInfo("sensor", fmt.Sprintf("Sensor removed: %s", sensorID))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "removed",
		"sensor_id":  sensorID,
		"removed_at": removedAt,
	})
}

// deduplicateGatewayEchoes pairs the query and response packets emitted for one
// lookup. The capture path preserves the original client and resolver on both,
// so distinct clients (or resolvers) must never be collapsed. Current sensors
// provide an explicit direction marker, which also lets an answerless NXDOMAIN or
// NODATA response pair with its query. The answer-bearing heuristic is retained
// only when both events are from a legacy sensor with no markers.
func deduplicateGatewayEchoes(events []models.Event) []models.Event {
	if len(events) <= 1 {
		return events
	}

	hasAnswerData := func(event models.Event) bool {
		if event.ResolvedIP != "" {
			return true
		}
		metadata := map[string]any{}
		if json.Unmarshal([]byte(event.Metadata), &metadata) != nil {
			return false
		}
		answers, ok := metadata["dns_answers"].([]any)
		return ok && len(answers) > 0
	}
	direction := func(event models.Event) string {
		metadata := map[string]any{}
		if json.Unmarshal([]byte(event.Metadata), &metadata) != nil {
			return ""
		}
		value, _ := metadata["dns_direction"].(string)
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "query":
			return "query"
		case "response":
			return "response"
		default:
			return ""
		}
	}
	sameLookup := func(a, b models.Event) bool {
		if normalizeDNSName(a.Domain) != normalizeDNSName(b.Domain) ||
			strings.ToUpper(strings.TrimSpace(a.QueryType)) != strings.ToUpper(strings.TrimSpace(b.QueryType)) ||
			normalizeAddress(a.SourceIP) != normalizeAddress(b.SourceIP) ||
			normalizeAddress(a.ServerIP) != normalizeAddress(b.ServerIP) {
			return false
		}
		delta := a.Timestamp.Sub(b.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta > 2*time.Second {
			return false
		}
		aDirection, bDirection := direction(a), direction(b)
		if aDirection != "" || bDirection != "" {
			return aDirection != "" && bDirection != "" && aDirection != bDirection
		}
		return hasAnswerData(a) != hasAnswerData(b)
	}
	mergeInto := func(kept *models.Event, other models.Event) {
		if kept.ResolvedIP == "" {
			kept.ResolvedIP = other.ResolvedIP
		}
		if kept.ServerIP == "" {
			kept.ServerIP = other.ServerIP
		}
		merged := map[string]any{}
		if other.Metadata != "" {
			_ = json.Unmarshal([]byte(other.Metadata), &merged)
		}
		if kept.Metadata != "" {
			keptMeta := map[string]any{}
			if err := json.Unmarshal([]byte(kept.Metadata), &keptMeta); err == nil {
				for key, value := range keptMeta {
					merged[key] = value
				}
			}
		}
		if len(merged) > 0 {
			if raw, err := json.Marshal(merged); err == nil {
				kept.Metadata = string(raw)
			}
		}
		for _, tag := range kept.Tags {
			if tag == "deduplicated" {
				return
			}
		}
		kept.Tags = append(kept.Tags, "deduplicated")
	}

	used := make([]bool, len(events))
	result := make([]models.Event, 0, len(events))
	dedupCount := 0
	for index := range events {
		if used[index] {
			continue
		}
		kept := events[index]
		partner := -1
		for candidate := index + 1; candidate < len(events); candidate++ {
			if !used[candidate] && sameLookup(kept, events[candidate]) {
				partner = candidate
				break
			}
		}
		if partner >= 0 {
			used[partner] = true
			other := events[partner]
			if direction(other) == "response" || (direction(kept) == "" && hasAnswerData(other)) {
				kept, other = other, kept
			}
			mergeInto(&kept, other)
			dedupCount++
		}
		result = append(result, kept)
	}

	if dedupCount > 0 {
		log.Printf("Deduplication: paired %d DNS query/response echoes", dedupCount)
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
			ObservationID string   `json:"observation_id,omitempty"`
			Timestamp     int64    `json:"timestamp"` // unix millis or seconds (auto-detected for compat)
			Domain        string   `json:"domain"`
			QueryType     string   `json:"query_type"`
			ClientIP      string   `json:"client_ip"`
			ResponseIP    string   `json:"response_ip,omitempty"`
			ServerIP      string   `json:"server_ip,omitempty"`
			Direction     string   `json:"direction,omitempty"`
			RCode         string   `json:"response_code,omitempty"`
			Blocked       bool     `json:"blocked"`
			Source        string   `json:"source"`
			Answers       []string `json:"answers,omitempty"` // resolved destinations from sensor (for actionability)
			Process       string   `json:"process,omitempty"` // originating process hint (if sensor has local visibility)
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

	// Convert DNS queries to Events
	events := make([]models.Event, 0, len(body.Queries))
	for _, q := range body.Queries {
		if q.Domain == "" || q.ClientIP == "" {
			continue // skip invalid queries
		}

		// Timestamp: support millis (preferred for precision) or legacy seconds
		var upstreamTimestamp time.Time
		if q.Timestamp > 1_000_000_000_000 { // millis
			upstreamTimestamp = time.UnixMilli(q.Timestamp).UTC()
		} else {
			upstreamTimestamp = time.Unix(q.Timestamp, 0).UTC()
		}
		// GHSA-9m7g: same clamp as the generic /ingest path — a sensor must not be
		// able to plant a far-future cursor via a forged/skewed DNS query timestamp.
		ts := clampFutureTimestamp(upstreamTimestamp, time.Now().UTC())

		event := models.Event{
			Timestamp: ts,
			EventType: "dns_query",
			// Core's processor derives the stable per-install HMAC. Adapters never
			// choose or trust a caller-provided grouping pseudonym.
			SourceHash:     "",
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
		// The authenticated sensor identity and original (pre-clamp) observation
		// time make retransmission idempotent even after a partial batch failure.
		direction := strings.ToLower(strings.TrimSpace(q.Direction))
		if direction != "query" && direction != "response" {
			direction = ""
		}
		responseCode := strings.TrimSpace(q.RCode)
		observationID := strings.TrimSpace(q.ObservationID)
		event.EventID = deterministicSensorDNSObservationEventID(sensorID, upstreamTimestamp, event, q.Answers, q.Process, direction, responseCode, observationID)

		// Store wire semantics and answers in metadata for actionability and robust
		// query/response pairing. An explicit response marker is meaningful even
		// when the response has no answers (NXDOMAIN/NODATA).
		// This helps users see what the query actually resolved to without extra lookups.
		metadata := map[string]any{}
		if observationID != "" {
			metadata["observation_id"] = observationID
		}
		if direction != "" {
			metadata["dns_direction"] = direction
		}
		if responseCode != "" {
			metadata["dns_response_code"] = responseCode
		}
		if len(q.Answers) > 0 {
			metadata["dns_answers"] = q.Answers
			// Also surface first answer in ResolvedIP for backward/ simple views
			if event.ResolvedIP == "" {
				event.ResolvedIP = q.Answers[0]
			}
		}

		if q.Process != "" {
			metadata["process"] = q.Process
		}
		if len(metadata) > 0 {
			if encoded, err := json.Marshal(metadata); err == nil {
				event.Metadata = string(encoded)
			}
		}

		// Device context is deliberately resolved inside the unified processor at
		// q.Timestamp. Looking up the device that owns ClientIP *now* would corrupt
		// delayed events after DHCP/VLAN reuse and defeat temporal identity.

		events = append(events, event)
	}

	if len(events) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": 0})
		return
	}

	// Deduplicate gateway echoes before enrichment
	events = deduplicateGatewayEchoes(events)

	// The authenticated sensor ID is part of the temporal identity context.
	summary := s.processEvents(r.Context(), events, "sensor_dns", sensorID)
	if summary.Failed > 0 {
		log.Printf("Sensor DNS processing failures: %d (first: %v)", summary.Failed, summary.FirstError)
		_ = s.DB.MarkCollectionError(r.Context(), "sensor:"+sensorID, "sensor", "Sensor "+sensorID, "event processing failed", time.Now().UTC())
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "processing failed"})
		return
	}
	acceptedCount := summary.Inserted + summary.Duplicates
	_ = s.DB.MarkCollectionSuccess(r.Context(), "sensor:"+sensorID, "sensor", "Sensor "+sensorID, int64(acceptedCount), time.Now().UTC())

	s.logInfo("ingest", fmt.Sprintf("Sensor %s ingested %d DNS queries", sensorID, acceptedCount))
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": acceptedCount, "inserted": summary.Inserted, "duplicates": summary.Duplicates,
	})
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

// handleListConnectors returns the health of all registered firewall connectors
// (spec 001, T4.4). Admin-only; used by the setup guide's verification step.
func (s *Server) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	connectors := []firewall.NamedHealth{}
	if s.Firewall != nil {
		connectors = s.Firewall.ListNamed()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connectors": connectors,
		"total":      len(connectors),
	})
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

// csvSanitizeCell neutralizes CSV formula injection (GHSA-45j4). A spreadsheet
// treats any cell whose first character is =, +, -, @, or a leading tab/CR as a
// formula, so an attacker-influenced value (e.g. a syslog-sourced domain or
// threat description) beginning with one of those could execute when the export is
// opened. We defang by prefixing such a cell with a single quote. Correct quoting
// of commas/newlines/quotes is handled separately by encoding/csv.
func csvSanitizeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// writeEventsCSV serializes events as RFC 4180 CSV using encoding/csv (correct
// quoting of embedded commas, quotes, and newlines) with every cell passed through
// csvSanitizeCell to neutralize formula injection (GHSA-45j4).
func writeEventsCSV(w io.Writer, events []models.Event) {
	cw := csv.NewWriter(w)
	header := []string{
		"event_id", "timestamp", "event_type", "source_hash", "source_ip", "server_ip",
		"domain", "query_type", "resolved_ip", "blocked", "outcome", "anomaly_score", "tags", "geo",
		"device_vendor", "network_segment", "dns_source", "threat_desc", "dns_answers", "process",
	}
	_ = cw.Write(header)

	for _, e := range events {
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
		row := []string{
			e.EventID, e.Timestamp.Format(time.RFC3339), e.EventType, e.SourceHash,
			e.SourceIP, e.ServerIP, e.Domain, e.QueryType, e.ResolvedIP, strconv.FormatBool(e.Blocked), e.Outcome,
			strconv.FormatFloat(e.AnomalyScore, 'f', 4, 64), tagsStr, e.Geo,
			e.DeviceVendor, e.NetworkSegment, e.DNSSource, e.ThreatDesc, answersStr, processStr,
		}
		for i, cell := range row {
			row[i] = csvSanitizeCell(cell)
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

// maxTimestampSkew is how far ahead of server time an event Timestamp may be before
// it is treated as clock skew or forgery (GHSA-9m7g). Telemetry uses the event
// Timestamp as its persistent cursor, so a single far-future event (e.g. dated 2036)
// would permanently strand every normal event behind it. Both ingest paths clamp to
// this bound so neither the generic /ingest path nor the sensor DNS ingest path can
// plant a future cursor.
const maxTimestampSkew = time.Hour

// clampFutureTimestamp returns ts, or now when ts is more than maxTimestampSkew ahead
// of now. A zero ts is returned unchanged so callers can apply their own default.
func clampFutureTimestamp(ts, now time.Time) time.Time {
	if !ts.IsZero() && ts.After(now.Add(maxTimestampSkew)) {
		return now
	}
	return ts
}

// servableScanTargets returns the enabled scan targets that still pass
// discovery.ValidateScanTarget. This is the single choke point for handing scan
// work to sensors: even if an invalid target (e.g. a pre-upgrade 0.0.0.0/0, Issue #7)
// is disabled at startup, re-validating here guarantees a bad row that slips into the
// DB by any path is never dispatched to the root-running sensor.
func (s *Server) servableScanTargets() ([]models.ScanTarget, error) {
	targets, err := s.DB.GetEnabledScanTargets()
	if err != nil {
		return nil, err
	}
	valid := make([]models.ScanTarget, 0, len(targets))
	for _, t := range targets {
		if verr := discovery.ValidateScanTarget(t.CIDR); verr != nil {
			s.logWarn("scan", fmt.Sprintf("Skipping invalid scan target %q (%s): %v", t.CIDR, t.TargetID, verr))
			continue
		}
		valid = append(valid, t)
	}
	return valid, nil
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
