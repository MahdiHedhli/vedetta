package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/api"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/dnsingest"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/dnspoller"
	"github.com/vedetta-network/vedetta/backend/internal/firewall"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

// buildVersion is the release version of this binary. It defaults to "dev" for
// local/source builds and is injected by release CI via
// -ldflags "-X main.buildVersion=<tag>" (issue #38). Printed by --version.
var buildVersion = "dev"

func main() {
	// --version: print the build version and exit. Kept ahead of any DB/setup work
	// so it stays a cheap, side-effect-free build probe (issue #38).
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("vedetta-core %s\n", buildVersion)
			return
		}
	}

	port := os.Getenv("VEDETTA_PORT")
	if port == "" {
		port = "8080"
	}

	// Listen address. SAFE BY DEFAULT (beta-gate B6): bind loopback only so a
	// bare-metal / host-network install is not exposed on the LAN. Operators who
	// front Core with a reverse proxy (see docs/reverse-proxy.md) or need
	// direct LAN access set VEDETTA_LISTEN_ADDR explicitly.
	//
	// DOCKER: inside a container 127.0.0.1 is unreachable through Docker's
	// published port and from sibling containers, so docker-compose.yml sets
	// VEDETTA_LISTEN_ADDR=0.0.0.0 for the backend service (the container is
	// isolated on the compose network; the host port mapping is what's exposed).
	listenAddr := os.Getenv("VEDETTA_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}

	dbPath := os.Getenv("VEDETTA_DB_PATH")
	if dbPath == "" {
		dbPath = "/data/vedetta.db"
	}

	// Open database
	db, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Seed default whitelist rules if none exist
	if err := db.SeedDefaultWhitelistRules(); err != nil {
		log.Printf("WARNING: failed to seed default whitelist rules: %v", err)
	}

	// Issue #7: an upgraded DB may carry scan targets written before write-time
	// validation existed (e.g. a planted 0.0.0.0/0). Disable any stored target that
	// fails discovery.ValidateScanTarget so it can never be handed to the root sensor.
	if n, err := db.ScrubInvalidScanTargets(); err != nil {
		log.Printf("WARNING: failed to scrub invalid scan targets: %v", err)
	} else if n > 0 {
		log.Printf("Disabled %d invalid stored scan target(s) at startup", n)
	}

	// Provision the collector's ingest credential from the shared VEDETTA_INGEST_TOKEN
	// secret (the same value is given to the collector container). Without this,
	// /ingest keeps working only until the first token is created (e.g. when a
	// sensor registers), after which the tokenless collector gets 401 and UniFi
	// ingestion silently stops (beta-gate B5). Idempotent.
	if raw := strings.TrimSpace(os.Getenv("VEDETTA_INGEST_TOKEN")); raw != "" {
		if created, err := db.EnsureTokenFromRaw(raw, auth.ScopeIngest, "compose-provisioned ingest token"); err != nil {
			log.Printf("WARNING: could not provision ingest token from VEDETTA_INGEST_TOKEN: %v", err)
		} else if created {
			log.Printf("Provisioned ingest-scope token from VEDETTA_INGEST_TOKEN")
		}
	}

	// Provision the telemetry daemon's READ credential from the shared
	// VEDETTA_CORE_TOKEN secret (the same value is given to the telemetry
	// container, which reads it as VEDETTA_CORE_TOKEN and presents it when
	// polling GET /api/v1/events). The read endpoints are gated to require at
	// least read scope once an active admin exists (beta-gate B6); without this
	// least-privilege token the tokenless telemetry reader would get 401/403 and
	// silently stop after the first admin token is created. Idempotent.
	if raw := strings.TrimSpace(os.Getenv("VEDETTA_CORE_TOKEN")); raw != "" {
		if created, err := db.EnsureTokenFromRaw(raw, auth.ScopeRead, "compose-provisioned read token"); err != nil {
			log.Printf("WARNING: could not provision read token from VEDETTA_CORE_TOKEN: %v", err)
		} else if created {
			log.Printf("Provisioned read-scope token from VEDETTA_CORE_TOKEN")
		}
	}

	// Issue #34: the collector ingest secret (VEDETTA_INGEST_TOKEN) and the
	// telemetry read secret (VEDETTA_CORE_TOKEN) MUST be distinct. EnsureTokenFromRaw
	// dedups by hash, so two IDENTICAL values provision only ONE scope — the other
	// machine client (collector ingest OR telemetry read) then gets 403 and its
	// pipeline silently stops. Fail fast (issue #34) rather than run degraded.
	if _, _, collision := api.MachineCredentialState(); collision {
		log.Printf("=====================================================================")
		log.Printf("FATAL: VEDETTA_INGEST_TOKEN and VEDETTA_CORE_TOKEN are IDENTICAL.")
		log.Printf("They must be DISTINCT secrets. Identical values hash-collide, so")
		log.Printf("only ONE scope (ingest OR read) is provisioned and the other client")
		log.Printf("— collector ingest or telemetry read — will get 403 and stop.")
		log.Printf("Generate two DIFFERENT strong values, e.g. `openssl rand -hex 32`.")
		log.Printf("=====================================================================")
		log.Fatalf("refusing to start with colliding machine credentials")
	}

	// Start retention enforcer (daily cleanup of old events)
	stopRetention := db.StartRetentionEnforcer()
	defer stopRetention()

	// Initialize threat intelligence database and enrichment engine
	threatDB, err := threatintel.NewThreatIntelDB(db.DB)
	if err != nil {
		log.Printf("Threat intel DB init failed (non-fatal): %v", err)
	}

	// Wire whitelist checking into the enricher for early noise suppression.
	// This is critical for signal-to-noise: whitelisted domains should never
	// generate high anomaly scores.
	enricher := dnsintel.NewEnricherWithWhitelist(threatDB, func(domain string) bool {
		if db == nil {
			return false
		}
		return db.IsDomainWhitelisted(domain)
	})
	// Firewall (spec 001) enrichment wiring: tag/source-IP whitelist for
	// firewall_log events and device-inventory cross-ref for risk scoring.
	enricher.FirewallWhitelisted = func(tags []string, sourceIP string) (string, bool) {
		if db == nil {
			return "", false
		}
		return db.IsEventWhitelisted(tags, sourceIP)
	}
	enricher.DeviceByIP = func(ip string) *models.Device {
		if db == nil {
			return nil
		}
		dev, err := db.GetDeviceByIP(ip)
		if err != nil {
			return nil
		}
		return dev
	}
	stopEviction := enricher.StartEviction()
	defer stopEviction()

	// Start threat intelligence feed downloads
	if threatDB != nil {
		feedScheduler := threatintel.NewFeedScheduler(threatDB)
		feedScheduler.Start()
		defer feedScheduler.Stop()
		log.Println("Threat intelligence feed scheduler active")
	}

	// Set up activity log (ring buffer for UI)
	activityLog := api.NewActivityLog(500)
	activityLog.Info("system", "Vedetta Core starting")

	// Set up the API server (Core)
	srv := &api.Server{
		DB:          db,
		Enricher:    enricher,
		ScanQueue:   &api.ScanQueue{},
		ActivityLog: activityLog,
	}

	// First-admin bootstrap setup code (GHSA-6cmx). Before any admin token exists,
	// POST /api/v1/auth/tokens is reachable unauthenticated on the LAN. To stop any
	// LAN client from minting a permanent admin, minting the first admin now requires
	// this single-use code. Generate one (or take VEDETTA_SETUP_CODE) ONLY while no
	// active admin exists, and log it clearly like an enrollment code. Once an admin
	// exists we leave SetupCode empty and never log it.
	if hasAdmin, err := db.HasActiveAdminToken(); err == nil && !hasAdmin {
		setupCode := strings.TrimSpace(os.Getenv("VEDETTA_SETUP_CODE"))
		if setupCode == "" {
			setupCode = api.NewSetupCode()
		}
		srv.SetupCode = setupCode
		log.Printf("=====================================================================")
		log.Printf("FIRST-ADMIN SETUP CODE: %s", setupCode)
		log.Printf("Present it as the X-Vedetta-Setup-Code header when creating the first")
		log.Printf("admin token (POST /api/v1/auth/tokens, scope=admin). Single use.")
		log.Printf("=====================================================================")
	}

	// Optional: built-in scanner for Linux host-network deployments.
	// The primary discovery path is via native sensors (vedetta-sensor).
	scanner, scanErr := discovery.NewScanner()
	if scanErr == nil {
		scanCIDR := os.Getenv("VEDETTA_SCAN_CIDR")
		if scanCIDR == "" || scanCIDR == "auto" {
			scanCIDR = discovery.BestSubnet("")
		}

		// GHSA-c5gj: refuse an operator-supplied scan CIDR that isn't a clean target
		// before it can ever reach nmap. An invalid value disables the built-in
		// scanner rather than risking option injection.
		if scanCIDR != "" {
			if err := discovery.ValidateScanTarget(scanCIDR); err != nil {
				log.Printf("Ignoring invalid VEDETTA_SCAN_CIDR %q: %v — built-in scanner disabled", scanCIDR, err)
				scanCIDR = ""
			}
		}

		scanInterval := os.Getenv("VEDETTA_SCAN_INTERVAL")
		if scanInterval == "" {
			scanInterval = "5m"
		}
		interval, _ := time.ParseDuration(scanInterval)
		if interval == 0 {
			interval = 5 * time.Minute
		}

		withPorts := os.Getenv("VEDETTA_SCAN_PORTS") == "true"
		targetAdapter := &store.TargetAdapter{DB: db}

		if scanCIDR != "" {
			scheduler := discovery.NewScheduler(scanner, db, targetAdapter, scanCIDR, interval, withPorts)
			srv.Scheduler = scheduler
			scheduler.Start()
			defer scheduler.Stop()
			log.Printf("Built-in scanner active: cidr=%s interval=%s", scanCIDR, interval)
		} else {
			log.Printf("nmap available but no subnet detected — waiting for sensor data or UI configuration")
		}
	} else {
		log.Printf("nmap not available — Core will receive data from sensors")
	}

	// Set up DNS ingestion manager
	dnsEventSink := func(query dnsingest.DNSQuery) error {
		// This is a placeholder; actual event conversion happens in the API handlers
		return nil
	}

	dnsManager := dnsingest.NewManager(dnsEventSink)

	// Get or generate install salt for source_hash computation (used by both Pi-hole and AdGuard)
	installSalt := os.Getenv("VEDETTA_INSTALL_SALT")
	if installSalt == "" {
		installSalt = "vedetta-install-salt" // fallback; in production, should be persisted
	}

	// Optional: Pi-hole DNS query poller
	piholeURL := os.Getenv("VEDETTA_PIHOLE_URL")
	piholeToken := os.Getenv("VEDETTA_PIHOLE_TOKEN")
	if piholeURL != "" && piholeToken != "" {
		// Parse polling interval (default 60s)
		piholeInterval := 60 * time.Second
		if intervalStr := os.Getenv("VEDETTA_PIHOLE_INTERVAL"); intervalStr != "" {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				piholeInterval = d
			}
		}

		piholeClient := dnspoller.NewPiHoleClient(piholeURL, piholeToken)
		poller := dnspoller.NewPoller(piholeClient, db, enricher, activityLog, installSalt, piholeInterval)
		piholeSrc := dnsingest.NewPiHoleSource(poller)
		dnsManager.Register(piholeSrc)
		log.Printf("Pi-hole poller registered: url=%s interval=%s", piholeURL, piholeInterval)
	}

	// Optional: AdGuard Home DNS query poller
	adguardURL := os.Getenv("VEDETTA_ADGUARD_URL")
	adguardUser := os.Getenv("VEDETTA_ADGUARD_USER")
	adguardPass := os.Getenv("VEDETTA_ADGUARD_PASS")
	if adguardURL != "" {
		// Parse polling interval (default 60s)
		adguardInterval := 60 * time.Second
		if intervalStr := os.Getenv("VEDETTA_ADGUARD_INTERVAL"); intervalStr != "" {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				adguardInterval = d
			}
		}

		adguardClient := dnspoller.NewAdGuardHTTPClient(adguardURL, adguardUser, adguardPass)
		adguardPoller := dnspoller.NewAdGuardPoller(adguardClient, db, enricher, activityLog, installSalt, adguardInterval)
		adguardSrc := dnsingest.NewAdGuardSource(adguardPoller)
		dnsManager.Register(adguardSrc)
		log.Printf("AdGuard Home poller registered: url=%s interval=%s", adguardURL, adguardInterval)
	}

	// Set up firewall connector manager
	fwSink := func(events []models.Event) error {
		_, err := db.InsertEvents(events)
		return err
	}
	fwManager := firewall.NewManager(fwSink)

	// Optional: UniFi firewall connector (spec 001, off by default).
	// Registered only when a host and at least one credential (API key preferred,
	// or username/password) are configured. This is enrichment (IPS events +
	// client inventory); the supported event path is syslog → collector → ingest.
	unifiHost := os.Getenv("VEDETTA_UNIFI_HOST")
	unifiUser := os.Getenv("VEDETTA_UNIFI_USER")
	unifiPass := os.Getenv("VEDETTA_UNIFI_PASS")
	unifiAPIKey := os.Getenv("VEDETTA_UNIFI_API_KEY")
	if unifiHost != "" && (unifiAPIKey != "" || unifiUser != "") {
		unifiPort := 443
		if p := os.Getenv("VEDETTA_UNIFI_PORT"); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				unifiPort = n
			}
		}
		unifiCfg := firewall.ConnectorConfig{
			Name:          "unifi",
			Type:          "unifi",
			Host:          unifiHost,
			Port:          unifiPort,
			Username:      unifiUser,
			Password:      unifiPass,
			APIKey:        unifiAPIKey,
			TLSSkipVerify: os.Getenv("VEDETTA_UNIFI_TLS_SKIP_VERIFY") == "true",
			PollInterval:  60 * time.Second,
			Enabled:       true,
		}
		unifiConn := firewall.NewUniFiConnector(unifiCfg)
		fwManager.Register(unifiCfg, unifiConn)

		// Client-inventory sync into the device registry (enrichment only, never
		// creates events). Maps UniFi network names to canonical segments.
		fwManager.SetDeviceSink(func(clients []firewall.ClientInfo) error {
			now := time.Now()
			for _, c := range clients {
				host := discovery.DiscoveredHost{
					IPAddress:       c.IP,
					MACAddress:      c.MAC,
					Hostname:        c.Hostname,
					Vendor:          c.Vendor,
					DiscoverySource: "unifi_connector",
				}
				if _, err := db.UpsertDevice(host, now, segmentFromUniFiNetwork(c.Network)); err != nil {
					log.Printf("UniFi inventory: upsert device %s failed: %v", c.IP, err)
				}
			}
			return nil
		}, 300*time.Second)

		authMode := "cookie"
		if unifiAPIKey != "" {
			authMode = "api_key"
		}
		log.Printf("UniFi firewall connector registered: host=%s auth=%s", unifiHost, authMode)
	}

	srv.Firewall = fwManager

	if err := fwManager.Start(); err != nil {
		log.Printf("WARNING: Firewall connector manager failed to start: %v", err)
	} else {
		defer fwManager.Stop()
	}

	// Start DNS ingestion manager
	if err := dnsManager.Start(); err != nil {
		log.Printf("WARNING: DNS ingestion manager failed to start: %v", err)
	} else {
		defer dnsManager.Stop()
	}

	// PIECE 4: daily retention enforcement (non-blocking). Config from retention_config.
	// Documented: use incremental_vacuum or offline VACUUM for Pi 4 SD longevity post-delete.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		_ = db.EnforceRetention() // initial
		for range ticker.C {
			_ = db.EnforceRetention()
		}
	}()
	log.Printf("Retention job started (daily)")

	router := api.NewRouter(srv)

	addr := net.JoinHostPort(listenAddr, port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Vedetta Core starting on %s", addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

// segmentFromUniFiNetwork maps a UniFi network/VLAN name to a canonical Vedetta
// segment (default|iot|guest). Unknown networks default to "default"; the raw
// network name is preserved by the connector for reference.
func segmentFromUniFiNetwork(network string) string {
	n := strings.ToLower(strings.TrimSpace(network))
	switch {
	case n == "":
		return "default"
	case strings.Contains(n, "guest"):
		return "guest"
	case strings.Contains(n, "iot") || strings.Contains(n, "smart") || strings.Contains(n, "camera"):
		return "iot"
	default:
		return "default"
	}
}
