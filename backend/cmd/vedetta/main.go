package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/api"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

func main() {
	port := os.Getenv("VEDETTA_PORT")
	if port == "" {
		port = "8080"
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

	// Start retention enforcer (daily cleanup of old events)
	stopRetention := db.StartRetentionEnforcer()
	defer stopRetention()

	// Initialize threat intelligence database and enrichment engine
	threatDB, err := threatintel.NewThreatIntelDB(db.DB)
	if err != nil {
		log.Printf("Threat intel DB init failed (non-fatal): %v", err)
	}

	enricher := dnsintel.NewEnricher(threatDB)
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

	// Optional: built-in scanner for Linux host-network deployments.
	// The primary discovery path is via native sensors (vedetta-sensor).
	scanner, scanErr := discovery.NewScanner()
	if scanErr == nil {
		scanCIDR := os.Getenv("VEDETTA_SCAN_CIDR")
		if scanCIDR == "" || scanCIDR == "auto" {
			scanCIDR = discovery.BestSubnet("")
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

	router := api.NewRouter(srv)

	httpSrv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Vedetta Core starting on :%s", port)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
