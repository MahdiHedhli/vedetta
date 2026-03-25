package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/api"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/store"
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

	scanCIDR := os.Getenv("VEDETTA_SCAN_CIDR")
	scanInterval := os.Getenv("VEDETTA_SCAN_INTERVAL")
	if scanInterval == "" {
		scanInterval = "5m"
	}

	// Open database
	db, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Auto-detect subnet if not explicitly configured
	if scanCIDR == "" || scanCIDR == "auto" {
		detected := discovery.BestSubnet("192.168.1.0/24")
		log.Printf("Auto-detected scan subnet: %s", detected)
		scanCIDR = detected
	}

	// Set up the API server
	srv := &api.Server{DB: db}

	// Set up nmap scanner (optional — may not be available)
	scanner, err := discovery.NewScanner()
	if err != nil {
		log.Printf("WARNING: nmap not available — network scanning disabled: %v", err)
	} else {
		interval, err := time.ParseDuration(scanInterval)
		if err != nil {
			interval = 5 * time.Minute
		}

		withPorts := os.Getenv("VEDETTA_SCAN_PORTS") == "true"
		targetAdapter := &store.TargetAdapter{DB: db}
		scheduler := discovery.NewScheduler(scanner, db, targetAdapter, scanCIDR, interval, withPorts)
		srv.Scheduler = scheduler
		scheduler.Start()
		defer scheduler.Stop()
	}

	router := api.NewRouter(srv)

	httpSrv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Vedetta backend starting on :%s (scan_cidr=%s, scan_interval=%s)", port, scanCIDR, scanInterval)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
