package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// Vedetta Threat Network Backend
//
// Central service that:
// 1. Receives anonymized event batches from opted-in nodes
// 2. Deduplicates and stores in ClickHouse / TimescaleDB
// 3. Exposes internal API for threat feed queries:
//    - Top queried domains, anomaly clusters
//    - DGA candidates, new device fingerprints
//
// Schema is versioned from day one.

func main() {
	port := os.Getenv("THREAT_NETWORK_PORT")
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "ok",
			"service":        "vedetta-threat-network",
			"schema_version": 1,
		})
	})

	mux.HandleFunc("/api/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		// TODO: Validate, deduplicate, and store batch
		writeJSON(w, http.StatusAccepted, map[string]any{
			"accepted": true,
		})
	})

	mux.HandleFunc("/api/v1/feed/top-domains", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"domains": []any{}})
	})

	mux.HandleFunc("/api/v1/feed/anomalies", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"anomalies": []any{}})
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("Threat Network backend starting on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
