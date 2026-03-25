package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Vedetta Telemetry Daemon
//
// Responsible for:
// 1. Reading normalized events from local SIEM storage
// 2. Stripping PII (HMAC source IPs, remove hostnames, round geo to country)
// 3. Batching anonymized events
// 4. Transmitting to the central threat network with retry logic
//
// This daemon only runs when the user has explicitly opted in.

func main() {
	optIn := os.Getenv("VEDETTA_TELEMETRY_OPTIN")
	if optIn != "true" {
		log.Println("Telemetry daemon: opt-in not enabled. Sleeping.")
		// Block until signal — container stays healthy but idle
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		return
	}

	backendURL := os.Getenv("VEDETTA_THREAT_NETWORK_URL")
	if backendURL == "" {
		backendURL = "http://threat-network:9090"
	}

	log.Printf("Telemetry daemon starting. Target: %s", backendURL)

	// TODO: Implement batch reader, PII stripper, and transmitter
	// For now, just stay alive
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Telemetry daemon shutting down.")
}
