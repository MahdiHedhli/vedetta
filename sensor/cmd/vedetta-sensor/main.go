package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

var (
	version = "0.1.0-dev"
)

func main() {
	// CLI flags
	coreURL := flag.String("core", "http://localhost:8080", "Vedetta Core API URL")
	cidr := flag.String("cidr", "auto", "CIDR to scan (or 'auto' to detect)")
	interval := flag.Duration("interval", 5*time.Minute, "Scan interval")
	scanPorts := flag.Bool("ports", false, "Include top-100 port scan")
	oneshot := flag.Bool("once", false, "Run a single scan and exit")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vedetta-sensor %s\n", version)
		os.Exit(0)
	}

	log.SetPrefix("[vedetta-sensor] ")
	log.SetFlags(log.Ldate | log.Ltime)

	// Resolve scan target
	scanCIDR := *cidr
	if scanCIDR == "" || scanCIDR == "auto" {
		detected := netscan.BestSubnet("")
		if detected == "" {
			log.Fatal("Could not auto-detect LAN subnet. Use --cidr to specify one.")
		}
		scanCIDR = detected
		log.Printf("Auto-detected LAN subnet: %s", scanCIDR)
	}

	// Verify nmap is available
	scanner, err := netscan.NewScanner()
	if err != nil {
		log.Fatalf("nmap not available: %v", err)
	}
	log.Printf("nmap found: %s", scanner.BinaryPath)

	// Set up Core API client
	core := client.New(*coreURL)

	// Register this sensor with Core
	if err := core.Register(scanCIDR); err != nil {
		log.Printf("WARNING: Could not register with Core at %s: %v", *coreURL, err)
		log.Printf("Scans will continue — results will be pushed when Core becomes available")
	} else {
		log.Printf("Registered with Core at %s", *coreURL)
	}

	log.Printf("Starting scan loop: cidr=%s interval=%s ports=%v", scanCIDR, *interval, *scanPorts)

	// Run first scan immediately
	runScan(scanner, core, scanCIDR, *scanPorts)

	if *oneshot {
		return
	}

	// Periodic scan loop with graceful shutdown
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			runScan(scanner, core, scanCIDR, *scanPorts)
		case s := <-sig:
			log.Printf("Received %s, shutting down", s)
			return
		}
	}
}

func runScan(scanner *netscan.Scanner, core *client.CoreClient, cidr string, withPorts bool) {
	log.Printf("Scanning %s ...", cidr)

	result, err := scanner.Scan(cidr, withPorts)
	if err != nil {
		log.Printf("Scan failed: %v", err)
		return
	}

	log.Printf("Scan complete: %d hosts found in %s", len(result.Hosts), result.Duration)

	if len(result.Hosts) == 0 {
		return
	}

	// Push results to Core
	if err := core.PushDevices(result, cidr); err != nil {
		log.Printf("Failed to push results to Core: %v", err)
		log.Printf("(Core may be offline — results will be retried next scan)")
	} else {
		log.Printf("Pushed %d devices to Core", len(result.Hosts))
	}
}
