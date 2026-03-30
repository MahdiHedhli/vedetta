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
	primary := flag.Bool("primary", false, "Register as the primary sensor")
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
	if err := core.Register(scanCIDR, *primary); err != nil {
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

func runScan(scanner *netscan.Scanner, core *client.CoreClient, primaryCIDR string, withPorts bool) {
	// Fetch work from Core (queued scans and enabled targets)
	var work *client.WorkResponse
	if w, err := core.FetchWork(); err == nil {
		work = w
		if len(work.ScanQueue) > 0 {
			log.Printf("Fetched %d queued scans from Core", len(work.ScanQueue))
		}
		if len(work.Targets) > 0 {
			log.Printf("Fetched %d enabled scan targets from Core", len(work.Targets))
		}
	} else {
		log.Printf("Could not fetch work from Core: %v (scanning primary CIDR only)", err)
	}

	// Build a set of CIDRs to scan, avoiding duplicates
	type scanTask struct {
		cidr      string
		segment   string
		scanPorts bool
	}
	scansMap := make(map[string]scanTask)

	// Add primary CIDR
	scansMap[primaryCIDR] = scanTask{cidr: primaryCIDR, segment: "default", scanPorts: withPorts}

	// Add queued scans from work
	if work != nil {
		for _, req := range work.ScanQueue {
			if _, exists := scansMap[req.CIDR]; !exists {
				scansMap[req.CIDR] = scanTask{
					cidr:      req.CIDR,
					segment:   req.Segment,
					scanPorts: req.ScanPorts || withPorts,
				}
			}
		}

		// Add enabled targets from work
		for _, target := range work.Targets {
			if _, exists := scansMap[target.CIDR]; !exists {
				scansMap[target.CIDR] = scanTask{
					cidr:      target.CIDR,
					segment:   target.Segment,
					scanPorts: target.ScanPorts || withPorts,
				}
			}
		}
	}

	// Execute all scans
	totalHosts := 0
	for _, task := range scansMap {
		log.Printf("Scanning %s (segment=%s) ...", task.cidr, task.segment)

		result, err := scanner.Scan(task.cidr, task.scanPorts)
		if err != nil {
			log.Printf("Scan failed for %s: %v", task.cidr, err)
			continue
		}

		log.Printf("Scan complete for %s: %d hosts found in %s", task.cidr, len(result.Hosts), result.Duration)

		if len(result.Hosts) == 0 {
			continue
		}

		totalHosts += len(result.Hosts)

		// Push results to Core with the correct segment
		if err := core.PushDevices(result, task.cidr, task.segment); err != nil {
			log.Printf("Failed to push results to Core for %s: %v", task.cidr, err)
		} else {
			log.Printf("Pushed %d devices to Core for %s", len(result.Hosts), task.cidr)
		}
	}

	if totalHosts > 0 {
		log.Printf("Scan cycle complete: %d total hosts discovered", totalHosts)
	}
}
