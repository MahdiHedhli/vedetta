package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/dnscap"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
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
	dnsEnabled := flag.Bool("dns", true, "Enable passive DNS capture")
	dnsIface := flag.String("dns-iface", "auto", "Network interface for DNS capture (or 'auto')")
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

	// Enumerate local network interfaces
	interfaces, err := netinfo.ListInterfaces()
	if err != nil {
		log.Printf("WARNING: Could not enumerate network interfaces: %v", err)
		interfaces = []netinfo.NetworkInterface{}
	} else if len(interfaces) > 0 {
		log.Printf("Discovered %d network interfaces", len(interfaces))
		for _, iface := range interfaces {
			log.Printf("  - %s (%s) IPs: %v", iface.Name, iface.MAC, iface.IPs)
		}
	}

	// Register this sensor with Core
	if err := core.Register(scanCIDR, *primary, interfaces); err != nil {
		log.Printf("WARNING: Could not register with Core at %s: %v", *coreURL, err)
		log.Printf("Scans will continue — results will be pushed when Core becomes available")
	} else {
		log.Printf("Registered with Core at %s", *coreURL)
	}

	log.Printf("Starting scan loop: cidr=%s interval=%s ports=%v", scanCIDR, *interval, *scanPorts)

	// Set up passive DNS capture (if enabled)
	var wg sync.WaitGroup
	var capturer *dnscap.Capturer

	if *dnsEnabled {
		dnsQueries := make(chan dnscap.Query, 100)

		capturer, err = dnscap.NewCapturer(dnscap.Config{
			Interface:    *dnsIface,
			BatchSize:    100,
			BatchTimeout: 10 * time.Second,
			OnQuery: func(q dnscap.Query) {
				select {
				case dnsQueries <- q:
				default:
					// Queue full, skip
				}
			},
		})

		if err != nil {
			log.Printf("WARNING: Failed to initialize DNS capture: %v", err)
		} else {
			if err := capturer.Start(); err != nil {
				log.Printf("WARNING: Failed to start DNS capture: %v", err)
			} else {
				log.Printf("Passive DNS capture active on interface %s", *dnsIface)

				// Start DNS batch push goroutine
				wg.Add(1)
				go func() {
					defer wg.Done()
					pushDNSQueries(core, dnsQueries)
				}()
			}
		}
	}

	// Run first scan immediately
	runScan(scanner, core, scanCIDR, *scanPorts)

	if *oneshot {
		if capturer != nil {
			capturer.Stop()
		}
		wg.Wait()
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
			if capturer != nil {
				capturer.Stop()
			}
			wg.Wait()
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

// pushDNSQueries batches captured DNS queries and pushes them to Core.
func pushDNSQueries(core *client.CoreClient, queries chan dnscap.Query) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	batch := make([]dnscap.DNSQuery, 0, 100)

	for {
		select {
		case q, ok := <-queries:
			if !ok {
				// Channel closed
				if len(batch) > 0 {
					pushBatch(core, batch)
				}
				return
			}

			batch = append(batch, dnscap.DNSQuery{
				Timestamp:  q.Timestamp.Unix(),
				Domain:     q.Domain,
				QueryType:  q.QueryType,
				ClientIP:   q.ClientIP,
				ServerIP:   q.ServerIP,
				Blocked:    q.Blocked,
				Source:     q.Source,
			})

			// Send if batch is full
			if len(batch) >= 100 {
				pushBatch(core, batch)
				batch = make([]dnscap.DNSQuery, 0, 100)
			}

		case <-ticker.C:
			// Send batch on timer even if not full
			if len(batch) > 0 {
				pushBatch(core, batch)
				batch = make([]dnscap.DNSQuery, 0, 100)
			}
		}
	}
}

func pushBatch(core *client.CoreClient, queries []dnscap.DNSQuery) {
	if len(queries) == 0 {
		return
	}

	req := struct {
		SensorID string              `json:"sensor_id"`
		Queries  []dnscap.DNSQuery   `json:"queries"`
	}{
		SensorID: core.SensorID,
		Queries:  queries,
	}

	if err := core.PushDNS(req); err != nil {
		log.Printf("Failed to push %d DNS queries to Core: %v", len(queries), err)
	} else {
		log.Printf("Pushed %d DNS queries to Core", len(queries))
	}
}
