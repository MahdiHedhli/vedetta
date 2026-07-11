package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/dnscap"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
	"github.com/vedetta-network/vedetta/sensor/internal/passive"
)

// buildVersion is stamped by release CI via -ldflags "-X main.buildVersion=<tag>".
// It defaults to "dev" for local/source builds.
var buildVersion = "dev"

func main() {
	// CLI flags
	coreURL := flag.String("core", "http://localhost:8080", "Vedetta Core API URL")
	cidr := flag.String("cidr", "auto", "CIDR to scan (or 'auto' to detect)")
	interval := flag.Duration("interval", 5*time.Minute, "Scan interval")
	scanPorts := flag.Bool("ports", false, "Include top-100 port scan")
	primary := flag.Bool("primary", false, "Register as the primary sensor")
	oneshot := flag.Bool("once", false, "Run a single scan and exit")
	reset := flag.Bool("reset", false, "Reset sensor authentication (clears local token so you can re-register cleanly)")
	dnsEnabled := flag.Bool("dns", true, "Enable passive DNS capture")
	dnsIface := flag.String("dns-iface", "auto", "Network interface for DNS capture (or 'auto')")
	passiveEnabled := flag.Bool("passive-discovery", true, "Enable passive device discovery")
	passiveIface := flag.String("passive-iface", "auto", "Network interface for passive device discovery (or 'auto')")
	passiveARP := flag.Bool("passive-arp", true, "Enable passive ARP discovery")
	passiveDHCP := flag.Bool("passive-dhcp", true, "Enable passive DHCP discovery")
	passiveMDNS := flag.Bool("passive-mdns", true, "Enable passive mDNS discovery")
	passiveSSDP := flag.Bool("passive-ssdp", true, "Enable passive SSDP/UPnP discovery")
	printCapturePlan := flag.Bool("print-capture-plan", false, "Print the recommended DNS/passive capture interfaces and exit")
	showVersion := flag.Bool("version", false, "Show version")
	enrollCode := flag.String("enroll-code", "", "One-time enrollment code from Core (or set VEDETTA_ENROLL_CODE). Required to register a NEW sensor once Core has admin auth configured.")
	flag.Parse()

	// Did the operator explicitly pass --core? A bare `--reset` (e.g. from the
	// installer) just clears the token and exits; `--reset --core ...` clears and
	// re-registers in the same process (see below).
	coreExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "core" {
			coreExplicit = true
		}
	})

	if *showVersion {
		fmt.Printf("vedetta-sensor %s\n", buildVersion)
		os.Exit(0)
	}

	log.SetPrefix("[vedetta-sensor] ")
	log.SetFlags(log.Ldate | log.Ltime)

	// Handle --reset flag (very important for home users when auth gets into a bad state).
	if *reset {
		tokenPath, err := client.DefaultTokenPath()
		if err == nil {
			if rmErr := os.Remove(tokenPath); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("WARNING: could not remove sensor token %s: %v", tokenPath, rmErr)
			}
		}
		log.Println("Sensor authentication token has been cleared.")
		if !coreExplicit {
			// Bare `--reset` (the installer's reset step): clear and exit. The service
			// (re)start then re-registers, supplying the enrollment code.
			log.Println("Restart the sensor with --core to re-register. Within a few minutes the ORIGINAL --enroll-code still works (idempotent recovery); after that window — or once an admin has revoked the sensor — ask an admin for a FRESH reset code bound to this sensor (POST /api/v1/enrollment-codes with {\"sensor_id\":...}) and pass it as --enroll-code. A generic new-sensor code will not reactivate an existing sensor.")
			os.Exit(0)
		}
		// `--reset --core ...`: fall through and re-register in THIS process so a reset
		// never strands the sensor (issue #44). If the original registration response
		// was lost, re-supplying the SAME --enroll-code within its short TTL returns the
		// same idempotent token. After that window (or once the token was revoked), the
		// sensor needs a FRESH admin-minted RESET code bound to this sensor_id — a
		// generic new-sensor code will not reactivate an existing sensor.
		log.Println("Re-registering after reset ...")
		if strings.TrimSpace(*enrollCode) == "" && strings.TrimSpace(os.Getenv("VEDETTA_ENROLL_CODE")) == "" {
			log.Println("NOTE: no --enroll-code supplied. If this sensor was already enrolled, recovery within a few minutes of the original enrollment still works with the ORIGINAL code; after that window an admin must mint a FRESH reset code bound to this sensor_id (POST /api/v1/enrollment-codes with {\"sensor_id\":...}) and you pass it as --enroll-code. A generic new-sensor code will not reactivate an existing sensor.")
		}
	}

	// Resolve scan target
	scanCIDR := *cidr
	if scanCIDR == "" || scanCIDR == "auto" {
		detected := netscan.BestSubnet("")
		if detected == "" && !*printCapturePlan {
			log.Fatal("Could not auto-detect LAN subnet. Use --cidr to specify one.")
		}
		scanCIDR = detected
		if scanCIDR != "" {
			log.Printf("Auto-detected LAN subnet: %s", scanCIDR)
		}
	}

	if *printCapturePlan {
		if err := printCaptureRecommendations(*coreURL, scanCIDR, *dnsIface, *passiveIface); err != nil {
			log.Fatalf("Could not print capture plan: %v", err)
		}
		return
	}

	// Verify nmap is available
	scanner, err := netscan.NewScanner()
	if err != nil {
		log.Fatalf("nmap not available: %v", err)
	}
	log.Printf("nmap found: %s", scanner.BinaryPath)

	// Set up Core API client
	core, err := client.New(*coreURL)
	if err != nil {
		log.Fatalf("Could not initialize Core client: %v", err)
	}
	if core.TokenConfigured() {
		log.Printf("Loaded persisted sensor token from %s", core.TokenPath)
	}
	core.EnrollCode = strings.TrimSpace(*enrollCode)
	if core.EnrollCode == "" {
		core.EnrollCode = strings.TrimSpace(os.Getenv("VEDETTA_ENROLL_CODE"))
	}

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

	// Register this sensor with Core, retrying with backoff. A transient Core
	// outage at boot must not permanently leave the sensor unregistered (it was
	// previously attempted exactly once).
	if registerWithRetry(core, scanCIDR, *primary, interfaces) {
		log.Printf("Registered with Core at %s", *coreURL)
	} else {
		log.Printf("WARNING: Could not register with Core at %s after retries", *coreURL)
		log.Printf("Scans will continue — results will be pushed when Core becomes available")
	}

	log.Printf("Starting scan loop: cidr=%s interval=%s ports=%v", scanCIDR, *interval, *scanPorts)

	// Set up passive DNS capture (if enabled)
	var wg sync.WaitGroup
	var capturer *dnscap.Capturer
	var passiveCapturer *passive.Capturer
	var passiveHosts chan netscan.DiscoveredHost
	var dnsQueries chan dnscap.Query
	// Dropped-event counters. The capture channels are bounded; an overflowing
	// capture burst previously vanished with a bare `default:` and no trace. Count
	// drops so an operator can see when the sensor is shedding load.
	var droppedDNS, droppedHosts atomic.Int64

	if *dnsEnabled {
		dnsQueries = make(chan dnscap.Query, 100)

		capturer, err = dnscap.NewCapturer(dnscap.Config{
			Interface:    *dnsIface,
			CoreURL:      *coreURL,
			CIDR:         scanCIDR,
			BatchSize:    100,
			BatchTimeout: 10 * time.Second,
			OnQuery: func(q dnscap.Query) {
				select {
				case dnsQueries <- q:
				default:
					droppedDNS.Add(1) // queue full — shedding load, reported below
				}
			},
		})

		if err != nil {
			log.Printf("WARNING: Failed to initialize DNS capture: %v", err)
		} else {
			if err := capturer.Start(); err != nil {
				if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "operation not permitted") {
					log.Printf("WARNING: Failed to start DNS capture on %s (permission denied). Run with sudo for packet capture: sudo %s --core %s --dns-iface %s", *dnsIface, os.Args[0], *coreURL, *dnsIface)
				} else {
					log.Printf("WARNING: Failed to start DNS capture: %v", err)
				}
			} else {
				log.Printf("Passive DNS capture active on interface %s", capturer.Interface())

				// Start DNS batch push goroutine
				wg.Add(1)
				go func() {
					defer wg.Done()
					pushDNSQueries(core, dnsQueries)
				}()
			}
		}
	}

	if *passiveEnabled {
		passiveHosts = make(chan netscan.DiscoveredHost, 200)
		passiveCapturer, err = passive.NewCapturer(passive.Config{
			Interface:  *passiveIface,
			CoreURL:    *coreURL,
			CIDR:       scanCIDR,
			EnableARP:  *passiveARP,
			EnableDHCP: *passiveDHCP,
			EnableMDNS: *passiveMDNS,
			EnableSSDP: *passiveSSDP,
			OnHost: func(host netscan.DiscoveredHost) {
				select {
				case passiveHosts <- host:
				default:
					droppedHosts.Add(1) // queue full — shedding load, reported below
				}
			},
		})
		if err != nil {
			log.Printf("WARNING: Failed to initialize passive discovery: %v", err)
		} else if err := passiveCapturer.Start(); err != nil {
			if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "operation not permitted") {
				log.Printf("WARNING: Failed to start passive discovery on %s (permission denied). Run with sudo for packet capture: sudo %s --core %s --passive-iface %s", *passiveIface, os.Args[0], *coreURL, *passiveIface)
			} else {
				log.Printf("WARNING: Failed to start passive discovery: %v", err)
			}
		} else {
			log.Printf("Passive discovery active on interface %s (arp=%v dhcp=%v mdns=%v ssdp=%v)", passiveCapturer.Interface(), *passiveARP, *passiveDHCP, *passiveMDNS, *passiveSSDP)
			wg.Add(1)
			go func() {
				defer wg.Done()
				pushPassiveHosts(core, scanCIDR, passiveHosts)
			}()
		}
	}

	// Run first scan immediately
	runScan(scanner, core, scanCIDR, *scanPorts)

	if *oneshot {
		shutdownCaptures(capturer, passiveCapturer, dnsQueries, passiveHosts, &wg)
		return
	}

	// Assemble the periodic-scan run state so the loop can be driven identically by
	// the interactive/Unix front-end here and by the Windows service front-end
	// (service_windows.go), each supplying its own cancellation context.
	run := &sensorRun{
		scanner:         scanner,
		core:            core,
		scanCIDR:        scanCIDR,
		primary:         *primary,
		scanPorts:       *scanPorts,
		interval:        *interval,
		interfaces:      interfaces,
		capturer:        capturer,
		passiveCapturer: passiveCapturer,
		dnsQueries:      dnsQueries,
		passiveHosts:    passiveHosts,
		wg:              &wg,
		droppedDNS:      &droppedDNS,
		droppedHosts:    &droppedHosts,
	}

	// Interactive / Unix front-end: cancel the run on SIGINT/SIGTERM. os.Interrupt
	// is SIGINT; SIGTERM is delivered on Unix and is a harmless, never-delivered
	// no-op on Windows (the Windows service handles stop via the SCM instead).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run.loop(ctx)
}

// sensorRun holds the state the periodic scan loop needs so the loop can be driven
// identically from the interactive/Unix front-end (main) and, later, the Windows
// service front-end (service_windows.go) — each supplying its own cancellation
// context (signal-cancelled on Unix; SCM-cancelled under the Windows SCM).
type sensorRun struct {
	scanner         *netscan.Scanner
	core            *client.CoreClient
	scanCIDR        string
	primary         bool
	scanPorts       bool
	interval        time.Duration
	interfaces      []netinfo.NetworkInterface
	capturer        *dnscap.Capturer
	passiveCapturer *passive.Capturer
	dnsQueries      chan dnscap.Query
	passiveHosts    chan netscan.DiscoveredHost
	wg              *sync.WaitGroup
	droppedDNS      *atomic.Int64
	droppedHosts    *atomic.Int64
}

// loop runs periodic scans until ctx is cancelled, then drains captures within the
// bounded shutdown window. This is the single run body shared by every platform
// front-end; cancellation source (signal vs SCM) is the front-end's concern.
func (r *sensorRun) loop(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// If registration never succeeded (transient Core outage at boot, or a
			// registration whose response was lost after the backend consumed the
			// enrollment code), keep retrying with the SAME retained enrollment code
			// so the sensor recovers the idempotent token instead of running
			// unregistered forever (issue #44).
			ensureRegistered(r.core, r.scanCIDR, r.primary, r.interfaces)
			runScan(r.scanner, r.core, r.scanCIDR, r.scanPorts)
			if d, h := r.droppedDNS.Load(), r.droppedHosts.Load(); d > 0 || h > 0 {
				log.Printf("Cumulative dropped events (capture buffers overflowed): %d DNS queries, %d passive hosts", d, h)
			}
		case <-ctx.Done():
			log.Printf("Shutdown requested, draining captures")
			if d, h := r.droppedDNS.Load(), r.droppedHosts.Load(); d > 0 || h > 0 {
				log.Printf("Dropped during run: %d DNS queries, %d passive hosts", d, h)
			}
			shutdownCaptures(r.capturer, r.passiveCapturer, r.dnsQueries, r.passiveHosts, r.wg)
			return
		}
	}
}

// registerRetryBaseDelay is the initial backoff between registration attempts.
// It is a variable (not a const) so tests can shrink it.
var registerRetryBaseDelay = 2 * time.Second

// registerWithRetry registers the sensor with Core, retrying with exponential
// backoff so a transient Core outage at boot does not leave the sensor
// permanently unregistered. Every attempt reuses the same enrollment code held on
// the client, so if the backend already consumed the code and minted a token the
// sensor never received, a retry recovers that idempotent token (issue #44).
// Returns true once registration succeeds.
func registerWithRetry(core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) bool {
	const maxAttempts = 4
	delay := registerRetryBaseDelay
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := core.Register(cidr, primary, interfaces); err == nil {
			return true
		} else {
			log.Printf("Register attempt %d/%d failed: %v", attempt, maxAttempts, err)
		}
		if attempt < maxAttempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return false
}

// ensureRegistered performs one registration attempt when the sensor still has no
// persisted token. It reuses the enrollment code retained on the client, so a
// registration whose response was lost — the backend consumed the code and minted
// a token the sensor never saw — recovers the idempotent token on a later attempt
// rather than stranding the sensor (issue #44). It is a no-op (returns true) once
// a token is configured. Returns true when the sensor is registered.
func ensureRegistered(core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) bool {
	if core.TokenConfigured() {
		return true
	}
	if err := core.Register(cidr, primary, interfaces); err != nil {
		log.Printf("Re-registration attempt failed (will retry next cycle): %v", err)
		return false
	}
	log.Printf("Recovered registration with Core — persisted sensor token")
	return true
}

// shutdownCaptures stops the capturers, closes the capture channels so their push
// goroutines drain and return, and waits with a bounded timeout. Closing
// dnsQueries — not just passiveHosts — is essential: pushDNSQueries only returns
// when its channel is closed, so leaving it open deadlocked wg.Wait() forever on
// SIGTERM whenever DNS capture had started (beta-gate B8). The timeout guarantees
// shutdown even if a push goroutine is wedged on a slow Core.
func shutdownCaptures(capturer *dnscap.Capturer, passiveCapturer *passive.Capturer,
	dnsQueries chan dnscap.Query, passiveHosts chan netscan.DiscoveredHost, wg *sync.WaitGroup) {
	if capturer != nil {
		capturer.Stop()
	}
	if passiveCapturer != nil {
		passiveCapturer.Stop()
	}
	if dnsQueries != nil {
		close(dnsQueries)
	}
	if passiveHosts != nil {
		close(passiveHosts)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Printf("WARNING: capture push goroutines did not finish within 10s — forcing shutdown")
	}
}

func printCaptureRecommendations(coreURL, scanCIDR, dnsIface, passiveIface string) error {
	dnsSelection, err := netinfo.SelectCaptureInterface(netinfo.CaptureSelectionOptions{
		Preferred: dnsIface,
		CoreURL:   coreURL,
		ScanCIDR:  scanCIDR,
		Purpose:   "dns capture",
	})
	if err != nil {
		return err
	}

	passiveSelection, err := netinfo.SelectCaptureInterface(netinfo.CaptureSelectionOptions{
		Preferred: passiveIface,
		CoreURL:   coreURL,
		ScanCIDR:  scanCIDR,
		Purpose:   "passive discovery",
	})
	if err != nil {
		return err
	}

	fmt.Println(netinfo.FormatCaptureSelection(dnsSelection, "dns capture"))
	fmt.Println()
	fmt.Println(netinfo.FormatCaptureSelection(passiveSelection, "passive discovery"))

	return nil
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
				Timestamp: q.Timestamp.UnixMilli(),
				Domain:    q.Domain,
				QueryType: q.QueryType,
				ClientIP:  q.ClientIP,
				ServerIP:  q.ServerIP,
				Blocked:   q.Blocked,
				Source:    q.Source,
				Answers:   q.Answers,
				Process:   q.Process,
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
		SensorID string            `json:"sensor_id"`
		Queries  []dnscap.DNSQuery `json:"queries"`
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

func pushPassiveHosts(core *client.CoreClient, cidr string, observations chan netscan.DiscoveredHost) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	pending := make(map[string]netscan.DiscoveredHost)

	flush := func() {
		if len(pending) == 0 {
			return
		}

		hosts := make([]netscan.DiscoveredHost, 0, len(pending))
		for _, host := range pending {
			hosts = append(hosts, host)
		}

		result := &netscan.ScanResult{
			Hosts:    hosts,
			ScanTime: time.Now(),
			Duration: 0,
		}
		if err := core.PushDevices(result, cidr, "default"); err != nil {
			log.Printf("Failed to push %d passive discovery hosts to Core: %v", len(hosts), err)
		} else {
			log.Printf("Pushed %d passive discovery hosts to Core", len(hosts))
		}

		clear(pending)
	}

	for {
		select {
		case host, ok := <-observations:
			if !ok {
				flush()
				return
			}
			if host.IPAddress == "" {
				continue
			}

			key := host.MACAddress
			if key == "" {
				key = host.IPAddress
			}
			if key == "" {
				continue
			}

			pending[key] = mergePassiveHost(pending[key], host)
			if len(pending) >= 50 {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func mergePassiveHost(existing, observed netscan.DiscoveredHost) netscan.DiscoveredHost {
	if existing.IPAddress == "" && existing.MACAddress == "" && existing.Hostname == "" && existing.Vendor == "" && existing.Status == "" && len(existing.OpenPorts) == 0 {
		return observed
	}
	if existing.IPAddress == "" {
		existing.IPAddress = observed.IPAddress
	}
	if existing.MACAddress == "" {
		existing.MACAddress = observed.MACAddress
	}
	if existing.Hostname == "" {
		existing.Hostname = observed.Hostname
	}
	if existing.Vendor == "" {
		existing.Vendor = observed.Vendor
	}
	// Enriched passive-discovery fields (spec 004): keep the model, friendly
	// name, and services correlated on the sensor so Core receives them. Without
	// this, a later bare ARP/DHCP observation would drop mDNS-derived metadata.
	if existing.Model == "" {
		existing.Model = observed.Model
	}
	if existing.FriendlyName == "" {
		existing.FriendlyName = observed.FriendlyName
	}
	for _, svc := range observed.Services {
		if !containsString(existing.Services, svc) {
			existing.Services = append(existing.Services, svc)
		}
	}
	if existing.Status == "" {
		existing.Status = observed.Status
	}
	return existing
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
