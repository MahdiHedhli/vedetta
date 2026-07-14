package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

// elevationHint returns an OS-appropriate "re-run with privileges" instruction for
// a capture that was denied permission — "Run as Administrator" on Windows (where
// there is no sudo and captures run under an elevated service), "sudo" elsewhere.
func elevationHint(argv string) string {
	if runtime.GOOS == "windows" {
		return "Run as Administrator, or install as a service: " + argv
	}
	return "Run with sudo for packet capture: sudo " + argv
}

// runSelfCheck validates the sensor's runtime dependencies from THIS process's
// environment WITHOUT installing, scanning, capturing, or persisting anything, and
// returns 0 only if every MANDATORY gate passes. The two mandatory gates mirror the
// only two log.Fatalf points on the long-running service path — nmap resolution
// (netscan.NewScanner) and Core-client/token init (client.New) — so a green --check
// means the daemon will not crash-loop on startup. An offline Core and insufficient
// capture privilege are warnings because the daemon tolerates them. With
// --require-token, a missing or rejected token is fatal. Without it, the token is not
// validated so reset/enrollment preflight can proceed with a deliberately obsolete one.
// The installer runs this under the service manager's exact PATH + token-file env, so
// a dependency the daemon cannot see (e.g. Homebrew nmap off launchd's minimal PATH)
// fails the install loudly instead of after a false "installed".
func runSelfCheck(coreURL, cidr string, requireToken bool) int {
	fatal := 0
	if target := strings.TrimSpace(cidr); target != "" && target != "auto" {
		if err := netscan.ValidateLocalTarget(target); err != nil {
			fmt.Printf("FAIL scan target: %v\n", err)
			fatal++
		} else {
			fmt.Printf("OK   scan target supported by this sensor: %s\n", target)
		}
	} else {
		fmt.Println("INFO scan target will be auto-detected when networking is available")
	}
	if s, err := netscan.NewScanner(); err != nil {
		fmt.Printf("FAIL nmap: %v (PATH=%s)\n", err, os.Getenv("PATH"))
		fatal++
	} else {
		checkCtx, cancelCheck := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.Check(checkCtx)
		cancelCheck()
		if err != nil {
			fmt.Printf("FAIL nmap execution: %v\n", err)
			fatal++
		} else {
			fmt.Printf("OK   nmap executable under scan credential: %s\n", s.BinaryPath)
		}
	}

	core, err := client.New(coreURL)
	if err != nil {
		fmt.Printf("FAIL core client/token init: %v\n", err)
		fatal++
	} else {
		tokenConfigured := core.TokenConfigured()
		if requireToken && !tokenConfigured {
			fmt.Println("FAIL sensor token is required but no non-empty persisted token is configured")
			fatal++
		}

		reachabilityCtx, cancelReachability := context.WithTimeout(context.Background(), 5*time.Second)
		rerr := core.Reachable(reachabilityCtx)
		cancelReachability()
		if rerr != nil {
			if client.IsTransientReachabilityError(rerr) {
				fmt.Printf("WARN core temporarily unreachable at %s: %v (the running sensor retries)\n", coreURL, rerr)
				if requireToken && tokenConfigured {
					fmt.Println("WARN sensor token could not be validated while Core is unreachable")
				} else if tokenConfigured {
					fmt.Println("INFO persisted sensor token present; validation was not requested")
				} else if !requireToken {
					fmt.Println("WARN not enrolled yet (no token) — pass --enroll-code to register")
				}
			} else {
				fmt.Printf("FAIL invalid or unsafe Core configuration at %s: %v\n", coreURL, rerr)
				fatal++
			}
		} else {
			fmt.Printf("OK   core reachable: %s\n", coreURL)
			if requireToken && tokenConfigured {
				authCtx, cancelAuth := context.WithTimeout(context.Background(), 5*time.Second)
				authErr := core.AuthCheck(authCtx)
				cancelAuth()
				if authErr != nil {
					// Do not print the response body here: a non-Core or compromised endpoint
					// must not be able to reflect credential material into installer logs.
					fmt.Println("FAIL sensor token was rejected or could not be validated by reachable Core")
					fatal++
				} else {
					fmt.Println("OK   sensor token valid")
				}
			} else if !tokenConfigured {
				fmt.Println("WARN not enrolled yet (no token) — pass --enroll-code to register")
			} else {
				fmt.Println("INFO persisted sensor token present; validation was not requested")
			}
		}
	}

	if runtime.GOOS == "windows" {
		fmt.Println("INFO Windows privilege is not exercised by --check; interactive capture requires Administrator and the installed service runs as LocalSystem")
	} else if os.Geteuid() != 0 {
		fmt.Println("WARN not root — DNS/passive capture will be degraded (the service runs as root)")
	}

	if fatal > 0 {
		fmt.Printf("preflight FAILED: %d mandatory dependency gap(s) — the daemon would not operate correctly\n", fatal)
		return 1
	}
	fmt.Println("preflight OK")
	return 0
}

func clearPersistedSensorToken() error {
	return client.ClearPersistedToken()
}

func validateResetEnrollment(reset, coreExplicit bool, enrollmentCode string) error {
	if reset && coreExplicit && strings.TrimSpace(enrollmentCode) == "" {
		return fmt.Errorf("--reset with an explicit --core requires a bound reset code via --enroll-code or VEDETTA_ENROLL_CODE")
	}
	return nil
}

func main() {
	// CLI flags
	coreURL := flag.String("core", "http://localhost:8080", "Vedetta Core API URL")
	cidr := flag.String("cidr", "auto", "CIDR to scan (or 'auto' to detect)")
	interval := flag.Duration("interval", 5*time.Minute, "Scan interval")
	scanPorts := flag.Bool("ports", false, "Include top-100 port scan")
	primary := flag.Bool("primary", false, "Register as the primary sensor")
	oneshot := flag.Bool("once", false, "Run a single scan and exit")
	reset := flag.Bool("reset", false, "Reset sensor authentication. With an explicit --core, preflight and re-register before replacing the credential; a bare --reset removes the local token.")
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
	selfCheck := flag.Bool("check", false, "Verify runtime dependencies (nmap, token/client init, Core reachability) from THIS process's environment, print a per-dependency report, and exit non-zero on any fatal gap. The installer runs it under the service's exact PATH to catch problems the daemon would hit.")
	requireToken := flag.Bool("require-token", false, "With --check, require a non-empty persisted sensor token and validate it when Core is reachable. An offline Core remains a warning so installation is possible during an outage.")
	enrollCode := flag.String("enroll-code", "", "One-time enrollment code from Core (or set VEDETTA_ENROLL_CODE). Required to register a NEW sensor once Core has admin auth configured.")
	enrollOnly := flag.Bool("enroll-only", false, "Register with Core using the enrollment code, persist the sensor token, and exit. The installer runs this (with the code in the environment, not on the command line) so the secret never lives in the long-running service configuration.")
	flag.Parse()

	// Did the operator explicitly pass --core? A bare `--reset` clears the token and
	// exits; `--reset --core ...` preflights local persistence and performs one
	// reset/re-registration action without deleting the old file first.
	coreExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "core" {
			coreExplicit = true
		}
	})
	enrollmentCode := strings.TrimSpace(*enrollCode)
	if enrollmentCode == "" {
		enrollmentCode = strings.TrimSpace(os.Getenv("VEDETTA_ENROLL_CODE"))
	}

	if *showVersion {
		fmt.Printf("vedetta-sensor %s\n", buildVersion)
		os.Exit(0)
	}

	log.SetPrefix("[vedetta-sensor] ")
	log.SetFlags(log.Ldate | log.Ltime)

	// Report the linker-stamped build version to Core at registration (a "0.1.0-dev"
	// literal was previously hardcoded, so released sensors mis-reported their version).
	client.Version = buildVersion

	// Diagnostics dispatch before reset handling so even an accidental
	// `--reset --check` remains read-only. --require-token is scoped to this mode;
	// silently ignoring it on a normal run would falsely imply auth was verified.
	if *requireToken && !*selfCheck {
		log.Fatal("--require-token may only be used with --check")
	}
	if *selfCheck {
		os.Exit(runSelfCheck(*coreURL, *cidr, *requireToken))
	}
	if err := validateResetEnrollment(*reset, coreExplicit, enrollmentCode); err != nil {
		log.Fatal(err)
	}

	// Handle --reset flag (very important for home users when auth gets into a bad state).
	if *reset {
		if !coreExplicit {
			if err := clearPersistedSensorToken(); err != nil {
				log.Fatalf("Sensor authentication token was not cleared: %v", err)
			}
			log.Println("Sensor authentication token has been cleared.")
			// Bare `--reset` (the installer's reset step): clear and exit. The service
			// (re)start then re-registers, supplying the enrollment code.
			log.Println("Restart the sensor with --core to re-register. Within a few minutes the ORIGINAL --enroll-code still works (idempotent recovery); after that window — or once an admin has revoked the sensor — ask an admin for a FRESH reset code bound to this sensor (POST /api/v1/enrollment-codes with {\"sensor_id\":...}) and pass it as --enroll-code. A generic new-sensor code will not reactivate an existing sensor.")
			os.Exit(0)
		}
		// `--reset --core ...`: keep the old file and re-register in THIS process. The
		// client suppresses its old bearer in memory below so the bound reset code is
		// authoritative, and preflights the local replacement path before contacting
		// Core. The remote rotation and local write cannot be one transaction: if the
		// response is lost or persistence fails afterward, re-supplying the SAME code
		// within its short TTL returns the same idempotent token. After that window the
		// sensor needs a FRESH admin-minted reset code bound to this sensor_id.
		log.Println("Re-registering after reset; preflighting local persistence before the credential is rotated ...")
	}

	// --print-capture-plan is a Unix-only interactive diagnostic (recommends DNS/passive
	// capture interfaces). Run it BEFORE NewScanner so it still prints on a host without
	// nmap — NewScanner is fatal there, and this diagnostic needs neither the scanner nor
	// the Core client.
	if *printCapturePlan {
		planCIDR := strings.TrimSpace(*cidr)
		if planCIDR == "" || planCIDR == "auto" {
			planCIDR = netscan.BestSubnet("")
		}
		if err := printCaptureRecommendations(*coreURL, planCIDR, *dnsIface, *passiveIface); err != nil {
			log.Fatalf("Could not print capture plan: %v", err)
		}
		return
	}

	// Set up the device scanner (local: nmap presence on Unix, native ICMP/ARP on
	// Windows). No network.
	scanner, err := netscan.NewScanner()
	if err != nil {
		log.Fatalf("device scanner unavailable: %v", err)
	}
	log.Printf("Device scanner ready: %s", scanner.BinaryPath)

	// Set up the Core API client (loads any persisted token; no network).
	core, err := client.New(*coreURL)
	if err != nil {
		log.Fatalf("Could not initialize Core client: %v", err)
	}
	if core.TokenConfigured() && !*reset {
		log.Printf("Loaded persisted sensor token from %s", core.TokenPath)
	}
	core.EnrollCode = enrollmentCode
	if *reset {
		// Exercise the complete local secure-write/replace/fsync path before Core can
		// revoke the old credential. This catches predictable permission/disk errors.
		// It cannot make the remote rotation and local filesystem one transaction;
		// after a post-response failure, replay the same still-valid code or mint a
		// fresh bound reset code.
		if err := core.PreflightTokenPersistence(); err != nil {
			log.Fatalf("Could not safely prepare sensor token replacement before reset: %v", err)
		}
		core.SuppressTokenForReset()
	}

	// Assemble the run with the RAW config. Everything network-dependent — CIDR
	// auto-detection, interface enumeration, capture start, registration, scanning —
	// happens in serve()/prepare(), which run AFTER the Windows service has connected to
	// the SCM. Doing any of it here would let a boot before DHCP (no LAN address yet)
	// exit this process before dispatch → Error 1053.
	run := &sensorRun{
		scanner:        scanner,
		core:           core,
		coreURL:        *coreURL,
		cidrFlag:       *cidr,
		primary:        *primary,
		scanPorts:      *scanPorts,
		interval:       *interval,
		dnsEnabled:     *dnsEnabled,
		dnsIface:       *dnsIface,
		passiveEnabled: *passiveEnabled,
		passiveIface:   *passiveIface,
		passiveARP:     *passiveARP,
		passiveDHCP:    *passiveDHCP,
		passiveMDNS:    *passiveMDNS,
		passiveSSDP:    *passiveSSDP,
	}

	// Enrollment-only mode (installer step): interactive, the network is up. Resolve the
	// CIDR eagerly, register, persist the token, and exit — the secret is spent here and
	// NEVER lives in the long-running service's configuration.
	if *enrollOnly {
		if err := run.prepare(context.Background(), false); err != nil {
			log.Fatalf("enrollment: %v", err)
		}
		if registerWithRetry(context.Background(), core, run.scanCIDR, run.primary, run.interfaces) {
			log.Printf("Enrollment complete — sensor token persisted to %s", core.TokenPath)
			return
		}
		log.Fatalf("enrollment failed: could not register with Core at %s (check --core, the enrollment code, and connectivity)", *coreURL)
	}

	if *oneshot {
		// One scan and exit (interactive). Resolve eagerly, scan once, drain.
		ctx := context.Background()
		if err := run.prepare(ctx, false); err != nil {
			log.Fatalf("scan: %v", err)
		}
		run.startCaptures()
		run.register(ctx)
		runScan(ctx, run.scanner, run.core, run.scanCIDR, run.scanPorts)
		run.shutdown()
		return
	}

	// Hand off to the platform front-end. On Unix (and a Windows console) the run is
	// cancelled by SIGINT/SIGTERM; under the Windows SCM it is cancelled by
	// Stop/Shutdown. Both call run.serve, which defers ALL network-dependent init until
	// after the front-end has connected to its control channel.
	runFrontend(run)
}

// sensorRun holds the sensor's config plus the runtime state its lifecycle needs, so
// the lifecycle can be driven identically by the interactive/Unix front-end
// (front_unix.go) and the Windows service front-end (front_windows.go), each supplying
// its own cancellation context. The struct is always used via pointer and never copied,
// so wg/atomic fields are held by value.
type sensorRun struct {
	// static config (from flags)
	scanner        *netscan.Scanner
	core           *client.CoreClient
	coreURL        string
	cidrFlag       string // raw --cidr ("auto" or a CIDR); resolved in prepare()
	primary        bool
	scanPorts      bool
	interval       time.Duration
	dnsEnabled     bool
	dnsIface       string
	passiveEnabled bool
	passiveIface   string
	passiveARP     bool
	passiveDHCP    bool
	passiveMDNS    bool
	passiveSSDP    bool

	// runtime state populated by prepare() + startCaptures()
	scanCIDR        string
	interfaces      []netinfo.NetworkInterface
	capturer        *dnscap.Capturer
	passiveCapturer *passive.Capturer
	dnsQueries      chan dnscap.Query
	passiveHosts    chan netscan.DiscoveredHost
	wg              sync.WaitGroup
	droppedDNS      atomic.Int64
	droppedHosts    atomic.Int64
}

// serve runs the full operational lifecycle: resolve the scan target + interfaces
// (retrying if the LAN has no address yet), start the captures, register, run the
// first scan, then loop. It is called by the platform front-end AFTER that front-end
// has connected to its control channel — on Windows, after svc.Run has reached the SCM.
// EVERYTHING network-dependent lives here, not in main, so the Windows service reaches
// the dispatcher within the SCM connect deadline even when the machine boots before
// DHCP assigns an address or Core is unreachable.
func (r *sensorRun) serve(ctx context.Context) {
	if err := r.prepare(ctx, true); err != nil {
		log.Printf("sensor stopping before startup completed: %v", err) // ctx cancelled during CIDR wait
		return
	}
	r.startCaptures()
	log.Printf("Starting scan loop: cidr=%s interval=%s ports=%v", r.scanCIDR, r.interval, r.scanPorts)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		r.heartbeatLoop(ctx)
	}()
	defer func() { <-heartbeatDone }()
	// Registration can itself consume several bounded HTTP attempts. Start liveness
	// first so an already-enrolled sensor is not marked stale while Core is slow.
	r.register(ctx)
	runScan(ctx, r.scanner, r.core, r.scanCIDR, r.scanPorts)
	r.loop(ctx)
}

// prepare resolves the scan CIDR and enumerates network interfaces. When wait is true
// (the long-running service/console path) it keeps retrying auto-detection until a LAN
// address exists or ctx is cancelled, so a service that auto-starts before DHCP reaches
// Running and begins work once networking comes up — no restart needed. When wait is
// false (interactive --enroll-only/--once) it resolves once and errors if none is found.
func (r *sensorRun) prepare(ctx context.Context, wait bool) error {
	cidr, err := r.resolveScanCIDR(ctx, wait)
	if err != nil {
		return err
	}
	r.scanCIDR = cidr

	ifaces, err := netinfo.ListInterfaces()
	if err != nil {
		log.Printf("WARNING: Could not enumerate network interfaces: %v", err)
		ifaces = []netinfo.NetworkInterface{}
	} else if len(ifaces) > 0 {
		log.Printf("Discovered %d network interfaces", len(ifaces))
		for _, iface := range ifaces {
			log.Printf("  - %s (%s) IPs: %v", iface.Name, iface.MAC, iface.IPs)
		}
	}
	r.interfaces = ifaces
	return nil
}

// bestSubnet / subnetRetryDelay are indirected as vars so tests can inject a fake
// detector and shrink the retry interval.
var (
	bestSubnet       = netscan.BestSubnet
	subnetRetryDelay = 10 * time.Second
)

// resolveScanCIDR returns the explicit --cidr, or auto-detects the LAN subnet. In wait
// mode it retries auto-detection until an address appears or ctx is cancelled (so a
// service that boots before DHCP does not fail); otherwise it errors immediately.
func (r *sensorRun) resolveScanCIDR(ctx context.Context, wait bool) (string, error) {
	if c := strings.TrimSpace(r.cidrFlag); c != "" && c != "auto" {
		if err := netscan.ValidateLocalTarget(c); err != nil {
			return "", fmt.Errorf("invalid explicit --cidr: %w", err)
		}
		return c, nil
	}
	for {
		if d := bestSubnet(""); d != "" {
			if err := netscan.ValidateLocalTarget(d); err != nil {
				return "", fmt.Errorf("auto-detected invalid LAN subnet %q: %w", d, err)
			}
			log.Printf("Auto-detected LAN subnet: %s", d)
			return d, nil
		}
		if !wait {
			return "", fmt.Errorf("could not auto-detect a LAN subnet (no address assigned?); pass --cidr")
		}
		log.Printf("No LAN address yet; retrying subnet auto-detection in %s", subnetRetryDelay)
		select {
		case <-time.After(subnetRetryDelay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// startCaptures creates and starts the DNS (ETW/pcap) and passive capturers plus their
// push goroutines. Called after prepare() so the capturer knows the scan CIDR (used to
// attribute this host's DNS to its LAN address). All failures are logged and non-fatal —
// the sensor keeps running (e.g. capture may fail while scan/registration still work).
func (r *sensorRun) startCaptures() {
	if r.dnsEnabled {
		r.dnsQueries = make(chan dnscap.Query, 100)
		capturer, err := dnscap.NewCapturer(dnscap.Config{
			Interface:    r.dnsIface,
			CoreURL:      r.coreURL,
			CIDR:         r.scanCIDR,
			BatchSize:    100,
			BatchTimeout: 10 * time.Second,
			OnQuery: func(q dnscap.Query) {
				select {
				case r.dnsQueries <- q:
				default:
					r.droppedDNS.Add(1) // queue full — shedding load, reported in loop
				}
			},
		})
		if err != nil {
			log.Printf("WARNING: Failed to initialize DNS capture: %v", err)
		} else if err := capturer.Start(); err != nil {
			if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "operation not permitted") {
				log.Printf("WARNING: Failed to start DNS capture on %s (permission denied). %s", r.dnsIface, elevationHint(fmt.Sprintf("%s --core %s --dns-iface %s", os.Args[0], r.coreURL, r.dnsIface)))
			} else {
				log.Printf("WARNING: Failed to start DNS capture: %v", err)
			}
		} else {
			r.capturer = capturer
			log.Printf("Passive DNS capture active on interface %s", capturer.Interface())
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				pushDNSQueries(r.core, r.dnsQueries)
			}()
		}
	}

	if r.passiveEnabled {
		r.passiveHosts = make(chan netscan.DiscoveredHost, 200)
		pc, err := passive.NewCapturer(passive.Config{
			Interface:  r.passiveIface,
			CoreURL:    r.coreURL,
			CIDR:       r.scanCIDR,
			EnableARP:  r.passiveARP,
			EnableDHCP: r.passiveDHCP,
			EnableMDNS: r.passiveMDNS,
			EnableSSDP: r.passiveSSDP,
			OnHost: func(host netscan.DiscoveredHost) {
				select {
				case r.passiveHosts <- host:
				default:
					r.droppedHosts.Add(1) // queue full — shedding load, reported in loop
				}
			},
		})
		if err != nil {
			log.Printf("WARNING: Failed to initialize passive discovery: %v", err)
		} else if err := pc.Start(); err != nil {
			if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "operation not permitted") {
				log.Printf("WARNING: Failed to start passive discovery on %s (permission denied). %s", r.passiveIface, elevationHint(fmt.Sprintf("%s --core %s --passive-iface %s", os.Args[0], r.coreURL, r.passiveIface)))
			} else {
				log.Printf("WARNING: Failed to start passive discovery: %v", err)
			}
		} else {
			r.passiveCapturer = pc
			log.Printf("Passive discovery active on interface %s (arp=%v dhcp=%v mdns=%v ssdp=%v)", pc.Interface(), r.passiveARP, r.passiveDHCP, r.passiveMDNS, r.passiveSSDP)
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				pushPassiveHosts(r.core, r.scanCIDR, r.passiveHosts)
			}()
		}
	}
}

// shutdown stops the capturers and drains their push goroutines within the bounded
// window.
func (r *sensorRun) shutdown() {
	shutdownCaptures(r.capturer, r.passiveCapturer, r.dnsQueries, r.passiveHosts, &r.wg)
}

// register performs the initial registration with bounded, context-aware retries. A
// failure is not fatal — the sensor stays up (Running, in a retrying state) and the
// loop re-attempts registration each cycle (issue #44 idempotent recovery).
func (r *sensorRun) register(ctx context.Context) {
	if registerWithRetry(ctx, r.core, r.scanCIDR, r.primary, r.interfaces) {
		log.Printf("Registered with Core at %s", r.coreURL)
	} else {
		log.Printf("WARNING: could not register with Core at %s yet; staying up and retrying each scan cycle", r.coreURL)
	}
}

// loop runs periodic scans until ctx is cancelled, then drains captures within the
// bounded shutdown window. This is the single run body shared by every platform
// front-end; cancellation source (signal vs SCM) is the front-end's concern.
func (r *sensorRun) loop(ctx context.Context) {
	scanTicker := time.NewTicker(r.interval)
	defer scanTicker.Stop()

	for {
		select {
		case <-scanTicker.C:
			// If registration never succeeded (transient Core outage at boot, or a
			// registration whose response was lost after the backend consumed the
			// enrollment code), keep retrying with the SAME retained enrollment code
			// so the sensor recovers the idempotent token instead of running
			// unregistered forever (issue #44).
			ensureRegistered(ctx, r.core, r.scanCIDR, r.primary, r.interfaces)
			runScan(ctx, r.scanner, r.core, r.scanCIDR, r.scanPorts)
			if d, h := r.droppedDNS.Load(), r.droppedHosts.Load(); d > 0 || h > 0 {
				log.Printf("Cumulative dropped events (capture buffers overflowed): %d DNS queries, %d passive hosts", d, h)
			}
		case <-ctx.Done():
			log.Printf("Shutdown requested, draining captures")
			if d, h := r.droppedDNS.Load(), r.droppedHosts.Load(); d > 0 || h > 0 {
				log.Printf("Dropped during run: %d DNS queries, %d passive hosts", d, h)
			}
			r.shutdown()
			return
		}
	}
}

// heartbeatLoop is deliberately independent from scan scheduling. A permitted Nmap
// scan can run for four minutes, longer than Core's two-minute process-staleness
// window; putting heartbeat ticks in the synchronous scan loop would mark a healthy
// sensor stale while it was doing exactly the requested work.
func (r *sensorRun) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(sensorHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// Fetching work is not a heartbeat: it drains queued scans.
			if err := r.core.Heartbeat(ctx); err != nil && ctx.Err() == nil {
				log.Printf("Sensor heartbeat failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// Short enough that Core can miss several heartbeats before its two-minute
// process-reachability window marks a sensor stale. Indirected for deterministic
// service-loop tests.
var sensorHeartbeatInterval = 30 * time.Second

// registerRetryBaseDelay is the initial backoff between registration attempts.
// It is a variable (not a const) so tests can shrink it.
var registerRetryBaseDelay = 2 * time.Second

// registerWithRetry registers the sensor with Core, retrying with exponential
// backoff so a transient Core outage at boot does not leave the sensor
// permanently unregistered. Every attempt reuses the same enrollment code held on
// the client, so if the backend already consumed the code and minted a token the
// sensor never received, a retry recovers that idempotent token (issue #44).
// Returns true once registration succeeds.
func registerWithRetry(ctx context.Context, core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) bool {
	const maxAttempts = 4
	delay := registerRetryBaseDelay
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return false // cancelled (e.g. service Stop during boot) — abort promptly
		}
		if err := core.Register(ctx, cidr, primary, interfaces); err == nil {
			return true
		} else {
			log.Printf("Register attempt %d/%d failed: %v", attempt, maxAttempts, err)
		}
		if attempt < maxAttempts {
			select {
			case <-time.After(delay):
				delay *= 2
			case <-ctx.Done():
				return false // don't sleep out the backoff after a Stop request
			}
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
func ensureRegistered(ctx context.Context, core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) bool {
	if core.TokenConfigured() {
		return true
	}
	if err := core.Register(ctx, cidr, primary, interfaces); err != nil {
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

func runScan(ctx context.Context, scanner *netscan.Scanner, core *client.CoreClient, primaryCIDR string, withPorts bool) {
	if ctx.Err() != nil {
		return
	}
	// Fetch work from Core (queued scans and enabled targets)
	var work *client.WorkResponse
	if w, err := core.FetchWork(ctx); err == nil {
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
		if ctx.Err() != nil {
			return // stop between targets on a Stop/Shutdown request (bounded drain)
		}
		log.Printf("Scanning %s (segment=%s) ...", task.cidr, task.segment)

		result, err := scanner.ScanContext(ctx, task.cidr, task.scanPorts)
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
		if err := core.PushDevices(ctx, result, task.cidr, task.segment); err != nil {
			log.Printf("Failed to push results to Core for %s: %v", task.cidr, err)
		} else {
			log.Printf("Pushed %d devices to Core for %s", len(result.Hosts), task.cidr)
		}
	}

	if totalHosts > 0 {
		log.Printf("Scan cycle complete: %d total hosts discovered", totalHosts)
	}
}

// dnsPushConfig bounds every in-memory stage of DNS delivery. A failed request keeps
// its immutable batch and retries it; once the bounded queue is full, newly completed
// batches are shed explicitly instead of growing memory without limit while Core is
// offline. The capture callback has its own bounded channel and drop counter as the
// first line of overload protection.
type dnsPushConfig struct {
	BatchSize          int
	QueuedBatches      int
	MaxUnpaired        int
	PairWindow         time.Duration
	FlushInterval      time.Duration
	RetryBaseDelay     time.Duration
	RetryMaxDelay      time.Duration
	AttemptTimeout     time.Duration
	ShutdownFlushLimit time.Duration
}

var productionDNSPushConfig = dnsPushConfig{
	BatchSize:          100,
	QueuedBatches:      10,
	MaxUnpaired:        512,
	PairWindow:         2 * time.Second,
	FlushInterval:      250 * time.Millisecond,
	RetryBaseDelay:     500 * time.Millisecond,
	RetryMaxDelay:      30 * time.Second,
	AttemptTimeout:     5 * time.Second,
	ShutdownFlushLimit: 8 * time.Second, // below shutdownCaptures' 10s hard cap
}

type pendingDNSQuery struct {
	query     dnscap.Query
	arrivedAt time.Time
}

// dnsQueryCoalescer holds query/response halves until their partner arrives (or the
// short pairing window expires). This happens before HTTP chunking, so a batch
// boundary cannot split the common two-packet representation of one DNS exchange.
// Pairing is FIFO and one-to-one: two retransmitted queries plus one response yield
// one exchange and one still-distinct query.
type dnsQueryCoalescer struct {
	window      time.Duration
	maxUnpaired int
	unpaired    []pendingDNSQuery
}

func newDNSQueryCoalescer(window time.Duration, maxUnpaired int) *dnsQueryCoalescer {
	if window <= 0 {
		window = 2 * time.Second
	}
	if maxUnpaired <= 0 {
		maxUnpaired = 512
	}
	return &dnsQueryCoalescer{window: window, maxUnpaired: maxUnpaired}
}

func normalizedDNSDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "query":
		return "query"
	case "response":
		return "response"
	default:
		return ""
	}
}

func dnsQueryHasAnswerData(q dnscap.Query) bool {
	return len(q.Answers) > 0
}

func sameDNSExchange(a, b dnscap.Query, window time.Duration) bool {
	if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(a.Domain), "."), strings.TrimSuffix(strings.TrimSpace(b.Domain), ".")) ||
		!strings.EqualFold(strings.TrimSpace(a.QueryType), strings.TrimSpace(b.QueryType)) ||
		strings.TrimSpace(a.ClientIP) != strings.TrimSpace(b.ClientIP) ||
		strings.TrimSpace(a.ServerIP) != strings.TrimSpace(b.ServerIP) {
		return false
	}
	delta := a.Timestamp.Sub(b.Timestamp)
	if delta < 0 {
		delta = -delta
	}
	if delta > window {
		return false
	}
	aDirection, bDirection := normalizedDNSDirection(a.Direction), normalizedDNSDirection(b.Direction)
	if aDirection != "" || bDirection != "" {
		// Never guess across a partially marked pair. Current capture backends mark
		// both halves; this protects new records from an ambiguous legacy record.
		return aDirection != "" && bDirection != "" && aDirection != bDirection
	}
	// Compatibility for captures from older sensors that had no direction field.
	// Only an answer-bearing/answerless pair is distinguishable in that format.
	return dnsQueryHasAnswerData(a) != dnsQueryHasAnswerData(b)
}

func mergeDNSExchange(a, b dnscap.Query) dnscap.Query {
	response, query := a, b
	if normalizedDNSDirection(b.Direction) == "response" ||
		(normalizedDNSDirection(a.Direction) == "" && dnsQueryHasAnswerData(b)) {
		response, query = b, a
	}
	response.Direction = "response"
	if response.ObservationID == "" {
		response.ObservationID = query.ObservationID
	}
	if response.Domain == "" {
		response.Domain = query.Domain
	}
	if response.QueryType == "" {
		response.QueryType = query.QueryType
	}
	if response.ClientIP == "" {
		response.ClientIP = query.ClientIP
	}
	if response.ServerIP == "" {
		response.ServerIP = query.ServerIP
	}
	if response.Source == "" {
		response.Source = query.Source
	}
	if response.Process == "" {
		response.Process = query.Process
	}
	response.Blocked = response.Blocked || query.Blocked
	seenAnswers := make(map[string]bool, len(response.Answers)+len(query.Answers))
	answers := make([]string, 0, len(response.Answers)+len(query.Answers))
	for _, answer := range append(append([]string(nil), response.Answers...), query.Answers...) {
		key := strings.ToLower(strings.TrimSpace(answer))
		if key == "" || seenAnswers[key] {
			continue
		}
		seenAnswers[key] = true
		answers = append(answers, answer)
	}
	response.Answers = answers
	return response
}

// add returns records that are now safe to chunk. A matched exchange returns one
// merged response immediately. An unmatched record remains pending. If the pairing
// buffer reaches its cap, the oldest record is released rather than growing memory.
func (c *dnsQueryCoalescer) add(query dnscap.Query, now time.Time) []dnscap.Query {
	if query.ObservationID == "" {
		query.ObservationID = dnscap.NewObservationID()
	}
	for i, pending := range c.unpaired {
		if sameDNSExchange(pending.query, query, c.window) {
			c.unpaired = append(c.unpaired[:i], c.unpaired[i+1:]...)
			return []dnscap.Query{mergeDNSExchange(pending.query, query)}
		}
	}
	c.unpaired = append(c.unpaired, pendingDNSQuery{query: query, arrivedAt: now})
	if len(c.unpaired) <= c.maxUnpaired {
		return nil
	}
	oldest := c.unpaired[0].query
	c.unpaired = c.unpaired[1:]
	return []dnscap.Query{oldest}
}

func (c *dnsQueryCoalescer) expire(now time.Time) []dnscap.Query {
	cutoff := now.Add(-c.window)
	ready := make([]dnscap.Query, 0)
	kept := c.unpaired[:0]
	for _, pending := range c.unpaired {
		if !pending.arrivedAt.After(cutoff) {
			ready = append(ready, pending.query)
		} else {
			kept = append(kept, pending)
		}
	}
	c.unpaired = kept
	return ready
}

func (c *dnsQueryCoalescer) flush() []dnscap.Query {
	ready := make([]dnscap.Query, 0, len(c.unpaired))
	for _, pending := range c.unpaired {
		ready = append(ready, pending.query)
	}
	c.unpaired = nil
	return ready
}

func capturedDNSQuery(q dnscap.Query) dnscap.DNSQuery {
	observationID := q.ObservationID
	if observationID == "" {
		// Defensive compatibility for any future capture source that bypasses the
		// coalescer. Production capture paths assign this before buffering.
		observationID = dnscap.NewObservationID()
	}
	return dnscap.DNSQuery{
		ObservationID: observationID,
		Timestamp:     q.Timestamp.UnixMilli(), Domain: q.Domain, QueryType: q.QueryType,
		ClientIP: q.ClientIP, ServerIP: q.ServerIP, Direction: normalizedDNSDirection(q.Direction),
		RCode: strings.TrimSpace(q.RCode), Blocked: q.Blocked, Source: q.Source,
		Answers: append([]string(nil), q.Answers...), Process: q.Process,
	}
}

// pushDNSQueries coalesces captured query/response packets, chunks the resulting
// exchanges, and hands immutable batches to a retrying delivery worker.
func pushDNSQueries(core *client.CoreClient, queries chan dnscap.Query) {
	pushDNSQueriesWithConfig(core, queries, productionDNSPushConfig)
}

func pushDNSQueriesWithConfig(core *client.CoreClient, queries <-chan dnscap.Query, cfg dnsPushConfig) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.QueuedBatches <= 0 {
		cfg.QueuedBatches = 1
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 250 * time.Millisecond
	}
	if cfg.ShutdownFlushLimit <= 0 {
		cfg.ShutdownFlushLimit = 8 * time.Second
	}

	deliveryCtx, cancelDelivery := context.WithCancel(context.Background())
	defer cancelDelivery()
	batches := make(chan []dnscap.DNSQuery, cfg.QueuedBatches)
	deliveryDone := make(chan struct{})
	go func() {
		defer close(deliveryDone)
		deliverDNSBatches(deliveryCtx, core, batches, cfg)
	}()

	coalescer := newDNSQueryCoalescer(cfg.PairWindow, cfg.MaxUnpaired)
	ready := make([]dnscap.DNSQuery, 0, cfg.BatchSize)
	dropped := 0
	enqueueChunk := func(chunk []dnscap.DNSQuery) {
		if len(chunk) == 0 {
			return
		}
		immutable := append([]dnscap.DNSQuery(nil), chunk...)
		select {
		case batches <- immutable:
		default:
			dropped += len(immutable)
			log.Printf("WARNING: DNS delivery queue full while Core is unavailable; dropped %d newly captured records (total %d)", len(immutable), dropped)
		}
	}
	emit := func(captured []dnscap.Query) {
		for _, query := range captured {
			ready = append(ready, capturedDNSQuery(query))
			if len(ready) == cfg.BatchSize {
				enqueueChunk(ready)
				ready = make([]dnscap.DNSQuery, 0, cfg.BatchSize)
			}
		}
	}
	flushReady := func() {
		if len(ready) > 0 {
			enqueueChunk(ready)
			ready = make([]dnscap.DNSQuery, 0, cfg.BatchSize)
		}
	}

	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case query, ok := <-queries:
			if !ok {
				emit(coalescer.flush())
				flushReady()
				close(batches)
				timer := time.NewTimer(cfg.ShutdownFlushLimit)
				select {
				case <-deliveryDone:
					if !timer.Stop() {
						<-timer.C
					}
				case <-timer.C:
					log.Printf("WARNING: DNS delivery did not drain within %s; abandoning retained batches for bounded shutdown", cfg.ShutdownFlushLimit)
					cancelDelivery()
					select {
					case <-deliveryDone:
					case <-time.After(250 * time.Millisecond):
						// net/http honors cancellation, but this final cap keeps the
						// service stop bounded even with a non-conforming transport.
						log.Printf("WARNING: DNS HTTP transport ignored cancellation; leaving delivery goroutine during process shutdown")
					}
				}
				return
			}
			emit(coalescer.add(query, time.Now()))
		case now := <-ticker.C:
			emit(coalescer.expire(now))
			flushReady()
		}
	}
}

func deliverDNSBatches(ctx context.Context, core *client.CoreClient, batches <-chan []dnscap.DNSQuery, cfg dnsPushConfig) {
	for queries := range batches {
		request := dnscap.DNSPushRequest{SensorID: core.SensorID, Queries: queries}
		backoff := cfg.RetryBaseDelay
		if backoff <= 0 {
			backoff = 500 * time.Millisecond
		}
		maxBackoff := cfg.RetryMaxDelay
		if maxBackoff < backoff {
			maxBackoff = backoff
		}
		for {
			attemptTimeout := cfg.AttemptTimeout
			if attemptTimeout <= 0 {
				attemptTimeout = 5 * time.Second
			}
			attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			err := core.PushDNS(attemptCtx, request)
			cancel()
			if err == nil {
				log.Printf("Pushed %d DNS records to Core", len(queries))
				break
			}
			log.Printf("Failed to push %d DNS records to Core (retained for retry in %s): %v", len(queries), backoff, err)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
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
		// context.Background so the shutdown drain still flushes (bounded by shutdownCaptures).
		if err := core.PushDevices(context.Background(), result, cidr, "default"); err != nil {
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
	for _, evidence := range observed.IdentityEvidence {
		duplicate := false
		for _, current := range existing.IdentityEvidence {
			if current.Type == evidence.Type && current.Value == evidence.Value {
				duplicate = true
				break
			}
		}
		if !duplicate && len(existing.IdentityEvidence) < 32 {
			existing.IdentityEvidence = append(existing.IdentityEvidence, evidence)
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
