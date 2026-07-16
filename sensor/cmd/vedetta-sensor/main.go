package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
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
// environment WITHOUT installing, enrolling, scanning, capturing, or mutating Core
// state, and returns 0 only if every MANDATORY gate passes. Local client initialization
// may create/verify the token directory and normalize a legacy Windows token ACL. The
// two mandatory gates mirror the
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
	arpDiscovery := flag.Bool("arp-discovery", true, "Enable unprivileged ARP-cache discovery (reads the OS neighbor cache; passive, no root)")
	arpSweep := flag.Bool("arp-sweep", false, "Warm the ARP cache with a lightweight unprivileged TCP/UDP sweep (active; off by default)")
	arpPollInterval := flag.Duration("arp-poll-interval", 30*time.Second, "How often to read the OS ARP/neighbor cache")
	arpSweepInterval := flag.Duration("arp-sweep-interval", 5*time.Minute, "How often to warm the ARP cache when --arp-sweep is set (<=0 warms once at startup)")
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
	passiveIfaceExplicit := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "core":
			coreExplicit = true
		case "passive-iface":
			passiveIfaceExplicit = true
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
	// `--reset --check` cannot clear the token or enroll. --require-token is scoped to
	// this mode;
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
		scanner:              scanner,
		core:                 core,
		coreURL:              *coreURL,
		cidrFlag:             *cidr,
		primary:              *primary,
		scanPorts:            *scanPorts,
		interval:             *interval,
		dnsEnabled:           *dnsEnabled,
		dnsIface:             *dnsIface,
		passiveEnabled:       *passiveEnabled,
		passiveIface:         *passiveIface,
		passiveIfaceExplicit: passiveIfaceExplicit,
		passiveARP:           *passiveARP,
		passiveDHCP:          *passiveDHCP,
		passiveMDNS:          *passiveMDNS,
		passiveSSDP:          *passiveSSDP,

		arpEnabled:       *arpDiscovery,
		arpSweep:         *arpSweep,
		arpPollInterval:  *arpPollInterval,
		arpSweepInterval: *arpSweepInterval,
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
		// Interactive one-shot delivery is finite and signal-aware. It always drains
		// captures before returning and a registration/delivery failure exits non-zero.
		ctx, stop := interactiveContext()
		err := run.runOneShot(ctx)
		stop()
		if err != nil {
			log.Printf("one-shot scan failed: %v", err)
			os.Exit(1)
		}
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
	// passiveIfaceExplicit distinguishes a user-pinned OS interface from the
	// default "auto" capture selection. ARP link resolution must never inherit an
	// interface that pcap happened to auto-select before DHCP was ready.
	passiveIfaceExplicit bool
	passiveARP           bool
	passiveDHCP          bool
	passiveMDNS          bool
	passiveSSDP          bool

	arpEnabled       bool
	arpSweep         bool
	arpPollInterval  time.Duration
	arpSweepInterval time.Duration
	// oneShotDelivery is a test seam for the interactive finite-attempt policy.
	// Production leaves it nil and uses oneShotScanDeliveryConfig.
	oneShotDelivery *scanDeliveryConfig

	// runtime state populated by prepare() + startCaptures()
	scanCIDR           string
	interfaces         []netinfo.NetworkInterface
	capturer           *dnscap.Capturer
	passiveCapturer    *passive.Capturer
	arpSource          *netscan.Source
	dnsQueries         chan dnscap.Query
	passiveHosts       chan netscan.DiscoveredHost
	passiveSinkStarted bool
	wg                 sync.WaitGroup
	droppedDNS         atomic.Int64
	droppedHosts       atomic.Int64
	// registrationConfirmed means this process received a successful Register
	// response. A token file alone is not proof that Core still accepts the identity.
	registrationConfirmed atomic.Bool
	// scanFn is a lifecycle test seam. Production leaves it nil and scan executes
	// runScan; tests can prove registration gates without invoking nmap.
	scanFn func(context.Context, *netscan.Scanner, *client.CoreClient, string, bool, scanDeliveryConfig) error
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
	stopHeartbeat := r.startHeartbeat(ctx)
	defer stopHeartbeat()
	// Registration can itself consume several bounded HTTP attempts. Start liveness
	// first so an already-enrolled sensor is not marked stale while Core is slow.
	if err := r.scanIfRegistered(ctx, true); err != nil && ctx.Err() == nil {
		log.Printf("Initial scan deferred: %v", err)
	}
	r.loop(ctx)
}

// startHeartbeat returns a stop function that cancels the heartbeat before waiting
// for its goroutine. Keeping those operations in one function is deliberate:
// separate defers run in reverse order and can deadlock during panic unwinding if
// the wait runs before cancellation.
func (r *sensorRun) startHeartbeat(ctx context.Context) func() {
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		r.heartbeatLoop(heartbeatCtx)
	}()
	return func() {
		cancelHeartbeat()
		<-heartbeatDone
	}
}

// runOneShot owns the complete interactive lifecycle so every error path still stops
// the ARP/capture sources and drains their delivery workers. Unlike service mode, the
// immutable active-scan report has a finite attempt budget.
func (r *sensorRun) runOneShot(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.prepare(ctx, false); err != nil {
		return fmt.Errorf("prepare one-shot scan: %w", err)
	}
	r.startCaptures()
	defer r.shutdown()
	delivery := oneShotScanDeliveryConfig
	if r.oneShotDelivery != nil {
		delivery = *r.oneShotDelivery
	}
	return r.scanIfRegisteredWithConfig(ctx, false, delivery)
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
	// Resolve the operator's interface intent once and feed the same value to both
	// Windows source-bound ICMP and the neighbor-cache Source. The scanner still
	// resolves/revalidates the live OS link for every target; this only ensures the
	// two paths cannot make different preferred-interface choices.
	discoveryIface := ""
	if r.arpEnabled || runtime.GOOS == "windows" {
		discoveryIface = explicitARPInterface(r.passiveIface, r.passiveIfaceExplicit, net.InterfaceByName)
	}
	if r.scanner != nil {
		r.scanner.ConfigureNativeDiscovery(discoveryIface, r.arpEnabled)
	}

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
				cfg := productionDNSPushConfig
				cfg.OnAuthorizationError = r.authorizationRejected
				pushDNSQueriesWithConfig(r.core, r.dnsQueries, cfg)
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
			r.ensurePassiveSink()
		}
	}

	// Unprivileged ARP-cache discovery: reads the OS neighbor cache (passive) and, when
	// --arp-sweep is set, warms it first. It shares the passive host sink/drain — if
	// passive discovery is disabled those don't exist yet, so create them here.
	if r.arpEnabled {
		// Ensure the shared host sink + drain exist even when passive discovery is off
		// or failed to start (in which case r.passiveHosts was allocated but never
		// drained — the ARP source would otherwise fill the buffer and drop forever).
		r.ensurePassiveSink()
		src := netscan.NewSource(netscan.SourceConfig{
			CIDR:          r.scanCIDR,
			Interface:     discoveryIface,
			Sweep:         r.arpSweep,
			PollInterval:  r.arpPollInterval,
			SweepInterval: r.arpSweepInterval,
			// An explicit --cidr can be known before DHCP assigns the matching
			// local address. Keep the post-SCM source alive until that link appears.
			WaitForLink: true,
			OnHostContext: func(ctx context.Context, host netscan.DiscoveredHost) bool {
				// Cache reads arrive as a bounded snapshot (at most the configured
				// /22). Backpressure here is safe: the outbox drain never blocks on
				// HTTP. Context cancellation also releases a blocked enqueue if the
				// sink has exited, keeping service shutdown bounded.
				select {
				case r.passiveHosts <- host:
					return true
				case <-ctx.Done():
					return false
				}
			},
		})
		if err := src.Start(); err != nil {
			log.Printf("WARNING: Failed to start ARP-cache discovery: %v", err)
		} else {
			r.arpSource = src
			log.Printf("ARP-cache discovery active (sweep=%v poll=%s)", r.arpSweep, r.arpPollInterval)
		}
	}
}

// explicitARPInterface returns an OS interface only when the operator genuinely
// pinned --passive-iface to an existing interface. The passive pcap capturer's
// auto-selected interface is intentionally not inherited: at boot before DHCP it can
// select a different physical link, which would make the ARP source retry that wrong
// link forever. "auto" and pcap's pseudo-interface "any" are not OS link identities.
func explicitARPInterface(value string, explicitlySet bool, lookup func(string) (*net.Interface, error)) string {
	if !explicitlySet {
		return ""
	}
	name := strings.TrimSpace(value)
	if name == "" || strings.EqualFold(name, "auto") || strings.EqualFold(name, "any") {
		return ""
	}
	if lookup == nil {
		return ""
	}
	if _, err := lookup(name); err != nil {
		log.Printf("WARNING: --passive-iface %q is not a valid OS interface for ARP discovery; resolving the ARP link from --cidr instead: %v", name, err)
		return ""
	}
	return name
}

// ensurePassiveSink lazily creates the shared discovered-host channel and its single
// drain goroutine (pushPassiveHosts). Both passive discovery and the ARP source push
// here; whichever needs it first starts the drain. This is called only from the
// single-threaded startCaptures, so the started flag needs no synchronization. It fixes
// the case where passive discovery allocated the channel but failed to start its drain,
// leaving a sink that fills and drops.
func (r *sensorRun) ensurePassiveSink() {
	if r.passiveHosts == nil {
		r.passiveHosts = make(chan netscan.DiscoveredHost, 200)
	}
	if r.passiveSinkStarted {
		return
	}
	r.passiveSinkStarted = true
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		cfg := productionHostPushConfig
		cfg.OnAuthorizationError = r.authorizationRejected
		pushPassiveHostsWithConfig(r.core, r.scanCIDR, r.passiveHosts, &r.droppedHosts, cfg)
	}()
}

// shutdown stops the capturers and drains their push goroutines within the bounded
// window.
func (r *sensorRun) shutdown() {
	// Stop the ARP source BEFORE shutdownCaptures closes r.passiveHosts, so its poll
	// loop can never send on a closed channel. Stop() blocks until the loop has drained.
	if r.arpSource != nil {
		r.arpSource.Stop()
	}
	shutdownCaptures(r.capturer, r.passiveCapturer, r.dnsQueries, r.passiveHosts, &r.wg)
}

// register performs the initial registration with bounded, context-aware retries. A
// failure is not fatal — the sensor stays up (Running, in a retrying state) and the
// loop re-attempts registration each cycle (issue #44 idempotent recovery).
func (r *sensorRun) register(ctx context.Context) error {
	if err := registerWithRetryError(ctx, r.core, r.scanCIDR, r.primary, r.interfaces); err == nil {
		r.registrationConfirmed.Store(true)
		log.Printf("Registered with Core at %s", r.coreURL)
		return nil
	} else {
		r.registrationConfirmed.Store(false)
		if client.IsAuthorizationError(err) {
			logSensorResetGuidance(err)
			return err
		}
		log.Printf("WARNING: could not register with Core at %s yet; staying up and retrying each scan cycle", r.coreURL)
		return err
	}
}

// scanIfRegistered is the single gate for the initial service scan, periodic scans,
// and interactive --once. A failed bootstrap must not enter retained scan delivery:
// PushDevices cannot authenticate without a token, and retrying that local error would
// otherwise pin the lifecycle forever before the next registration-recovery cycle.
func (r *sensorRun) scanIfRegistered(ctx context.Context, initial bool) error {
	return r.scanIfRegisteredWithConfig(ctx, initial, productionScanDeliveryConfig)
}

func (r *sensorRun) scanIfRegisteredWithConfig(ctx context.Context, initial bool, delivery scanDeliveryConfig) error {
	var registrationErr error
	if initial {
		registrationErr = r.register(ctx)
	} else {
		registrationErr = r.ensureRegistered(ctx)
	}
	if registrationErr != nil || !r.registrationConfirmed.Load() || !r.core.TokenConfigured() {
		if ctx.Err() == nil {
			log.Printf("Skipping scan until sensor registration succeeds")
		}
		if registrationErr != nil {
			return fmt.Errorf("sensor registration not confirmed: %w", registrationErr)
		}
		return fmt.Errorf("sensor registration not confirmed")
	}
	var err error
	if r.scanFn != nil {
		err = r.scanFn(ctx, r.scanner, r.core, r.scanCIDR, r.scanPorts, delivery)
	} else {
		err = runScanWithConfig(ctx, r.scanner, r.core, r.scanCIDR, r.scanPorts, delivery)
	}
	if client.IsAuthorizationError(err) {
		// A token can be revoked after registration (or between FetchWork and report
		// delivery). Stop the terminal retry, close the process-local scan gate, and
		// force the next cycle back through Register instead of trusting the token file.
		r.authorizationRejected(err)
	}
	return err
}

func (r *sensorRun) ensureRegistered(ctx context.Context) error {
	if r.registrationConfirmed.Load() && r.core.TokenConfigured() {
		return nil
	}
	if err := r.core.Register(ctx, r.scanCIDR, r.primary, r.interfaces); err != nil {
		r.registrationConfirmed.Store(false)
		if client.IsAuthorizationError(err) {
			logSensorResetGuidance(err)
		} else {
			log.Printf("Re-registration attempt failed (will retry next cycle): %v", err)
		}
		return err
	}
	r.registrationConfirmed.Store(true)
	log.Printf("Recovered registration with Core — persisted/validated sensor token")
	return nil
}

func logSensorResetGuidance(err error) {
	log.Printf("Sensor credential was rejected by Core (%v). Scanning is paused. If the token was revoked, run --reset and re-enroll with a fresh admin-minted reset code bound to this sensor ID; a generic new-sensor code cannot reactivate it.", err)
}

// authorizationRejected is the process-wide transition for a terminal 401/403 from
// any sensor API path. Capture delivery runs concurrently with the scan/heartbeat
// lifecycle, so the registration gate is atomic. A rejected worker invokes this once
// before switching to a safe drain/drop mode; the next scan cycle must validate with
// Register again and the operator receives the same bound reset-code guidance.
func (r *sensorRun) authorizationRejected(err error) {
	if r != nil {
		r.registrationConfirmed.Store(false)
	}
	logSensorResetGuidance(err)
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
			if err := r.scanIfRegistered(ctx, false); err != nil && ctx.Err() == nil {
				log.Printf("Scan cycle deferred/failed: %v", err)
			}
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
				if client.IsAuthorizationError(err) {
					r.authorizationRejected(err)
				} else {
					log.Printf("Sensor heartbeat failed: %v", err)
				}
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
	return registerWithRetryError(ctx, core, cidr, primary, interfaces) == nil
}

func registerWithRetryError(ctx context.Context, core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) error {
	const maxAttempts = 4
	delay := registerRetryBaseDelay
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err // cancelled (e.g. service Stop during boot) — abort promptly
		}
		if err := core.Register(ctx, cidr, primary, interfaces); err == nil {
			return nil
		} else {
			lastErr = err
			log.Printf("Register attempt %d/%d failed: %v", attempt, maxAttempts, err)
			if client.IsAuthorizationError(err) {
				return err // retry cannot repair a rejected persisted credential
			}
		}
		if attempt < maxAttempts {
			select {
			case <-time.After(delay):
				delay *= 2
			case <-ctx.Done():
				return ctx.Err() // don't sleep out the backoff after a Stop request
			}
		}
	}
	return lastErr
}

// ensureRegistered performs one explicit registration validation. A persisted token
// is only a credential candidate, not proof that Core still accepts this sensor; the
// sensorRun lifecycle avoids repeated validation only after this process has observed
// a successful Register response. This free helper remains for focused tests/tools.
func ensureRegistered(ctx context.Context, core *client.CoreClient, cidr string, primary bool, interfaces []netinfo.NetworkInterface) bool {
	if err := core.Register(ctx, cidr, primary, interfaces); err != nil {
		if client.IsAuthorizationError(err) {
			logSensorResetGuidance(err)
		} else {
			log.Printf("Re-registration attempt failed (will retry next cycle): %v", err)
		}
		return false
	}
	log.Printf("Recovered registration with Core — persisted/validated sensor token")
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

// scanDeliveryConfig bounds active/native scan reporting without dropping a scan whose
// Core request failed or was only partially accepted. One immutable result is retained
// at a time, each HTTP attempt has a deadline, and retry backoff is capped. The parent
// service context is the only terminal condition so an SCM Stop cancels both a request
// and its backoff immediately.
type scanDeliveryConfig struct {
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	AttemptTimeout time.Duration
	// MaxAttempts <= 0 keeps service-mode delivery retrying until its context is
	// cancelled. Interactive --once sets a finite budget and therefore returns a
	// meaningful non-zero exit instead of hanging forever on a blackhole/207.
	MaxAttempts int
	// Scan is a deterministic test seam. Production leaves it nil and uses the
	// platform scanner's context-aware entry point.
	Scan func(context.Context, *netscan.Scanner, string, bool) (*netscan.ScanResult, error)
}

var productionScanDeliveryConfig = scanDeliveryConfig{
	RetryBaseDelay: 500 * time.Millisecond,
	RetryMaxDelay:  30 * time.Second,
	AttemptTimeout: 30 * time.Second,
}

var oneShotScanDeliveryConfig = scanDeliveryConfig{
	RetryBaseDelay: 500 * time.Millisecond,
	RetryMaxDelay:  2 * time.Second,
	AttemptTimeout: 5 * time.Second,
	MaxAttempts:    3,
}

func cloneScanResult(result *netscan.ScanResult) *netscan.ScanResult {
	if result == nil {
		return nil
	}
	cloned := *result
	cloned.Hosts = append([]netscan.DiscoveredHost(nil), result.Hosts...)
	for i := range cloned.Hosts {
		cloned.Hosts[i].OpenPorts = append([]int(nil), result.Hosts[i].OpenPorts...)
		cloned.Hosts[i].Services = append([]string(nil), result.Hosts[i].Services...)
		cloned.Hosts[i].IdentityEvidence = append([]netscan.IdentityEvidence(nil), result.Hosts[i].IdentityEvidence...)
	}
	return &cloned
}

func deliverScanResult(ctx context.Context, core *client.CoreClient, result *netscan.ScanResult, cidr, segment string) error {
	return deliverScanResultWithConfig(ctx, core, result, cidr, segment, productionScanDeliveryConfig)
}

func deliverScanResultWithConfig(ctx context.Context, core *client.CoreClient, result *netscan.ScanResult, cidr, segment string, cfg scanDeliveryConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if core == nil {
		return fmt.Errorf("deliver scan result: nil Core client")
	}
	if !core.TokenConfigured() {
		return fmt.Errorf("deliver scan result: sensor is not registered with Core")
	}
	retained := cloneScanResult(result)
	if retained == nil {
		return fmt.Errorf("deliver scan result: nil scan result")
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 500 * time.Millisecond
	}
	if cfg.RetryMaxDelay < cfg.RetryBaseDelay {
		cfg.RetryMaxDelay = cfg.RetryBaseDelay
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 30 * time.Second
	}

	backoff := cfg.RetryBaseDelay
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
		err := core.PushDevices(attemptCtx, retained, cidr, segment)
		cancel()
		if err == nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if client.IsAuthorizationError(err) {
			return fmt.Errorf("deliver immutable scan result: %w", err)
		}
		if cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts {
			return fmt.Errorf("deliver immutable scan result exhausted %d attempts: %w", attempt, err)
		}
		log.Printf("Failed to push immutable scan result for %s (segment=%s, attempt=%d; retained for retry in %s): %v", cidr, segment, attempt, backoff, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < cfg.RetryMaxDelay {
			if backoff > cfg.RetryMaxDelay/2 {
				backoff = cfg.RetryMaxDelay
			} else {
				backoff *= 2
			}
		}
	}
}

func runScan(ctx context.Context, scanner *netscan.Scanner, core *client.CoreClient, primaryCIDR string, withPorts bool) error {
	return runScanWithConfig(ctx, scanner, core, primaryCIDR, withPorts, productionScanDeliveryConfig)
}

func runScanWithConfig(ctx context.Context, scanner *netscan.Scanner, core *client.CoreClient, primaryCIDR string, withPorts bool, delivery scanDeliveryConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Defense in depth for any future caller that bypasses sensorRun's lifecycle gate.
	// In particular, never enter immutable delivery's retry loop for a deterministic
	// local "sensor auth token not configured" error.
	if core == nil || !core.TokenConfigured() {
		log.Printf("Skipping scan: sensor is not registered with Core")
		return fmt.Errorf("sensor is not registered with Core")
	}
	if scanner == nil {
		return fmt.Errorf("nil device scanner")
	}
	// Fetch work from Core (queued scans and enabled targets)
	var work *client.WorkResponse
	if delivery.MaxAttempts <= 0 {
		// FetchWork drains queued work. After a service scan succeeds, delivery
		// retains that result in this process until Core accepts it; scan failure or
		// process loss still needs the lease/ack recovery tracked in issue #106.
		// A finite one-shot process can also exhaust its delivery budget and exit.
		// Therefore --once scans only its requested primary CIDR and leaves Core's
		// queued work untouched for the long-running service.
		if w, err := core.FetchWork(ctx); err == nil {
			work = w
			if len(work.ScanQueue) > 0 {
				log.Printf("Fetched %d queued scans from Core", len(work.ScanQueue))
			}
			if len(work.Targets) > 0 {
				log.Printf("Fetched %d enabled scan targets from Core", len(work.Targets))
			}
		} else if client.IsAuthorizationError(err) {
			return fmt.Errorf("fetch sensor work: %w", err)
		} else {
			log.Printf("Could not fetch work from Core: %v (scanning primary CIDR only)", err)
		}
	}

	// Build a deterministic list of CIDRs to scan, avoiding duplicates. Map iteration
	// used to make a bad/off-link task randomly run before a good queued task; returning
	// on that first error then lost the rest after FetchWork had drained Core's queue.
	type scanTask struct {
		cidr      string
		segment   string
		scanPorts bool
	}
	type scanKey struct {
		cidr    string
		segment string
	}
	seenScans := make(map[scanKey]int)
	scans := make([]scanTask, 0, 1)
	addScan := func(task scanTask) {
		task.cidr = strings.TrimSpace(task.cidr)
		task.segment = strings.TrimSpace(task.segment)
		if task.segment == "" {
			task.segment = "default"
		}
		key := scanKey{cidr: task.cidr, segment: task.segment}
		if index, exists := seenScans[key]; exists {
			// A recurring target may duplicate an on-demand request while asking
			// for stronger port coverage. Preserve the strongest requirement.
			scans[index].scanPorts = scans[index].scanPorts || task.scanPorts
			return
		}
		seenScans[key] = len(scans)
		scans = append(scans, task)
	}

	// Primary first, then queued work in server order, then recurring targets.
	addScan(scanTask{cidr: primaryCIDR, segment: "default", scanPorts: withPorts})

	// Add queued scans from work
	if work != nil {
		for _, req := range work.ScanQueue {
			addScan(scanTask{
				cidr:      req.CIDR,
				segment:   req.Segment,
				scanPorts: req.ScanPorts || withPorts,
			})
		}

		// Add enabled targets from work
		for _, target := range work.Targets {
			addScan(scanTask{
				cidr:      target.CIDR,
				segment:   target.Segment,
				scanPorts: target.ScanPorts || withPorts,
			})
		}
	}

	// Execute all scans
	totalHosts := 0
	var scanErrors []error
	for _, task := range scans {
		if ctx.Err() != nil {
			return ctx.Err() // stop between targets on a Stop/Shutdown request (bounded drain)
		}
		log.Printf("Scanning %s (segment=%s) ...", task.cidr, task.segment)
		var result *netscan.ScanResult
		var err error
		if delivery.Scan != nil {
			result, err = delivery.Scan(ctx, scanner, task.cidr, task.scanPorts)
		} else {
			result, err = scanner.ScanContext(ctx, task.cidr, task.scanPorts)
		}
		if err != nil {
			log.Printf("Scan failed for %s: %v", task.cidr, err)
			wrapped := fmt.Errorf("scan %s: %w", task.cidr, err)
			if delivery.MaxAttempts > 0 {
				// --once has exactly one primary task and must surface its failure.
				return wrapped
			}
			scanErrors = append(scanErrors, wrapped)
			continue
		}

		log.Printf("Scan complete for %s: %d hosts found in %s", task.cidr, len(result.Hosts), result.Duration)

		if len(result.Hosts) == 0 {
			continue
		}

		totalHosts += len(result.Hosts)

		// Retain the exact result in this process until Core fully accepts it. This is
		// especially important for queued scan work: FetchWork drains that queue, so
		// treating a 207 partial response as success would otherwise lose failed hosts.
		// Durable recovery across a process/host failure is the lease/ack follow-up #106.
		if err := deliverScanResultWithConfig(ctx, core, result, task.cidr, task.segment, delivery); err != nil {
			if ctx.Err() == nil {
				log.Printf("Failed to deliver retained scan results to Core for %s: %v", task.cidr, err)
			}
			// Authorization and cancellation apply to the whole sensor, not one target.
			// Transient service delivery retries internally until recovery/cancellation.
			if client.IsAuthorizationError(err) || ctx.Err() != nil || delivery.MaxAttempts > 0 {
				return err
			}
			scanErrors = append(scanErrors, fmt.Errorf("deliver scan %s: %w", task.cidr, err))
			continue
		} else {
			log.Printf("Pushed %d devices to Core for %s", len(result.Hosts), task.cidr)
		}
	}

	if totalHosts > 0 {
		log.Printf("Scan cycle complete: %d total hosts discovered", totalHosts)
	}
	if len(scanErrors) > 0 {
		return errors.Join(scanErrors...)
	}
	return nil
}

// dnsPushConfig bounds every in-memory stage of DNS delivery. A failed request keeps
// its immutable batch and retries it; once the bounded queue is full, newly completed
// batches are shed explicitly instead of growing memory without limit while Core is
// offline. The capture callback has its own bounded channel and drop counter as the
// first line of overload protection.
type dnsPushConfig struct {
	BatchSize            int
	QueuedBatches        int
	MaxUnpaired          int
	PairWindow           time.Duration
	FlushInterval        time.Duration
	RetryBaseDelay       time.Duration
	RetryMaxDelay        time.Duration
	AttemptTimeout       time.Duration
	ShutdownFlushLimit   time.Duration
	OnAuthorizationError func(error)
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
	authorizationRejected := make(chan error, 1)
	go func() {
		defer close(deliveryDone)
		deliverDNSBatches(deliveryCtx, core, batches, cfg, authorizationRejected)
	}()

	coalescer := newDNSQueryCoalescer(cfg.PairWindow, cfg.MaxUnpaired)
	ready := make([]dnscap.DNSQuery, 0, cfg.BatchSize)
	dropped := 0
	authRejected := false
	enqueueChunk := func(chunk []dnscap.DNSQuery) {
		if len(chunk) == 0 {
			return
		}
		immutable := append([]dnscap.DNSQuery(nil), chunk...)
		if authRejected {
			dropped += len(immutable)
			return
		}
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
		case err := <-authorizationRejected:
			authRejected = true
			authorizationRejected = nil
			log.Printf("WARNING: DNS delivery stopped after Core rejected the sensor credential; safely draining and dropping new capture records until restart/reset: %v", err)
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

func deliverDNSBatches(ctx context.Context, core *client.CoreClient, batches <-chan []dnscap.DNSQuery, cfg dnsPushConfig, authorizationRejected chan<- error) {
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
			if client.IsAuthorizationError(err) {
				if cfg.OnAuthorizationError != nil {
					cfg.OnAuthorizationError(err)
				}
				select {
				case authorizationRejected <- err:
				default:
				}
				return
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

type hostPushConfig struct {
	BatchSize            int
	MaxPending           int
	FlushInterval        time.Duration
	RetryBaseDelay       time.Duration
	RetryMaxDelay        time.Duration
	AttemptTimeout       time.Duration
	ShutdownFlushLimit   time.Duration
	Now                  func() time.Time
	OnAuthorizationError func(error)
}

var productionHostPushConfig = hostPushConfig{
	BatchSize:          50,
	MaxPending:         2048, // one complete /22 snapshot plus passive enrichment
	FlushInterval:      15 * time.Second,
	RetryBaseDelay:     500 * time.Millisecond,
	RetryMaxDelay:      30 * time.Second,
	AttemptTimeout:     5 * time.Second,
	ShutdownFlushLimit: 8 * time.Second,
	Now:                time.Now,
}

type pendingHostSet struct {
	hosts                 map[string]netscan.DiscoveredHost
	order                 []string
	nextSequence          uint64
	deliveryEpochProvider func() string
}

func newPendingHostSet(deliveryEpochProvider ...func() string) *pendingHostSet {
	pending := &pendingHostSet{hosts: make(map[string]netscan.DiscoveredHost)}
	if len(deliveryEpochProvider) > 0 {
		pending.deliveryEpochProvider = deliveryEpochProvider[0]
	}
	return pending
}

func passiveHostKey(host netscan.DiscoveredHost) string {
	ip := strings.TrimSpace(host.IPAddress)
	mac := strings.ToLower(strings.TrimSpace(host.MACAddress))
	if ip == "" {
		return ""
	}
	if isARPCacheSource(host.DiscoverySource) {
		// Cache mappings represent current ownership edges. One IP must have only
		// the latest mapping queued; retaining old/new MAC keys independently lets
		// a failed old retry reclaim the address after the new edge succeeds.
		return "arp-cache-ip:" + ip
	}
	if mac != "" {
		// Preserve simultaneous old/new or proxy-ARP bindings for one MAC. Core's
		// temporal resolver, not a browser-side first-wins fold, adjudicates them.
		return "mac:" + mac + "|ip:" + ip
	}
	return "ip:" + ip
}

func isARPCacheSource(source string) bool {
	return strings.EqualFold(strings.TrimSpace(source), "arp_cache")
}

func (p *pendingHostSet) add(host netscan.DiscoveredHost, limit int, now time.Time) bool {
	// Bound the first observation as well as later merges. Current parsers already
	// enforce this cap, but the outbox is the final memory-safety boundary shared by
	// every discovery producer.
	host.Services = mergeHostServices(nil, host.Services)
	key := passiveHostKey(host)
	if key == "" {
		return true
	}
	if host.ObservedAt.IsZero() {
		host.ObservedAt = now.UTC()
	}
	if host.DeliverySequence == 0 {
		p.nextSequence++
		host.DeliverySequence = p.nextSequence
	} else if host.DeliverySequence > p.nextSequence {
		p.nextSequence = host.DeliverySequence
	}
	if existing, ok := p.hosts[key]; ok {
		p.hosts[key] = mergeQueuedHost(existing, host)
		return true
	}
	if len(p.hosts) >= limit {
		return false
	}
	p.hosts[key] = host
	p.order = append(p.order, key)
	return true
}

func mergeQueuedHost(existing, observed netscan.DiscoveredHost) netscan.DiscoveredHost {
	if isARPCacheSource(existing.DiscoverySource) && isARPCacheSource(observed.DiscoverySource) &&
		strings.TrimSpace(existing.IPAddress) == strings.TrimSpace(observed.IPAddress) {
		// Queue sequence reflects local observation order and survives retries. It
		// therefore wins over wall-clock timestamps, which can jump during NTP
		// correction; a failed older request must never reclaim the IP afterward.
		if observed.DeliverySequence > existing.DeliverySequence ||
			(observed.DeliverySequence == existing.DeliverySequence && observed.ObservedAt.After(existing.ObservedAt)) {
			return observed
		}
		return existing
	}
	merged := mergePassiveHost(existing, observed)
	if observed.DeliverySequence > merged.DeliverySequence {
		merged.DeliverySequence = observed.DeliverySequence
	}
	return merged
}

func (p *pendingHostSet) pop(limit int) []netscan.DiscoveredHost {
	if limit <= 0 || limit > len(p.order) {
		limit = len(p.order)
	}
	batch := make([]netscan.DiscoveredHost, 0, limit)
	for len(batch) < limit && len(p.order) > 0 {
		key := p.order[0]
		p.order = p.order[1:]
		host, ok := p.hosts[key]
		if !ok {
			continue
		}
		if p.deliveryEpochProvider != nil {
			// Core, not sensor wall time or first packet arrival, orders process
			// sessions. Restamp a retained batch after re-registration so an old
			// in-flight epoch cannot reclaim identity after a process restart.
			host.DeliveryEpoch = strings.TrimSpace(p.deliveryEpochProvider())
		}
		delete(p.hosts, key)
		batch = append(batch, host)
	}
	return batch
}

func latestHostObservation(hosts []netscan.DiscoveredHost, fallback time.Time) time.Time {
	latest := time.Time{}
	for _, host := range hosts {
		if host.ObservedAt.After(latest) {
			latest = host.ObservedAt
		}
	}
	if latest.IsZero() {
		return fallback.UTC()
	}
	return latest.UTC()
}

type hostDeliveryResult struct {
	batch []netscan.DiscoveredHost
	err   error
}

func pushPassiveHosts(core *client.CoreClient, cidr string, observations <-chan netscan.DiscoveredHost, dropped *atomic.Int64) {
	pushPassiveHostsWithConfig(core, cidr, observations, dropped, productionHostPushConfig)
}

// pushPassiveHostsWithConfig is a bounded outbox (latest cache mapping per IP;
// latest enrichment per MAC/IP). HTTP delivery
// runs separately from ingestion, so a full /22 ARP snapshot cannot overflow the
// 200-entry capture channel while Core is slow. Failed batches move to the tail,
// retaining newer observations and preventing a stable table prefix from starving the
// rest of the network.
func pushPassiveHostsWithConfig(core *client.CoreClient, cidr string, observations <-chan netscan.DiscoveredHost, dropped *atomic.Int64, cfg hostPushConfig) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.MaxPending < cfg.BatchSize {
		cfg.MaxPending = cfg.BatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 15 * time.Second
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 500 * time.Millisecond
	}
	if cfg.RetryMaxDelay < cfg.RetryBaseDelay {
		cfg.RetryMaxDelay = cfg.RetryBaseDelay
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 5 * time.Second
	}
	if cfg.ShutdownFlushLimit <= 0 {
		cfg.ShutdownFlushLimit = 8 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	pending := newPendingHostSet(core.DeliveryEpoch)
	results := make(chan hostDeliveryResult, 1)
	deliveryCtx, cancelDelivery := context.WithCancel(context.Background())
	defer cancelDelivery()
	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()

	backoff := cfg.RetryBaseDelay
	var retryTimer *time.Timer
	var retryC <-chan time.Time
	var shutdownTimer *time.Timer
	var shutdownC <-chan time.Time
	var inflight []netscan.DiscoveredHost
	flushRequested := false
	closing := false
	defer func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
	}()

	countDropped := func(n int64) {
		if dropped != nil && n > 0 {
			dropped.Add(n)
		}
	}
	startDelivery := func() {
		if len(inflight) > 0 || retryC != nil || len(pending.hosts) == 0 {
			return
		}
		forceDrain := closing || flushRequested
		if !forceDrain && len(pending.hosts) < cfg.BatchSize {
			return
		}
		inflight = pending.pop(cfg.BatchSize)
		flushRequested = forceDrain && len(pending.hosts) > 0
		batch := append([]netscan.DiscoveredHost(nil), inflight...)
		go func() {
			attemptCtx, cancel := context.WithTimeout(deliveryCtx, cfg.AttemptTimeout)
			defer cancel()
			result := &netscan.ScanResult{
				Hosts: batch, ScanTime: latestHostObservation(batch, cfg.Now()), Duration: 0,
			}
			err := core.PushDevices(attemptCtx, result, cidr, "default")
			results <- hostDeliveryResult{batch: batch, err: err}
		}()
	}
	requeue := func(batch []netscan.DiscoveredHost) {
		now := cfg.Now()
		for _, host := range batch {
			if !pending.add(host, cfg.MaxPending, now) {
				countDropped(1)
			}
		}
	}

	for {
		startDelivery()
		if closing && len(inflight) == 0 && len(pending.hosts) == 0 {
			return
		}
		select {
		case host, ok := <-observations:
			if !ok {
				observations = nil
				closing = true
				flushRequested = true
				shutdownTimer = time.NewTimer(cfg.ShutdownFlushLimit)
				shutdownC = shutdownTimer.C
				continue
			}
			if !pending.add(host, cfg.MaxPending, cfg.Now()) {
				countDropped(1)
			}
		case <-ticker.C:
			flushRequested = true
		case result := <-results:
			inflight = nil
			if result.err != nil {
				if client.IsAuthorizationError(result.err) {
					if cfg.OnAuthorizationError != nil {
						cfg.OnAuthorizationError(result.err)
					}
					abandoned := int64(len(result.batch) + len(pending.hosts))
					countDropped(abandoned)
					log.Printf("WARNING: discovery delivery stopped after Core rejected the sensor credential; abandoning %d retained hosts and safely draining new observations until restart/reset: %v", abandoned, result.err)
					if observations != nil {
						for range observations {
							countDropped(1)
						}
					}
					return
				}
				log.Printf("Failed to push %d discovery hosts to Core (retained for retry in %s): %v", len(result.batch), backoff, result.err)
				requeue(result.batch)
				flushRequested = true
				retryTimer = time.NewTimer(backoff)
				retryC = retryTimer.C
				if backoff < cfg.RetryMaxDelay {
					backoff *= 2
					if backoff > cfg.RetryMaxDelay {
						backoff = cfg.RetryMaxDelay
					}
				}
			} else {
				log.Printf("Pushed %d discovery hosts to Core", len(result.batch))
				backoff = cfg.RetryBaseDelay
			}
		case <-retryC:
			retryC = nil
			retryTimer = nil
			flushRequested = true
		case <-shutdownC:
			cancelDelivery()
			countDropped(int64(len(pending.hosts) + len(inflight)))
			log.Printf("WARNING: discovery delivery did not drain within %s; abandoning %d retained hosts for bounded shutdown", cfg.ShutdownFlushLimit, len(pending.hosts)+len(inflight))
			return
		}
	}
}

func mergePassiveHost(existing, observed netscan.DiscoveredHost) netscan.DiscoveredHost {
	if existing.IPAddress == "" && existing.MACAddress == "" && existing.Hostname == "" && existing.Vendor == "" && existing.Status == "" && len(existing.OpenPorts) == 0 {
		observed.Services = mergeHostServices(nil, observed.Services)
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
	existing.Services = mergeHostServices(existing.Services, observed.Services)
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
	} else if existing.Status == "observed" && observed.Status == "up" {
		existing.Status = observed.Status
	}
	if existing.DiscoverySource == "" || (existing.DiscoverySource == "arp_cache" && observed.DiscoverySource != "" && observed.DiscoverySource != "arp_cache") {
		existing.DiscoverySource = observed.DiscoverySource
	}
	if observed.ObservedAt.After(existing.ObservedAt) {
		existing.ObservedAt = observed.ObservedAt
	}
	return existing
}

// mergeHostServices preserves first-seen order while enforcing the same per-host cap
// as the mDNS parser. The retained outbox can merge observations indefinitely while
// Core is offline, so the parser's packet-local guard alone is not sufficient.
func mergeHostServices(existing, observed []string) []string {
	capacity := len(existing) + len(observed)
	if capacity > netscan.MaxServicesPerHost {
		capacity = netscan.MaxServicesPerHost
	}
	merged := make([]string, 0, capacity)
	for _, list := range [][]string{existing, observed} {
		for _, service := range list {
			if len(merged) >= netscan.MaxServicesPerHost {
				return merged
			}
			if service == "" || containsString(merged, service) {
				continue
			}
			merged = append(merged, service)
		}
	}
	return merged
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
