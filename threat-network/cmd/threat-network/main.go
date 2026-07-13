// Command threat-network is the community threat-network backend: it registers
// opted-in reporters, ingests signed privacy-reduced telemetry batches, runs a
// multi-reporter consensus job, and publishes an advisory-only community feed.
//
// See specs/003-threat-network/ for spec, plan, tasks, and the feed contract;
// the ingest wire format is owned by
// specs/002-telemetry-service/contracts/telemetry-export.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/adminauth"
	"github.com/vedetta-network/vedetta/threat-network/internal/api"
	"github.com/vedetta-network/vedetta/threat-network/internal/consensus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("threat-network stopped: %v", err)
	}
}

type runMode struct {
	consensusOnce bool
	denylist      string
	reinstate     string
	reason        string
}

type httpShutdowner interface {
	Shutdown(context.Context) error
}

func shutdownHTTPServers(ctx context.Context, servers ...httpShutdowner) {
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server httpShutdowner) {
			defer wg.Done()
			_ = server.Shutdown(ctx)
		}(server)
	}
	wg.Wait()
}

func run() error {
	var (
		consensusOnce = flag.Bool("consensus-once", false, "run a single consensus pass and exit")
		denylist      = flag.String("denylist", "", "reporter_id to denylist, then exit")
		reinstate     = flag.String("reinstate", "", "reporter_id to reinstate, then exit")
		reason        = flag.String("reason", "manual", "reason for denylist")
	)
	flag.Parse()

	dbPath := os.Getenv("THREAT_NETWORK_DB")
	if dbPath == "" {
		dbPath = "/data/threat-network.db"
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if n, err := db.SeedDefaultAllowlist(); err != nil {
		log.Printf("warning: allowlist seed failed: %v", err)
	} else {
		log.Printf("allowlist seeded: %d domains", n)
	}

	// Recovery and admin subcommands must remain usable when the current corpus
	// release is corrupt. The daemon path still validates and warms the immutable
	// release before either listener is constructed or started.
	handled, err := prepareRunMode(db, runMode{
		consensusOnce: *consensusOnce,
		denylist:      *denylist,
		reinstate:     *reinstate,
		reason:        *reason,
	})
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	port := os.Getenv("THREAT_NETWORK_PORT")
	if port == "" {
		port = "9090"
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	srv := api.NewServer(db, logger)
	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	var adminHTTP *http.Server
	if os.Getenv("THREAT_NETWORK_ADMIN_ENABLED") == "true" {
		tokenPath := os.Getenv("THREAT_NETWORK_ADMIN_TOKEN_FILE")
		authenticator, authErr := adminauth.LoadFile(tokenPath)
		if authErr != nil {
			return fmt.Errorf("management API enabled but token file is invalid: %w", authErr)
		}
		adminAddr := os.Getenv("THREAT_NETWORK_ADMIN_ADDR")
		if adminAddr == "" {
			adminAddr = "127.0.0.1:9091"
		}
		allowNonLoopback := os.Getenv("THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK") == "true"
		if err = validateAdminListenAddr(adminAddr, allowNonLoopback); err != nil {
			return fmt.Errorf("management API address is unsafe: %w", err)
		}
		adminHost, _, _ := net.SplitHostPort(adminAddr)
		if !net.ParseIP(adminHost).IsLoopback() {
			log.Printf("WARNING: plaintext management API uses a non-loopback in-process bind; this is safe only inside an isolated container with loopback-only host publication, or behind authenticated TLS termination; never expose port 9091 directly")
		}
		adminHTTP = &http.Server{
			Addr:              adminAddr,
			Handler:           srv.AdminHandler(authenticator),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Evict idle per-IP rate-limiter buckets until shutdown (bounds memory).
	srv.StartSweepers(ctx)

	// Background jobs: consensus every 15 min, retention purge daily.
	go runTicker(ctx, 15*time.Minute, func() {
		if err := consensus.New(db).Run(); err != nil {
			logger.Printf("consensus error: %v", err)
		}
	})
	go runTicker(ctx, 24*time.Hour, func() {
		if r, err := db.Purge(time.Now()); err != nil {
			logger.Printf("retention error: %v", err)
		} else {
			logger.Printf("retention purge signals=%d receipts=%d nonces=%d revoked_feed=%d",
				r.Signals, r.Receipts, r.Nonces, r.RevokedFeed)
		}
	})

	serverErrors := make(chan error, 2)
	go func() {
		logger.Printf("threat-network backend starting on :%s (db=%s)", port, dbPath)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("public API: %w", err)
		}
	}()
	if adminHTTP != nil {
		go func() {
			logger.Printf("threat-network management API starting on %s", adminHTTP.Addr)
			if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("management API: %w", err)
			}
		}()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serverErrors:
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdowners := []httpShutdowner{httpSrv}
	if adminHTTP != nil {
		shutdowners = append(shutdowners, adminHTTP)
	}
	shutdownHTTPServers(shutdownCtx, shutdowners...)
	logger.Printf("threat-network backend stopped")
	return serveErr
}

// prepareRunMode dispatches every early-exit CLI mode before validating the
// public corpus. A damaged imported release must not prevent an operator from
// running recovery or reporter-administration commands, while daemon startup
// must continue to fail closed before binding a listener.
func prepareRunMode(db *store.DB, mode runMode) (bool, error) {
	switch {
	case mode.denylist != "":
		if err := db.DenylistReporter(mode.denylist, mode.reason); err != nil {
			return true, fmt.Errorf("denylist: %w", err)
		}
		log.Printf("denylisted reporter_id=%s", mode.denylist)
		return true, nil
	case mode.reinstate != "":
		if err := db.ReinstateReporter(mode.reinstate); err != nil {
			return true, fmt.Errorf("reinstate: %w", err)
		}
		log.Printf("reinstated reporter_id=%s", mode.reinstate)
		return true, nil
	case mode.consensusOnce:
		if err := consensus.New(db).Run(); err != nil {
			return true, fmt.Errorf("consensus run: %w", err)
		}
		log.Printf("consensus run complete")
		return true, nil
	}

	if _, _, err := db.CurrentCorpusSnapshot(); err != nil {
		return false, fmt.Errorf("validate current device corpus release: %w", err)
	}
	return false, nil
}

// validateAdminListenAddr makes a plaintext bearer listener an explicit
// deployment decision. Hostnames are intentionally refused: DNS resolution can
// change, while the management boundary needs to be obvious from configuration.
func validateAdminListenAddr(addr string, allowNonLoopback bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("must be a host:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host must be a literal IP address")
	}
	if !ip.IsLoopback() && !allowNonLoopback {
		return fmt.Errorf("non-loopback binding requires THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK=true and an isolated loopback-published container or authenticated TLS termination")
	}
	return nil
}

func runTicker(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
