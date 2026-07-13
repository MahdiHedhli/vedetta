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
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/adminauth"
	"github.com/vedetta-network/vedetta/threat-network/internal/api"
	"github.com/vedetta-network/vedetta/threat-network/internal/consensus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("threat-network stopped after listener failure: %v", err)
	}
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
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()
	// Validate and warm the immutable corpus release once at startup. Public
	// manifest/status reads remain metadata-only after this; a corrupt imported
	// release therefore fails closed before either listener starts.
	if _, _, err = db.CurrentCorpusSnapshot(); err != nil {
		log.Fatalf("validate current device corpus release: %v", err)
	}

	if n, err := db.SeedDefaultAllowlist(); err != nil {
		log.Printf("warning: allowlist seed failed: %v", err)
	} else {
		log.Printf("allowlist seeded: %d domains", n)
	}

	// Admin subcommands (config/CLI only — no web UI, per T6.1).
	switch {
	case *denylist != "":
		if err := db.DenylistReporter(*denylist, *reason); err != nil {
			log.Fatalf("denylist: %v", err)
		}
		log.Printf("denylisted reporter_id=%s", *denylist)
		return nil
	case *reinstate != "":
		if err := db.ReinstateReporter(*reinstate); err != nil {
			log.Fatalf("reinstate: %v", err)
		}
		log.Printf("reinstated reporter_id=%s", *reinstate)
		return nil
	case *consensusOnce:
		if err := consensus.New(db).Run(); err != nil {
			log.Fatalf("consensus run: %v", err)
		}
		log.Printf("consensus run complete")
		return nil
	}

	port := os.Getenv("THREAT_NETWORK_PORT")
	if port == "" {
		port = "9090"
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	srv := api.NewServer(db, logger)
	httpSrv := &http.Server{
		Addr:         ":" + port,
		Handler:      srv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	var adminHTTP *http.Server
	if os.Getenv("THREAT_NETWORK_ADMIN_ENABLED") == "true" {
		tokenPath := os.Getenv("THREAT_NETWORK_ADMIN_TOKEN_FILE")
		authenticator, authErr := adminauth.LoadFile(tokenPath)
		if authErr != nil {
			log.Fatalf("management API enabled but token file is invalid: %v", authErr)
		}
		adminAddr := os.Getenv("THREAT_NETWORK_ADMIN_ADDR")
		if adminAddr == "" {
			adminAddr = "127.0.0.1:9091"
		}
		allowNonLoopback := os.Getenv("THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK") == "true"
		if err = validateAdminListenAddr(adminAddr, allowNonLoopback); err != nil {
			log.Fatalf("management API address is unsafe: %v", err)
		}
		adminHTTP = &http.Server{
			Addr:         adminAddr,
			Handler:      srv.AdminHandler(authenticator),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
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
	_ = httpSrv.Shutdown(shutdownCtx)
	if adminHTTP != nil {
		_ = adminHTTP.Shutdown(shutdownCtx)
	}
	logger.Printf("threat-network backend stopped")
	return serveErr
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
		return fmt.Errorf("non-loopback binding requires THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK=true")
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
