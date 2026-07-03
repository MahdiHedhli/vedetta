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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/api"
	"github.com/vedetta-network/vedetta/threat-network/internal/consensus"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func main() {
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
		return
	case *reinstate != "":
		if err := db.ReinstateReporter(*reinstate); err != nil {
			log.Fatalf("reinstate: %v", err)
		}
		log.Printf("reinstated reporter_id=%s", *reinstate)
		return
	case *consensusOnce:
		if err := consensus.New(db).Run(); err != nil {
			log.Fatalf("consensus run: %v", err)
		}
		log.Printf("consensus run complete")
		return
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

	go func() {
		logger.Printf("threat-network backend starting on :%s (db=%s)", port, dbPath)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	logger.Printf("threat-network backend stopped")
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
