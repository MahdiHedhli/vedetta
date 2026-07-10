// Command telemetry is the Vedetta opt-in, privacy-reduced threat-export daemon.
//
// It is ON by default (opt-out): only VEDETTA_TELEMETRY_OPTIN=false disables it,
// in which case it performs no Core reads, no network egress, no reporter
// registration, and no state writes beyond a single log line.
//
// When opted in it reads Core's events API on a cursor-driven interval, gates and
// strips events through a structurally-allowlisted pipeline (no raw IPs, MACs,
// or hostnames ever leave the node), aggregates to domain-level signals, signs
// and ships them to the community threat network, and exposes a localhost
// /healthz + /status surface.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
	"github.com/vedetta-network/vedetta/telemetry/internal/corereader"
	"github.com/vedetta-network/vedetta/telemetry/internal/pipeline"
	"github.com/vedetta-network/vedetta/telemetry/internal/status"
	"github.com/vedetta-network/vedetta/telemetry/internal/transmit"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("telemetry: config error: %v", err)
	}

	// ON by default (opt-out). If explicitly disabled, stay inert.
	if !cfg.OptIn {
		log.Println("Telemetry: disabled (VEDETTA_TELEMETRY_OPTIN=false). No data leaves this host.")
		waitForSignal()
		return
	}

	// Loud disclosure — on-by-default sharing must never be silent.
	log.Println("Telemetry: ON — contributing anonymized, advisory-only threat signals to the community feed.")
	log.Println("           No source IPs / MACs / hostnames ever leave your network (see PRIVACY.md and")
	log.Println("           specs/003-threat-network/anonymization-proof.md). Opt out any time:")
	log.Println("           set VEDETTA_TELEMETRY_OPTIN=false and restart.")
	if cfg.CoreToken == "" {
		log.Println("           Note: no VEDETTA_CORE_TOKEN set — reading Core's current (unauthenticated) events;")
		log.Println("           set a token once Core read auth is enabled so telemetry keeps reading.")
	}

	if err := run(cfg); err != nil {
		log.Fatalf("telemetry: %v", err)
	}
}

func run(cfg *config.Config) error {
	log.Printf("Telemetry daemon starting (dry_run=%v). Core=%s ThreatNetwork=%s",
		cfg.DryRun, cfg.CoreURL, cfg.ThreatNetworkURL)

	if err := config.EnsureStateDir(cfg.StateDir); err != nil {
		return err
	}

	st := status.NewState(cfg.OptIn, cfg.DryRun)

	// Status server on localhost.
	statusSrv := &http.Server{Addr: cfg.StatusAddr, Handler: st.Handler()}
	go func() {
		if err := statusSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("status server error: %v", err)
		}
	}()
	log.Printf("status surface on http://%s/status", cfg.StatusAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ensure salt. Salt failure is fatal (we cannot compute distinct_asset_count
	// safely without it).
	salt, err := transmit.EnsureSalt(cfg.StateDir)
	if err != nil {
		return err
	}

	// Register reporter. Failure is non-fatal: the loop keeps retrying on ticks
	// (surfaced on /status).
	reporter, regErr := transmit.EnsureReporter(ctx, cfg.StateDir, cfg.ThreatNetworkURL, cfg.VedettaVersion, nil)
	if regErr != nil {
		log.Printf("reporter registration deferred: %v", regErr)
		st.Update(func(s *status.Snapshot) { s.LastError = "registration: " + regErr.Error() })
	} else {
		st.Update(func(s *status.Snapshot) { s.ReporterRegistered = true })
	}

	maxItems := cfg.MaxBatchItems
	if reporter.MaxBatchItems > 0 && reporter.MaxBatchItems < maxItems {
		maxItems = reporter.MaxBatchItems
	}

	spool := transmit.NewSpool(cfg.StateDir)
	tx := transmit.New(cfg.ThreatNetworkURL, reporter, spool, cfg.DryRun, maxItems)

	p := &pipeline.Pipeline{
		Cfg:      cfg,
		Reader:   corereader.NewClient(cfg.CoreURL, cfg.CoreToken),
		Tx:       tx,
		Salt:     salt,
		State:    st,
		StateDir: cfg.StateDir,
	}

	st.Update(func(s *status.Snapshot) { s.SpoolDepth = spool.Depth() })

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.TickInterval)
	defer ticker.Stop()

	// Run an initial tick immediately once registered so operators see activity
	// without waiting a full interval. In dry-run this exercises the full
	// pipeline to the spool with zero egress.
	if regErr == nil {
		runTickSafely(ctx, p)
	}

	for {
		select {
		case <-sigCh:
			log.Println("Telemetry daemon shutting down.")
			st.SetLive(false)
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = statusSrv.Shutdown(shutCtx)
			shutCancel()
			return nil
		case <-ticker.C:
			if !st.Get().ReporterRegistered {
				if r, err := transmit.EnsureReporter(ctx, cfg.StateDir, cfg.ThreatNetworkURL, cfg.VedettaVersion, nil); err == nil {
					p.Tx.Reporter = r
					st.Update(func(s *status.Snapshot) { s.ReporterRegistered = true })
				}
			}
			runTickSafely(ctx, p)
		}
	}
}

// runTickSafely runs a tick, recovering from any panic so a single bad tick
// never crashes the daemon.
func runTickSafely(ctx context.Context, p *pipeline.Pipeline) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("tick panic recovered: %v", r)
		}
	}()
	p.RunTick(ctx)
}

func waitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
