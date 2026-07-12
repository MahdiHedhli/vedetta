//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// runFrontend cancels the run on SIGINT/SIGTERM and drives the scan loop. There is
// no OS service manager on the Unix path — systemd/launchd deliver SIGTERM on stop,
// which triggers the graceful capture drain inside run.loop.
func runFrontend(run *sensorRun) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	run.loop(ctx)
}
