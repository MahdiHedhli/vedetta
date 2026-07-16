//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceName is the Windows service name the installer registers.
const serviceName = "VedettaSensor"

// runFrontend runs under the Windows Service Control Manager when started as a
// service, and falls back to Ctrl+C handling from a console.
func runFrontend(run *sensorRun) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("could not determine Windows service context (%v); running interactively", err)
		isService = false
	}
	if isService {
		// A LocalSystem service has no usable stderr, so log output would vanish and a
		// failed enrollment / ETW start / Core push would be invisible while the service
		// still reported Running. Redirect logs to an ACL-restricted file under
		// %ProgramData%\Vedetta (the installer locks that directory to SYSTEM +
		// Administrators) before dispatching to the SCM.
		setupServiceLogging()
		if err := svc.Run(serviceName, &sensorService{run: run}); err != nil {
			log.Printf("Windows service run error: %v", err)
		}
		return
	}
	// Console: Ctrl+C only (SIGTERM is not delivered on Windows).
	ctx, stop := interactiveContext()
	defer stop()
	run.serve(ctx)
}

func interactiveContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// sensorService adapts sensorRun.serve to the SCM control handler. Crucially, ALL
// Core I/O (registration retries, scanning) happens inside serve, which runs only
// after svc.Run has connected to the SCM — so the service reaches the dispatcher
// within the SCM connect deadline (~30s) even when Core is blackholed at boot. The
// service reports Running immediately and lets registration retry in the background
// (a degraded/retrying-but-up state), rather than blocking StartPending on Core.
type sensorService struct{ run *sensorRun }

func (s *sensorService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // guarantees cleanup on every return path (and satisfies go vet lostcancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run.serve(ctx) // registration + scanning happen HERE, after SCM dispatch
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Cancellation now threads through registration, HTTP, and scanning, so
				// this drain is genuinely bounded (the capture drain adds up to ~10s).
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				select {
				case <-done:
				case <-time.After(18 * time.Second):
					log.Printf("WARNING: service did not finish draining within 18s; stopping anyway")
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				log.Printf("unexpected Windows service control request: %d", c.Cmd)
			}
		case <-done:
			// serve returned on its own (it should only return on cancel).
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// setupServiceLogging redirects the standard logger to a size-capped file under
// %ProgramData%\Vedetta, which the installer ACL-restricts to SYSTEM + Administrators.
func setupServiceLogging() {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	dir := filepath.Join(base, "Vedetta")
	_ = os.MkdirAll(dir, 0o700)
	log.SetOutput(&rotatingWriter{path: filepath.Join(dir, "sensor.log"), max: 8 << 20})
}

// rotatingWriter is a minimal size-capped log sink: it appends to path and, when a
// write would exceed max bytes, rotates the file to path+".1" (keeping one previous
// file) and starts fresh. Logging never blocks or crashes the sensor — write errors
// are swallowed. Keeping this tiny avoids pulling in a logging dependency for beta.
type rotatingWriter struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		if fi, err := os.Stat(w.path); err == nil {
			w.size = fi.Size()
		}
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return len(p), nil // never fail the caller on a logging problem
		}
		w.f = f
	}

	if w.size+int64(len(p)) > w.max {
		_ = w.f.Close()
		_ = os.Rename(w.path, w.path+".1") // keep exactly one previous file
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			w.f = nil
			return len(p), nil
		}
		w.f = f
		w.size = 0
	}

	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
