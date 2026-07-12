//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

// serviceName is the Windows service name the installer registers.
const serviceName = "VedettaSensor"

// runFrontend runs under the Windows Service Control Manager when the process was
// started as a service, and falls back to Ctrl+C handling from a console.
func runFrontend(run *sensorRun) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("could not determine Windows service context (%v); running interactively", err)
		isService = false
	}
	if isService {
		if err := svc.Run(serviceName, &sensorService{run: run}); err != nil {
			log.Printf("Windows service run error: %v", err)
		}
		return
	}
	// Console: Ctrl+C only (SIGTERM is not delivered on Windows).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	run.loop(ctx)
}

// sensorService adapts the shared sensorRun.loop to the SCM control handler. It
// reports Running as soon as the loop goroutine is launched, and on Stop/Shutdown
// cancels the run context and waits for the capture drain before reporting Stopped.
type sensorService struct{ run *sensorRun }

func (s *sensorService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run.loop(ctx) // drains captures when ctx is cancelled
	}()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// WaitHint must exceed the ~10s capture drain in shutdownCaptures.
				status <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				<-done
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				log.Printf("unexpected Windows service control request: %d", c.Cmd)
			}
		case <-done:
			// The loop returned unexpectedly (it should only exit on cancel).
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
