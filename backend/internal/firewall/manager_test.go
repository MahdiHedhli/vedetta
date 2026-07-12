package firewall

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

type concurrentHealthConnector struct{}

func (*concurrentHealthConnector) Name() string { return "concurrent-health" }
func (*concurrentHealthConnector) Discover(context.Context) (*FirewallInfo, error) {
	return nil, nil
}
func (*concurrentHealthConnector) Connect(context.Context) error { return nil }
func (*concurrentHealthConnector) Disconnect() error             { return nil }
func (*concurrentHealthConnector) Poll(context.Context) ([]FirewallEvent, error) {
	return []FirewallEvent{{
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
		Action:    "allow",
		Protocol:  "tcp",
		SrcIP:     "192.0.2.10",
		DstIP:     "198.51.100.5",
		DstPort:   443,
		Rule:      "synthetic-health-race",
	}}, nil
}
func (*concurrentHealthConnector) Health() ConnectorHealth {
	return ConnectorHealth{Connected: true}
}
func (*concurrentHealthConnector) AcknowledgeEvents([]FirewallEvent) {}

func TestManagerHealthConcurrentWithSinkErrorUpdates(t *testing.T) {
	const (
		pollCycles   = 128
		healthCycles = pollCycles * 4
	)

	var sinkCalls atomic.Uint64
	mgr := NewManager(func([]models.Event) error {
		call := sinkCalls.Add(1)
		runtime.Gosched()
		if call%2 == 1 {
			return fmt.Errorf("synthetic persistence failure")
		}
		return nil
	})
	conn := &concurrentHealthConnector{}
	mgr.Register(ConnectorConfig{Name: conn.Name(), Type: "test"}, conn)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for range pollCycles {
			mgr.doPoll(conn.Name(), conn)
			runtime.Gosched()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range healthCycles {
			health, err := mgr.Health(conn.Name())
			if err != nil {
				errs <- err
				return
			}
			if health.LastError != "" && !strings.Contains(health.LastError, "synthetic persistence failure") {
				errs <- fmt.Errorf("unexpected health error: %q", health.LastError)
				return
			}
			runtime.Gosched()
		}
	}()

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if got := sinkCalls.Load(); got != pollCycles {
		t.Fatalf("sink calls = %d, want %d", got, pollCycles)
	}
	// The final (even-numbered) call succeeds, so the manager-level error must
	// be cleared after all concurrent reads have completed.
	health, err := mgr.Health(conn.Name())
	if err != nil {
		t.Fatal(err)
	}
	if health.LastError != "" {
		t.Fatalf("final successful poll did not clear sink error: %q", health.LastError)
	}
}
