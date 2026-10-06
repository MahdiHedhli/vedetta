package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
)

type recordingSecurityPusher struct {
	calls  [][]string
	errors []error
	block  bool
}

func (p *recordingSecurityPusher) PushSecurity(ctx context.Context, observations []iotsecurity.Observation) error {
	ids := make([]string, len(observations))
	for i := range observations {
		ids[i] = observations[i].ObservationID
	}
	p.calls = append(p.calls, ids)
	if p.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(p.errors) > 0 {
		err := p.errors[0]
		p.errors = p.errors[1:]
		return err
	}
	return nil
}

func testSecurityPushConfig() securityPushConfig {
	return securityPushConfig{FlushInterval: time.Millisecond, AttemptTimeout: 10 * time.Millisecond, RetryInterval: time.Millisecond, MaxRetryInterval: 2 * time.Millisecond}
}

func TestSecurityDeliveryRetriesExactObservationIdentities(t *testing.T) {
	queue := make(chan iotsecurity.Observation, 2)
	queue <- iotsecurity.Observation{ObservationID: "first"}
	queue <- iotsecurity.Observation{ObservationID: "second"}
	close(queue)
	pusher := &recordingSecurityPusher{errors: []error{errors.New("response lost after persistence")}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pushSecurityObservations(ctx, pusher, queue, testSecurityPushConfig())
	if len(pusher.calls) != 2 || !reflect.DeepEqual(pusher.calls[0], []string{"first", "second"}) || !reflect.DeepEqual(pusher.calls[0], pusher.calls[1]) {
		t.Fatalf("retry changed batch identities: %v", pusher.calls)
	}
}

func TestSecurityDeliveryStopsOnUnsupportedCore(t *testing.T) {
	queue := make(chan iotsecurity.Observation, 1)
	queue <- iotsecurity.Observation{ObservationID: "first"}
	close(queue)
	pusher := &recordingSecurityPusher{errors: []error{client.ErrSecurityUnsupported}}
	pushSecurityObservations(context.Background(), pusher, queue, testSecurityPushConfig())
	if len(pusher.calls) != 1 {
		t.Fatalf("retried unsupported endpoint: %v", pusher.calls)
	}
}

func TestSecurityDeliveryStopsOnRejectedCredential(t *testing.T) {
	queue := make(chan iotsecurity.Observation, 1)
	queue <- iotsecurity.Observation{ObservationID: "first"}
	close(queue)
	pusher := &recordingSecurityPusher{errors: []error{&client.HTTPStatusError{StatusCode: 403}}}
	cfg := testSecurityPushConfig()
	rejections := 0
	cfg.OnAuthorizationError = func(error) { rejections++ }
	pushSecurityObservations(context.Background(), pusher, queue, cfg)
	if len(pusher.calls) != 1 || rejections != 1 {
		t.Fatalf("terminal rejection retried: calls=%d callbacks=%d", len(pusher.calls), rejections)
	}
}

func TestSecurityDeliveryCancellationWithFullPendingBatch(t *testing.T) {
	queue := make(chan iotsecurity.Observation, 16)
	for i := 0; i < 16; i++ {
		queue <- iotsecurity.Observation{ObservationID: "synthetic"}
	}
	close(queue)
	pusher := &recordingSecurityPusher{block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	pushSecurityObservations(ctx, pusher, queue, testSecurityPushConfig())
	if time.Since(started) > time.Second {
		t.Fatal("delivery ignored cancellation")
	}
	if len(pusher.calls) == 0 {
		t.Fatal("test never entered blocked delivery")
	}
}

func TestSecurityQueueReportsLossAndDisablesEnqueue(t *testing.T) {
	runtime := &securityRuntime{queue: make(chan iotsecurity.Observation, securityQueueLimit)}
	for i := 0; i <= securityQueueLimit; i++ {
		runtime.enqueue(iotsecurity.Observation{})
	}
	if len(runtime.queue) != securityQueueLimit || runtime.dropped.Load() != 1 {
		t.Fatalf("queue not bounded: queued=%d dropped=%d", len(runtime.queue), runtime.dropped.Load())
	}
	runtime.disabled.Store(true)
	runtime.enqueue(iotsecurity.Observation{})
	if runtime.dropped.Load() != 1 {
		t.Fatal("disabled delivery still queues observations")
	}
}

func TestSecurityHostIdentityNeverUsesScannedTarget(t *testing.T) {
	interfaces := []netinfo.NetworkInterface{{Name: "eth-example", IsUp: true, IPs: []string{"192.0.2.10"}}}
	if got := securitySubjectIP(interfaces, "auto", "198.51.100.0/24"); got != "192.0.2.10" {
		t.Fatalf("local audit attributed to %q", got)
	}
	if got := securitySubjectIP(nil, "auto", "198.51.100.4/32"); got != "" {
		t.Fatalf("invented subject %q", got)
	}
}

func TestLocalSecurityAuditRejectsChangedDHCPAddress(t *testing.T) {
	reads := 0
	lookup := func() string {
		reads++
		if reads == 1 {
			return "192.0.2.10"
		}
		return "192.0.2.11"
	}
	if _, err := collectLocalSecurityAudit(t.TempDir(), lookup); err == nil {
		t.Fatal("audit was attributed using a stale local IP")
	}
	if _, err := collectLocalSecurityAudit(t.TempDir(), func() string { return "" }); err == nil {
		t.Fatal("audit accepted without local identity")
	}
}

func TestFilesystemAuditModeNeedsNoCoreOrScanner(t *testing.T) {
	var output bytes.Buffer
	if err := runSecurityAudit(context.Background(), t.TempDir(), "", false, "invalid-core", &output); err != nil {
		t.Fatal(err)
	}
	var observation iotsecurity.Observation
	if err := json.Unmarshal(output.Bytes(), &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Kind != "host_audit" || len(observation.Coverage) == 0 {
		t.Fatalf("missing audit coverage: %+v", observation)
	}
	if err := runSecurityAudit(context.Background(), t.TempDir(), "", true, "invalid-core", &output); err == nil {
		t.Fatal("audit submission accepted without a target identity")
	}
}
