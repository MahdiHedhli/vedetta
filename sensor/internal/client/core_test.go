package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoreClientRegisterPersistsAndReloadsToken(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "sensor-token")
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if r.URL.Path != "/api/v1/sensor/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Sensor-ID"); got != "sensor-test" {
			t.Fatalf("expected X-Sensor-ID header, got %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		switch requestCount {
		case 1:
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("expected first registration to be anonymous, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:    "registered",
				SensorID:  "sensor-test",
				AuthToken: "bootstrap-token",
				TokenID:   "token-1",
			})
		case 2:
			if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-token" {
				t.Fatalf("expected persisted bearer token on re-registration, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:   "registered",
				SensorID: "sensor-test",
			})
		default:
			t.Fatalf("unexpected extra registration request #%d", requestCount)
		}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-test"

	if err := core.Register(context.Background(), "192.168.1.0/24", true, nil); err != nil {
		t.Fatalf("register sensor: %v", err)
	}
	if !core.TokenConfigured() {
		t.Fatal("expected token to be configured after registration")
	}

	// Verify the persisted token is locked down. The check is platform-specific:
	// POSIX asserts 0600, Windows inspects the NTFS DACL (os.FileMode perms are
	// synthetic there — the old 0600 assert made the Windows CI job red at 0666).
	assertTokenSecured(t, core.TokenPath)

	data, err := os.ReadFile(core.TokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "bootstrap-token" {
		t.Fatalf("expected persisted bootstrap token, got %q", string(data))
	}

	reloaded, err := New(server.URL)
	if err != nil {
		t.Fatalf("reload core client: %v", err)
	}
	reloaded.SensorID = "sensor-test"

	if got := reloaded.authTokenSnapshot(); got != "bootstrap-token" {
		t.Fatalf("expected reloaded token, got %q", got)
	}
	if err := reloaded.Register(context.Background(), "192.168.1.0/24", true, nil); err != nil {
		t.Fatalf("re-register sensor: %v", err)
	}
}

func TestCoreClientConcurrentRegistrationAndAuthenticatedRequests(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "sensor-token")
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/register":
			n := registrations.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:    "registered",
				SensorID:  "sensor-race-test",
				AuthToken: fmt.Sprintf("rotated-token-%d", n),
			})
		case "/api/v1/sensor/dns":
			if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); !strings.HasPrefix(token, "rotated-token-") {
				http.Error(w, "missing complete token", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-race-test"
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
		t.Fatalf("initial registration: %v", err)
	}

	errors := make(chan error, 500)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
				errors <- fmt.Errorf("registration %d: %w", i, err)
			}
		}
	}()
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := core.PushDNS(context.Background(), map[string]any{"queries": []any{}}); err != nil {
					errors <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Errorf("concurrent client operation: %v", err)
	}
	if !core.TokenConfigured() {
		t.Fatal("rotated token was not retained")
	}
}

func TestCoreClientHeartbeatUsesBoundSensorAuthentication(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "sensor-token")
	if err := os.WriteFile(tokenPath, []byte("synthetic-heartbeat-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensor/heartbeat" {
			t.Errorf("unexpected heartbeat request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer synthetic-heartbeat-token" {
			t.Errorf("heartbeat authorization = %q", got)
		}
		if got := r.Header.Get("X-Sensor-ID"); got != "sensor-heartbeat-client" {
			t.Errorf("heartbeat sensor id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
		received <- struct{}{}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-heartbeat-client"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := core.Heartbeat(ctx); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("heartbeat request was not received")
	}
}
