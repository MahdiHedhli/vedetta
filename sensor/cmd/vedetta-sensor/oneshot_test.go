package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

func newOneShotTestRun(t *testing.T, baseURL string, cfg scanDeliveryConfig) *sensorRun {
	t.Helper()
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-one-shot-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	core, err := client.New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-one-shot"
	run := &sensorRun{
		core: core, coreURL: baseURL, cidrFlag: "192.0.2.0/24",
		dnsEnabled: false, passiveEnabled: false, arpEnabled: false,
		oneShotDelivery: &cfg,
	}
	run.scanFn = func(ctx context.Context, _ *netscan.Scanner, core *client.CoreClient, cidr string, _ bool, delivery scanDeliveryConfig) error {
		observed := time.Now().UTC()
		return deliverScanResultWithConfig(ctx, core, &netscan.ScanResult{
			ScanTime: observed,
			Hosts: []netscan.DiscoveredHost{{
				IPAddress: "192.0.2.10", Status: "up", DiscoverySource: "synthetic", ObservedAt: observed,
			}},
		}, cidr, "default", delivery)
	}
	return run
}

func oneShotTestConfig() scanDeliveryConfig {
	return scanDeliveryConfig{
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  time.Millisecond,
		AttemptTimeout: 50 * time.Millisecond,
		MaxAttempts:    3,
	}
}

func writeRegistrationOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "registered"})
}

func TestRunOneShotFiniteDeliveryOutcomes(t *testing.T) {
	tests := []struct {
		name         string
		device       func(http.ResponseWriter, *http.Request)
		wantErr      bool
		wantAttempts int32
		wantAuth     bool
	}{
		{
			name: "success",
			device: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "failed": 0})
			},
			wantAttempts: 1,
		},
		{
			name: "permanent 207",
			device: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusMultiStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 0, "failed": 1})
			},
			wantErr: true, wantAttempts: 3,
		},
		{
			name: "unauthorized",
			device: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "revoked", http.StatusUnauthorized)
			},
			wantErr: true, wantAttempts: 1, wantAuth: true,
		},
		{
			name: "blackhole",
			device: func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(200 * time.Millisecond):
				}
			},
			wantErr: true, wantAttempts: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/sensor/register":
					writeRegistrationOK(w)
				case "/api/v1/sensor/devices":
					attempts.Add(1)
					tt.device(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			run := newOneShotTestRun(t, server.URL, oneShotTestConfig())
			err := run.runOneShot(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("runOneShot error = %v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantAuth && !client.IsAuthorizationError(err) {
				t.Fatalf("authorization error classification lost: %v", err)
			}
			if got := attempts.Load(); got != tt.wantAttempts {
				t.Fatalf("device attempts = %d, want %d", got, tt.wantAttempts)
			}
		})
	}
}

func TestRunOneShotSignalCancellationInterruptsDelivery(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/register":
			writeRegistrationOK(w)
		case "/api/v1/sensor/devices":
			close(started)
			select {
			case <-r.Context().Done():
			case <-time.After(200 * time.Millisecond):
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := oneShotTestConfig()
	cfg.AttemptTimeout = time.Hour
	run := newOneShotTestRun(t, server.URL, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run.runOneShot(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("one-shot delivery never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("one-shot ignored signal cancellation")
	}
}
