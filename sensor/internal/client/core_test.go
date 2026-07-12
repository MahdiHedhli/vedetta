package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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

	if reloaded.authToken != "bootstrap-token" {
		t.Fatalf("expected reloaded token, got %q", reloaded.authToken)
	}
	if err := reloaded.Register(context.Background(), "192.168.1.0/24", true, nil); err != nil {
		t.Fatalf("re-register sensor: %v", err)
	}
}
