package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/iotsecurity"
)

func TestPushSecurityAcknowledgmentAndAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, response         string
		status                 int
		wantError, unsupported bool
	}{
		{"accepted", `{"accepted":1,"duplicates":0,"failed":0}`, 200, false, false},
		{"replay", `{"accepted":0,"duplicates":1,"failed":0}`, 200, false, false},
		{"silent loss", `{"accepted":0,"duplicates":0,"failed":0}`, 200, true, false},
		{"partial", `{"accepted":0,"duplicates":0,"failed":1}`, 200, true, false},
		{"old Core", `{}`, 404, true, true},
		{"revoked", `{}`, 403, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := iotsecurity.Observation{ObservationID: "observation-example", Timestamp: time.Now().UTC(), SubjectIP: "192.0.2.10", Kind: "coverage"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/sensor/security" || r.Method != "POST" {
					t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("X-Sensor-ID") != "sensor-example" {
					t.Errorf("sensor authentication not propagated")
				}
				var request struct {
					SensorID     string                    `json:"sensor_id"`
					Observations []iotsecurity.Observation `json:"observations"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request.SensorID != "sensor-example" || len(request.Observations) != 1 || request.Observations[0].ObservationID != observation.ObservationID {
					t.Errorf("observation identity changed: %+v", request)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			core := &CoreClient{BaseURL: server.URL, SensorID: "sensor-example", authToken: "synthetic-token", httpClient: server.Client()}
			err := core.PushSecurity(context.Background(), []iotsecurity.Observation{observation})
			if (err != nil) != tc.wantError {
				t.Fatalf("PushSecurity error=%v wantError=%v", err, tc.wantError)
			}
			if errors.Is(err, ErrSecurityUnsupported) != tc.unsupported {
				t.Fatalf("unsupported classification: %v", err)
			}
			if tc.status == 403 && !IsAuthorizationError(err) {
				t.Fatalf("authorization status lost: %v", err)
			}
		})
	}
}

func TestPushSecurityRejectsOversizedBatchBeforeNetwork(t *testing.T) {
	core := &CoreClient{}
	if err := core.PushSecurity(context.Background(), make([]iotsecurity.Observation, 33)); err == nil {
		t.Fatal("oversized batch accepted")
	}
}
