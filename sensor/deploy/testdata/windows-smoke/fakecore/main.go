package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	freshEnrollmentCode = "smoke-fresh-code"
	sensorToken         = "smoke-token-v1"
)

type coreState struct {
	mu       sync.RWMutex
	token    string
	sensorID string
}

type registration struct {
	SensorID string `json:"sensor_id"`
}

func main() {
	addressFile := strings.TrimSpace(os.Getenv("VEDETTA_SMOKE_ADDRESS_FILE"))
	if addressFile == "" {
		fmt.Fprintln(os.Stderr, "VEDETTA_SMOKE_ADDRESS_FILE is required")
		os.Exit(2)
	}
	listenAddress := strings.TrimSpace(os.Getenv("VEDETTA_SMOKE_LISTEN"))
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}

	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	if err := os.WriteFile(addressFile, []byte(listener.Addr().String()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write address file: %v\n", err)
		os.Exit(1)
	}

	state := &coreState{}
	server := &http.Server{Handler: state.routes()}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func (s *coreState) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/sensor/register", s.register)
	mux.HandleFunc("/api/v1/sensor/auth-check", s.authCheck)
	mux.HandleFunc("/api/v1/sensor/work", s.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"scan_queue": []any{}, "targets": []any{}})
	}))
	for _, path := range []string{
		"/api/v1/sensor/devices",
		"/api/v1/sensor/dns",
		"/api/v1/sensor/heartbeat",
	} {
		mux.HandleFunc(path, s.authenticated(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	return mux
}

func (s *coreState) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body registration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.SensorID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid registration"})
		return
	}

	code := strings.TrimSpace(r.Header.Get("X-Vedetta-Enrollment-Code"))
	if code != "" {
		if code != freshEnrollmentCode {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment rejected"})
			return
		}
		s.mu.Lock()
		s.token = sensorToken
		s.sensorID = body.SensorID
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"status":     "registered",
			"sensor_id":  body.SensorID,
			"auth_token": sensorToken,
			"token_id":   "smoke-token-id",
		})
		return
	}

	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sensor authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "registered",
		"sensor_id": body.SensorID,
	})
}

func (s *coreState) authCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sensor authentication required"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *coreState) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sensor authentication required"})
			return
		}
		next(w, r)
	}
}

func (s *coreState) authorized(r *http.Request) bool {
	s.mu.RLock()
	token := s.token
	sensorID := s.sensorID
	s.mu.RUnlock()
	return token != "" && sensorID != "" &&
		r.Header.Get("Authorization") == "Bearer "+token &&
		r.Header.Get("X-Sensor-ID") == sensorID
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
