package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// MachineCredentialState reports the compose-provisioned machine-credential
// configuration derived from the environment (issue #34): whether the collector
// ingest credential (VEDETTA_INGEST_TOKEN) and the telemetry read credential
// (VEDETTA_CORE_TOKEN) are set, and whether they COLLIDE. A collision matters
// because EnsureTokenFromRaw dedups by hash, so two identical values create only
// ONE scope — one of collector ingest or telemetry read would then 403. Shared
// by the startup collision warning (cmd/vedetta) and the /status health surface
// so operators see the same truth in logs and in the API.
func MachineCredentialState() (ingestConfigured, readConfigured, collision bool) {
	ingest := strings.TrimSpace(os.Getenv("VEDETTA_INGEST_TOKEN"))
	read := strings.TrimSpace(os.Getenv("VEDETTA_CORE_TOKEN"))
	ingestConfigured = ingest != ""
	readConfigured = read != ""
	collision = ingestConfigured && readConfigured && ingest == read
	return ingestConfigured, readConfigured, collision
}

// settingKeyTelemetryOptIn is the settings-store key that backs the telemetry
// opt-in toggle (issue #37). Kept in one place so the GET/PUT handlers and any
// future reader agree on it.
const settingKeyTelemetryOptIn = "telemetry_opt_in"

// envTelemetryOptIn returns the telemetry opt-in value implied by the
// VEDETTA_TELEMETRY_OPTIN environment variable. Telemetry is ON by default
// (opt-out): the effective value is true unless the env var is explicitly set to
// "false" (case-insensitive), matching docker-compose.yml and the telemetry
// daemon's own parsing.
func envTelemetryOptIn() bool {
	v := strings.TrimSpace(os.Getenv("VEDETTA_TELEMETRY_OPTIN"))
	if v == "" {
		return true
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	// Unparseable values keep the safe default (on/opt-out) rather than silently
	// disabling sharing.
	return true
}

// telemetryOptInState computes the effective telemetry opt-in and where it came
// from. Contract (issue #37): a persisted setting WINS over the env var; with no
// persisted setting the env var is used; the default effective value is true.
//
// opt_in and effective are the same boolean here (the effective opt-in); source
// records the provenance ("setting" when a persisted row decided it, otherwise
// "env").
func (s *Server) telemetryOptInState() (optIn bool, source string, effective bool) {
	if s.DB != nil {
		if raw, found, err := s.DB.GetSetting(settingKeyTelemetryOptIn); err == nil && found {
			if b, perr := strconv.ParseBool(strings.TrimSpace(raw)); perr == nil {
				return b, "setting", b
			}
			// A corrupt persisted value should not brick the endpoint; fall through
			// to env rather than returning an error.
		}
	}
	e := envTelemetryOptIn()
	return e, "env", e
}

// handleGetTelemetrySetting reports the effective telemetry opt-in.
// GET /api/v1/settings/telemetry (read scope, via RequireRead).
func (s *Server) handleGetTelemetrySetting(w http.ResponseWriter, r *http.Request) {
	optIn, source, effective := s.telemetryOptInState()
	writeJSON(w, http.StatusOK, map[string]any{
		"opt_in":    optIn,
		"source":    source,
		"effective": effective,
	})
}

// handlePutTelemetrySetting persists the telemetry opt-in.
// PUT /api/v1/settings/telemetry (admin, via RequireAdmin). Body: {"opt_in":bool}.
// Returns the resulting {opt_in, source, effective} — source is always "setting"
// after a successful persist.
func (s *Server) handlePutTelemetrySetting(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	var body struct {
		OptIn *bool `json:"opt_in"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&body); err != nil || body.OptIn == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "opt_in (boolean) required"})
		return
	}

	if err := s.DB.SetSetting(settingKeyTelemetryOptIn, strconv.FormatBool(*body.OptIn)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to persist setting"})
		return
	}

	optIn, source, effective := s.telemetryOptInState()
	writeJSON(w, http.StatusOK, map[string]any{
		"opt_in":    optIn,
		"source":    source,
		"effective": effective,
	})
}
