package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// handleCreateToken creates a new API token and returns it once (never again).
// POST /api/v1/auth/tokens
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	// Admin-only once an admin exists. During bootstrap (no active admin) minting is
	// keyed on active-admin, not total token count, so an auto-issued sensor token
	// can't lock setup out.
	hasAdmin, _ := s.DB.HasActiveAdminToken()
	if hasAdmin {
		scope := auth.GetScopeFromContext(r)
		if scope != auth.ScopeAdmin {
			http.Error(w, "only admins can create tokens", http.StatusForbidden)
			return
		}
	}

	var body struct {
		Scope    string `json:"scope"` // sensor | admin | ingest | read
		SensorID string `json:"sensor_id,omitempty"`
		Label    string `json:"label,omitempty"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	scope := auth.TokenScope(body.Scope)
	if scope != auth.ScopeSensor && scope != auth.ScopeAdmin && scope != auth.ScopeIngest && scope != auth.ScopeRead {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope must be 'sensor', 'admin', 'ingest', or 'read'"})
		return
	}

	// Bootstrap hardening (GHSA-6cmx): before any admin exists, this endpoint is
	// unauthenticated on the LAN. Previously any client could mint ANY scope,
	// including a permanent admin. Now, during bootstrap:
	//   (a) only the first admin token may be created — no other scope; and
	//   (b) the client must present the server-held single-use setup code.
	// Env-provisioned ingest/read tokens do NOT come through here (they use
	// store.EnsureTokenFromRaw), and sensor tokens are minted by handleSensorRegister,
	// so this does not break those paths.
	if !hasAdmin {
		if scope != auth.ScopeAdmin {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "only the first admin token may be created during setup"})
			return
		}
		// Atomically verify AND consume the single-use setup code under one lock, so a
		// concurrent replay of the correct code cannot mint two admins (GHSA-6cmx).
		if !s.consumeSetupCode(r.Header.Get("X-Vedetta-Setup-Code")) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "valid X-Vedetta-Setup-Code required to create the first admin token"})
			return
		}
	}

	// Generate the token
	rawToken, token, err := auth.GenerateToken(scope, body.SensorID, body.Label)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to generate token"})
		return
	}

	// Store the hashed token
	if err := s.DB.CreateToken(token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to store token"})
		return
	}

	// The setup code was already consumed atomically above (consumeSetupCode), so
	// nothing to clear here — a concurrent replay could never reach this point.

	log.Printf("Token created: %s (scope=%s, label=%s)", token.TokenID, scope, body.Label)
	s.logInfo("auth", fmt.Sprintf("Token created: %s (scope=%s)", token.TokenID, scope))

	// Return the raw token (only displayed once)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id":   token.TokenID,
		"token":      rawToken, // The actual secret — never returned again
		"scope":      token.Scope,
		"label":      token.Label,
		"created_at": token.CreatedAt,
		"warning":    "save this token now — it will not be displayed again",
	})
}

// handleListTokens returns all tokens (without raw values).
// GET /api/v1/auth/tokens
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	// Admin-only once an admin exists (see handleCreateToken).
	hasAdmin, _ := s.DB.HasActiveAdminToken()
	if hasAdmin {
		scope := auth.GetScopeFromContext(r)
		if scope != auth.ScopeAdmin {
			http.Error(w, "only admins can list tokens", http.StatusForbidden)
			return
		}
	}

	tokens, err := s.DB.ListTokens()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to list tokens"})
		return
	}

	// Don't expose token_hash in the response
	response := make([]map[string]any, 0, len(tokens))
	for _, token := range tokens {
		response = append(response, map[string]any{
			"token_id":   token.TokenID,
			"scope":      token.Scope,
			"sensor_id":  token.SensorID,
			"label":      token.Label,
			"created_at": token.CreatedAt,
			"last_used":  token.LastUsed,
			"revoked":    token.Revoked,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

// handleRevokeToken revokes a token by ID.
// DELETE /api/v1/auth/tokens/{tokenID}
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	// Revoke is gated by RequireStrictAdmin in the router, so this handler only ever
	// runs with a valid admin token — there is no bootstrap path here anymore, which
	// removes the LAN-peer machine-token-revocation DoS (GHSA-6cmx). The
	// last-active-admin guard below still applies.

	tokenID := chi.URLParam(r, "tokenID")
	if tokenID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "token_id required"})
		return
	}

	// Never let the last active admin be revoked — that would strip the ability to
	// manage the deployment with no recovery path (beta-gate B1a lockout).
	if target, err := s.DB.GetTokenByID(tokenID); err == nil && target.Scope == auth.ScopeAdmin && !target.Revoked {
		activeAdmins, err := s.DB.CountActiveAdminTokens()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check admin tokens"})
			return
		}
		if activeAdmins <= 1 {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "cannot revoke the last active admin token — create another admin token first"})
			return
		}
	}

	if err := s.DB.RevokeToken(tokenID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
		return
	}

	log.Printf("Token revoked: %s", tokenID)
	s.logInfo("auth", fmt.Sprintf("Token revoked: %s", tokenID))

	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "token_id": tokenID})
}

// handleSetupStatus returns the overall setup state for the onboarding wizard.
// GET /api/v1/auth/setup-status
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "database not available"})
		return
	}

	tokenCount, _ := s.DB.CountTokens()
	deviceCount, _ := s.DB.CountDevices()
	eventCount, _ := s.DB.CountEvents()
	sensors, _ := s.DB.ListSensors()
	sensorCount := len(sensors)

	// Determine which setup steps are complete
	steps := map[string]bool{
		"core_running":     true,
		"sensor_connected": sensorCount > 0,
		"devices_found":    deviceCount > 0,
		"events_flowing":   eventCount > 0,
		"auth_configured":  tokenCount > 0,
	}

	allComplete := steps["sensor_connected"] && steps["devices_found"] && steps["events_flowing"]

	writeJSON(w, http.StatusOK, map[string]any{
		"setup_complete": allComplete,
		"steps":          steps,
		"counts": map[string]int{
			"sensors": sensorCount,
			"devices": deviceCount,
			"events":  eventCount,
			"tokens":  tokenCount,
		},
		// GHSA-6cmx: tells the wizard to prompt for the first-admin setup code. Only
		// the boolean is exposed here — the code value is NEVER returned by any API.
		"needs_setup_code": s.needsSetupCode(),
	})
}
