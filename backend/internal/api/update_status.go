package api

import "net/http"

// handleUpdateStatus serves the read-only release-availability status the dashboard's update
// notifier renders. When no checker is wired (the notice is disabled) it reports
// enabled=false so the client simply shows nothing.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if s.UpdateChecker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.UpdateChecker.Status())
}
