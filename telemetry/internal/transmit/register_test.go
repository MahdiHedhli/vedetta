package transmit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func regServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/reporters/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req registerRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.InstallID == "" || req.SchemaVersion != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"reporter_id":     "9a1c2b3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d",
			"reporter_secret": "c2VjcmV0LWJhc2U2NC1leGFtcGxlLW9ubHk=",
			"config":          map[string]any{"min_upload_interval_seconds": 900, "max_batch_items": 250},
		})
	}))
}

func TestEnsureReporterRegistersAndPersists(t *testing.T) {
	srv := regServer(t)
	defer srv.Close()
	dir := t.TempDir()

	r, err := EnsureReporter(context.Background(), dir, srv.URL, "0.1.0-dev", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if r.ReporterID == "" || r.ReporterSecret == "" {
		t.Fatal("missing reporter identity")
	}
	// Persisted file must be 0600.
	info, err := os.Stat(filepath.Join(dir, reporterFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("reporter.json perm = %v, want 0600", info.Mode().Perm())
	}

	// Second call reuses persisted identity (no new registration needed even if
	// server would reject).
	r2, err := EnsureReporter(context.Background(), dir, "http://127.0.0.1:1", "0.1.0-dev", srv.Client())
	if err != nil {
		t.Fatalf("reuse should not hit network: %v", err)
	}
	if r2.ReporterID != r.ReporterID {
		t.Errorf("reporter id changed on reuse")
	}
}

func TestEnsureReporterReregistersOnLostState(t *testing.T) {
	srv := regServer(t)
	defer srv.Close()
	dir := t.TempDir()

	r1, _ := EnsureReporter(context.Background(), dir, srv.URL, "v", srv.Client())
	// Corrupt the reporter file.
	os.WriteFile(filepath.Join(dir, reporterFile), []byte("{garbage"), 0o600)
	r2, err := EnsureReporter(context.Background(), dir, srv.URL, "v", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	// New install id (fresh registration); reporter id may match the stub's fixed value.
	if r2.InstallID == r1.InstallID {
		t.Errorf("expected a fresh install UUID after lost state")
	}
}

func TestEnsureSaltPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	s1, err := EnsureSalt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != 32 {
		t.Errorf("salt len = %d", len(s1))
	}
	info, _ := os.Stat(filepath.Join(dir, saltFile))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("salt perm = %v, want 0600", info.Mode().Perm())
	}
	s2, _ := EnsureSalt(dir)
	if string(s1) != string(s2) {
		t.Errorf("salt should be stable across calls")
	}
}
