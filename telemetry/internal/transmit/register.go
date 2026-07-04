package transmit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
	"github.com/vedetta-network/vedetta/telemetry/internal/idgen"
)

// Reporter is the persisted registration identity (reporter.json, 0600).
type Reporter struct {
	Version           int    `json:"version"`
	InstallID         string `json:"install_id"`
	ReporterID        string `json:"reporter_id"`
	ReporterSecret    string `json:"reporter_secret"`
	MinUploadInterval int    `json:"min_upload_interval_seconds"`
	MaxBatchItems     int    `json:"max_batch_items"`
}

const (
	reporterFile = "reporter.json"
	saltFile     = "salt"
)

// capabilities advertised at registration (contract §2).
var capabilities = []string{
	"known_bad_domain_hit",
	"high_confidence_domain_candidate",
	"behavior_summary",
}

type registerRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	InstallID      string   `json:"install_id"`
	VedettaVersion string   `json:"vedetta_version"`
	Capabilities   []string `json:"capabilities"`
}

type registerResponse struct {
	ReporterID     string `json:"reporter_id"`
	ReporterSecret string `json:"reporter_secret"`
	Config         struct {
		MinUploadIntervalSeconds int `json:"min_upload_interval_seconds"`
		MaxBatchItems            int `json:"max_batch_items"`
	} `json:"config"`
}

// LoadReporter reads the persisted reporter identity. Missing/corrupt → not found.
func LoadReporter(stateDir string) (Reporter, bool, error) {
	var r Reporter
	found, err := config.ReadJSONFile(filepath.Join(stateDir, reporterFile), &r)
	if err != nil {
		return Reporter{}, false, err
	}
	if !found || r.ReporterID == "" || r.ReporterSecret == "" {
		return Reporter{}, false, nil
	}
	if err := config.CheckVersion(reporterFile, r.Version); err != nil {
		return Reporter{}, false, nil
	}
	return r, true, nil
}

// EnsureReporter returns a valid reporter, registering (and persisting) one if
// none exists. If the stored identity is lost/corrupt it re-registers with a
// fresh install UUID.
func EnsureReporter(ctx context.Context, stateDir, threatNetworkURL, vedettaVersion string, httpc *http.Client) (Reporter, error) {
	if r, ok, err := LoadReporter(stateDir); err != nil {
		return Reporter{}, err
	} else if ok {
		return r, nil
	}

	installID := idgen.UUIDv4()
	reqBody, _ := json.Marshal(registerRequest{
		SchemaVersion:  1,
		InstallID:      installID,
		VedettaVersion: vedettaVersion,
		Capabilities:   capabilities,
	})

	url := strings.TrimRight(threatNetworkURL, "/") + "/api/v1/reporters/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return Reporter{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return Reporter{}, fmt.Errorf("reporter registration: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Reporter{}, fmt.Errorf("reporter registration status %s", resp.Status)
	}
	var rr registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return Reporter{}, fmt.Errorf("decode registration response: %w", err)
	}
	if rr.ReporterID == "" || rr.ReporterSecret == "" {
		return Reporter{}, fmt.Errorf("registration response missing reporter_id/secret")
	}

	r := Reporter{
		Version:           config.StateFileVersion,
		InstallID:         installID,
		ReporterID:        rr.ReporterID,
		ReporterSecret:    rr.ReporterSecret,
		MinUploadInterval: rr.Config.MinUploadIntervalSeconds,
		MaxBatchItems:     rr.Config.MaxBatchItems,
	}
	// Persist with 0600 (contains the reporter secret).
	if err := config.WriteJSONFile(filepath.Join(stateDir, reporterFile), r, 0o600); err != nil {
		return Reporter{}, err
	}
	return r, nil
}

// EnsureSalt returns the telemetry-local HMAC salt, generating and persisting a
// fresh 32-byte salt (0600) on first use. This salt is deliberately distinct
// from Core's per-install salt so hashes can never be joined.
func EnsureSalt(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, saltFile)
	// Salt is raw bytes; read directly.
	if b, err := readSaltFile(path); err == nil && len(b) >= 16 {
		return b, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := config.WriteSecretBytes(path, salt); err != nil {
		return nil, err
	}
	return salt, nil
}
