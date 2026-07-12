package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// Version is the sensor version reported to Core at registration. main() overrides
// it with the linker-stamped buildVersion; the "dev" default marks a source build.
// (Previously a "0.1.0-dev" string literal was hardcoded in Register, so every
// released sensor mis-reported its version to Core regardless of the PE stamp.)
var Version = "dev"

// CoreClient communicates with the Vedetta Core API.
type CoreClient struct {
	BaseURL    string
	SensorID   string
	TokenPath  string
	tokenMu    sync.RWMutex
	authToken  string
	httpClient *http.Client
	// EnrollCode is an optional one-time enrollment code (from `--enroll-code` /
	// VEDETTA_ENROLL_CODE). Core requires it to register a NEW sensor once admin
	// auth is configured; it is sent only on the registration request.
	EnrollCode string
}

// SensorRegistration is the payload sent when the sensor first connects.
type SensorRegistration struct {
	SensorID   string                     `json:"sensor_id"`
	Hostname   string                     `json:"hostname"`
	OS         string                     `json:"os"`
	Arch       string                     `json:"arch"`
	CIDR       string                     `json:"cidr"`
	Version    string                     `json:"version"`
	IsPrimary  bool                       `json:"is_primary"`
	Interfaces []netinfo.NetworkInterface `json:"interfaces"`
}

// DeviceReport is what the sensor pushes after each scan.
type DeviceReport struct {
	SensorID string                   `json:"sensor_id"`
	CIDR     string                   `json:"cidr"`
	Segment  string                   `json:"segment"`
	ScanTime time.Time                `json:"scan_time"`
	Duration string                   `json:"duration"`
	Hosts    []netscan.DiscoveredHost `json:"hosts"`
}

// ScanRequest represents a queued scan from Core.
type ScanRequest struct {
	CIDR        string    `json:"cidr"`
	Segment     string    `json:"segment"`
	ScanPorts   bool      `json:"scan_ports"`
	RequestedAt time.Time `json:"requested_at"`
}

// ScanTarget represents a named scan target from Core.
type ScanTarget struct {
	TargetID     string     `json:"target_id"`
	Name         string     `json:"name"`
	CIDR         string     `json:"cidr"`
	Segment      string     `json:"segment"`
	ScanPorts    bool       `json:"scan_ports"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastScan     *time.Time `json:"last_scan,omitempty"`
	DNSCapture   bool       `json:"dns_capture"`
	DNSInterface string     `json:"dns_interface,omitempty"`
}

// WorkResponse is the response from /sensor/work endpoint.
type WorkResponse struct {
	ScanQueue []ScanRequest `json:"scan_queue"`
	Targets   []ScanTarget  `json:"targets"`
}

type sensorRegistrationResponse struct {
	Status       string `json:"status"`
	SensorID     string `json:"sensor_id"`
	AuthToken    string `json:"auth_token,omitempty"`
	TokenID      string `json:"token_id,omitempty"`
	TokenWarning string `json:"token_warning,omitempty"`
}

// New creates a CoreClient pointed at the given API base URL.
func New(baseURL string) (*CoreClient, error) {
	hostname, _ := os.Hostname()
	sensorID := fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)

	tokenPath, err := DefaultTokenPath()
	if err != nil {
		return nil, err
	}
	authToken, err := loadToken(tokenPath)
	if err != nil {
		return nil, err
	}

	return &CoreClient{
		BaseURL:   baseURL,
		SensorID:  sensorID,
		TokenPath: tokenPath,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// TokenConfigured reports whether the client has a persisted sensor token available.
func (c *CoreClient) TokenConfigured() bool {
	return c.authTokenSnapshot() != ""
}

// Register announces this sensor to the Core API and persists the one-time bootstrap token.
func (c *CoreClient) Register(ctx context.Context, cidr string, primary bool, interfaces []netinfo.NetworkInterface) error {
	hostname, _ := os.Hostname()
	reg := SensorRegistration{
		SensorID:   c.SensorID,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CIDR:       cidr,
		Version:    Version,
		IsPrimary:  primary,
		Interfaces: interfaces,
	}

	var resp sensorRegistrationResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sensor/register", reg, &resp, true); err != nil {
		return err
	}

	if resp.AuthToken != "" {
		if err := c.persistToken(resp.AuthToken); err != nil {
			return err
		}
	}

	if !c.TokenConfigured() {
		return fmt.Errorf("sensor registration did not return a usable auth token")
	}

	return nil
}

// PushDevices sends discovered hosts to Core for storage.
func (c *CoreClient) PushDevices(ctx context.Context, result *netscan.ScanResult, cidr string, segment ...string) error {
	seg := "default"
	if len(segment) > 0 {
		seg = segment[0]
	}
	report := DeviceReport{
		SensorID: c.SensorID,
		CIDR:     cidr,
		Segment:  seg,
		ScanTime: result.ScanTime,
		Duration: result.Duration.String(),
		Hosts:    result.Hosts,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/sensor/devices", report, nil, false)
}

// FetchWork retrieves pending scan requests and enabled targets from Core.
func (c *CoreClient) FetchWork(ctx context.Context) (*WorkResponse, error) {
	var work WorkResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/sensor/work", nil, &work, false); err != nil {
		return nil, err
	}
	return &work, nil
}

// Heartbeat reports that the sensor process can reach Core without draining the
// scan-work queue. Capture health remains based on successfully persisted event
// batches; this endpoint is only a process-reachability signal.
func (c *CoreClient) Heartbeat(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/sensor/heartbeat", nil, nil, false)
}

// PushDNS sends captured DNS queries to Core for ingestion. Callers that must flush
// during shutdown pass a non-cancelled context so the final drain still completes.
func (c *CoreClient) PushDNS(ctx context.Context, payload any) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/sensor/dns", payload, nil, false)
}

func (c *CoreClient) doJSON(ctx context.Context, method, path string, payload any, response any, allowBootstrap bool) error {
	req, err := c.newJSONRequest(ctx, method, path, payload, allowBootstrap)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if message := strings.TrimSpace(string(body)); message != "" {
			return fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, message)
		}
		return fmt.Errorf("%s %s returned %d", method, path, resp.StatusCode)
	}

	if response == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func (c *CoreClient) newJSONRequest(ctx context.Context, method, path string, payload any, allowBootstrap bool) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if path == "/api/v1/sensor/register" && strings.TrimSpace(c.EnrollCode) != "" {
		req.Header.Set("X-Vedetta-Enrollment-Code", strings.TrimSpace(c.EnrollCode))
	}

	if err := c.authorizeRequest(req, allowBootstrap); err != nil {
		return nil, err
	}

	return req, nil
}

func (c *CoreClient) authorizeRequest(req *http.Request, allowBootstrap bool) error {
	req.Header.Set("X-Sensor-ID", c.SensorID)

	// Capture one synchronized value for the whole request. Registration may
	// rotate/persist the token while capture delivery is already running.
	token := c.authTokenSnapshot()
	if token == "" {
		if allowBootstrap {
			return nil
		}
		return fmt.Errorf("sensor auth token not configured")
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (c *CoreClient) authTokenSnapshot() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return strings.TrimSpace(c.authToken)
}

func (c *CoreClient) persistToken(rawToken string) error {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return fmt.Errorf("sensor auth token is empty")
	}

	dir := filepath.Dir(c.TokenPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create sensor token directory: %w", err)
	}
	if err := securePath(dir, true); err != nil {
		return fmt.Errorf("secure sensor token directory: %w", err)
	}
	if err := os.WriteFile(c.TokenPath, []byte(token), 0o600); err != nil {
		return fmt.Errorf("write sensor token file: %w", err)
	}
	if err := securePath(c.TokenPath, false); err != nil {
		return fmt.Errorf("secure sensor token permissions: %w", err)
	}

	c.tokenMu.Lock()
	c.authToken = token
	c.tokenMu.Unlock()
	return nil
}

func DefaultTokenPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("VEDETTA_SENSOR_TOKEN_FILE")); override != "" {
		return override, nil
	}

	if runtime.GOOS == "windows" {
		// The sensor runs as a LocalSystem service, whose %USERPROFILE% is the odd
		// C:\Windows\System32\config\systemprofile; machine service state belongs in
		// %ProgramData%. The installer additionally locks the ACL down (spec 006 W6).
		base := strings.TrimSpace(os.Getenv("ProgramData"))
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Vedetta", "sensor-token"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for sensor token: %w", err)
	}

	return filepath.Join(homeDir, ".vedetta", "sensor-token"), nil
}

func loadToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat sensor token file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("sensor token path %s is a directory", path)
	}
	if hasInsecurePerms(info.Mode()) {
		if err := securePath(path, false); err != nil {
			return "", fmt.Errorf("secure sensor token permissions: %w", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read sensor token file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}
