package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// CoreClient communicates with the Vedetta Core API.
type CoreClient struct {
	BaseURL    string
	SensorID   string
	TokenPath  string
	authToken  string
	httpClient *http.Client
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

	tokenPath, err := defaultTokenPath()
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
	return strings.TrimSpace(c.authToken) != ""
}

// Register announces this sensor to the Core API and persists the one-time bootstrap token.
func (c *CoreClient) Register(cidr string, primary bool, interfaces []netinfo.NetworkInterface) error {
	hostname, _ := os.Hostname()
	reg := SensorRegistration{
		SensorID:   c.SensorID,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CIDR:       cidr,
		Version:    "0.1.0-dev",
		IsPrimary:  primary,
		Interfaces: interfaces,
	}

	var resp sensorRegistrationResponse
	if err := c.doJSON(http.MethodPost, "/api/v1/sensor/register", reg, &resp, true); err != nil {
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
func (c *CoreClient) PushDevices(result *netscan.ScanResult, cidr string, segment ...string) error {
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
	return c.doJSON(http.MethodPost, "/api/v1/sensor/devices", report, nil, false)
}

// FetchWork retrieves pending scan requests and enabled targets from Core.
func (c *CoreClient) FetchWork() (*WorkResponse, error) {
	var work WorkResponse
	if err := c.doJSON(http.MethodGet, "/api/v1/sensor/work", nil, &work, false); err != nil {
		return nil, err
	}
	return &work, nil
}

// PushDNS sends captured DNS queries to Core for ingestion.
func (c *CoreClient) PushDNS(payload any) error {
	return c.doJSON(http.MethodPost, "/api/v1/sensor/dns", payload, nil, false)
}

func (c *CoreClient) doJSON(method, path string, payload any, response any, allowBootstrap bool) error {
	req, err := c.newJSONRequest(method, path, payload, allowBootstrap)
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

func (c *CoreClient) newJSONRequest(method, path string, payload any, allowBootstrap bool) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if err := c.authorizeRequest(req, allowBootstrap); err != nil {
		return nil, err
	}

	return req, nil
}

func (c *CoreClient) authorizeRequest(req *http.Request, allowBootstrap bool) error {
	req.Header.Set("X-Sensor-ID", c.SensorID)

	if !c.TokenConfigured() {
		if allowBootstrap {
			return nil
		}
		return fmt.Errorf("sensor auth token not configured")
	}

	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.authToken))
	return nil
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
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure sensor token directory: %w", err)
	}
	if err := os.WriteFile(c.TokenPath, []byte(token), 0o600); err != nil {
		return fmt.Errorf("write sensor token file: %w", err)
	}
	if err := os.Chmod(c.TokenPath, 0o600); err != nil {
		return fmt.Errorf("secure sensor token permissions: %w", err)
	}

	c.authToken = token
	return nil
}

func defaultTokenPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("VEDETTA_SENSOR_TOKEN_FILE")); override != "" {
		return override, nil
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
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("secure sensor token permissions: %w", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read sensor token file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}
