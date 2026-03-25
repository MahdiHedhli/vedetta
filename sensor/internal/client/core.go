package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// CoreClient communicates with the Vedetta Core API.
type CoreClient struct {
	BaseURL    string
	SensorID   string
	httpClient *http.Client
}

// SensorRegistration is the payload sent when the sensor first connects.
type SensorRegistration struct {
	SensorID string `json:"sensor_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	CIDR     string `json:"cidr"`
	Version  string `json:"version"`
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

// New creates a CoreClient pointed at the given API base URL.
func New(baseURL string) *CoreClient {
	hostname, _ := os.Hostname()
	sensorID := fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)

	return &CoreClient{
		BaseURL:  baseURL,
		SensorID: sensorID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Register announces this sensor to the Core API.
func (c *CoreClient) Register(cidr string) error {
	hostname, _ := os.Hostname()
	reg := SensorRegistration{
		SensorID: c.SensorID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CIDR:     cidr,
		Version:  "0.1.0-dev",
	}
	return c.post("/api/v1/sensor/register", reg)
}

// PushDevices sends discovered hosts to Core for storage.
func (c *CoreClient) PushDevices(result *netscan.ScanResult, cidr string) error {
	report := DeviceReport{
		SensorID: c.SensorID,
		CIDR:     cidr,
		Segment:  "default",
		ScanTime: result.ScanTime,
		Duration: result.Duration.String(),
		Hosts:    result.Hosts,
	}
	return c.post("/api/v1/sensor/devices", report)
}

func (c *CoreClient) post(path string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := c.BaseURL + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-ID", c.SensorID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST %s returned %d", path, resp.StatusCode)
	}

	return nil
}
