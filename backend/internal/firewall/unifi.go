package firewall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// UniFiConnector is a firewall connector for Ubiquiti UniFi Network Application.
// Supports both UDM/UDR (UniFi OS with proxy) and standalone controllers.
type UniFiConnector struct {
	cfg           ConnectorConfig
	client        *http.Client
	baseURL       string
	isUniFiOS     bool // true if UDM/UDR, false if standalone controller
	connected     bool
	lastPoll      time.Time
	lastError     string
	eventCount    int64
	connectTime   time.Time
	mu            sync.RWMutex
}

// NewUniFiConnector creates a new UniFi firewall connector.
func NewUniFiConnector(cfg ConnectorConfig) *UniFiConnector {
	// Create HTTP client with custom TLS config for self-signed certificates
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create cookie jar for session management
	jar, _ := cookiejar.New()

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
	}

	return &UniFiConnector{
		cfg:    cfg,
		client: client,
	}
}

// Name returns the connector type identifier.
func (uc *UniFiConnector) Name() string {
	return "unifi"
}

// Discover attempts to auto-detect the UniFi firewall and its configuration.
func (uc *UniFiConnector) Discover(ctx context.Context) (*FirewallInfo, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Try to connect and get system info
	if err := uc.login(ctx); err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	defer uc.logout(ctx)

	// Fetch system info
	info, err := uc.getSystemInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	return info, nil
}

// Connect establishes a session with the UniFi controller.
func (uc *UniFiConnector) Connect(ctx context.Context) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Determine if UDM/UDR or standalone
	if err := uc.detectUniFiOS(ctx); err != nil {
		uc.lastError = err.Error()
		return err
	}

	// Perform login
	if err := uc.login(ctx); err != nil {
		uc.lastError = err.Error()
		return err
	}

	uc.connected = true
	uc.connectTime = time.Now()
	uc.lastError = ""

	return nil
}

// Disconnect gracefully closes the session.
func (uc *UniFiConnector) Disconnect() error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if uc.connected {
		_ = uc.logout(ctx)
	}

	uc.connected = false
	return nil
}

// Poll fetches new firewall events from UniFi.
func (uc *UniFiConnector) Poll(ctx context.Context) ([]FirewallEvent, error) {
	uc.mu.RLock()
	if !uc.connected {
		uc.mu.RUnlock()
		return nil, fmt.Errorf("not connected")
	}
	baseURL := uc.baseURL
	uc.mu.RUnlock()

	var events []FirewallEvent

	// Fetch IPS/IDS alerts from the last hour
	ipsEvents, err := uc.fetchIPSEvents(ctx, baseURL)
	if err != nil {
		uc.mu.Lock()
		uc.lastError = fmt.Sprintf("IPS fetch error: %v", err)
		uc.mu.Unlock()
		return nil, err
	}
	events = append(events, ipsEvents...)

	// Fetch firewall alarms
	alarmEvents, err := uc.fetchAlarms(ctx, baseURL)
	if err != nil {
		uc.mu.Lock()
		uc.lastError = fmt.Sprintf("Alarm fetch error: %v", err)
		uc.mu.Unlock()
		return nil, err
	}
	events = append(events, alarmEvents...)

	// Update metrics
	uc.mu.Lock()
	uc.lastPoll = time.Now()
	uc.eventCount += int64(len(events))
	if len(events) > 0 {
		uc.lastError = ""
	}
	uc.mu.Unlock()

	return events, nil
}

// Health returns the current health status of the connector.
func (uc *UniFiConnector) Health() ConnectorHealth {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	uptime := time.Duration(0)
	if !uc.connectTime.IsZero() {
		uptime = time.Since(uc.connectTime)
	}

	return ConnectorHealth{
		Connected:  uc.connected,
		LastPoll:   uc.lastPoll,
		LastError:  uc.lastError,
		EventCount: uc.eventCount,
		Uptime:     uptime,
	}
}

// --- Private helpers ---

// detectUniFiOS determines if the controller is UDM/UDR (UniFi OS) or standalone.
func (uc *UniFiConnector) detectUniFiOS(ctx context.Context) error {
	uc.baseURL = uc.buildURL("")

	// Try UDM/UDR first (UniFi OS with /proxy/network prefix)
	req, _ := http.NewRequestWithContext(ctx, "GET", uc.baseURL+"/proxy/network/api/self", nil)
	resp, err := uc.client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		uc.isUniFiOS = true
		uc.baseURL = uc.buildURL("/proxy/network")
		return nil
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Fall back to standalone controller (no proxy prefix)
	req, _ = http.NewRequestWithContext(ctx, "GET", uc.buildURL("")+"/api/self", nil)
	resp, err = uc.client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to detect UniFi controller type")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("controller returned status %d", resp.StatusCode)
	}

	uc.isUniFiOS = false
	uc.baseURL = uc.buildURL("")
	return nil
}

// login performs authentication with the UniFi controller.
func (uc *UniFiConnector) login(ctx context.Context) error {
	loginURL := uc.baseURL + "/api/auth/login"
	body := map[string]string{
		"username": uc.cfg.Username,
		"password": uc.cfg.Password,
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := uc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// logout performs session logout.
func (uc *UniFiConnector) logout(ctx context.Context) error {
	logoutURL := uc.baseURL + "/api/auth/logout"
	req, _ := http.NewRequestWithContext(ctx, "POST", logoutURL, nil)
	resp, err := uc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// getSystemInfo fetches UniFi system information.
func (uc *UniFiConnector) getSystemInfo(ctx context.Context) (*FirewallInfo, error) {
	selfURL := uc.baseURL + "/api/self"
	req, _ := http.NewRequestWithContext(ctx, "GET", selfURL, nil)
	resp, err := uc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get self failed: status %d", resp.StatusCode)
	}

	var selfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&selfResp); err != nil {
		return nil, err
	}

	data, ok := selfResp["data"].([]interface{})
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("invalid self response format")
	}

	selfData := data[0].(map[string]interface{})

	info := &FirewallInfo{
		Model:      getStringField(selfData, "model"),
		Firmware:   getStringField(selfData, "firmware"),
		Hostname:   getStringField(selfData, "hostname"),
		Features:   []string{"ips", "dpi"},
	}

	return info, nil
}

// fetchIPSEvents fetches IPS/IDS alert events from UniFi.
func (uc *UniFiConnector) fetchIPSEvents(ctx context.Context, baseURL string) ([]FirewallEvent, error) {
	ipsURL := baseURL + "/api/s/default/stat/event?type=IPS&within=3600"
	req, _ := http.NewRequestWithContext(ctx, "GET", ipsURL, nil)
	resp, err := uc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPS fetch failed: status %d", resp.StatusCode)
	}

	var ipsResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ipsResp); err != nil {
		return nil, err
	}

	data, ok := ipsResp["data"].([]interface{})
	if !ok {
		return []FirewallEvent{}, nil
	}

	var events []FirewallEvent
	for _, item := range data {
		event := uc.parseIPSEvent(item.(map[string]interface{}))
		if event != nil {
			events = append(events, *event)
		}
	}

	return events, nil
}

// fetchAlarms fetches firewall alarm events from UniFi.
func (uc *UniFiConnector) fetchAlarms(ctx context.Context, baseURL string) ([]FirewallEvent, error) {
	alarmURL := baseURL + "/api/s/default/stat/alarm"
	req, _ := http.NewRequestWithContext(ctx, "GET", alarmURL, nil)
	resp, err := uc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alarm fetch failed: status %d", resp.StatusCode)
	}

	var alarmResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&alarmResp); err != nil {
		return nil, err
	}

	data, ok := alarmResp["data"].([]interface{})
	if !ok {
		return []FirewallEvent{}, nil
	}

	var events []FirewallEvent
	for _, item := range data {
		event := uc.parseAlarmEvent(item.(map[string]interface{}))
		if event != nil {
			events = append(events, *event)
		}
	}

	return events, nil
}

// parseIPSEvent converts a UniFi IPS event to a FirewallEvent.
func (uc *UniFiConnector) parseIPSEvent(data map[string]interface{}) *FirewallEvent {
	event := &FirewallEvent{
		Timestamp:   time.Unix(int64(getFloatField(data, "timestamp")), 0),
		Action:      "block",
		Protocol:    getStringField(data, "proto"),
		SrcIP:       getStringField(data, "srcip"),
		SrcPort:     int(getFloatField(data, "srcport")),
		DstIP:       getStringField(data, "dstip"),
		DstPort:     int(getFloatField(data, "dstport")),
		Interface:   "wan",
		Direction:   "in",
		Rule:        getStringField(data, "msg"),
		Application: getStringField(data, "app"),
		RawLog:      formatRawLog(data),
	}

	if event.SrcIP == "" || event.DstIP == "" {
		return nil
	}

	return event
}

// parseAlarmEvent converts a UniFi alarm event to a FirewallEvent.
func (uc *UniFiConnector) parseAlarmEvent(data map[string]interface{}) *FirewallEvent {
	alarmType := getStringField(data, "alarm")

	// Only process firewall-related alarms
	if !strings.Contains(alarmType, "firewall") && !strings.Contains(alarmType, "threat") {
		return nil
	}

	event := &FirewallEvent{
		Timestamp:  time.Unix(int64(getFloatField(data, "timestamp")), 0),
		Action:     "alert",
		Protocol:   "",
		Interface:  "wan",
		Direction:  "in",
		Rule:       alarmType,
		RawLog:     formatRawLog(data),
	}

	return event
}

// buildURL constructs the full URL for API requests.
func (uc *UniFiConnector) buildURL(prefix string) string {
	scheme := "https"
	port := uc.cfg.Port
	if port == 0 {
		port = 443
	}

	return fmt.Sprintf("%s://%s:%d%s", scheme, uc.cfg.Host, port, prefix)
}

// --- Helper functions ---

func getStringField(m map[string]interface{}, key string) string {
	val, ok := m[key].(string)
	if !ok {
		return ""
	}
	return val
}

func getFloatField(m map[string]interface{}, key string) float64 {
	val, ok := m[key].(float64)
	if !ok {
		return 0
	}
	return val
}

func formatRawLog(data map[string]interface{}) string {
	b, _ := json.Marshal(data)
	return string(b)
}
