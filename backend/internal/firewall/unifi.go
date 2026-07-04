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
	cfg         ConnectorConfig
	client      *http.Client
	baseURL     string
	isUniFiOS   bool // true if UDM/UDR, false if standalone controller
	connected   bool
	lastPoll    time.Time
	lastError   string
	eventCount  int64
	connectTime time.Time
	// seenEvents is a high-water dedup set of event identity keys, so IPS/alarm
	// events re-reported by the controller within its lookback window (or across
	// Core restarts within a process lifetime) are not re-inserted.
	seenEvents map[string]struct{}
	mu         sync.RWMutex
}

// eventKey derives a stable identity for a FirewallEvent for dedup across polls.
func eventKey(fe FirewallEvent) string {
	return fmt.Sprintf("%d|%s|%s|%d|%s", fe.Timestamp.Unix(), fe.SrcIP, fe.DstIP, fe.DstPort, fe.Rule)
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
	jar, _ := cookiejar.New(nil)

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
	}

	return &UniFiConnector{
		cfg:        cfg,
		client:     client,
		seenEvents: make(map[string]struct{}),
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
//
// Two auth modes are supported:
//   - X-API-KEY (preferred): when cfg.APIKey is set, requests carry the
//     "X-API-KEY" header and no interactive login/cookie session is needed. This
//     is the read-only local API-key path documented as the setup default.
//   - Cookie login (fallback): username/password POST to /api/auth/login, session
//     cookie held in the client jar.
//
// TOFU note (accepted limitation): when cfg.TLSSkipVerify is set for self-signed
// controllers, the TLS certificate is not pinned. Certificate pinning is deferred
// to a later spec; this is an intentional, documented trade-off for the alpha
// (LAN-only, off-by-default connector).
func (uc *UniFiConnector) Connect(ctx context.Context) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Determine if UDM/UDR or standalone (also sets baseURL, incl. /proxy/network).
	if err := uc.detectUniFiOS(ctx); err != nil {
		uc.lastError = err.Error()
		return err
	}

	// API-key mode skips the cookie login entirely.
	if uc.usingAPIKey() {
		uc.connected = true
		uc.connectTime = time.Now()
		uc.lastError = ""
		return nil
	}

	// Cookie login fallback.
	if err := uc.login(ctx); err != nil {
		uc.lastError = err.Error()
		return err
	}

	uc.connected = true
	uc.connectTime = time.Now()
	uc.lastError = ""

	return nil
}

// usingAPIKey reports whether the connector should authenticate via X-API-KEY.
func (uc *UniFiConnector) usingAPIKey() bool {
	return strings.TrimSpace(uc.cfg.APIKey) != ""
}

// authenticate applies the configured auth to an outgoing request. For API-key
// mode it sets the X-API-KEY header; cookie mode relies on the client jar.
func (uc *UniFiConnector) authenticate(req *http.Request) {
	if uc.usingAPIKey() {
		req.Header.Set("X-API-KEY", uc.cfg.APIKey)
		req.Header.Set("Accept", "application/json")
	}
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

	// Dedup against previously-seen events (high-water set). The controller
	// re-reports events within its lookback window on every poll; only genuinely
	// new events are returned to the sink.
	uc.mu.Lock()
	fresh := events[:0:0]
	for _, e := range events {
		k := eventKey(e)
		if _, ok := uc.seenEvents[k]; ok {
			continue
		}
		uc.seenEvents[k] = struct{}{}
		fresh = append(fresh, e)
	}
	// Bound the dedup set so a long-running process doesn't grow unbounded.
	if len(uc.seenEvents) > 20000 {
		uc.seenEvents = make(map[string]struct{})
		for _, e := range fresh {
			uc.seenEvents[eventKey(e)] = struct{}{}
		}
	}
	uc.lastPoll = time.Now()
	uc.eventCount += int64(len(fresh))
	if len(fresh) > 0 {
		uc.lastError = ""
	}
	uc.mu.Unlock()

	return fresh, nil
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
	uc.authenticate(req)
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
	uc.authenticate(req)
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
	uc.authenticate(req)
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
		Model:    getStringField(selfData, "model"),
		Firmware: getStringField(selfData, "firmware"),
		Hostname: getStringField(selfData, "hostname"),
		Features: []string{"ips", "dpi"},
	}

	return info, nil
}

// fetchIPSEvents fetches IPS/IDS alert events from UniFi.
func (uc *UniFiConnector) fetchIPSEvents(ctx context.Context, baseURL string) ([]FirewallEvent, error) {
	ipsURL := baseURL + "/api/s/default/stat/event?type=IPS&within=3600"
	req, _ := http.NewRequestWithContext(ctx, "GET", ipsURL, nil)
	uc.authenticate(req)
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
	uc.authenticate(req)
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
		Timestamp:   parseUniFiTimestamp(data),
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
		IPS:         true,
		Severity:    parseIPSSeverity(data),
	}

	if event.SrcIP == "" || event.DstIP == "" {
		return nil
	}

	return event
}

// parseIPSSeverity maps a UniFi IPS event to a 1/2/3 severity. UniFi exposes
// severity under a few keys across versions; we normalize the common ones and
// fall back to 2 (medium) when absent.
func parseIPSSeverity(data map[string]interface{}) int {
	// Numeric severity fields first.
	for _, key := range []string{"inner_alert_severity", "severity", "catname_severity"} {
		if v := int(getFloatField(data, key)); v >= 1 && v <= 3 {
			return v
		}
	}
	// String category names (e.g. "high"/"medium"/"low").
	for _, key := range []string{"severity", "catname"} {
		switch strings.ToLower(getStringField(data, key)) {
		case "high", "critical", "3":
			return 3
		case "medium", "moderate", "2":
			return 2
		case "low", "1":
			return 1
		}
	}
	return 2
}

// parseUniFiTimestamp reads a UniFi event timestamp. UniFi reports epoch millis
// (key "time") or epoch seconds (key "timestamp"); handle both.
func parseUniFiTimestamp(data map[string]interface{}) time.Time {
	if ms := int64(getFloatField(data, "time")); ms > 1_000_000_000_000 {
		return time.UnixMilli(ms).UTC()
	}
	if s := int64(getFloatField(data, "timestamp")); s > 0 {
		return time.Unix(s, 0).UTC()
	}
	return time.Now().UTC()
}

// parseAlarmEvent converts a UniFi alarm event to a FirewallEvent.
func (uc *UniFiConnector) parseAlarmEvent(data map[string]interface{}) *FirewallEvent {
	alarmType := getStringField(data, "alarm")

	// Only process firewall-related alarms
	if !strings.Contains(alarmType, "firewall") && !strings.Contains(alarmType, "threat") {
		return nil
	}

	event := &FirewallEvent{
		Timestamp: time.Unix(int64(getFloatField(data, "timestamp")), 0),
		Action:    "alert",
		Protocol:  "",
		Interface: "wan",
		Direction: "in",
		Rule:      alarmType,
		RawLog:    formatRawLog(data),
	}

	return event
}

// ClientInfo is a normalized UniFi client (station) for device-registry sync.
// Enrichment only — never turned into an event.
type ClientInfo struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
	Network  string // UniFi network/VLAN name (mapped to a canonical segment by the caller)
}

// ListClients fetches the current connected clients from the controller
// (read-only stat/sta). Used for device-inventory enrichment. Returns an empty
// slice (not an error) when the controller reports no clients.
func (uc *UniFiConnector) ListClients(ctx context.Context) ([]ClientInfo, error) {
	uc.mu.RLock()
	connected := uc.connected
	baseURL := uc.baseURL
	uc.mu.RUnlock()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	url := baseURL + "/api/s/default/stat/sta"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	uc.authenticate(req)
	resp, err := uc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client list fetch failed: status %d", resp.StatusCode)
	}

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	data, ok := out["data"].([]interface{})
	if !ok {
		return []ClientInfo{}, nil
	}

	clients := make([]ClientInfo, 0, len(data))
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		hostname := getStringField(m, "hostname")
		if hostname == "" {
			hostname = getStringField(m, "name")
		}
		ci := ClientInfo{
			IP:       getStringField(m, "ip"),
			MAC:      getStringField(m, "mac"),
			Hostname: hostname,
			Vendor:   getStringField(m, "oui"),
			Network:  getStringField(m, "network"),
		}
		if ci.IP == "" && ci.MAC == "" {
			continue
		}
		clients = append(clients, ci)
	}
	return clients, nil
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
