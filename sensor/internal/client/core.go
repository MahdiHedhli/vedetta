package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	persistMu  sync.Mutex
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
	baseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	sensorID := fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)

	tokenPath, err := DefaultTokenPath()
	if err != nil {
		return nil, err
	}
	if err := ensureSecureDirectory(filepath.Dir(tokenPath)); err != nil {
		return nil, fmt.Errorf("secure sensor token directory: %w", err)
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

func normalizeBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid Core URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid Core URL: scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid Core URL: host is required")
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid Core URL: hostname is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("invalid Core URL: embedded credentials are not allowed")
	}
	if parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid Core URL: query strings, fragments, and opaque URLs are not allowed")
	}

	// url.Parse accepts numeric ports outside TCP's valid range (for example
	// http://127.0.0.1:99999). The resulting dial error is a *net.OpError, which is
	// otherwise indistinguishable from a temporary connection outage to the
	// installer. Reject an invalid explicit port here so --check cannot false-green
	// a permanently unusable Core URL. Bracketed IPv6 hosts without a port remain
	// valid; unbracketed IPv6 is rejected because its colons are ambiguous with a
	// host:port authority.
	host := parsed.Host
	explicitPort := false
	if strings.HasPrefix(host, "[") {
		closingBracket := strings.LastIndexByte(host, ']')
		if closingBracket < 0 {
			return "", fmt.Errorf("invalid Core URL: malformed bracketed host")
		}
		remainder := host[closingBracket+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") {
				return "", fmt.Errorf("invalid Core URL: malformed bracketed host")
			}
			explicitPort = true
		}
	} else {
		switch strings.Count(host, ":") {
		case 0:
		case 1:
			explicitPort = true
		default:
			return "", fmt.Errorf("invalid Core URL: IPv6 addresses must be enclosed in brackets")
		}
	}
	if explicitPort {
		port := parsed.Port()
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", fmt.Errorf("invalid Core URL: explicit port must be a number from 1 to 65535")
		}
	}
	return strings.TrimRight(parsed.String(), "/"), nil
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

// AuthCheck validates the configured sensor bearer and its sensor-ID binding without
// changing Core state. In particular it does not refresh last_seen/status or drain
// queued scan work, so diagnostics cannot make a stopped sensor appear online.
func (c *CoreClient) AuthCheck(ctx context.Context) error {
	req, err := c.newJSONRequest(ctx, http.MethodGet, "/api/v1/sensor/auth-check", nil, false)
	if err != nil {
		return err
	}

	// A diagnostic must prove that Core itself validated this exact request, and a
	// machine credential must never follow a redirect to another origin/downgrade.
	resp, err := c.doCoreRequest(req)
	if err != nil {
		return fmt.Errorf("GET /api/v1/sensor/auth-check: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("GET /api/v1/sensor/auth-check returned unexpected status %d", resp.StatusCode)
	}
	return nil
}

// doCoreRequest refuses every redirect for Core API traffic. Go may otherwise
// forward custom enrollment headers cross-origin and Authorization across some
// same-host redirects, including an HTTPS-to-HTTP downgrade. Callers receive the
// original 3xx response and must reject it as a non-success status.
func (c *CoreClient) doCoreRequest(req *http.Request) (*http.Response, error) {
	base := c.httpClient
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

// ReachabilityError distinguishes an ordinary temporary network outage from a
// permanent/unsafe Core configuration such as an unsupported URL scheme or a TLS
// certificate verification failure. Installers may tolerate only the former.
type ReachabilityError struct {
	Err       error
	Transient bool
}

func (e *ReachabilityError) Error() string { return e.Err.Error() }
func (e *ReachabilityError) Unwrap() error { return e.Err }

// IsTransientReachabilityError reports whether a Reachable failure is a genuine
// DNS/connect/timeout condition that a long-running sensor can reasonably retry.
func IsTransientReachabilityError(err error) bool {
	var reachabilityErr *ReachabilityError
	return errors.As(err, &reachabilityErr) && reachabilityErr.Transient
}

func transientNetworkFailure(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// TLS identity/chain failures are configuration or trust failures, never an
	// acceptable "Core is merely offline" condition.
	var verificationErr *tls.CertificateVerificationError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCertErr x509.CertificateInvalidError
	var rootsErr x509.SystemRootsError
	var recordHeaderErr tls.RecordHeaderError
	if errors.As(err, &verificationErr) ||
		errors.As(err, &unknownAuthorityErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCertErr) ||
		errors.As(err, &rootsErr) ||
		errors.As(err, &recordHeaderErr) {
		return false
	}

	// Do not classify *url.Error itself as transient: it implements net.Error even
	// for permanent request/configuration failures. Only its concrete transport cause
	// may make the failure retryable.
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &dnsErr) || errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// Reachable performs a cheap unauthenticated GET against Core and returns nil if the
// server answered at all — any HTTP status, including 401/404 — which proves the
// TCP/TLS/HTTP round-trip works. Failures are typed so --check can distinguish a
// retryable connect/DNS/timeout outage from a permanent URL/TLS trust problem. It
// sends no auth and reads no body.
func (c *CoreClient) Reachable(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return &ReachabilityError{Err: err}
	}
	resp, err := c.doCoreRequest(req)
	if err != nil {
		return &ReachabilityError{Err: err, Transient: transientNetworkFailure(err)}
	}
	_ = resp.Body.Close()
	return nil
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

	resp, err := c.doCoreRequest(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
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

// SuppressTokenForReset removes the currently loaded bearer from this process without
// deleting the persisted credential. A bound reset-code registration must be anonymous.
// The old file remains intact if Core rejects the request; once Core rotates the token,
// recovery from a local write failure relies on idempotent code replay or a fresh reset
// code rather than on that now-revoked old value.
func (c *CoreClient) SuppressTokenForReset() {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.tokenMu.Lock()
	c.authToken = ""
	c.tokenMu.Unlock()
}

// PreflightTokenPersistence exercises the same secure atomic replacement path
// before a reset code is spent. When a token already exists, it rewrites the same
// value; Core therefore still accepts it if the later reset request never happens.
// This catches predictable local permission/filesystem failures, but it is not a
// two-phase transaction with Core: recovery after a failure that occurs after Core
// rotates the credential still relies on enrollment-code replay or a fresh bound
// reset code.
func (c *CoreClient) PreflightTokenPersistence() error {
	if token := c.authTokenSnapshot(); token != "" {
		if err := c.persistToken(token); err != nil {
			return fmt.Errorf("round-trip existing sensor token: %w", err)
		}
		return nil
	}

	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	dir := filepath.Dir(c.TokenPath)
	if err := ensureSecureDirectory(dir); err != nil {
		return fmt.Errorf("secure sensor token directory: %w", err)
	}

	source, err := os.CreateTemp(dir, ".sensor-token-probe-source-*")
	if err != nil {
		return fmt.Errorf("create token persistence probe: %w", err)
	}
	sourcePath := source.Name()
	target, err := os.CreateTemp(dir, ".sensor-token-probe-target-*")
	if err != nil {
		_ = source.Close()
		_ = os.Remove(sourcePath)
		return fmt.Errorf("create token replacement probe: %w", err)
	}
	targetPath := target.Name()
	defer func() {
		_ = source.Close()
		_ = target.Close()
		_ = os.Remove(sourcePath)
		_ = os.Remove(targetPath)
	}()
	if err := source.Close(); err != nil {
		return fmt.Errorf("close token persistence probe: %w", err)
	}
	if err := target.Close(); err != nil {
		return fmt.Errorf("close token replacement probe: %w", err)
	}
	if err := securePath(sourcePath, false); err != nil {
		return fmt.Errorf("secure token persistence probe: %w", err)
	}
	if err := securePath(targetPath, false); err != nil {
		return fmt.Errorf("secure token replacement probe: %w", err)
	}
	source, err = os.OpenFile(sourcePath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open token persistence probe: %w", err)
	}
	if _, err := source.WriteString("vedetta-token-persistence-probe"); err != nil {
		return fmt.Errorf("write token persistence probe: %w", err)
	}
	if err := source.Sync(); err != nil {
		return fmt.Errorf("sync token persistence probe: %w", err)
	}
	if err := source.Close(); err != nil {
		return fmt.Errorf("close token persistence probe: %w", err)
	}
	if err := replaceTokenFile(sourcePath, targetPath); err != nil {
		return fmt.Errorf("replace token persistence probe: %w", err)
	}
	if err := syncTokenDirectory(dir); err != nil {
		return fmt.Errorf("sync token persistence probe directory: %w", err)
	}
	if err := os.Remove(targetPath); err != nil {
		return fmt.Errorf("remove token persistence probe: %w", err)
	}
	if err := syncTokenDirectory(dir); err != nil {
		return fmt.Errorf("sync token persistence probe cleanup: %w", err)
	}
	return nil
}

func (c *CoreClient) persistToken(rawToken string) error {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return fmt.Errorf("sensor auth token is empty")
	}
	c.persistMu.Lock()
	defer c.persistMu.Unlock()

	dir := filepath.Dir(c.TokenPath)
	if err := ensureSecureDirectory(dir); err != nil {
		return fmt.Errorf("secure sensor token directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".sensor-token-*")
	if err != nil {
		return fmt.Errorf("create temporary sensor token file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// Close before applying the platform security primitive. On Windows this lets
	// icacls replace inheritance cleanly; on POSIX CreateTemp already starts at 0600.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary sensor token file: %w", err)
	}
	if err := securePath(tmpPath, false); err != nil {
		return fmt.Errorf("secure temporary sensor token file: %w", err)
	}
	tmp, err = os.OpenFile(tmpPath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temporary sensor token file: %w", err)
	}
	if _, err := tmp.WriteString(token); err != nil {
		return fmt.Errorf("write temporary sensor token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary sensor token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary sensor token file: %w", err)
	}
	if err := replaceTokenFile(tmpPath, c.TokenPath); err != nil {
		return fmt.Errorf("replace sensor token file: %w", err)
	}
	committed = true
	if err := syncTokenDirectory(dir); err != nil {
		return fmt.Errorf("sync sensor token directory: %w", err)
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

// ClearPersistedToken removes only the local token leaf so an operator can
// recover from a corrupt, insecure, or symlinked token file. The dedicated
// parent directory must still satisfy the platform's exact ownership/DACL and
// non-reparse invariant; unlike New, this path never reads token contents.
func ClearPersistedToken() error {
	tokenPath, err := DefaultTokenPath()
	if err != nil {
		return err
	}
	tokenPath = filepath.Clean(tokenPath)
	parent := filepath.Dir(tokenPath)
	leaf := filepath.Base(tokenPath)
	if tokenPath == parent || leaf == "." || leaf == ".." || leaf == string(filepath.Separator) {
		return fmt.Errorf("refusing unsafe sensor token path %q", tokenPath)
	}
	if err := ensureSecureDirectory(parent); err != nil {
		return fmt.Errorf("secure sensor token directory: %w", err)
	}

	info, err := os.Lstat(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect sensor token %s: %w", tokenPath, err)
	}
	// os.Remove may fall back to removing a directory. Bare reset must only
	// unlink the token leaf, never delete an actual directory at that path.
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("sensor token path %s is a directory; refusing to remove it", tokenPath)
	}
	if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sensor token %s: %w", tokenPath, err)
	}
	return nil
}

func loadToken(path string) (string, error) {
	// Lstat is intentional: a sensor token path must name the token file itself,
	// never a symlink to some unrelated credential or system file.
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat sensor token file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("sensor token path %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("sensor token path %s is not a regular file", path)
	}
	if hasInsecurePerms(info.Mode()) {
		if err := securePath(path, false); err != nil {
			return "", fmt.Errorf("secure sensor token permissions: %w", err)
		}
	}

	data, err := readTokenFile(path)
	if err != nil {
		return "", fmt.Errorf("read sensor token file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}
