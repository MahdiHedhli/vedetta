package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testTokenDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatalf("prepare protected test token directory: %v", err)
	}
	return dir
}

func testTokenPath(t *testing.T) string {
	t.Helper()
	dir := testTokenDir(t)
	path := filepath.Join(dir, "sensor-token")
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", path)
	return path
}

func TestClearPersistedTokenAllowsMissingLeafAndRejectsDirectory(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := ClearPersistedToken(); err != nil {
		t.Fatalf("clear missing token: %v", err)
	}
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ClearPersistedToken(); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory token clear error = %v", err)
	}
	if info, err := os.Lstat(tokenPath); err != nil || !info.IsDir() {
		t.Fatalf("directory token path was removed: info=%v err=%v", info, err)
	}
}

func TestCoreClientRegisterPersistsAndReloadsToken(t *testing.T) {
	tokenPath := testTokenPath(t)
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if r.URL.Path != "/api/v1/sensor/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Sensor-ID"); got != "sensor-test" {
			t.Fatalf("expected X-Sensor-ID header, got %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		switch requestCount {
		case 1:
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("expected first registration to be anonymous, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:    "registered",
				SensorID:  "sensor-test",
				AuthToken: "bootstrap-token",
				TokenID:   "token-1",
			})
		case 2:
			if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-token" {
				t.Fatalf("expected persisted bearer token on re-registration, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:   "registered",
				SensorID: "sensor-test",
			})
		default:
			t.Fatalf("unexpected extra registration request #%d", requestCount)
		}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-test"

	if err := core.Register(context.Background(), "192.168.1.0/24", true, nil); err != nil {
		t.Fatalf("register sensor: %v", err)
	}
	if !core.TokenConfigured() {
		t.Fatal("expected token to be configured after registration")
	}

	// Verify the persisted token is locked down. The check is platform-specific:
	// POSIX asserts 0600, Windows inspects the NTFS DACL (os.FileMode perms are
	// synthetic there — the old 0600 assert made the Windows CI job red at 0666).
	assertTokenSecured(t, core.TokenPath)

	data, err := os.ReadFile(core.TokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "bootstrap-token" {
		t.Fatalf("expected persisted bootstrap token, got %q", string(data))
	}

	reloaded, err := New(server.URL)
	if err != nil {
		t.Fatalf("reload core client: %v", err)
	}
	reloaded.SensorID = "sensor-test"

	if got := reloaded.authTokenSnapshot(); got != "bootstrap-token" {
		t.Fatalf("expected reloaded token, got %q", got)
	}
	if err := reloaded.Register(context.Background(), "192.168.1.0/24", true, nil); err != nil {
		t.Fatalf("re-register sensor: %v", err)
	}
}

func TestCoreClientConcurrentRegistrationAndAuthenticatedRequests(t *testing.T) {
	tokenPath := testTokenPath(t)
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sensor/register":
			n := registrations.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
				Status:    "registered",
				SensorID:  "sensor-race-test",
				AuthToken: fmt.Sprintf("rotated-token-%d", n),
			})
		case "/api/v1/sensor/dns":
			if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); !strings.HasPrefix(token, "rotated-token-") {
				http.Error(w, "missing complete token", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatalf("new core client: %v", err)
	}
	core.SensorID = "sensor-race-test"
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
		t.Fatalf("initial registration: %v", err)
	}

	errors := make(chan error, 500)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
				errors <- fmt.Errorf("registration %d: %w", i, err)
			}
		}
	}()
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := core.PushDNS(context.Background(), map[string]any{"queries": []any{}}); err != nil {
					errors <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Errorf("concurrent client operation: %v", err)
	}
	if !core.TokenConfigured() {
		t.Fatal("rotated token was not retained")
	}
}

func TestCoreClientHeartbeatUsesBoundSensorAuthentication(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-heartbeat-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensor/heartbeat" {
			t.Errorf("unexpected heartbeat request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer synthetic-heartbeat-token" {
			t.Errorf("heartbeat authorization = %q", got)
		}
		if got := r.Header.Get("X-Sensor-ID"); got != "sensor-heartbeat-client" {
			t.Errorf("heartbeat sensor id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
		received <- struct{}{}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-heartbeat-client"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := core.Heartbeat(ctx); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("heartbeat request was not received")
	}
}

func TestCoreClientAuthCheckUsesBoundSensorAuthentication(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-auth-check-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/sensor/auth-check" {
			t.Errorf("unexpected auth-check request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer synthetic-auth-check-token" {
			t.Errorf("auth-check authorization = %q", got)
		}
		if got := r.Header.Get("X-Sensor-ID"); got != "sensor-auth-check-client" {
			t.Errorf("auth-check sensor id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
		received <- struct{}{}
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-auth-check-client"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := core.AuthCheck(ctx); err != nil {
		t.Fatalf("auth check: %v", err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("auth-check request was not received")
	}
}

func TestCoreClientAuthCheckRequiresExactNoContentAndRejectsRedirects(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-exact-status-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	t.Run("generic 200 is not proof of authentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		core, err := New(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		core.SensorID = "sensor-exact-status"
		if err := core.AuthCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "unexpected status 200") {
			t.Fatalf("AuthCheck 200 error = %v, want exact-status rejection", err)
		}
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		var redirected atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			redirected.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer source.Close()
		core, err := New(source.URL)
		if err != nil {
			t.Fatal(err)
		}
		core.SensorID = "sensor-no-redirect"
		if err := core.AuthCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "unexpected status 302") {
			t.Fatalf("AuthCheck redirect error = %v, want redirect rejection", err)
		}
		if got := redirected.Load(); got != 0 {
			t.Fatalf("AuthCheck followed redirect %d time(s)", got)
		}
	})
}

func TestCoreClientNeverRedirectsEnrollmentOrBearerCredentials(t *testing.T) {
	t.Run("cross-origin enrollment code", func(t *testing.T) {
		t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))
		var targetHits atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			if got := r.Header.Get("X-Vedetta-Enrollment-Code"); got != "" {
				t.Errorf("redirect target received enrollment code %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Vedetta-Enrollment-Code"); got != "SYNTHETIC-ENROLLMENT-SECRET" {
				t.Errorf("source enrollment code = %q", got)
			}
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer source.Close()

		core, err := New(source.URL)
		if err != nil {
			t.Fatal(err)
		}
		core.SensorID = "sensor-no-enrollment-redirect"
		core.EnrollCode = "SYNTHETIC-ENROLLMENT-SECRET"
		err = core.Register(context.Background(), "192.0.2.0/24", false, nil)
		if err == nil || !strings.Contains(err.Error(), "returned 307") {
			t.Fatalf("redirected enrollment error = %v, want rejected 307", err)
		}
		if got := targetHits.Load(); got != 0 {
			t.Fatalf("enrollment redirect target was contacted %d time(s)", got)
		}
	})

	t.Run("https downgrade bearer", func(t *testing.T) {
		tokenPath := testTokenPath(t)
		if err := os.WriteFile(tokenPath, []byte("SYNTHETIC-BEARER-SECRET"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
		var targetHits atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("plaintext redirect target received bearer %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer SYNTHETIC-BEARER-SECRET" {
				t.Errorf("source bearer = %q", got)
			}
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer source.Close()

		core, err := New(source.URL)
		if err != nil {
			t.Fatal(err)
		}
		core.SensorID = "sensor-no-downgrade"
		core.httpClient = source.Client() // trust only the synthetic TLS source
		err = core.Heartbeat(context.Background())
		if err == nil || !strings.Contains(err.Error(), "returned 307") {
			t.Fatalf("redirected heartbeat error = %v, want rejected 307", err)
		}
		if got := targetHits.Load(); got != 0 {
			t.Fatalf("bearer redirect target was contacted %d time(s)", got)
		}
	})
}

func TestReachableClassifiesTransientAndPermanentFailures(t *testing.T) {
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", testTokenPath(t))

	t.Run("connection failure is transient", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close()
		core, err := New(url)
		if err != nil {
			t.Fatal(err)
		}
		err = core.Reachable(context.Background())
		if err == nil || !IsTransientReachabilityError(err) {
			t.Fatalf("Reachable closed listener error = %v, want transient", err)
		}
	})

	t.Run("caller cancellation is permanent", func(t *testing.T) {
		core, err := New("http://192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = core.Reachable(ctx)
		if err == nil || IsTransientReachabilityError(err) {
			t.Fatalf("Reachable canceled context error = %v, want non-transient", err)
		}
	})

	t.Run("malformed URL is permanent", func(t *testing.T) {
		if _, err := New("://malformed"); err == nil {
			t.Fatal("New accepted malformed Core URL")
		}
	})

	for name, rawURL := range map[string]string{
		"hostless":           "http://",
		"unsupported scheme": "ftp://127.0.0.1",
		"embedded userinfo":  "https://user:pass@example.test",
		"query":              "https://example.test?redirect=elsewhere",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(rawURL); err == nil {
				t.Fatalf("New accepted unsafe Core URL %q", rawURL)
			}
		})
	}

	t.Run("untrusted TLS certificate is permanent", func(t *testing.T) {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		defer server.Close()
		core, err := New(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		err = core.Reachable(context.Background())
		if err == nil || IsTransientReachabilityError(err) {
			t.Fatalf("Reachable TLS verification error = %v, want permanent", err)
		}
	})
}

func TestNormalizeBaseURLValidatesExplicitPort(t *testing.T) {
	valid := map[string]string{
		"no explicit port":       "http://core.example.test",
		"default HTTP port":      "http://core.example.test:80",
		"default HTTPS port":     "https://core.example.test:443",
		"lowest explicit port":   "http://core.example.test:1",
		"highest explicit port":  "http://core.example.test:65535",
		"IPv6 without port":      "http://[2001:db8::1]",
		"IPv6 with port":         "https://[2001:db8::1]:8443",
		"IPv6 zone without port": "http://[fe80::1%25en0]",
	}
	for name, rawURL := range valid {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeBaseURL(rawURL)
			if err != nil {
				t.Fatalf("normalizeBaseURL(%q): %v", rawURL, err)
			}
			if got != rawURL {
				t.Fatalf("normalizeBaseURL(%q) = %q, want unchanged", rawURL, got)
			}
		})
	}

	for name, rawURL := range map[string]string{
		"zero":              "http://core.example.test:0",
		"above maximum":     "http://core.example.test:65536",
		"five-digit excess": "http://127.0.0.1:99999",
		"nonnumeric":        "http://core.example.test:not-a-port",
		"empty":             "http://core.example.test:",
		"IPv6 zero":         "http://[2001:db8::1]:0",
		"unbracketed IPv6":  "http://2001:db8::1",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := normalizeBaseURL(rawURL); err == nil {
				t.Fatalf("normalizeBaseURL(%q) = %q, want invalid-port error", rawURL, got)
			}
		})
	}
}

func TestSuppressTokenForResetRetainsOldFileUntilReplacement(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("synthetic-old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	reject := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensor/register" {
			t.Errorf("unexpected reset request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("reset registration sent the old bearer: %q", got)
		}
		if got := r.Header.Get("X-Vedetta-Enrollment-Code"); got != "SYNTHETIC-BOUND-RESET" {
			t.Errorf("reset enrollment code = %q", got)
		}
		if reject {
			http.Error(w, "synthetic reset rejected", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
			Status:    "registered",
			SensorID:  "sensor-reset-client",
			AuthToken: "synthetic-new-token",
		})
	}))
	defer server.Close()

	core, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	core.SensorID = "sensor-reset-client"
	core.EnrollCode = "SYNTHETIC-BOUND-RESET"
	core.SuppressTokenForReset()
	if core.TokenConfigured() {
		t.Fatal("old bearer remained active in memory during reset")
	}
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err == nil {
		t.Fatal("expected the first reset registration to fail")
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != "synthetic-old-token" {
		t.Fatalf("failed reset changed rollback token: data=%q err=%v", got, err)
	}

	reject = false
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
		t.Fatalf("successful reset registration: %v", err)
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != "synthetic-new-token" {
		t.Fatalf("replacement token was not atomically persisted: data=%q err=%v", got, err)
	}
	if got := core.authTokenSnapshot(); got != "synthetic-new-token" {
		t.Fatalf("replacement token was not activated in memory: %q", got)
	}
	assertTokenSecured(t, tokenPath)
}

func TestResetRegistrationReplayRecoversAfterLocalTokenWriteFailure(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensor/register" {
			http.NotFound(w, r)
			return
		}
		registrations.Add(1)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("reset replay sent stale bearer: %q", got)
		}
		if got := r.Header.Get("X-Vedetta-Enrollment-Code"); got != "SYNTHETIC-REPLAYABLE-RESET" {
			t.Errorf("reset replay code = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sensorRegistrationResponse{
			Status:    "registered",
			SensorID:  "sensor-reset-replay",
			AuthToken: "remembered-replacement-token",
		})
	}))
	defer server.Close()

	core := &CoreClient{
		BaseURL:    server.URL,
		SensorID:   "sensor-reset-replay",
		TokenPath:  tokenPath,
		authToken:  "stale-token",
		httpClient: server.Client(),
		EnrollCode: "SYNTHETIC-REPLAYABLE-RESET",
	}
	core.SuppressTokenForReset()
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err == nil {
		t.Fatal("expected first registration to fail while token target is a directory")
	}
	if core.TokenConfigured() {
		t.Fatal("failed local persistence activated a credential in memory")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatalf("remove synthetic blocking directory: %v", err)
	}
	// Core's bounded idempotency replay returns the remembered replacement token.
	// The client must retry anonymously and persist that same credential locally.
	if err := core.Register(context.Background(), "192.0.2.0/24", false, nil); err != nil {
		t.Fatalf("replay registration: %v", err)
	}
	if got := registrations.Load(); got != 2 {
		t.Fatalf("registration calls = %d, want 2", got)
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != "remembered-replacement-token" {
		t.Fatalf("replayed replacement not persisted: data=%q err=%v", got, err)
	}
	if got := core.authTokenSnapshot(); got != "remembered-replacement-token" {
		t.Fatalf("replayed replacement not activated: %q", got)
	}
	assertTokenSecured(t, tokenPath)
}

func TestPersistTokenReadersNeverObservePartialContent(t *testing.T) {
	tokenPath := testTokenPath(t)
	oldToken := strings.Repeat("a", 32*1024)
	newToken := strings.Repeat("b", 32*1024)
	if err := os.WriteFile(tokenPath, []byte(oldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	core := &CoreClient{TokenPath: tokenPath, authToken: oldToken}

	done := make(chan struct{})
	errs := make(chan error, 8)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				data, err := readTokenFile(tokenPath)
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				got := string(data)
				if got != oldToken && got != newToken {
					select {
					case errs <- fmt.Errorf("reader observed partial token of length %d", len(got)):
					default:
					}
					return
				}
			}
		}()
	}

	for i := 0; i < 40; i++ {
		token := oldToken
		if i%2 == 0 {
			token = newToken
		}
		if err := core.persistToken(token); err != nil {
			close(done)
			readers.Wait()
			t.Fatalf("persist token %d: %v", i, err)
		}
	}
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got, err := readTokenFile(tokenPath); err != nil || string(got) != core.authTokenSnapshot() {
		t.Fatalf("disk/in-memory token mismatch after atomic writes: disk_len=%d memory_len=%d err=%v", len(got), len(core.authTokenSnapshot()), err)
	}
}

func TestPersistTokenFailurePreservesTargetAndCleansTemporaryFile(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatal(err)
	}
	core := &CoreClient{TokenPath: tokenPath, authToken: "synthetic-old-token"}

	if err := core.persistToken("synthetic-new-token"); err == nil {
		t.Fatal("expected replacement over a directory to fail")
	}
	if info, err := os.Stat(tokenPath); err != nil || !info.IsDir() {
		t.Fatalf("failed persistence damaged the existing target: info=%v err=%v", info, err)
	}
	if got := core.authTokenSnapshot(); got != "synthetic-old-token" {
		t.Fatalf("failed persistence changed in-memory token: %q", got)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sensor-token-") {
			t.Fatalf("failed persistence left temporary credential file %q", entry.Name())
		}
	}
}

func TestPersistTokenSyncFailureKeepsMemoryAlignedWithCommittedRename(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	const oldToken = "synthetic-old-token"
	const newToken = "synthetic-new-token"
	if err := os.WriteFile(tokenPath, []byte(oldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("synthetic directory sync failure")
	core := &CoreClient{
		TokenPath:     tokenPath,
		authToken:     oldToken,
		directorySync: func(string) error { return syncErr },
	}

	err := core.persistToken(newToken)
	if !errors.Is(err, syncErr) {
		t.Fatalf("persistToken error = %v, want directory sync failure", err)
	}
	if got, err := readTokenFile(tokenPath); err != nil || string(got) != newToken {
		t.Fatalf("committed token on disk = %q, err=%v; want %q", got, err, newToken)
	}
	if got := core.authTokenSnapshot(); got != newToken {
		t.Fatalf("in-memory token after committed rename = %q, want %q", got, newToken)
	}
}

func TestPreflightTokenPersistencePreservesExistingTokenAndCleansProbe(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	const token = "synthetic-preflight-token"
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	core := &CoreClient{TokenPath: tokenPath, authToken: token}

	if err := core.PreflightTokenPersistence(); err != nil {
		t.Fatalf("preflight existing token: %v", err)
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != token {
		t.Fatalf("preflight changed token: data=%q err=%v", got, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "sensor-token" {
		t.Fatalf("preflight left unexpected files: %+v", entries)
	}
}

func TestPreflightTokenPersistenceWithoutExistingTokenLeavesNoCredential(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	core := &CoreClient{TokenPath: tokenPath}

	if err := core.PreflightTokenPersistence(); err != nil {
		t.Fatalf("preflight empty token path: %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("preflight created a credential target: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("preflight left probe files: %+v", entries)
	}
}
