package adminauth

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var testToken = strings.Repeat("t", MinTokenBytes)

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFileRejectsSymlinkAndBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := LoadFile(link); !errors.Is(err, ErrTokenFileType) {
			t.Fatalf("symlink error = %v, want %v", err, ErrTokenFileType)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(target, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(target); !errors.Is(err, ErrTokenPermissions) {
			t.Fatalf("permission error = %v, want %v", err, ErrTokenPermissions)
		}
	}
}

func requestWithBearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/admin", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestLoadFileTrimsWhitespaceAndRetainsOnlyDigest(t *testing.T) {
	a, err := LoadFile(writeTokenFile(t, " \n\t"+testToken+"\r\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := sha256.Sum256([]byte(testToken))
	if a.digest != want {
		t.Fatal("authenticator did not retain the expected digest")
	}
	if !a.Authenticate(requestWithBearer(testToken)) {
		t.Fatal("trimmed token should authenticate")
	}
}

func TestLoadFileRejectsMissingWeakMalformedAndOversizedTokens(t *testing.T) {
	tests := []struct {
		name    string
		path    func(*testing.T) string
		wantErr error
	}{
		{name: "path required", path: func(*testing.T) string { return " \t" }, wantErr: ErrTokenPathRequired},
		{name: "missing file", path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, wantErr: os.ErrNotExist},
		{name: "empty", path: func(t *testing.T) string { return writeTokenFile(t, " \n\t") }, wantErr: ErrTokenTooShort},
		{name: "31 bytes", path: func(t *testing.T) string { return writeTokenFile(t, strings.Repeat("a", MinTokenBytes-1)) }, wantErr: ErrTokenTooShort},
		{name: "embedded whitespace", path: func(t *testing.T) string { return writeTokenFile(t, strings.Repeat("a", MinTokenBytes)+" b") }, wantErr: ErrTokenMalformed},
		{name: "control byte", path: func(t *testing.T) string { return writeTokenFile(t, strings.Repeat("a", MinTokenBytes)+"\x00") }, wantErr: ErrTokenMalformed},
		{name: "token too large", path: func(t *testing.T) string { return writeTokenFile(t, strings.Repeat("a", MaxTokenBytes+1)) }, wantErr: ErrTokenTooLarge},
		{name: "file too large", path: func(t *testing.T) string { return writeTokenFile(t, strings.Repeat(" ", maxTokenFileBytes+1)) }, wantErr: ErrTokenTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFile(tt.path(t))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFileAcceptsLengthBoundaries(t *testing.T) {
	for _, size := range []int{MinTokenBytes, MaxTokenBytes} {
		t.Run(strconv.Itoa(size)+"-bytes", func(t *testing.T) {
			token := strings.Repeat("a", size)
			a, err := LoadFile(writeTokenFile(t, token))
			if err != nil {
				t.Fatalf("LoadFile(%d bytes): %v", size, err)
			}
			if !a.Authenticate(requestWithBearer(token)) {
				t.Fatalf("%d-byte boundary token should authenticate", size)
			}
		})
	}
	t.Run("maximum file bytes with surrounding whitespace", func(t *testing.T) {
		token := strings.Repeat("a", MaxTokenBytes)
		contents := strings.Repeat(" ", 32) + token + strings.Repeat("\n", 32)
		if len(contents) != maxTokenFileBytes {
			t.Fatalf("fixture length = %d, want %d", len(contents), maxTokenFileBytes)
		}
		a, err := LoadFile(writeTokenFile(t, contents))
		if err != nil {
			t.Fatalf("LoadFile(exact file limit): %v", err)
		}
		if !a.Authenticate(requestWithBearer(token)) {
			t.Fatal("exact-limit padded token should authenticate")
		}
	})
}

func TestAuthenticateRequiresExactBearerCredential(t *testing.T) {
	a, err := LoadFile(writeTokenFile(t, testToken))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "exact", header: "Bearer " + testToken, want: true},
		{name: "scheme is case insensitive", header: "bEaReR " + testToken, want: true},
		{name: "wrong token", header: "Bearer " + testToken[:31] + "x"},
		{name: "prefix", header: "Bearer " + testToken[:31]},
		{name: "suffix", header: "Bearer " + testToken + "x"},
		{name: "missing", header: ""},
		{name: "wrong scheme", header: "Basic " + testToken},
		{name: "extra field", header: "Bearer " + testToken + " extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/admin", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			if got := a.Authenticate(r); got != tt.want {
				t.Fatalf("Authenticate() = %t, want %t", got, tt.want)
			}
		})
	}
	if a.Authenticate(nil) {
		t.Fatal("nil request must not authenticate")
	}
	var nilAuth *Authenticator
	if nilAuth.Authenticate(requestWithBearer(testToken)) {
		t.Fatal("nil authenticator must not authenticate")
	}
}

func TestMiddlewareRejectsGenericallyAndCallsNextOnlyWhenAuthorized(t *testing.T) {
	a, err := LoadFile(writeTokenFile(t, testToken))
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, requestWithBearer("wrong-wrong-wrong-wrong-wrong-wrong"))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", unauthorized.Code)
	}
	if called != 0 {
		t.Fatal("unauthorized request reached protected handler")
	}
	if got := unauthorized.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := unauthorized.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	if got := unauthorized.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if body := unauthorized.Body.String(); body != "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"unauthorized\"}}\n" {
		t.Fatalf("unexpected unauthorized envelope: %q", body)
	}
	if body := unauthorized.Body.String(); strings.Contains(body, testToken) || strings.Contains(body, "wrong-wrong") {
		t.Fatal("unauthorized response reflected a credential")
	}

	authorized := httptest.NewRecorder()
	h.ServeHTTP(authorized, requestWithBearer(testToken))
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", authorized.Code)
	}
	if called != 1 {
		t.Fatalf("protected handler called %d times, want 1", called)
	}
}
