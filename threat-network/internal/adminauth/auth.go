// Package adminauth authenticates the loopback-only threat-network management
// API. It is deliberately separate from reporter authentication: a telemetry
// reporter credential must never authorize corpus administration.
package adminauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
)

const (
	// MinTokenBytes is the minimum accepted management bearer-token length.
	// Operators should provision a randomly generated token of at least this
	// size; length validation cannot itself establish entropy.
	MinTokenBytes = 32

	// MaxTokenBytes bounds both configuration mistakes and request-side hashing
	// work. It remains far above the expected 32- or 64-byte random token.
	MaxTokenBytes = 4 << 10 // 4 KiB

	// Permit a small amount of surrounding whitespace in a secret file while
	// keeping the file read bounded. Whitespace is removed before validation.
	maxTokenFileBytes = MaxTokenBytes + 64
)

var (
	ErrTokenPathRequired = errors.New("management token file path is required")
	ErrTokenTooShort     = errors.New("management token must be at least 32 bytes")
	ErrTokenTooLarge     = errors.New("management token file is too large")
	ErrTokenMalformed    = errors.New("management token contains invalid whitespace or control bytes")
	ErrTokenFileType     = errors.New("management token file must be a regular non-symlink file")
	ErrTokenPermissions  = errors.New("management token file must not be accessible by group or other users")
)

// Authenticator retains only the token's SHA-256 digest. The raw management
// credential is discarded immediately after LoadFile returns.
type Authenticator struct {
	digest [sha256.Size]byte
}

// LoadFile constructs an Authenticator from a bounded secret file. Leading and
// trailing whitespace (including the conventional final newline) is ignored.
// Errors never include the token contents.
func LoadFile(path string) (*Authenticator, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrTokenPathRequired
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect management token file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, ErrTokenFileType
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrTokenPermissions
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open management token file: %w", err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened management token file: %w", err)
	}
	// Re-check the opened descriptor, and bind it to the object Lstat reviewed.
	// This closes the path-swap window between inspection and open without
	// relying on platform-specific O_NOFOLLOW flags.
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, ErrTokenFileType
	}
	if runtime.GOOS != "windows" && openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, ErrTokenPermissions
	}

	// Read into one fixed-size allocation so slice growth cannot leave earlier
	// secret-bearing buffers for the garbage collector. The extra byte is a
	// sentinel that distinguishes an exact-limit file from an oversized one.
	raw := make([]byte, maxTokenFileBytes+1)
	// The Authenticator intentionally retains only a digest. Clear the bounded
	// read buffer on every return path, including a partial non-EOF read error.
	defer func() {
		clear(raw)
		runtime.KeepAlive(raw)
	}()
	n, err := io.ReadFull(f, raw)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read management token file: %w", err)
	}
	if n > maxTokenFileBytes {
		return nil, ErrTokenTooLarge
	}

	token := bytes.TrimSpace(raw[:n])
	if len(token) < MinTokenBytes {
		return nil, ErrTokenTooShort
	}
	if len(token) > MaxTokenBytes {
		return nil, ErrTokenTooLarge
	}
	for _, b := range token {
		// Bearer credentials must fit safely in one HTTP header token. In
		// particular, reject embedded whitespace and non-printable/non-ASCII
		// bytes rather than accepting a credential that cannot be presented.
		if b <= ' ' || b > '~' {
			return nil, ErrTokenMalformed
		}
	}

	digest := sha256.Sum256(token)
	return &Authenticator{digest: digest}, nil
}

// Authenticate reports whether r carries the configured management bearer
// credential. Authentication compares fixed-size SHA-256 digests in constant
// time and never exposes the configured or presented token.
func (a *Authenticator) Authenticate(r *http.Request) bool {
	if a == nil || r == nil {
		return false
	}

	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok || len(token) > MaxTokenBytes {
		return false
	}
	tokenBytes := []byte(token)
	defer func() {
		for i := range tokenBytes {
			tokenBytes[i] = 0
		}
	}()
	presented := sha256.Sum256(tokenBytes)
	return subtle.ConstantTimeCompare(a.digest[:], presented[:]) == 1
}

// Middleware protects next with management bearer authentication. It returns a
// deliberately generic response and does not reflect credentials or detailed
// authentication failures to the caller.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Authenticate(r) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("WWW-Authenticate", `Bearer realm="vedetta-threat-network-admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"UNAUTHORIZED","message":"unauthorized"}}`+"\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
