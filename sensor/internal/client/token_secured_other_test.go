//go:build !windows

package client

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// assertTokenSecured verifies the persisted token file is owner-only (0600) on POSIX.
func assertTokenSecured(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if perms := info.Mode().Perm(); perms != 0o600 {
		t.Fatalf("expected token perms 0600, got %#o", perms)
	}
}

func TestEnsureSecureDirectoryCreatesDedicatedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatalf("create secure token directory: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("lstat token directory: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("token directory mode/type = %v, want directory 0700", info.Mode())
	}
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatalf("verify existing secure token directory: %v", err)
	}
}

func TestEnsureSecureDirectoryRejectsInsecureDirectoryWithoutChmod(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(dir); err == nil || !strings.Contains(err.Error(), "refusing to change") {
		t.Fatalf("insecure existing directory error = %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing shared directory was changed to %#o", got)
	}
}

func TestEnsureSecureDirectoryRejectsSymlinkAndWrongType(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink directory error = %v", err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("symlink target changed: info=%v err=%v", info, err)
	}

	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(regular); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("regular-file directory error = %v", err)
	}
}

func TestLoadTokenRejectsUnsafePathsWithoutChangingThem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "sensor-token")
	if err := os.WriteFile(tokenPath, []byte("synthetic-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(tokenPath); err == nil || !strings.Contains(err.Error(), "refusing to change") {
		t.Fatalf("insecure token error = %v", err)
	}
	info, err := os.Lstat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("insecure token file was changed to %#o", got)
	}

	target := filepath.Join(dir, "unrelated-secret")
	if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink token error = %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unrelated" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}
}

func TestReadTokenFileValidatesTheOpenedDescriptor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "sensor-token")
	if err := os.WriteFile(tokenPath, []byte("synthetic-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readTokenFile(tokenPath); err != nil || string(got) != "synthetic-token" {
		t.Fatalf("secure descriptor read = %q, %v", got, err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(tokenPath); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("insecure opened descriptor error = %v", err)
	}

	target := filepath.Join(dir, "unrelated-secret")
	if err := os.WriteFile(target, []byte("must-not-be-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-token-direct")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(link); err == nil {
		t.Fatal("descriptor read followed a token symlink")
	}
}

func TestReadTokenFileRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "sensor-token")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create token FIFO: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readTokenFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO descriptor error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("token FIFO read blocked instead of failing closed")
	}
}

func TestClearPersistedTokenRecoversMalformedLeafWithoutFollowingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "sensor-token")
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)

	if err := os.WriteFile(tokenPath, []byte("malformed-permissions"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ClearPersistedToken(); err != nil {
		t.Fatalf("clear insecure token leaf: %v", err)
	}
	if _, err := os.Lstat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("insecure token leaf remained: %v", err)
	}

	target := filepath.Join(dir, "unrelated-secret")
	if err := os.WriteFile(target, []byte("must-survive-reset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := ClearPersistedToken(); err != nil {
		t.Fatalf("clear token symlink: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "must-survive-reset" {
		t.Fatalf("reset changed symlink referent: data=%q err=%v", data, err)
	}
}

func TestClearPersistedTokenRejectsUntrustedParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "sensor-token")
	if err := os.WriteFile(tokenPath, []byte("must-remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_SENSOR_TOKEN_FILE", tokenPath)
	if err := ClearPersistedToken(); err == nil {
		t.Fatal("clear accepted an untrusted token parent")
	}
	if data, err := os.ReadFile(tokenPath); err != nil || string(data) != "must-remain" {
		t.Fatalf("rejected clear changed token: data=%q err=%v", data, err)
	}
}

func TestSecurePathsRejectWrongOwnerWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, -1); err != nil {
		t.Fatalf("chown test directory: %v", err)
	}
	if err := ensureSecureDirectory(dir); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("wrong-owner directory error = %v", err)
	}

	trustedDir := filepath.Join(root, "Vedetta")
	if err := ensureSecureDirectory(trustedDir); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(trustedDir, "sensor-token")
	if err := os.WriteFile(tokenPath, []byte("foreign-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tokenPath, 65534, -1); err != nil {
		t.Fatalf("chown test token: %v", err)
	}
	if _, err := loadToken(tokenPath); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("wrong-owner token error = %v", err)
	}
}
