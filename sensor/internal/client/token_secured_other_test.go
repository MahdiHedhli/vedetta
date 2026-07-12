//go:build !windows

package client

import (
	"os"
	"testing"
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
