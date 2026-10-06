//go:build !windows

package iotsecurity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAuditDoesNotReadFIFOOrDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "root", ".cling"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr", "local", "bin", ".cling"), 0o755); err != nil {
		t.Fatal(err)
	}
	observation, err := Audit(root, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Files) != 0 || coverageFor(t, observation, "/root/.cling").Status != "skipped" || coverageFor(t, observation, "/usr/local/bin/.cling").Status != "skipped" {
		t.Fatal("special files must be skipped without blocking or reading")
	}
}
