package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/dbupdate"
)

func TestRunRejectsDuplicateBundleNames(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	fileA := filepath.Join(dir, "a.csv")
	fileB := filepath.Join(dir, "b.csv")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileA, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	flag.CommandLine = flag.NewFlagSet("dbbundle-test", flag.ContinueOnError)
	os.Args = []string{"dbbundle", "-key", keyPath, "-release", "db-2026.07", "-out", dir,
		"-file", "oui.csv=" + fileA, "-file", "oui.csv=" + fileB}
	if err := run(); err == nil || !strings.Contains(err.Error(), `duplicate -file name "oui.csv"`) {
		t.Fatalf("duplicate names: got %v", err)
	}
}

func TestReadBundleSourceEnforcesFileAndAggregateLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readBundleSource(path, 5, 10); !errors.Is(err, dbupdate.ErrManifestFile) {
		t.Fatalf("per-file limit: got %v, want ErrManifestFile", err)
	}
	if _, err := readBundleSource(path, 10, 5); !errors.Is(err, dbupdate.ErrManifestTooLarge) {
		t.Fatalf("aggregate limit: got %v, want ErrManifestTooLarge", err)
	}
	got, err := readBundleSource(path, 6, 6)
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("exact limits: got %q, %v", got, err)
	}
}
