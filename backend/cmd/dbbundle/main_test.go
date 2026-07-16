package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
